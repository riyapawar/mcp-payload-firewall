import { getRulesFromEdgeConfig } from "@/lib/edge-config";
import { type DlpRule, EdgeFirewall } from "@/lib/wasm/firewall";

// Edge Runtime on Vercel. For local testing use the /api/echo route with nodejs runtime.
export const runtime = "edge";

function jsonRpcError(id: unknown, message: string) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32600, message } }),
    { status: 403, headers: { "Content-Type": "application/json" } }
  );
}

// Always reads fresh rules from Edge Config — sub-millisecond in-process read on Vercel,
// so no stale-singleton problem after rule changes.
async function buildFirewall(): Promise<EdgeFirewall> {
  const rules = await getRulesFromEdgeConfig()
    .then((r) => r.filter((rule) => rule.enabled) as DlpRule[])
    .catch(() => [] as DlpRule[]);
  return new EdgeFirewall(rules);
}

async function proxyHandler(req: Request, path: string[]): Promise<Response> {
  const targetBase = req.headers.get("x-mcp-target") ?? process.env.UPSTREAM_MCP_URL ?? "";
  if (!targetBase) {
    return new Response(
      JSON.stringify({ error: "No upstream target configured" }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  const routePath = path.join("/");
  // Derive origin from the incoming request — reliable across deployments & custom domains
  const origin = new URL(req.url).origin;

  // Strip Next.js routing artifacts: Vercel Edge Runtime leaks [...path] segments
  // as ?path=... on req.url, which would be forwarded to the upstream verbatim.
  const reqUrl = new URL(req.url);
  reqUrl.searchParams.delete("path");
  const queryString = reqUrl.searchParams.toString();

  const upstreamUrl = new URL(
    "/" + path.join("/") + (queryString ? "?" + queryString : ""),
    targetBase
  );

  const firewall = await buildFirewall();

  // ── Scan + redact request body before forwarding ─────────────────────────
  let body: ArrayBuffer | undefined;

  if (req.method !== "GET" && req.method !== "HEAD") {
    const rawBuffer = await req.arrayBuffer();
    const rawBytes = new Uint8Array(rawBuffer);

    if (firewall.ruleCount > 0 && rawBytes.length > 0) {
      const redacted = firewall.redact(rawBytes);

      if (redacted.length === 0) {
        const scanResult = firewall.scan(new TextDecoder().decode(rawBytes));
        await writeAuditLog(routePath, "block", rawBytes, scanResult, origin).catch(() => {});
        return jsonRpcError(null, "Request payload blocked by DLP firewall");
      }

      const scanResult = firewall.scan(new TextDecoder().decode(rawBytes));
      if (scanResult.threats.length > 0) {
        await writeAuditLog(routePath, "redact", rawBytes, scanResult, origin).catch(() => {});
      }

      body = redacted.buffer as ArrayBuffer;
    } else {
      body = rawBuffer;
    }
  }

  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.delete("x-mcp-target");
  upstreamHeaders.delete("host");
  upstreamHeaders.delete("expect"); // Invoke-WebRequest sends Expect: 100-continue; undici rejects it
  if (body !== undefined) {
    upstreamHeaders.set("content-length", String(body.byteLength));
  }

  const upstreamRes = await fetch(upstreamUrl.toString(), {
    method: req.method,
    headers: upstreamHeaders,
    body,
  });

  if (firewall.ruleCount === 0) {
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  // ── Scan + redact response body ───────────────────────────────────────────
  const isSSE = upstreamRes.headers.get("content-type")?.includes("text/event-stream");

  if (isSSE) {
    // Streaming path for SSE: blocks abort the stream rather than returning a clean 403,
    // because response headers have already been sent before body chunks arrive.
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, controller) {
        const redacted = firewall.redact(chunk);

        if (redacted.length === 0 && chunk.length > 0) {
          controller.error(new Error("BLOCK"));
          await writeAuditLog(routePath, "block", chunk, undefined, origin).catch(() => {});
          return;
        }

        const scanResult = firewall.scan(new TextDecoder().decode(chunk));
        if (scanResult.threats.length > 0) {
          await writeAuditLog(routePath, "redact", chunk, scanResult, origin).catch(() => {});
        }

        controller.enqueue(redacted);
      },
    });

    void upstreamRes.body?.pipeTo(writable).catch(() => {});

    const responseHeaders = new Headers(upstreamRes.headers);
    responseHeaders.delete("content-length");
    return new Response(readable, { status: upstreamRes.status, headers: responseHeaders });
  }

  // Buffered path: read the full response so we can return a clean JSON-RPC error on block
  // (streaming would have already committed the 200 status before a block is detected).
  const responseBytes = new Uint8Array(await upstreamRes.arrayBuffer());

  if (responseBytes.length === 0) {
    return new Response(null, { status: upstreamRes.status, headers: upstreamRes.headers });
  }

  const redacted = firewall.redact(responseBytes);

  if (redacted.length === 0) {
    const scanResult = firewall.scan(new TextDecoder().decode(responseBytes));
    await writeAuditLog(routePath, "block", responseBytes, scanResult, origin).catch(() => {});
    return jsonRpcError(null, "Response payload blocked by DLP firewall");
  }

  const scanResult = firewall.scan(new TextDecoder().decode(responseBytes));
  if (scanResult.threats.length > 0) {
    await writeAuditLog(routePath, "redact", responseBytes, scanResult, origin).catch(() => {});
  }

  const responseHeaders = new Headers(upstreamRes.headers);
  responseHeaders.set("content-length", String(redacted.byteLength));

  return new Response(redacted.buffer as ArrayBuffer, { status: upstreamRes.status, headers: responseHeaders });
}

async function writeAuditLog(
  path: string,
  severity: string,
  chunk: Uint8Array,
  scanResult?: ReturnType<EdgeFirewall["scan"]>,
  origin?: string
) {
  const threat = scanResult?.threats[0];
  const logOrigin = origin ?? (process.env.VERCEL_URL
    ? `https://${process.env.VERCEL_URL}`
    : "http://localhost:3000");

  await fetch(`${logOrigin}/api/logs`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(process.env.FIREWALL_INTERNAL_KEY
        ? { "x-firewall-key": process.env.FIREWALL_INTERNAL_KEY }
        : {}),
    },
    body: JSON.stringify({
      ruleId: threat?.rule_id ?? null,
      ruleName: threat?.rule_name ?? null,
      matchedText: threat
        ? new TextDecoder().decode(chunk.slice(threat.offset, threat.offset + threat.length))
        : null,
      replacedWith: "[REDACTED]",
      path,
      severity,
    }),
  });
}

export async function GET(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function POST(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function PUT(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function DELETE(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function PATCH(req: Request, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  return proxyHandler(req, path);
}
