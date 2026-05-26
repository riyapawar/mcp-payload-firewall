import { getRulesFromEdgeConfig } from "@/lib/edge-config";
import {
  type DlpRule,
  EdgeFirewall,
  getFirewall,
  initFirewall,
} from "@/lib/wasm/firewall";

export const runtime = "edge";

// JSON-RPC error object returned when a block-severity rule fires
function jsonRpcError(id: unknown, message: string) {
  return new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: { code: -32600, message },
    }),
    {
      status: 403,
      headers: { "Content-Type": "application/json" },
    }
  );
}

async function getOrInitFirewall(): Promise<EdgeFirewall> {
  const existing = getFirewall();
  if (existing) return existing;

  let rules: DlpRule[] = [];
  try {
    const raw = await getRulesFromEdgeConfig();
    rules = raw.filter((r) => r.enabled) as DlpRule[];
  } catch {
    // Edge Config not configured — run with zero rules (pass-through)
  }

  return initFirewall(rules);
}

// Shared handler for GET, POST, PUT, DELETE, PATCH
async function proxyHandler(req: Request, path: string[]): Promise<Response> {
  // Target MCP server URL comes from the X-MCP-Target header or env default
  const targetBase =
    req.headers.get("x-mcp-target") ?? process.env.UPSTREAM_MCP_URL ?? "";

  if (!targetBase) {
    return new Response(
      JSON.stringify({ error: "No upstream target configured" }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  const upstreamUrl = new URL(
    "/" + path.join("/") + (req.url.includes("?") ? "?" + req.url.split("?")[1] : ""),
    targetBase
  );

  // Forward the request to the upstream MCP server
  const upstreamRes = await fetch(upstreamUrl.toString(), {
    method: req.method,
    headers: (() => {
      const h = new Headers(req.headers);
      h.delete("x-mcp-target");
      h.delete("host");
      return h;
    })(),
    body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
    // @ts-expect-error duplex is required for streaming body in some runtimes
    duplex: "half",
  });

  const firewall = await getOrInitFirewall();

  // If no active rules, pass through without a transform (latency savings)
  if (firewall.ruleCount === 0) {
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  const origin = new URL(req.url).origin;
  let blocked = false;

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      if (blocked) return; // drain remaining chunks after a block signal

      const redacted = firewall.redact(chunk);

      if (redacted.length === 0 && chunk.length > 0) {
        // Empty return from redact() = block-severity match
        blocked = true;
        controller.error(new Error("BLOCK"));

        // Fire-and-forget audit log for the block event
        logThreat(origin, path.join("/"), "block", chunk).catch(() => {});
        return;
      }

      // Log warn/redact threats asynchronously — never on the critical path
      const scanResult = firewall.scan(new TextDecoder().decode(chunk));
      if (scanResult.threats.length > 0) {
        logThreat(origin, path.join("/"), "redact", chunk, scanResult).catch(
          () => {}
        );
      }

      controller.enqueue(redacted);
    },
  });

  // Pipe upstream body through the firewall transform
  const pipePromise = upstreamRes.body
    ?.pipeTo(writable)
    .catch(() => {/* block or upstream error — stream already errored */});

  void pipePromise;

  if (blocked) {
    return jsonRpcError(null, "Payload blocked by DLP firewall");
  }

  const responseHeaders = new Headers(upstreamRes.headers);
  // Remove content-length — transform changes body size
  responseHeaders.delete("content-length");

  return new Response(readable, {
    status: upstreamRes.status,
    headers: responseHeaders,
  });
}

// Fire-and-forget: write to audit log via the internal /api/logs endpoint
async function logThreat(
  origin: string,
  path: string,
  severity: string,
  chunk: Uint8Array,
  scanResult?: ReturnType<EdgeFirewall["scan"]>
) {
  const threat = scanResult?.threats[0];
  await fetch(`${origin}/api/logs`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-firewall-key": process.env.FIREWALL_INTERNAL_KEY ?? "",
    },
    body: JSON.stringify({
      ruleId: threat?.rule_id ?? null,
      ruleName: null,
      matchedText: threat
        ? new TextDecoder().decode(
            chunk.slice(threat.offset, threat.offset + threat.length)
          )
        : null,
      replacedWith: "[REDACTED]",
      path,
      severity,
    }),
  });
}

export async function GET(
  req: Request,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function POST(
  req: Request,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function PUT(
  req: Request,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function DELETE(
  req: Request,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  return proxyHandler(req, path);
}

export async function PATCH(
  req: Request,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  return proxyHandler(req, path);
}
