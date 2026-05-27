import { auditLogs, db, dlpRules } from "@/lib/db";
import { getRulesFromEdgeConfig } from "@/lib/edge-config";
import {
  type DlpRule,
  EdgeFirewall,
  getFirewall,
  initFirewall,
} from "@/lib/wasm/firewall";
import { eq } from "drizzle-orm";

// Edge Runtime on Vercel. For local testing use the /api/echo route with nodejs runtime.
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
    // Try Edge Config first (< 1ms on Vercel); falls back to DB if not configured
    const fromEdgeConfig = await getRulesFromEdgeConfig();
    if (fromEdgeConfig.length > 0) {
      rules = fromEdgeConfig.filter((r) => r.enabled) as DlpRule[];
    } else {
      // Local dev or Edge Config not yet populated — read directly from DB
      rules = (await db
        .select()
        .from(dlpRules)
        .where(eq(dlpRules.enabled, true))) as DlpRule[];
    }
  } catch {
    // Last resort: no rules, pass-through
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

  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.delete("x-mcp-target");
  upstreamHeaders.delete("host");
  upstreamHeaders.delete("expect"); // Invoke-WebRequest sends Expect: 100-continue; undici rejects it

  // Buffer the request body — avoids duplex streaming issues in local dev
  const body =
    req.method !== "GET" && req.method !== "HEAD"
      ? await req.arrayBuffer()
      : undefined;

  const upstreamRes = await fetch(upstreamUrl.toString(), {
    method: req.method,
    headers: upstreamHeaders,
    body,
  });

  const firewall = await getOrInitFirewall();

  // If no active rules, pass through without a transform (latency savings)
  if (firewall.ruleCount === 0) {
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  const routePath = path.join("/");
  let blocked = false;

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
    async transform(chunk, controller) {
      if (blocked) return;

      const redacted = firewall.redact(chunk);

      if (redacted.length === 0 && chunk.length > 0) {
        blocked = true;
        controller.error(new Error("BLOCK"));
        await writeAuditLog(routePath, "block", chunk).catch(() => {});
        return;
      }

      const scanResult = firewall.scan(new TextDecoder().decode(chunk));
      if (scanResult.threats.length > 0) {
        await writeAuditLog(routePath, "redact", chunk, scanResult).catch(() => {});
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

// Direct DB write — no HTTP round-trip, works reliably in nodejs runtime
async function writeAuditLog(
  path: string,
  severity: string,
  chunk: Uint8Array,
  scanResult?: ReturnType<EdgeFirewall["scan"]>
) {
  const threat = scanResult?.threats[0];
  await db.insert(auditLogs).values({
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
