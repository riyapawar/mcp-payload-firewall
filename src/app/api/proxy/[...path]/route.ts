import { type AiFinding, type AiRule, scanWithAI } from "@/lib/ai-scanner";
import { getRulesFromEdgeConfig } from "@/lib/edge-config";
import { type DlpRule, EdgeFirewall } from "@/lib/wasm/firewall";

export const runtime = "edge";

function jsonRpcError(id: unknown, message: string) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32600, message } }),
    { status: 403, headers: { "Content-Type": "application/json" } }
  );
}

interface DlpResult {
  output: ArrayBuffer;
  blocked: boolean;
  /** First finding to log, if any */
  finding: { ruleId: string | null; ruleName: string | null; matchedText: string | null; severity: string } | null;
}

/** Run regex + AI DLP on a text payload. Returns redacted output and metadata. */
async function applyDlp(
  rawBytes: Uint8Array,
  firewall: EdgeFirewall,
  aiRules: AiRule[],
  useAI: boolean
): Promise<DlpResult> {
  const originalText = new TextDecoder().decode(rawBytes);

  // ── Regex layer ──────────────────────────────────────────────────────────
  const regexRedacted = firewall.redact(rawBytes);
  if (regexRedacted.length === 0 && rawBytes.length > 0) {
    const scan = firewall.scan(originalText);
    const t = scan.threats[0];
    return {
      output: rawBytes.buffer as ArrayBuffer,
      blocked: true,
      finding: t ? { ruleId: t.rule_id, ruleName: t.rule_name, matchedText: originalText.slice(t.offset, t.offset + t.length), severity: "block" } : null,
    };
  }

  const regexScan = firewall.scan(originalText);

  // ── AI layer ─────────────────────────────────────────────────────────────
  let aiFindings: AiFinding[] = [];
  if (useAI) {
    aiFindings = await scanWithAI(originalText, aiRules, process.env.OPENAI_API_KEY!).catch(() => []);
  }

  // Check for AI block
  const aiBlock = aiFindings.find((f) => f.severity === "block");
  if (aiBlock) {
    return {
      output: rawBytes.buffer as ArrayBuffer,
      blocked: true,
      finding: { ruleId: aiBlock.ruleId, ruleName: aiBlock.ruleName, matchedText: aiBlock.matchedText, severity: "block" },
    };
  }

  // Apply AI redactions on top of regex-redacted text
  let processedText = new TextDecoder().decode(regexRedacted);
  for (const f of aiFindings.filter((f) => f.severity === "redact")) {
    // replaceAll so every occurrence is caught; if regex already removed it, this is a no-op
    processedText = processedText.replaceAll(f.matchedText, f.replacement);
  }

  const output = new TextEncoder().encode(processedText).buffer as ArrayBuffer;

  // Pick the first finding to surface in the audit log
  const firstRegex = regexScan.threats[0];
  const firstAI = aiFindings.find((f) => f.severity === "redact" || f.severity === "warn");
  const finding =
    firstRegex
      ? { ruleId: firstRegex.rule_id, ruleName: firstRegex.rule_name, matchedText: originalText.slice(firstRegex.offset, firstRegex.offset + firstRegex.length), severity: firstRegex.severity }
      : firstAI
      ? { ruleId: firstAI.ruleId, ruleName: firstAI.ruleName, matchedText: firstAI.matchedText, severity: firstAI.severity }
      : null;

  return { output, blocked: false, finding };
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
  const origin = new URL(req.url).origin;

  // Strip Next.js routing artifacts from query string before forwarding
  const reqUrl = new URL(req.url);
  reqUrl.searchParams.delete("path");
  const queryString = reqUrl.searchParams.toString();

  const upstreamUrl = new URL(
    "/" + path.join("/") + (queryString ? "?" + queryString : ""),
    targetBase
  );

  // Load + partition rules
  const allRules = await getRulesFromEdgeConfig()
    .then((r) => r.filter((rule) => rule.enabled))
    .catch(() => []);

  const regexRules = allRules.filter((r) => !r.ruleType || r.ruleType === "regex") as DlpRule[];
  const aiRules = allRules.filter((r) => r.ruleType === "ai") as AiRule[];
  const firewall = new EdgeFirewall(regexRules);
  const useAI = aiRules.length > 0 && !!process.env.OPENAI_API_KEY;
  const hasRules = firewall.ruleCount > 0 || useAI;

  // ── Scan + redact request body ───────────────────────────────────────────
  let body: ArrayBuffer | undefined;

  if (req.method !== "GET" && req.method !== "HEAD") {
    const rawBytes = new Uint8Array(await req.arrayBuffer());

    if (hasRules && rawBytes.length > 0) {
      const result = await applyDlp(rawBytes, firewall, aiRules, useAI);

      if (result.blocked) {
        await writeAuditLog(routePath, "block", result.finding, origin).catch(() => {});
        return jsonRpcError(null, "Request payload blocked by DLP firewall");
      }

      if (result.finding) {
        await writeAuditLog(routePath, result.finding.severity, result.finding, origin).catch(() => {});
      }

      body = result.output;
    } else {
      body = rawBytes.buffer as ArrayBuffer;
    }
  }

  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.delete("x-mcp-target");
  upstreamHeaders.delete("host");
  upstreamHeaders.delete("expect");
  if (body !== undefined) {
    upstreamHeaders.set("content-length", String(body.byteLength));
  }

  const upstreamRes = await fetch(upstreamUrl.toString(), {
    method: req.method,
    headers: upstreamHeaders,
    body,
  });

  if (!hasRules) {
    return new Response(upstreamRes.body, {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  // ── Scan + redact response body ───────────────────────────────────────────
  const isSSE = upstreamRes.headers.get("content-type")?.includes("text/event-stream");

  if (isSSE) {
    // Streaming SSE: blocks abort the stream (headers already committed)
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, controller) {
        const result = await applyDlp(chunk, firewall, aiRules, useAI);

        if (result.blocked) {
          controller.error(new Error("BLOCK"));
          await writeAuditLog(routePath, "block", result.finding, origin).catch(() => {});
          return;
        }

        if (result.finding) {
          await writeAuditLog(routePath, result.finding.severity, result.finding, origin).catch(() => {});
        }

        controller.enqueue(new Uint8Array(result.output));
      },
    });

    void upstreamRes.body?.pipeTo(writable).catch(() => {});

    const responseHeaders = new Headers(upstreamRes.headers);
    responseHeaders.delete("content-length");
    return new Response(readable, { status: upstreamRes.status, headers: responseHeaders });
  }

  // Buffered path: full response in memory for clean block detection
  const responseBytes = new Uint8Array(await upstreamRes.arrayBuffer());

  if (responseBytes.length === 0) {
    return new Response(null, { status: upstreamRes.status, headers: upstreamRes.headers });
  }

  const result = await applyDlp(responseBytes, firewall, aiRules, useAI);

  if (result.blocked) {
    await writeAuditLog(routePath, "block", result.finding, origin).catch(() => {});
    return jsonRpcError(null, "Response payload blocked by DLP firewall");
  }

  if (result.finding) {
    await writeAuditLog(routePath, result.finding.severity, result.finding, origin).catch(() => {});
  }

  const responseHeaders = new Headers(upstreamRes.headers);
  responseHeaders.set("content-length", String(result.output.byteLength));

  return new Response(result.output, { status: upstreamRes.status, headers: responseHeaders });
}

async function writeAuditLog(
  path: string,
  severity: string,
  finding: { ruleId: string | null; ruleName: string | null; matchedText: string | null } | null,
  origin: string
) {
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
      ruleId: finding?.ruleId ?? null,
      ruleName: finding?.ruleName ?? null,
      matchedText: finding?.matchedText ?? null,
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
