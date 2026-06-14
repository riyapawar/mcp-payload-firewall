import { type AiFinding, type AiRule, scanWithAI } from "@/lib/ai-scanner";
import {
  getRulesFromEdgeConfig,
  getServersFromEdgeConfig,
  getTokenHashesFromEdgeConfig,
} from "@/lib/edge-config";
import { type DlpRule, EdgeFirewall } from "@/lib/wasm/firewall";

export const runtime = "edge";

function jsonRpcError(message: string) {
  return new Response(
    JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message } }),
    { status: 403, headers: { "Content-Type": "application/json" } }
  );
}

async function sha256hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

interface DlpResult {
  output: ArrayBuffer;
  blocked: boolean;
  finding: {
    ruleId: string | null;
    ruleName: string | null;
    matchedText: string | null;
    severity: string;
  } | null;
}

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
      finding: t
        ? {
            ruleId: t.rule_id,
            ruleName: t.rule_name,
            matchedText: originalText.slice(t.offset, t.offset + t.length),
            severity: "block",
          }
        : null,
    };
  }

  const regexScan = firewall.scan(originalText);

  // ── AI layer ─────────────────────────────────────────────────────────────
  let aiFindings: AiFinding[] = [];
  if (useAI) {
    aiFindings = await scanWithAI(
      originalText,
      aiRules,
      process.env.OPENAI_API_KEY!
    ).catch(() => []);
  }

  const aiBlock = aiFindings.find((f) => f.severity === "block");
  if (aiBlock) {
    return {
      output: rawBytes.buffer as ArrayBuffer,
      blocked: true,
      finding: {
        ruleId: aiBlock.ruleId,
        ruleName: aiBlock.ruleName,
        matchedText: aiBlock.matchedText,
        severity: "block",
      },
    };
  }

  let processedText = new TextDecoder().decode(regexRedacted);
  for (const f of aiFindings.filter((f) => f.severity === "redact")) {
    processedText = processedText.replaceAll(f.matchedText, f.replacement);
  }

  const output = new TextEncoder().encode(processedText).buffer as ArrayBuffer;

  const firstRegex = regexScan.threats[0];
  const firstAI = aiFindings.find(
    (f) => f.severity === "redact" || f.severity === "warn"
  );
  const finding = firstRegex
    ? {
        ruleId: firstRegex.rule_id,
        ruleName: firstRegex.rule_name,
        matchedText: originalText.slice(
          firstRegex.offset,
          firstRegex.offset + firstRegex.length
        ),
        severity: firstRegex.severity,
      }
    : firstAI
    ? {
        ruleId: firstAI.ruleId,
        ruleName: firstAI.ruleName,
        matchedText: firstAI.matchedText,
        severity: firstAI.severity,
      }
    : null;

  return { output, blocked: false, finding };
}

async function proxyHandler(req: Request, path: string[]): Promise<Response> {
  const origin = new URL(req.url).origin;

  // ── Token authentication ────────────────────────────────────────────────
  // Enforcement is opt-in: if no tokens are configured, all traffic passes.
  // Once the first token is added via the dashboard, auth is required.
  const tokenHashes = await getTokenHashesFromEdgeConfig();
  if (tokenHashes.length > 0) {
    const raw =
      req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ??
      req.headers.get("x-api-key") ??
      "";
    if (!raw) {
      return new Response(
        JSON.stringify({ error: "Missing API token. Pass Authorization: Bearer <token> or X-API-Key: <token>" }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }
    const hash = await sha256hex(raw);
    if (!tokenHashes.includes(hash)) {
      return new Response(
        JSON.stringify({ error: "Invalid API token" }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  // ── Upstream resolution ─────────────────────────────────────────────────
  // Preferred: X-MCP-Server: <registered-name>  (SSRF-safe)
  // Fallback:  UPSTREAM_MCP_URL env var  (admin-controlled, safe)
  // Rejected:  free-form X-MCP-Target when a server registry exists
  const servers = await getServersFromEdgeConfig();
  const hasRegistry = Object.keys(servers).length > 0;

  const serverName = req.headers.get("x-mcp-server");
  let targetBase = "";
  let resolvedServerName: string | null = null;

  if (serverName) {
    targetBase = servers[serverName] ?? "";
    if (!targetBase) {
      return new Response(
        JSON.stringify({ error: `Unknown server "${serverName}". Register it in the dashboard first.` }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
    }
    resolvedServerName = serverName;
  } else if (!hasRegistry) {
    // No server registry yet — allow legacy X-MCP-Target for backward compat
    targetBase = req.headers.get("x-mcp-target") ?? process.env.UPSTREAM_MCP_URL ?? "";
  } else {
    // Registry exists but no X-MCP-Server header — fall back to env default only
    targetBase = process.env.UPSTREAM_MCP_URL ?? "";
  }

  if (!targetBase) {
    return new Response(
      JSON.stringify({
        error: hasRegistry
          ? "No upstream target. Pass X-MCP-Server: <name> with a registered server name."
          : "No upstream target configured. Pass X-MCP-Target or set UPSTREAM_MCP_URL.",
      }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  const routePath = path.join("/");

  const reqUrl = new URL(req.url);
  reqUrl.searchParams.delete("path");
  const queryString = reqUrl.searchParams.toString();

  const upstreamUrl = new URL(
    "/" + path.join("/") + (queryString ? "?" + queryString : ""),
    targetBase
  );

  // ── Load + partition DLP rules ───────────────────────────────────────────
  const allRules = await getRulesFromEdgeConfig()
    .then((r) => r.filter((rule) => rule.enabled))
    .catch(() => []);

  const regexRules = allRules.filter(
    (r) => !r.ruleType || r.ruleType === "regex"
  ) as DlpRule[];
  const aiRules = allRules.filter((r) => r.ruleType === "ai") as AiRule[];
  const firewall = new EdgeFirewall(regexRules);
  const useAI = aiRules.length > 0 && !!process.env.OPENAI_API_KEY;
  const hasRules = firewall.ruleCount > 0 || useAI;

  // ── Scan request body ────────────────────────────────────────────────────
  let body: ArrayBuffer | undefined;

  if (req.method !== "GET" && req.method !== "HEAD") {
    const rawBytes = new Uint8Array(await req.arrayBuffer());

    if (hasRules && rawBytes.length > 0) {
      const result = await applyDlp(rawBytes, firewall, aiRules, useAI);

      if (result.blocked) {
        await writeAuditLog(
          routePath, "block", result.finding, origin, "request", resolvedServerName
        ).catch(() => {});
        return jsonRpcError(
          `Request payload blocked by DLP rule: ${result.finding?.ruleName ?? "unknown"}`
        );
      }

      if (result.finding) {
        await writeAuditLog(
          routePath, result.finding.severity, result.finding, origin, "request", resolvedServerName
        ).catch(() => {});
      }

      body = result.output;
    } else {
      body = rawBytes.buffer as ArrayBuffer;
    }
  }

  const upstreamHeaders = new Headers(req.headers);
  upstreamHeaders.delete("x-mcp-target");
  upstreamHeaders.delete("x-mcp-server");
  upstreamHeaders.delete("x-api-key");
  upstreamHeaders.delete("authorization");
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

  // ── Scan response body ───────────────────────────────────────────────────
  const isSSE = upstreamRes.headers
    .get("content-type")
    ?.includes("text/event-stream");

  if (isSSE) {
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
      async transform(chunk, controller) {
        const result = await applyDlp(chunk, firewall, aiRules, useAI);

        if (result.blocked) {
          controller.error(new Error("BLOCK"));
          await writeAuditLog(
            routePath, "block", result.finding, origin, "response", resolvedServerName
          ).catch(() => {});
          return;
        }

        if (result.finding) {
          await writeAuditLog(
            routePath, result.finding.severity, result.finding, origin, "response", resolvedServerName
          ).catch(() => {});
        }

        controller.enqueue(new Uint8Array(result.output));
      },
    });

    void upstreamRes.body?.pipeTo(writable).catch(() => {});

    const responseHeaders = new Headers(upstreamRes.headers);
    responseHeaders.delete("content-length");
    return new Response(readable, {
      status: upstreamRes.status,
      headers: responseHeaders,
    });
  }

  const responseBytes = new Uint8Array(await upstreamRes.arrayBuffer());

  if (responseBytes.length === 0) {
    return new Response(null, {
      status: upstreamRes.status,
      headers: upstreamRes.headers,
    });
  }

  const result = await applyDlp(responseBytes, firewall, aiRules, useAI);

  if (result.blocked) {
    await writeAuditLog(
      routePath, "block", result.finding, origin, "response", resolvedServerName
    ).catch(() => {});
    return jsonRpcError(
      `Response payload blocked by DLP rule: ${result.finding?.ruleName ?? "unknown"}`
    );
  }

  if (result.finding) {
    await writeAuditLog(
      routePath, result.finding.severity, result.finding, origin, "response", resolvedServerName
    ).catch(() => {});
  }

  const responseHeaders = new Headers(upstreamRes.headers);
  responseHeaders.set("content-length", String(result.output.byteLength));

  return new Response(result.output, {
    status: upstreamRes.status,
    headers: responseHeaders,
  });
}

async function writeAuditLog(
  path: string,
  severity: string,
  finding: {
    ruleId: string | null;
    ruleName: string | null;
    matchedText: string | null;
  } | null,
  origin: string,
  direction: "request" | "response",
  serverName: string | null
) {
  const logOrigin =
    origin ??
    (process.env.VERCEL_URL
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
      direction,
      serverName,
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
