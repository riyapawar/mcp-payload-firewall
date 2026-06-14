import { get } from "@vercel/edge-config";
import type { DlpRule, RegisteredServer } from "./db/schema";

// ── Readers (called from Edge Runtime) ──────────────────────────────────────

export async function getRulesFromEdgeConfig(): Promise<DlpRule[]> {
  try {
    return (await get<DlpRule[]>("dlp_rules")) ?? [];
  } catch {
    return [];
  }
}

/** Returns a name→url map of enabled registered servers. */
export async function getServersFromEdgeConfig(): Promise<Record<string, string>> {
  try {
    return (await get<Record<string, string>>("mcp_servers")) ?? {};
  } catch {
    return {};
  }
}

/** Returns the list of SHA-256 hex hashes for valid proxy API tokens. */
export async function getTokenHashesFromEdgeConfig(): Promise<string[]> {
  try {
    return (await get<string[]>("proxy_token_hashes")) ?? [];
  } catch {
    return [];
  }
}

// ── Writers (called from Node.js API routes after DB mutations) ──────────────

async function patchEdgeConfig(
  items: Array<{ key: string; value: unknown }>
): Promise<void> {
  const token = process.env.VERCEL_EDGE_CONFIG_TOKEN;
  const edgeConfigId = process.env.EDGE_CONFIG?.match(/ecfg_[a-zA-Z0-9]+/)?.[0];

  if (!token || !edgeConfigId) return; // skip in local dev without Edge Config

  const res = await fetch(
    `https://api.vercel.com/v1/edge-config/${edgeConfigId}/items`,
    {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        items: items.map((i) => ({ operation: "upsert", key: i.key, value: i.value })),
      }),
    }
  );

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Edge Config sync failed: ${res.status} ${body}`);
  }
}

export async function syncRulesToEdgeConfig(rules: DlpRule[]): Promise<void> {
  await patchEdgeConfig([{ key: "dlp_rules", value: rules }]);
}

export async function syncServersToEdgeConfig(
  servers: RegisteredServer[]
): Promise<void> {
  const map = Object.fromEntries(
    servers.filter((s) => s.enabled).map((s) => [s.name, s.url])
  );
  await patchEdgeConfig([{ key: "mcp_servers", value: map }]);
}

export async function syncTokenHashesToEdgeConfig(hashes: string[]): Promise<void> {
  await patchEdgeConfig([{ key: "proxy_token_hashes", value: hashes }]);
}
