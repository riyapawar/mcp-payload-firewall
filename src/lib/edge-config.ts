import { get } from "@vercel/edge-config";
import type { DlpRule } from "./db/schema";

export const EDGE_CONFIG_KEY = "dlp_rules";

/**
 * Read the active rule set from Vercel Edge Config.
 * Falls back to an empty array if the key doesn't exist yet.
 */
export async function getRulesFromEdgeConfig(): Promise<DlpRule[]> {
  try {
    const rules = await get<DlpRule[]>(EDGE_CONFIG_KEY);
    return rules ?? [];
  } catch {
    return [];
  }
}

/**
 * Push the full active rule set to Vercel Edge Config.
 * Called after every create/update/delete on /api/rules.
 *
 * Requires VERCEL_EDGE_CONFIG_TOKEN and EDGE_CONFIG env vars.
 */
export async function syncRulesToEdgeConfig(rules: DlpRule[]): Promise<void> {
  const token = process.env.VERCEL_EDGE_CONFIG_TOKEN;
  const edgeConfigId = process.env.EDGE_CONFIG?.match(/ecfg_[a-zA-Z0-9]+/)?.[0];

  if (!token || !edgeConfigId) {
    // Skip sync during local dev without Edge Config configured
    return;
  }

  const res = await fetch(
    `https://api.vercel.com/v1/edge-config/${edgeConfigId}/items`,
    {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        items: [
          {
            operation: "upsert",
            key: EDGE_CONFIG_KEY,
            value: rules,
          },
        ],
      }),
    }
  );

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Edge Config sync failed: ${res.status} ${body}`);
  }
}
