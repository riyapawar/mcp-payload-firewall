"use client";

import type { DlpRule } from "@/lib/db/schema";
import { Pencil, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { RuleDialog } from "./RuleDialog";

const severityBadge: Record<string, string> = {
  block: "text-red-400 bg-red-400/10 ring-red-400/20",
  redact: "text-amber-400 bg-amber-400/10 ring-amber-400/20",
  warn: "text-blue-400 bg-blue-400/10 ring-blue-400/20",
};

export function RulesTable({ rules }: { rules: DlpRule[] }) {
  const router = useRouter();
  const [deleting, setDeleting] = useState<string | null>(null);

  async function toggleEnabled(rule: DlpRule) {
    await fetch("/api/rules", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: rule.id, enabled: !rule.enabled }),
    });
    router.refresh();
  }

  async function deleteRule(id: string) {
    setDeleting(id);
    await fetch(`/api/rules?id=${id}`, { method: "DELETE" });
    setDeleting(null);
    router.refresh();
  }

  if (rules.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-zinc-700 py-12 text-center text-sm text-zinc-500">
        No rules yet. Add one to start protecting your MCP traffic.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-800 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
            <th className="px-5 py-3">Name</th>
            <th className="px-5 py-3">Pattern</th>
            <th className="px-5 py-3">Severity</th>
            <th className="px-5 py-3">Enabled</th>
            <th className="px-5 py-3" />
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800">
          {rules.map((rule) => (
            <tr key={rule.id} className="group transition-colors hover:bg-zinc-800/40">
              <td className="px-5 py-3">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-zinc-200">{rule.name}</span>
                  {rule.ruleType === "ai" && (
                    <span className="inline-flex items-center rounded-full bg-violet-500/10 px-1.5 py-0.5 text-xs font-medium text-violet-400 ring-1 ring-inset ring-violet-500/20">
                      AI
                    </span>
                  )}
                </div>
              </td>
              <td className="px-5 py-3">
                {rule.ruleType === "ai" ? (
                  <span className="text-xs italic text-zinc-500 max-w-[220px] truncate block">{rule.pattern}</span>
                ) : (
                  <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
                    {rule.pattern}
                  </code>
                )}
              </td>
              <td className="px-5 py-3">
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset capitalize ${
                    severityBadge[rule.severity] ?? "text-zinc-400 bg-zinc-800 ring-zinc-700"
                  }`}
                >
                  {rule.severity}
                </span>
              </td>
              <td className="px-5 py-3">
                <button
                  onClick={() => toggleEnabled(rule)}
                  className={`relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none ${
                    rule.enabled ? "bg-emerald-500" : "bg-zinc-700"
                  }`}
                  aria-label="toggle"
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white shadow transition ${
                      rule.enabled ? "translate-x-4" : "translate-x-0"
                    }`}
                  />
                </button>
              </td>
              <td className="px-5 py-3">
                <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity justify-end">
                  <RuleDialog
                    rule={{
                      id: rule.id,
                      name: rule.name,
                      pattern: rule.pattern,
                      replacement: rule.replacement,
                      severity: rule.severity,
                      ruleType: rule.ruleType ?? "regex",
                    }}
                    trigger={
                      <button className="rounded p-1 text-zinc-500 hover:text-zinc-300">
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                    }
                  />
                  <button
                    onClick={() => deleteRule(rule.id)}
                    disabled={deleting === rule.id}
                    className="rounded p-1 text-zinc-500 hover:text-red-400 disabled:opacity-40"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
