import { db, auditLogs, dlpRules, registeredServers, apiTokens } from "@/lib/db";
import { count, eq, desc } from "drizzle-orm";
import { AlertTriangle, KeyRound, Server, ShieldBan, ShieldCheck } from "lucide-react";

async function getStats() {
  const [[totalRules], [enabledRules], [blockedCount], [redactedCount], [serverCount], [tokenCount]] =
    await Promise.all([
      db.select({ count: count() }).from(dlpRules),
      db.select({ count: count() }).from(dlpRules).where(eq(dlpRules.enabled, true)),
      db.select({ count: count() }).from(auditLogs).where(eq(auditLogs.severity, "block")),
      db.select({ count: count() }).from(auditLogs).where(eq(auditLogs.severity, "redact")),
      db.select({ count: count() }).from(registeredServers),
      db.select({ count: count() }).from(apiTokens),
    ]);

  const recentLogs = await db
    .select()
    .from(auditLogs)
    .orderBy(desc(auditLogs.triggeredAt))
    .limit(8);

  return {
    totalRules: totalRules.count,
    enabledRules: enabledRules.count,
    blockedCount: blockedCount.count,
    redactedCount: redactedCount.count,
    serverCount: serverCount.count,
    tokenCount: tokenCount.count,
    recentLogs,
  };
}

const severityConfig: Record<string, { label: string; className: string }> = {
  block:  { label: "blocked",  className: "text-red-400 bg-red-400/10 ring-1 ring-red-400/20" },
  redact: { label: "redacted", className: "text-amber-400 bg-amber-400/10 ring-1 ring-amber-400/20" },
  warn:   { label: "warn",     className: "text-blue-400 bg-blue-400/10 ring-1 ring-blue-400/20" },
};

const directionLabel: Record<string, string> = {
  request: "outbound",
  response: "inbound",
};

export default async function DashboardPage() {
  const stats = await getStats();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-0.5 text-sm text-zinc-500">
          Traffic overview and recent firewall events
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label="DLP Rules"
          value={stats.enabledRules}
          sub={`${stats.totalRules} total`}
          icon={ShieldCheck}
          iconClass="text-emerald-400"
          accent="border-emerald-500/20"
        />
        <StatCard
          label="Streams Blocked"
          value={stats.blockedCount}
          sub="all time"
          icon={ShieldBan}
          iconClass="text-red-400"
          accent="border-red-500/20"
        />
        <StatCard
          label="Payloads Redacted"
          value={stats.redactedCount}
          sub="all time"
          icon={AlertTriangle}
          iconClass="text-amber-400"
          accent="border-amber-500/20"
        />
        <StatCard
          label="Servers / Tokens"
          value={`${stats.serverCount} / ${stats.tokenCount}`}
          sub="registered"
          icon={Server}
          iconClass="text-zinc-400"
          accent="border-zinc-700"
        />
      </div>

      {/* Setup nudge */}
      {(stats.serverCount === 0 || stats.tokenCount === 0) && (
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-5 py-4 text-sm">
          <p className="font-medium text-amber-300">Finish setup</p>
          <ul className="mt-1.5 space-y-1 text-amber-400/70">
            {stats.serverCount === 0 && (
              <li>
                → <a href="/servers" className="underline underline-offset-2 hover:text-amber-300">Register an MCP server</a> to enable SSRF-safe routing
              </li>
            )}
            {stats.tokenCount === 0 && (
              <li>
                → <a href="/tokens" className="underline underline-offset-2 hover:text-amber-300">Create an API token</a> to require authentication on the proxy
              </li>
            )}
          </ul>
        </div>
      )}

      {/* Recent activity */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-zinc-400">Recent activity</h2>
        <div className="rounded-xl border border-zinc-800/60 bg-zinc-900 overflow-hidden">
          {stats.recentLogs.length === 0 ? (
            <p className="px-6 py-10 text-center text-sm text-zinc-600">
              No firewall events yet. Send traffic through{" "}
              <code className="rounded bg-zinc-800 px-1 py-0.5 text-xs text-zinc-400">
                /api/proxy/*
              </code>{" "}
              to see results.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800/60 text-left text-[11px] font-medium uppercase tracking-wider text-zinc-600">
                  <th className="px-5 py-2.5">Severity</th>
                  <th className="px-5 py-2.5">Direction</th>
                  <th className="px-5 py-2.5">Rule</th>
                  <th className="px-5 py-2.5">Path</th>
                  <th className="px-5 py-2.5 text-right">Time</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {stats.recentLogs.map((log) => {
                  const sev = severityConfig[log.severity];
                  return (
                    <tr key={log.id} className="transition-colors hover:bg-zinc-800/30">
                      <td className="px-5 py-2.5">
                        <span
                          className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${sev?.className ?? "text-zinc-400 bg-zinc-800"}`}
                        >
                          {sev?.label ?? log.severity}
                        </span>
                      </td>
                      <td className="px-5 py-2.5">
                        <span className="text-xs text-zinc-500">
                          {directionLabel[log.direction ?? "request"] ?? "—"}
                        </span>
                      </td>
                      <td className="px-5 py-2.5 text-xs text-zinc-300">
                        {log.ruleName ?? <span className="text-zinc-700">—</span>}
                      </td>
                      <td className="max-w-[180px] truncate px-5 py-2.5 text-xs text-zinc-600">
                        {log.path}
                      </td>
                      <td className="whitespace-nowrap px-5 py-2.5 text-right text-[11px] text-zinc-600">
                        {log.triggeredAt?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  iconClass,
  accent,
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: React.ElementType;
  iconClass: string;
  accent: string;
}) {
  return (
    <div
      className={`rounded-xl border bg-zinc-900 p-5 border-zinc-800/60 border-l-2 ${accent}`}
    >
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium text-zinc-500">{label}</p>
        <Icon className={`h-3.5 w-3.5 ${iconClass}`} />
      </div>
      <p className="mt-3 text-2xl font-semibold tracking-tight text-zinc-100">
        {value}
      </p>
      <p className="mt-0.5 text-xs text-zinc-600">{sub}</p>
    </div>
  );
}
