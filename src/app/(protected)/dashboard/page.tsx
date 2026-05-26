import { db, auditLogs, dlpRules } from "@/lib/db";
import { count, eq } from "drizzle-orm";
import { AlertTriangle, CheckCircle2, ShieldBan, ShieldCheck } from "lucide-react";

async function getStats() {
  const [totalRules] = await db.select({ count: count() }).from(dlpRules);
  const [enabledRules] = await db
    .select({ count: count() })
    .from(dlpRules)
    .where(eq(dlpRules.enabled, true));
  const [blockedCount] = await db
    .select({ count: count() })
    .from(auditLogs)
    .where(eq(auditLogs.severity, "block"));
  const [redactedCount] = await db
    .select({ count: count() })
    .from(auditLogs)
    .where(eq(auditLogs.severity, "redact"));

  const recentLogs = await db
    .select()
    .from(auditLogs)
    .orderBy(auditLogs.triggeredAt)
    .limit(10);

  return {
    totalRules: totalRules.count,
    enabledRules: enabledRules.count,
    blockedCount: blockedCount.count,
    redactedCount: redactedCount.count,
    recentLogs,
  };
}

const severityColors: Record<string, string> = {
  block: "text-red-400 bg-red-400/10",
  redact: "text-amber-400 bg-amber-400/10",
  warn: "text-blue-400 bg-blue-400/10",
};

export default async function DashboardPage() {
  const stats = await getStats();

  const cards = [
    {
      label: "Total Rules",
      value: stats.totalRules,
      icon: ShieldCheck,
      color: "text-emerald-400",
    },
    {
      label: "Active Rules",
      value: stats.enabledRules,
      icon: CheckCircle2,
      color: "text-blue-400",
    },
    {
      label: "Streams Blocked",
      value: stats.blockedCount,
      icon: ShieldBan,
      color: "text-red-400",
    },
    {
      label: "Payloads Redacted",
      value: stats.redactedCount,
      icon: AlertTriangle,
      color: "text-amber-400",
    },
  ];

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Real-time overview of your MCP traffic firewall
        </p>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {cards.map(({ label, value, icon: Icon, color }) => (
          <div
            key={label}
            className="rounded-xl border border-zinc-800 bg-zinc-900 p-5"
          >
            <div className="flex items-center justify-between">
              <p className="text-sm text-zinc-400">{label}</p>
              <Icon className={`h-4 w-4 ${color}`} />
            </div>
            <p className="mt-2 text-3xl font-bold">{value}</p>
          </div>
        ))}
      </div>

      {/* Recent activity */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900">
        <div className="border-b border-zinc-800 px-6 py-4">
          <h2 className="font-semibold">Recent Activity</h2>
        </div>
        {stats.recentLogs.length === 0 ? (
          <p className="px-6 py-8 text-center text-sm text-zinc-500">
            No firewall events yet. Send traffic through{" "}
            <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">
              /api/proxy/*
            </code>{" "}
            to see results.
          </p>
        ) : (
          <ul className="divide-y divide-zinc-800">
            {stats.recentLogs.map((log) => (
              <li key={log.id} className="flex items-center gap-4 px-6 py-3">
                <span
                  className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${
                    severityColors[log.severity] ?? "text-zinc-400 bg-zinc-800"
                  }`}
                >
                  {log.severity}
                </span>
                <span className="flex-1 truncate text-sm text-zinc-300">
                  {log.path}
                </span>
                {log.matchedText && (
                  <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
                    {log.matchedText.slice(0, 40)}
                  </code>
                )}
                <span className="text-xs text-zinc-600">
                  {log.triggeredAt?.toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
