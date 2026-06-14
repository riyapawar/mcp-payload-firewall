import { auditLogs, db } from "@/lib/db";
import { desc } from "drizzle-orm";

const severityConfig: Record<string, { label: string; className: string }> = {
  block:  { label: "block",  className: "text-red-400 bg-red-400/10 ring-1 ring-red-400/20" },
  redact: { label: "redact", className: "text-amber-400 bg-amber-400/10 ring-1 ring-amber-400/20" },
  warn:   { label: "warn",   className: "text-blue-400 bg-blue-400/10 ring-1 ring-blue-400/20" },
};

export default async function LogsPage({
  searchParams,
}: {
  searchParams: Promise<{ page?: string }>;
}) {
  const sp = await searchParams;
  const page = Math.max(1, parseInt(sp.page ?? "1"));
  const limit = 50;
  const offset = (page - 1) * limit;

  const logs = await db
    .select()
    .from(auditLogs)
    .orderBy(desc(auditLogs.triggeredAt))
    .limit(limit)
    .offset(offset);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Audit Logs</h1>
        <p className="mt-0.5 text-sm text-zinc-500">
          Every firewall event — request and response, in order
        </p>
      </div>

      <div className="rounded-xl border border-zinc-800/60 bg-zinc-900 overflow-hidden">
        {logs.length === 0 ? (
          <p className="px-6 py-12 text-center text-sm text-zinc-600">
            No events yet.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800/60 text-left text-[11px] font-medium uppercase tracking-wider text-zinc-600">
                <th className="px-5 py-2.5">Time</th>
                <th className="px-5 py-2.5">Severity</th>
                <th className="px-5 py-2.5">Direction</th>
                <th className="px-5 py-2.5">Rule</th>
                <th className="px-5 py-2.5">Server</th>
                <th className="px-5 py-2.5">Matched</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {logs.map((log) => {
                const sev = severityConfig[log.severity];
                const isInbound = log.direction === "response";
                return (
                  <tr key={log.id} className="transition-colors hover:bg-zinc-800/30">
                    <td className="whitespace-nowrap px-5 py-3 text-[11px] text-zinc-600">
                      {log.triggeredAt?.toLocaleString([], {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium capitalize ${sev?.className ?? "text-zinc-400 bg-zinc-800"}`}
                      >
                        {sev?.label ?? log.severity}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`text-[11px] font-medium ${isInbound ? "text-violet-400" : "text-zinc-500"}`}
                        title={isInbound ? "Data returned from MCP server" : "Data sent by client"}
                      >
                        {isInbound ? "← inbound" : "→ outbound"}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-zinc-300">
                      {log.ruleName ?? <span className="text-zinc-700">—</span>}
                    </td>
                    <td className="px-5 py-3">
                      {log.serverName ? (
                        <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-[11px] text-zinc-400">
                          {log.serverName}
                        </code>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                    <td className="max-w-[200px] px-5 py-3">
                      {log.matchedText ? (
                        <code className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-[11px] text-zinc-400">
                          {log.matchedText.length > 48
                            ? log.matchedText.slice(0, 48) + "…"
                            : log.matchedText}
                        </code>
                      ) : (
                        <span className="text-zinc-700">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="flex items-center justify-between text-xs text-zinc-600">
        <span>{logs.length < limit ? `${logs.length} events` : `Page ${page}`}</span>
        <div className="flex gap-2">
          {page > 1 && (
            <a
              href={`/logs?page=${page - 1}`}
              className="rounded-md border border-zinc-800 px-3 py-1.5 text-zinc-500 transition-colors hover:border-zinc-700 hover:text-zinc-300"
            >
              Previous
            </a>
          )}
          {logs.length === limit && (
            <a
              href={`/logs?page=${page + 1}`}
              className="rounded-md border border-zinc-800 px-3 py-1.5 text-zinc-500 transition-colors hover:border-zinc-700 hover:text-zinc-300"
            >
              Next
            </a>
          )}
        </div>
      </div>
    </div>
  );
}
