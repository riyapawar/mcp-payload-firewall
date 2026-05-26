import { auditLogs, db } from "@/lib/db";
import { desc } from "drizzle-orm";

const severityBadge: Record<string, string> = {
  block: "text-red-400 bg-red-400/10",
  redact: "text-amber-400 bg-amber-400/10",
  warn: "text-blue-400 bg-blue-400/10",
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
        <h1 className="text-2xl font-bold tracking-tight">Audit Logs</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Every firewall event, in order
        </p>
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        {logs.length === 0 ? (
          <p className="px-6 py-10 text-center text-sm text-zinc-500">
            No events recorded yet.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                <th className="px-5 py-3">Time</th>
                <th className="px-5 py-3">Severity</th>
                <th className="px-5 py-3">Path</th>
                <th className="px-5 py-3">Rule</th>
                <th className="px-5 py-3">Matched</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {logs.map((log) => (
                <tr key={log.id}>
                  <td className="whitespace-nowrap px-5 py-3 text-xs text-zinc-500">
                    {log.triggeredAt?.toLocaleString()}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${
                        severityBadge[log.severity] ?? "text-zinc-400 bg-zinc-800"
                      }`}
                    >
                      {log.severity}
                    </span>
                  </td>
                  <td className="max-w-[160px] truncate px-5 py-3 text-zinc-400">
                    {log.path}
                  </td>
                  <td className="px-5 py-3 text-zinc-300">
                    {log.ruleName ?? <span className="text-zinc-600">—</span>}
                  </td>
                  <td className="px-5 py-3">
                    {log.matchedText ? (
                      <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">
                        {log.matchedText.slice(0, 60)}
                      </code>
                    ) : (
                      <span className="text-zinc-600">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      <div className="flex justify-end gap-2">
        {page > 1 && (
          <a
            href={`/logs?page=${page - 1}`}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200"
          >
            Previous
          </a>
        )}
        {logs.length === limit && (
          <a
            href={`/logs?page=${page + 1}`}
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200"
          >
            Next
          </a>
        )}
      </div>
    </div>
  );
}
