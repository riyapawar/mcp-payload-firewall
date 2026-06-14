import { ServerDialog } from "@/components/ServerDialog";
import { ServerTable } from "@/components/ServerTable";
import { db, registeredServers } from "@/lib/db";
import { Plus } from "lucide-react";

export default async function ServersPage() {
  const servers = await db.select().from(registeredServers).orderBy(registeredServers.createdAt);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">MCP Servers</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Register upstream MCP servers. The proxy resolves{" "}
            <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">X-MCP-Server: &lt;name&gt;</code>{" "}
            to the stored URL — no arbitrary target URLs are accepted.
          </p>
        </div>
        <ServerDialog
          trigger={
            <button className="flex items-center gap-1.5 rounded-md bg-red-500 px-3 py-2 text-sm font-medium text-white transition hover:bg-red-400">
              <Plus className="h-4 w-4" />
              Register server
            </button>
          }
        />
      </div>

      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <h2 className="mb-3 text-sm font-medium text-zinc-300">How to use</h2>
        <div className="space-y-2 text-xs text-zinc-500">
          <p>
            Once registered, point your MCP client at the proxy and reference the server by name:
          </p>
          <pre className="rounded-md bg-zinc-950 p-3 text-zinc-400 overflow-x-auto">{`POST https://your-deployment.vercel.app/api/proxy/messages
X-MCP-Server: production
Authorization: Bearer mcpfw_...`}</pre>
          <p className="text-zinc-600">
            The proxy looks up <code className="text-zinc-500">production</code> in this registry, forwards to the stored URL, and applies DLP rules to both request and response.
          </p>
        </div>
      </div>

      <ServerTable servers={servers} />
    </div>
  );
}
