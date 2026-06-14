"use client";

import { Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

interface Token {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

export default function TokensPage() {
  const router = useRouter();
  const [tokens, setTokens] = useState<Token[]>([]);
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/tokens")
      .then((r) => r.json())
      .then(setTokens);
  }, []);

  async function createToken() {
    if (!name.trim()) return;
    setLoading(true);
    const res = await fetch("/api/tokens", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    setLoading(false);
    if (res.ok) {
      setNewToken(data.token);
      setName("");
      setTokens((prev) => [
        ...prev,
        { id: data.id, name: data.name, createdAt: data.createdAt, lastUsedAt: null },
      ]);
    }
  }

  async function revokeToken(id: string) {
    setDeleting(id);
    await fetch(`/api/tokens?id=${id}`, { method: "DELETE" });
    setTokens((prev) => prev.filter((t) => t.id !== id));
    setDeleting(null);
    router.refresh();
  }

  async function copyToken() {
    if (!newToken) return;
    await navigator.clipboard.writeText(newToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">API Tokens</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Tokens are required to use the proxy once at least one is created. Pass as{" "}
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">Authorization: Bearer &lt;token&gt;</code>{" "}
          or{" "}
          <code className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs">X-API-Key: &lt;token&gt;</code>.
        </p>
      </div>

      {/* One-time token reveal */}
      {newToken && (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5">
          <p className="mb-2 text-sm font-medium text-emerald-400">
            Token created — copy it now. It will not be shown again.
          </p>
          <div className="flex items-center gap-3">
            <code className="flex-1 rounded-md bg-zinc-950 px-3 py-2 text-xs text-zinc-300 break-all">
              {newToken}
            </code>
            <button
              onClick={copyToken}
              className="shrink-0 rounded-md border border-zinc-700 px-3 py-2 text-xs text-zinc-300 transition hover:bg-zinc-800"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <button
            onClick={() => setNewToken(null)}
            className="mt-3 text-xs text-zinc-600 hover:text-zinc-400"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Create new token */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <h2 className="mb-3 text-sm font-medium text-zinc-300">New token</h2>
        <div className="flex gap-3">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && createToken()}
            placeholder="Token name (e.g. claude-desktop, ci-pipeline)"
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-500"
          />
          <button
            onClick={createToken}
            disabled={loading || !name.trim()}
            className="rounded-md bg-red-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-400 disabled:opacity-50"
          >
            {loading ? "Creating…" : "Create"}
          </button>
        </div>
      </div>

      {/* Token list */}
      {tokens.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-700 py-12 text-center text-sm text-zinc-500">
          No tokens yet. Create one above. Until a token exists, the proxy accepts all traffic.
        </div>
      ) : (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                <th className="px-5 py-3">Name</th>
                <th className="px-5 py-3">Created</th>
                <th className="px-5 py-3">Last used</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800">
              {tokens.map((token) => (
                <tr key={token.id} className="group">
                  <td className="px-5 py-3 font-medium text-zinc-200">{token.name}</td>
                  <td className="px-5 py-3 text-xs text-zinc-500">
                    {new Date(token.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-5 py-3 text-xs text-zinc-500">
                    {token.lastUsedAt
                      ? new Date(token.lastUsedAt).toLocaleDateString()
                      : "Never"}
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex justify-end opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => revokeToken(token.id)}
                        disabled={deleting === token.id}
                        className="flex items-center gap-1.5 rounded px-2 py-1 text-xs text-zinc-500 hover:text-red-400 disabled:opacity-40"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Revoke
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
