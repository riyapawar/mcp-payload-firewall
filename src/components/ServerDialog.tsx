"use client";

import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

interface ServerDialogProps {
  trigger: React.ReactNode;
  server?: {
    id: string;
    name: string;
    url: string;
    description: string | null;
  };
}

export function ServerDialog({ trigger, server }: ServerDialogProps) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isEdit = !!server;

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const fd = new FormData(e.currentTarget);
    const body = {
      ...(isEdit ? { id: server.id } : {}),
      name: fd.get("name"),
      url: fd.get("url"),
      description: fd.get("description") || null,
    };

    const res = await fetch("/api/servers", {
      method: isEdit ? "PATCH" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    setLoading(false);

    if (!res.ok) {
      const data = await res.json();
      setError(data.error ?? "Something went wrong");
      return;
    }

    setOpen(false);
    router.refresh();
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>{trigger}</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
          <div className="mb-5 flex items-center justify-between">
            <Dialog.Title className="text-base font-semibold">
              {isEdit ? "Edit Server" : "Register MCP Server"}
            </Dialog.Title>
            <Dialog.Close className="rounded-md p-1 text-zinc-500 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-zinc-300">
                Name
              </label>
              <input
                name="name"
                defaultValue={server?.name}
                placeholder="production"
                required
                disabled={isEdit}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 font-mono text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-500 disabled:opacity-50"
              />
              <p className="mt-1 text-xs text-zinc-500">
                Used as the <code className="text-zinc-400">X-MCP-Server</code> header value. Letters, numbers, hyphens, underscores only.
              </p>
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-zinc-300">
                URL
              </label>
              <input
                name="url"
                type="url"
                defaultValue={server?.url}
                placeholder="https://your-mcp-server.example.com"
                required
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-500"
              />
            </div>

            <div>
              <label className="mb-1.5 block text-sm font-medium text-zinc-300">
                Description <span className="text-zinc-600">(optional)</span>
              </label>
              <input
                name="description"
                defaultValue={server?.description ?? ""}
                placeholder="Production MCP server for the data pipeline"
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-zinc-500"
              />
            </div>

            {error && (
              <p className="rounded-md bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {error}
              </p>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <Dialog.Close className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200">
                Cancel
              </Dialog.Close>
              <button
                type="submit"
                disabled={loading}
                className="rounded-md bg-red-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-400 disabled:opacity-50"
              >
                {loading ? "Saving…" : isEdit ? "Save changes" : "Register server"}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
