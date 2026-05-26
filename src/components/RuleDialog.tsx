"use client";

import { cn } from "@/lib/utils";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

interface RuleDialogProps {
  trigger: React.ReactNode;
  rule?: {
    id: string;
    name: string;
    pattern: string;
    replacement: string;
    severity: string;
  };
}

export function RuleDialog({ trigger, rule }: RuleDialogProps) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEdit = !!rule;

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const fd = new FormData(e.currentTarget);
    const body = {
      ...(isEdit ? { id: rule.id } : {}),
      name: fd.get("name"),
      pattern: fd.get("pattern"),
      replacement: fd.get("replacement") || "[REDACTED]",
      severity: fd.get("severity"),
    };

    const res = await fetch("/api/rules", {
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
              {isEdit ? "Edit Rule" : "New DLP Rule"}
            </Dialog.Title>
            <Dialog.Close className="rounded-md p-1 text-zinc-500 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <Field label="Name" name="name" defaultValue={rule?.name} placeholder="API Key Detector" required />
            <Field
              label="Pattern (regex)"
              name="pattern"
              defaultValue={rule?.pattern}
              placeholder="sk-[a-zA-Z0-9]{20,}"
              required
              mono
            />
            <Field
              label="Replacement"
              name="replacement"
              defaultValue={rule?.replacement ?? "[REDACTED]"}
              placeholder="[REDACTED]"
            />

            <div>
              <label className="mb-1.5 block text-sm font-medium text-zinc-300">
                Severity
              </label>
              <select
                name="severity"
                defaultValue={rule?.severity ?? "redact"}
                className="w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-1 focus:ring-zinc-500"
              >
                <option value="redact">Redact — replace match in-stream</option>
                <option value="block">Block — abort entire stream</option>
                <option value="warn">Warn — log only, pass through</option>
              </select>
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
                {loading ? "Saving…" : isEdit ? "Save changes" : "Create rule"}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Field({
  label,
  name,
  defaultValue,
  placeholder,
  required,
  mono,
}: {
  label: string;
  name: string;
  defaultValue?: string;
  placeholder?: string;
  required?: boolean;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-zinc-300">
        {label}
      </label>
      <input
        name={name}
        defaultValue={defaultValue}
        placeholder={placeholder}
        required={required}
        className={cn(
          "w-full rounded-md border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600",
          "focus:outline-none focus:ring-1 focus:ring-zinc-500",
          mono && "font-mono"
        )}
      />
    </div>
  );
}
