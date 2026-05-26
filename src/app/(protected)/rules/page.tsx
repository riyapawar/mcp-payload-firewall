import { RuleDialog } from "@/components/RuleDialog";
import { RulesTable } from "@/components/RulesTable";
import { db, dlpRules } from "@/lib/db";
import { Plus } from "lucide-react";

export default async function RulesPage() {
  const rules = await db.select().from(dlpRules).orderBy(dlpRules.createdAt);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">DLP Rules</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Configure patterns to redact or block in MCP payloads
          </p>
        </div>
        <RuleDialog
          trigger={
            <button className="flex items-center gap-2 rounded-lg bg-red-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-red-400">
              <Plus className="h-4 w-4" />
              New rule
            </button>
          }
        />
      </div>

      <RulesTable rules={rules} />
    </div>
  );
}
