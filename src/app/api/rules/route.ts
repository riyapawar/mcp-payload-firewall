import { auth } from "@/lib/auth";
import { db, dlpRules } from "@/lib/db";
import { syncRulesToEdgeConfig } from "@/lib/edge-config";
import { eq } from "drizzle-orm";
import { NextRequest, NextResponse } from "next/server";

// GET /api/rules — list all rules
export async function GET() {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const rules = await db.select().from(dlpRules).orderBy(dlpRules.createdAt);
  return NextResponse.json(rules);
}

// POST /api/rules — create a rule
export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const { name, pattern, replacement, severity, ruleType } = body;

  if (!name || !pattern || !severity) {
    return NextResponse.json({ error: "name, pattern, and severity are required" }, { status: 400 });
  }

  // Only validate regex syntax for regex-type rules
  if (!ruleType || ruleType === "regex") {
    try { new RegExp(pattern); } catch {
      return NextResponse.json({ error: "Invalid regex pattern" }, { status: 400 });
    }
  }

  const [rule] = await db
    .insert(dlpRules)
    .values({ name, pattern, replacement: replacement ?? "[REDACTED]", severity, ruleType: ruleType ?? "regex" })
    .returning();

  await syncAfterMutation();
  return NextResponse.json(rule, { status: 201 });
}

// PATCH /api/rules — update a rule
export async function PATCH(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const { id, ...updates } = body;
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  if (updates.pattern && (!updates.ruleType || updates.ruleType === "regex")) {
    try { new RegExp(updates.pattern); } catch {
      return NextResponse.json({ error: "Invalid regex pattern" }, { status: 400 });
    }
  }

  const [rule] = await db
    .update(dlpRules)
    .set({ ...updates, updatedAt: new Date() })
    .where(eq(dlpRules.id, id))
    .returning();

  if (!rule) return NextResponse.json({ error: "Not found" }, { status: 404 });

  await syncAfterMutation();
  return NextResponse.json(rule);
}

// DELETE /api/rules?id=<uuid>
export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const id = req.nextUrl.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  await db.delete(dlpRules).where(eq(dlpRules.id, id));
  await syncAfterMutation();
  return new NextResponse(null, { status: 204 });
}

// After any mutation, push the fresh active rule set to Edge Config
async function syncAfterMutation() {
  try {
    const rules = await db
      .select()
      .from(dlpRules)
      .where(eq(dlpRules.enabled, true));
    await syncRulesToEdgeConfig(rules);
  } catch (err) {
    console.error("Edge Config sync error:", err);
    // Non-fatal — proxy will fall back to DB on next cold start
  }
}
