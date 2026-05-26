import { auth } from "@/lib/auth";
import { auditLogs, db } from "@/lib/db";
import { desc, eq } from "drizzle-orm";
import { NextRequest, NextResponse } from "next/server";

// GET /api/logs?severity=block&limit=50&offset=0
export async function GET(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = req.nextUrl;
  const severity = searchParams.get("severity");
  const limit = Math.min(parseInt(searchParams.get("limit") ?? "50"), 200);
  const offset = parseInt(searchParams.get("offset") ?? "0");

  const rows = await db
    .select()
    .from(auditLogs)
    .where(severity ? eq(auditLogs.severity, severity) : undefined)
    .orderBy(desc(auditLogs.triggeredAt))
    .limit(limit)
    .offset(offset);
  return NextResponse.json(rows);
}

// POST /api/logs — internal endpoint called by the edge proxy (fire-and-forget)
export async function POST(req: NextRequest) {
  // Lightweight shared-secret check — proxy sends X-Firewall-Key header
  const key = req.headers.get("x-firewall-key");
  if (key !== process.env.FIREWALL_INTERNAL_KEY) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = await req.json();
  const { ruleId, ruleName, matchedText, replacedWith, path, severity } = body;

  const [log] = await db
    .insert(auditLogs)
    .values({ ruleId, ruleName, matchedText, replacedWith, path, severity })
    .returning();

  return NextResponse.json(log, { status: 201 });
}
