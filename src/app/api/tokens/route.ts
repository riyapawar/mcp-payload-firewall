import { auth } from "@/lib/auth";
import { apiTokens, db } from "@/lib/db";
import { syncTokenHashesToEdgeConfig } from "@/lib/edge-config";
import crypto from "crypto";
import { eq } from "drizzle-orm";
import { NextRequest, NextResponse } from "next/server";

export async function GET() {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  // Never return hashes — only metadata
  const tokens = await db
    .select({
      id: apiTokens.id,
      name: apiTokens.name,
      createdAt: apiTokens.createdAt,
      lastUsedAt: apiTokens.lastUsedAt,
    })
    .from(apiTokens)
    .orderBy(apiTokens.createdAt);

  return NextResponse.json(tokens);
}

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { name } = await req.json();
  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });

  // Generate token — shown once, never stored
  const raw = "mcpfw_" + crypto.randomBytes(32).toString("hex");
  const hash = crypto.createHash("sha256").update(raw).digest("hex");

  const [token] = await db
    .insert(apiTokens)
    .values({ name, tokenHash: hash })
    .returning({
      id: apiTokens.id,
      name: apiTokens.name,
      createdAt: apiTokens.createdAt,
    });

  await syncAfterMutation();

  // Include the raw token in this response only — it is not persisted
  return NextResponse.json({ ...token, token: raw }, { status: 201 });
}

export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const id = req.nextUrl.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  await db.delete(apiTokens).where(eq(apiTokens.id, id));
  await syncAfterMutation();
  return new NextResponse(null, { status: 204 });
}

async function syncAfterMutation() {
  try {
    const all = await db.select({ tokenHash: apiTokens.tokenHash }).from(apiTokens);
    await syncTokenHashesToEdgeConfig(all.map((t) => t.tokenHash));
  } catch (err) {
    console.error("Token hash sync error:", err);
  }
}
