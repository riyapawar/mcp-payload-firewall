import { auth } from "@/lib/auth";
import { db, registeredServers } from "@/lib/db";
import { syncServersToEdgeConfig } from "@/lib/edge-config";
import { eq } from "drizzle-orm";
import { NextRequest, NextResponse } from "next/server";

export async function GET() {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const servers = await db.select().from(registeredServers).orderBy(registeredServers.createdAt);
  return NextResponse.json(servers);
}

export async function POST(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { name, url, description } = await req.json();

  if (!name || !url) {
    return NextResponse.json({ error: "name and url are required" }, { status: 400 });
  }

  try { new URL(url); } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  // Names become the X-MCP-Server header value — only allow safe identifiers
  if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
    return NextResponse.json(
      { error: "Name must contain only letters, numbers, hyphens, and underscores" },
      { status: 400 }
    );
  }

  const [server] = await db
    .insert(registeredServers)
    .values({ name, url, description })
    .returning();

  await syncAfterMutation();
  return NextResponse.json(server, { status: 201 });
}

export async function PATCH(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id, ...updates } = await req.json();
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  if (updates.url) {
    try { new URL(updates.url); } catch {
      return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
    }
  }

  const [server] = await db
    .update(registeredServers)
    .set(updates)
    .where(eq(registeredServers.id, id))
    .returning();

  if (!server) return NextResponse.json({ error: "Not found" }, { status: 404 });

  await syncAfterMutation();
  return NextResponse.json(server);
}

export async function DELETE(req: NextRequest) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const id = req.nextUrl.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id required" }, { status: 400 });

  await db.delete(registeredServers).where(eq(registeredServers.id, id));
  await syncAfterMutation();
  return new NextResponse(null, { status: 204 });
}

async function syncAfterMutation() {
  try {
    const all = await db.select().from(registeredServers);
    await syncServersToEdgeConfig(all);
  } catch (err) {
    console.error("Edge Config sync error:", err);
  }
}
