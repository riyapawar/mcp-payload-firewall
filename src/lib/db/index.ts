import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema";

// Neon HTTP driver — works in both Node.js API routes and the Edge Runtime.
// Use DATABASE_URL (pooled) for all runtime queries.
const sql = neon(process.env.DATABASE_URL!);

export const db = drizzle(sql, { schema });
export * from "./schema";
