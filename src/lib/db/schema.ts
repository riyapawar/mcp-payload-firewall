import {
  boolean,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

export const severityEnum = pgEnum("severity", ["block", "redact", "warn"]);

export const dlpRules = pgTable("dlp_rules", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  pattern: text("pattern").notNull(),
  replacement: text("replacement").notNull().default("[REDACTED]"),
  severity: severityEnum("severity").notNull().default("redact"),
  enabled: boolean("enabled").notNull().default(true),
  ruleType: text("rule_type").$type<"regex" | "ai">().notNull().default("regex"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
});

// Registered upstream MCP servers. The proxy resolves X-MCP-Server: <name>
// to the stored URL — no free-form target URLs accepted.
export const registeredServers = pgTable("registered_servers", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull().unique(),
  url: text("url").notNull(),
  description: text("description"),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
});

// API tokens for proxy access. Only the SHA-256 hash is persisted.
// The raw token is shown once at creation time and never stored.
export const apiTokens = pgTable("api_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
});

export const auditLogs = pgTable("audit_logs", {
  id: uuid("id").primaryKey().defaultRandom(),
  ruleId: uuid("rule_id").references(() => dlpRules.id, {
    onDelete: "set null",
  }),
  ruleName: text("rule_name"),
  matchedText: text("matched_text"),
  replacedWith: text("replaced_with"),
  path: text("path").notNull(),
  severity: text("severity").notNull(),
  // "request" = agent was leaking data outbound; "response" = server returned sensitive data
  direction: text("direction").$type<"request" | "response">().default("request"),
  serverName: text("server_name"),
  triggeredAt: timestamp("triggered_at", { withTimezone: true }).defaultNow(),
});

export type DlpRule = typeof dlpRules.$inferSelect;
export type NewDlpRule = typeof dlpRules.$inferInsert;
export type RegisteredServer = typeof registeredServers.$inferSelect;
export type NewRegisteredServer = typeof registeredServers.$inferInsert;
export type ApiToken = typeof apiTokens.$inferSelect;
export type NewApiToken = typeof apiTokens.$inferInsert;
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
