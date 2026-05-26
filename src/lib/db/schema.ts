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
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
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
  triggeredAt: timestamp("triggered_at", { withTimezone: true }).defaultNow(),
});

export type DlpRule = typeof dlpRules.$inferSelect;
export type NewDlpRule = typeof dlpRules.$inferInsert;
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
