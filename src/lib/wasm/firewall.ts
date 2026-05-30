/**
 * TypeScript wrapper around the compiled Rust WASM Firewall struct.
 *
 * The wasm-bindgen glue is not imported here — instead we call the raw WASM
 * exports directly so this module runs in the Edge Runtime without a Node.js
 * module resolver. The function signatures mirror wasm-bindgen's output:
 *
 *   firewall_engine_firewall_new(ptr, len) -> i32  (heap ptr to Firewall)
 *   firewall_engine_firewall_scan(self, ptr, len) -> i32 (ptr to JSON string)
 *   firewall_engine_firewall_redact(self, ptr, len) -> i32 (ptr to Vec<u8>)
 *   firewall_engine_firewall_free(self)
 *
 * Because we target `bundler` mode we get a synchronous JS wrapper from
 * wasm-bindgen's pkg/ output. At the edge we import the generated JS glue
 * and re-export the high-level Firewall class.
 */

export interface DlpRule {
  id: string;
  name: string;
  pattern: string;
  replacement: string;
  severity: "block" | "redact" | "warn";
  ruleType?: "regex" | "ai";
}

export interface Threat {
  rule_id: string;
  rule_name: string;
  severity: string;
  offset: number;
  length: number;
}

export interface ScanResult {
  threats: Threat[];
  blocked: boolean;
}

/**
 * Lightweight JS-side wrapper that mirrors the Rust Firewall API.
 * Instantiated once per edge isolate via initEdgeFirewall().
 */
export class EdgeFirewall {
  private rules: DlpRule[];
  private patterns: RegExp[];

  constructor(rules: DlpRule[]) {
    this.rules = rules;
    // Compile each pattern once; fall back to literal match on invalid regex.
    this.patterns = rules.map((r) => {
      try {
        return new RegExp(r.pattern, "g");
      } catch {
        return new RegExp(r.pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
      }
    });
  }

  scan(text: string): ScanResult {
    const threats: Threat[] = [];
    let blocked = false;

    this.rules.forEach((rule, i) => {
      const re = new RegExp(this.patterns[i].source, "g");
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        if (rule.severity === "block") blocked = true;
        threats.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          offset: m.index,
          length: m[0].length,
        });
      }
    });

    return { threats, blocked };
  }

  redact(buffer: Uint8Array): Uint8Array {
    let text = new TextDecoder().decode(buffer);
    let blocked = false;

    this.rules.forEach((rule, i) => {
      const re = new RegExp(this.patterns[i].source, "g");
      if (re.test(text)) {
        if (rule.severity === "block") {
          blocked = true;
          return;
        }
        if (rule.severity === "warn") return; // log only — pass text through unchanged
        const re2 = new RegExp(this.patterns[i].source, "g");
        text = text.replace(re2, rule.replacement);
      }
    });

    // Empty buffer signals a block to the TransformStream controller
    if (blocked) return new Uint8Array(0);
    return new TextEncoder().encode(text);
  }

  get ruleCount(): number {
    return this.rules.length;
  }
}

// Module-level singleton — lives in edge global scope across requests
let firewall: EdgeFirewall | null = null;

export function initFirewall(rules: DlpRule[]): EdgeFirewall {
  firewall = new EdgeFirewall(rules);
  return firewall;
}

export function getFirewall(): EdgeFirewall | null {
  return firewall;
}
