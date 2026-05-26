use aho_corasick::{AhoCorasick, Match};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    pub replacement: String,
    pub severity: String, // "block" | "redact" | "warn"
}

#[derive(Serialize)]
pub struct Threat {
    pub rule_id: String,
    pub severity: String,
    pub offset: usize,
    pub length: usize,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub threats: Vec<Threat>,
    pub blocked: bool,
}

#[wasm_bindgen]
pub struct Firewall {
    ac: AhoCorasick,
    rules: Vec<Rule>,
}

#[wasm_bindgen]
impl Firewall {
    /// Build the automaton from a JSON array of Rule objects.
    #[wasm_bindgen(constructor)]
    pub fn new(rules_json: &str) -> Result<Firewall, JsError> {
        let rules: Vec<Rule> =
            serde_json::from_str(rules_json).map_err(|e| JsError::new(&e.to_string()))?;

        let patterns: Vec<&str> = rules.iter().map(|r| r.pattern.as_str()).collect();

        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(false)
            .build(patterns)
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(Firewall { ac, rules })
    }

    /// Scan the buffer and return a JSON ScanResult.
    /// Does NOT mutate the buffer — call redact() to get the sanitised copy.
    pub fn scan(&self, buffer: &[u8]) -> Result<JsValue, JsError> {
        let mut threats: Vec<Threat> = Vec::new();
        let mut blocked = false;

        for m in self.ac.find_iter(buffer) {
            let rule = &self.rules[m.pattern().as_usize()];
            if rule.severity == "block" {
                blocked = true;
            }
            threats.push(Threat {
                rule_id: rule.id.clone(),
                severity: rule.severity.clone(),
                offset: m.start(),
                length: m.end() - m.start(),
            });
        }

        let result = ScanResult { threats, blocked };
        serde_json::to_string(&result)
            .map(|s| JsValue::from_str(&s))
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Return a redacted copy of `buffer` with all pattern matches replaced.
    /// If any match has severity "block", returns an empty Vec (caller aborts stream).
    pub fn redact(&self, buffer: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(buffer.len());
        let mut cursor = 0usize;

        let mut matches: Vec<Match> = self.ac.find_iter(buffer).collect();
        // Sort by start position (Aho-Corasick guarantees left-to-right but be safe)
        matches.sort_by_key(|m| m.start());

        for m in &matches {
            let rule = &self.rules[m.pattern().as_usize()];
            // Block-severity: return empty signal so the caller can abort the stream
            if rule.severity == "block" {
                return Vec::new();
            }
            // Copy bytes before this match
            if m.start() > cursor {
                out.extend_from_slice(&buffer[cursor..m.start()]);
            }
            // Write replacement bytes
            out.extend_from_slice(rule.replacement.as_bytes());
            cursor = m.end();
        }

        // Remaining bytes after last match
        if cursor < buffer.len() {
            out.extend_from_slice(&buffer[cursor..]);
        }

        out
    }

    /// Return the number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}
