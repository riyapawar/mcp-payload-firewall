export interface AiRule {
  id: string;
  name: string;
  pattern: string; // natural language description of what to detect
  severity: "block" | "redact" | "warn";
  replacement: string;
}

export interface AiFinding {
  ruleId: string;
  ruleName: string;
  matchedText: string;
  severity: "block" | "redact" | "warn";
  replacement: string;
}

/**
 * Calls GPT-4o-mini to semantically detect sensitive content.
 * Returns only findings whose matchedText is a verbatim substring of the input —
 * hallucinated matches are filtered out before returning.
 */
export async function scanWithAI(
  text: string,
  rules: AiRule[],
  apiKey: string
): Promise<AiFinding[]> {
  if (!text.trim() || rules.length === 0) return [];

  const rulesText = rules
    .map((r, i) => `${i + 1}. "${r.name}" (severity: ${r.severity}): ${r.pattern}`)
    .join("\n");

  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      temperature: 0,
      response_format: { type: "json_object" },
      max_tokens: 1024,
      messages: [
        {
          role: "system",
          content: `You are a data loss prevention security scanner.
Given a list of rules and a text payload, identify sensitive data matching each rule.

For each match return the EXACT verbatim substring from the input — character-for-character, no paraphrasing.
Return JSON: {"findings": [{"rule_index": <1-based>, "matched_text": "<exact text from input>"}]}
Return {"findings": []} if nothing matches.`,
        },
        {
          role: "user",
          content: `Rules:\n${rulesText}\n\nText to scan:\n${text}`,
        },
      ],
    }),
  });

  if (!res.ok) return [];

  let raw: { findings?: { rule_index: number; matched_text: string }[] };
  try {
    const data = await res.json();
    raw = JSON.parse(data.choices?.[0]?.message?.content ?? '{"findings":[]}');
  } catch {
    return [];
  }

  return (raw.findings ?? [])
    .map((f) => {
      const rule = rules[f.rule_index - 1];
      // Discard hallucinated matches — matched_text must exist verbatim in input
      if (!rule || !f.matched_text || !text.includes(f.matched_text)) return null;
      return {
        ruleId: rule.id,
        ruleName: rule.name,
        matchedText: f.matched_text,
        severity: rule.severity,
        replacement: rule.replacement,
      };
    })
    .filter((f): f is AiFinding => f !== null);
}
