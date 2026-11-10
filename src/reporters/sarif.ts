import type { Finding, Severity } from "../core/finding.js";
import type { ScanResult } from "../core/scan.js";
import { RULES } from "../rules/index.js";

/**
 * SARIF 2.1.0 for GitHub code scanning (and any other SARIF consumer). Findings carry
 * titles, explanations and fixes only: never code excerpts, so never secret values.
 */
const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note" };
/** GitHub turns security-severity into its Critical / High / Medium / Low labels. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };

export function renderSarif(projects: Array<{ prefix: string; result: ScanResult }>, version: string): string {
  const findings: Array<Finding & { uri: string }> = projects.flatMap(({ prefix, result }) =>
    result.findings.map((f) => ({ ...f, uri: prefix ? `${prefix}/${f.file}` : f.file })),
  );
  const used = new Set(findings.map((f) => f.ruleId));
  const rules = RULES.filter((r) => used.has(r.id)).map((r) => ({
    id: r.id,
    name: r.title.replace(/[^A-Za-z0-9]+(.)?/g, (_m, c: string | undefined) => (c ? c.toUpperCase() : "")),
    shortDescription: { text: r.title },
    fullDescription: { text: r.docs.summary },
    help: {
      text: `${r.docs.summary}\n\nRun \`npx seaworthy-cli explain ${r.id}\` for an example of the problem and the fix.`,
      markdown: `${r.docs.summary}\n\nRun \`npx seaworthy-cli explain ${r.id}\` for an example of the problem and the fix.`,
    },
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: { tags: ["security"], "security-severity": SECURITY_SEVERITY[r.severity], precision: r.confidence === "high" ? "high" : "medium" },
  }));
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId),
    level: LEVEL[f.severity],
    message: { text: `${f.title}. ${f.why} Fix: ${f.fix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.uri.replace(/\\/g, "/"), uriBaseId: "%SRCROOT%" },
          region: { startLine: Math.max(1, f.line), startColumn: Math.max(1, f.column) },
        },
      },
    ],
    // Stable across line moves, so GitHub doesn't reopen an alert when code shifts.
    partialFingerprints: { "seaworthy/v1": `${f.ruleId}:${f.uri}:${f.title}` },
    properties: { "security-severity": SECURITY_SEVERITY[f.severity], confidence: f.confidence },
  }));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "Seaworthy",
              version,
              semanticVersion: version,
              informationUri: "https://dynamomaritime.com/seaworthy",
              rules,
            },
          },
          results,
        },
      ],
    },
    null,
    2,
  );
}
