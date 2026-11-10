import { SEVERITIES, type Finding, type Severity } from "../core/finding.js";

export const SEVERITY_MEANING: Record<Severity, string> = {
  critical: "someone could steal data or money today, with no special access",
  high: "a serious weakness to fix before launch",
  medium: "worth fixing soon, though harder to exploit",
  low: "good practice, low risk on its own",
};

/** A few sentences a non-specialist (a founder, a client) can read and act on. */
export function plainSummary(projectName: string, findings: Finding[]): string[] {
  if (findings.length === 0) {
    return [
      `Seaworthy found no problems in ${projectName} at the confidence level used for this scan.`,
      "That means none of the checks it runs found an issue. It does not mean the app has no security problems: no automated tool catches everything.",
    ];
  }
  const counts = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  const list = counts.map(([s, n]) => `${n} ${s}`);
  const total = findings.length;
  const out = [
    `Seaworthy found ${total} problem${total === 1 ? "" : "s"} in ${projectName}: ${joinList(list)}.`,
  ];
  const first = findings[0]!;
  out.push(`Start with "${first.title}" in ${first.file}, then work down the list. Each finding says why it matters and how to fix it.`);
  return out;
}

const cap = (s: string) => s[0]!.toUpperCase() + s.slice(1);

function joinList(items: string[]): string {
  if (items.length <= 1) return items.join("");
  return `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}
