import { SEVERITIES, type Finding, type Severity } from "../core/finding.js";
import type { ScanResult } from "../core/scan.js";
import { STACK_LABELS } from "../core/stack.js";
import type { ProjectFiles } from "../core/project.js";
import { redact } from "../rules/secrets/patterns.js";

/**
 * GitHub-flavoured Markdown, for $GITHUB_STEP_SUMMARY and pull-request comments.
 *
 * It is posted where other people read it, so: code appears only as the same masked
 * three-line excerpt the terminal shows, and any text that can come from the scanned code
 * (file names, table and variable names inside explanations) is escaped, so it can't add
 * HTML, images, links or @mentions to a comment.
 */

export const SEVERITY_ICON: Record<Severity, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "⚪" };
const cap = (s: string) => s[0]!.toUpperCase() + s.slice(1);

/** GitHub rejects comments over 65,536 characters; stay well clear. */
export const MAX_MARKDOWN = 60_000;

export interface MarkdownOptions {
  /** Turns a file and line into a link (e.g. to the commit on GitHub), or undefined for none. */
  link?: (file: string, line: number) => string | undefined;
}

/** A plain scan: every finding shown, worst first. */
export function renderMarkdown(
  projects: Array<{ name: string; result: ScanResult; project: ProjectFiles }>,
  version: string,
  opts: MarkdownOptions & { notes?: string[] } = {},
): string {
  const out: string[] = ["<!-- seaworthy -->"];
  for (const { name, result, project } of projects) {
    const counts = countLine(result.findings);
    out.push(
      result.failed
        ? `### ✖ Not seaworthy: ${counts}`
        : `### ✔ Seaworthy${result.findings.length ? `: nothing at or above your fail threshold (${counts} below it)` : ": no findings"}`,
    );
    out.push(meta(version, name, result));
    out.push(...findingSections(result.findings, project, opts));
    out.push(...footnotes(result));
  }
  for (const n of opts.notes ?? []) out.push("", `> ${text(n)}`);
  return finish(out);
}

/** "2 critical, 1 high". */
export function countLine(findings: Array<{ severity: Severity }>): string {
  return SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
}

export function meta(version: string, name: string, result: ScanResult): string {
  const stack = result.stack.map((s) => STACK_LABELS[s]).join(", ") || "no known stack";
  return `<sub>Seaworthy ${text(version)} · ${text(name)} · ${text(stack)} · ${result.filesScanned} files, ${result.rulesRun.length} rules</sub>`;
}

/**
 * Each finding in full: heading, location, masked excerpt, why and fix. Once the text gets
 * long, the rest are listed one per line so the whole thing still fits in a comment.
 */
export function findingSections(findings: Finding[], project: ProjectFiles, opts: MarkdownOptions, budget = 45_000): string[] {
  const out: string[] = [];
  let used = 0;
  let i = 0;
  for (; i < findings.length; i++) {
    const block = fullFinding(findings[i]!, project, opts).join("\n");
    if (used + block.length > budget && i > 0) break;
    used += block.length;
    out.push("", block);
  }
  if (i < findings.length) {
    out.push("", `<details><summary>${findings.length - i} more, listed briefly</summary>`, "");
    for (const f of findings.slice(i, i + 200)) out.push(`- ${briefFinding(f, opts)}`);
    if (findings.length - i > 200) out.push(`- …and ${findings.length - i - 200} more. Run Seaworthy locally to see them all.`);
    out.push("", "</details>");
  }
  return out;
}

export function fullFinding(f: Finding, project: ProjectFiles, opts: MarkdownOptions): string[] {
  const lines = project.lines(f.file);
  const width = String(f.line + 1).length;
  const excerpt: string[] = [];
  for (let n = Math.max(1, f.line - 1); n <= Math.min(lines.length, f.line + 1); n++) {
    const code = redact(lines[n - 1] ?? "").slice(0, 140);
    excerpt.push(`${n === f.line ? ">" : " "} ${String(n).padStart(width)} │ ${code}`);
  }
  const out = [
    `#### ${SEVERITY_ICON[f.severity]} ${cap(f.severity)} · ${text(f.title)} · ${code(f.ruleId)}`,
    location(f, opts),
  ];
  if (excerpt.length) out.push("", ...fence(excerpt));
  out.push("", `**Why** ${text(f.why)}`, "", `**Fix** ${text(f.fix)}`);
  return out;
}

/** "🔴 Critical · Table without row-level security · `file:20` · `SW-D01`". */
export function briefFinding(f: { severity: Severity; title: string; ruleId: string; file: string; line: number }, opts: MarkdownOptions): string {
  return `${SEVERITY_ICON[f.severity]} ${cap(f.severity)} · ${text(f.title)} · ${location(f, opts)} · ${code(f.ruleId)}`;
}

function location(f: { file: string; line: number }, opts: MarkdownOptions): string {
  const label = code(`${f.file}:${f.line}`);
  const url = opts.link?.(f.file, f.line);
  return url ? `[${label}](${url})` : label;
}

export function footnotes(result: ScanResult): string[] {
  const notes: string[] = [];
  if (result.hiddenLowConfidence) notes.push(`${result.hiddenLowConfidence} lower-confidence finding(s) hidden (see them with \`--min-confidence medium\`).`);
  if (result.suppressed.length) notes.push(`${result.suppressed.length} finding(s) suppressed by \`seaworthy-ignore\` comments.`);
  if (result.missingReason.length) notes.push(`${result.missingReason.length} \`seaworthy-ignore\` comment(s) have no reason, so they are not honoured.`);
  for (const e of result.ruleErrors) notes.push(`Rule ${code(e.ruleId)} crashed and was skipped: ${text(e.message)}`);
  return notes.length ? ["", `<sub>${notes.join(" ")}</sub>`] : [];
}

export function finish(out: string[]): string {
  let s = out.join("\n").replace(/\n{3,}/g, "\n\n") + "\n";
  if (s.length > MAX_MARKDOWN) s = s.slice(0, MAX_MARKDOWN) + "\n\n…cut short to fit. Run Seaworthy locally for the full report.\n";
  return s;
}

// ── Escaping ────────────────────────────────────────────────────────────────

/**
 * Prose that may carry names from the scanned code. Our own `inline code` spans are kept
 * (nothing renders inside them); everything else is escaped so it shows as plain text.
 */
export function text(s: string): string {
  return s
    .replace(/\s*\n\s*/g, " ")
    .split(/(`[^`\n]+`)/)
    .map((part, i) => (i % 2 === 1 ? part : part.split(URL).map((p, j) => (j % 2 === 1 ? p : plain(p))).join("")))
    .join("");
}

/** Plain https URLs (our checkout link) stay clickable; nothing in them can form markup. */
const URL = /(https:\/\/[A-Za-z0-9.-]+(?:\/[A-Za-z0-9_\-./?=&%~]*)?)/;

function plain(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_[\]!|~#])/g, "\\$1")
    .replace(/@/g, "@&#8203;"); // no @mentions: they would notify people
}

/** An inline code span that survives backticks in its content. */
export function code(s: string): string {
  const one = s.replace(/\s*\n\s*/g, " ");
  const longest = Math.max(0, ...(one.match(/`+/g) ?? []).map((m) => m.length));
  const tick = "`".repeat(longest + 1);
  const pad = one.startsWith("`") || one.endsWith("`") ? " " : "";
  return `${tick}${pad}${one}${pad}${tick}`;
}

/** A fenced block longer than any backtick run inside it. */
function fence(lines: string[]): string[] {
  const longest = Math.max(2, ...lines.flatMap((l) => (l.match(/`+/g) ?? []).map((m) => m.length)));
  const f = "`".repeat(longest + 1);
  return [f, ...lines, f];
}
