import pc from "picocolors";
import { basename } from "node:path";
import type { ScanResult } from "../core/scan.js";
import { SEVERITIES, type Finding, type Severity } from "../core/finding.js";
import { STACK_LABELS } from "../core/stack.js";
import type { ProjectFiles } from "../core/project.js";
import { redact } from "../rules/secrets/patterns.js";

const BADGE: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(pc.bold(s))),
  high: (s) => pc.red(pc.bold(s)),
  medium: (s) => pc.yellow(pc.bold(s)),
  low: (s) => pc.dim(pc.bold(s)),
};

export function renderTerminal(result: ScanResult, project: ProjectFiles, version: string): string {
  const out: string[] = [];
  const stack = result.stack.map((s) => STACK_LABELS[s]).join(", ") || "no known stack";
  out.push("");
  out.push(`  ${pc.bold("Seaworthy")} ${pc.dim(version)}  ${pc.dim("·")}  ${basename(result.root)}  ${pc.dim("·")}  ${pc.dim(stack)}`);
  out.push(pc.dim(`  ${result.filesScanned} files, ${result.rulesRun.length} rules, ${result.durationMs} ms. Your code never left this machine.`));
  out.push("");

  const counts = SEVERITIES.map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  if (!result.failed) {
    const extra = counts.length ? pc.dim(` (${counts.map(([s, n]) => `${n} ${s}`).join(", ")} below your threshold)`) : "";
    out.push(`  ${pc.green(pc.bold("✔ Seaworthy"))}: no findings at or above your fail threshold${extra}`);
  } else {
    out.push(`  ${pc.red(pc.bold("✖ Not seaworthy"))}: ${counts.map(([s, n]) => `${n} ${s}`).join(", ")}`);
  }

  for (const f of result.findings) out.push("", ...renderFinding(f, project));

  const notes: string[] = [];
  if (result.hiddenLowConfidence) notes.push(`${result.hiddenLowConfidence} lower-confidence finding(s) hidden. See them with --min-confidence medium.`);
  if (result.suppressed.length) notes.push(`${result.suppressed.length} finding(s) suppressed by seaworthy-ignore comments.`);
  for (const m of result.missingReason) notes.push(`${m.file}:${m.line} has seaworthy-ignore ${m.ruleId} with no reason, so it is not honoured.`);
  for (const e of result.ruleErrors) notes.push(`Rule ${e.ruleId} crashed and was skipped: ${e.message}`);
  if (result.skippedLarge.length) notes.push(`${result.skippedLarge.length} file(s) over 1 MB skipped.`);
  if (notes.length) out.push("", ...notes.map((n) => pc.dim(`  ${n}`)));
  out.push("");
  return out.join("\n");
}

export function renderFinding(f: Finding, project: ProjectFiles): string[] {
  // A finding in git history has no excerpt: today's file, if it exists, holds different lines.
  const lines = f.commit ? [] : project.lines(f.file);
  const out = [
    `  ${BADGE[f.severity](` ${f.severity.toUpperCase()} `)}  ${pc.bold(f.title)}  ${pc.dim(f.ruleId)}`,
    `  ${pc.cyan(`${f.file}:${f.line}:${f.column}`)}${f.commit ? pc.dim(`  in commit ${f.commit}`) : ""}`,
  ];
  const width = String(f.line + 1).length;
  for (let n = Math.max(1, f.line - 1); n <= Math.min(lines.length, f.line + 1); n++) {
    const code = redact(lines[n - 1] ?? "").slice(0, 140);
    const gutter = String(n).padStart(width);
    out.push(n === f.line ? `  ${pc.red(">")} ${gutter} │ ${code}` : pc.dim(`    ${gutter} │ ${code}`));
  }
  out.push(`  ${pc.bold("Why")}  ${f.why}`);
  out.push(`  ${pc.bold("Fix")}  ${f.fix}`);
  return out;
}
