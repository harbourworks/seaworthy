import pc from "picocolors";
import { basename } from "node:path";
import { atLeastSeverity, type Finding, type Severity } from "../core/finding.js";
import type { ProjectFiles } from "../core/project.js";
import type { ScanResult } from "../core/scan.js";
import { STACK_LABELS } from "../core/stack.js";
import type { FindingDiff } from "./compare.js";
import { renderFinding } from "../reporters/terminal.js";
import { briefFinding, code, countLine, findingSections, finish, footnotes, meta, text, type MarkdownOptions } from "../reporters/markdown.js";

/**
 * Pull-request checks (Pro): the base ref and the working tree are both scanned, and only
 * what the change introduces is reported in full. Fixed findings are listed; findings that
 * were already there are only counted.
 */
export interface PrCheck {
  ref: string;
  sha: string;
  diff: FindingDiff;
  failOn: Severity;
}

/** Marks the comment, so the workflow updates one comment instead of adding one per push. */
export const PR_COMMENT_MARKER = "<!-- seaworthy-pr-check -->";

/** Fails only on new findings at or above the threshold. */
export const prFailed = (c: PrCheck): boolean => c.diff.added.some((f) => atLeastSeverity(f.severity, c.failOn));

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function renderPrMarkdown(
  name: string,
  result: ScanResult,
  project: ProjectFiles,
  check: PrCheck,
  version: string,
  opts: MarkdownOptions & { notes?: string[] } = {},
): string {
  const { added, fixed, stillPresent } = check.diff;
  const failing = added.filter((f) => atLeastSeverity(f.severity, check.failOn));
  const out: string[] = [PR_COMMENT_MARKER];
  if (failing.length) {
    out.push(`### ✖ Seaworthy: ${plural(added.length, "new problem")} in this pull request (${countLine(added)})`);
  } else if (added.length) {
    out.push(`### ✔ Seaworthy: no new problems at or above ${check.failOn} (${plural(added.length, "new finding")} below it)`);
  } else {
    out.push(`### ✔ Seaworthy: no new problems in this pull request`);
  }
  const parts = [
    `Compared with ${code(check.ref)} (${code(check.sha.slice(0, 7))}).`,
    fixed.length ? `**${plural(fixed.length, "problem")} fixed.**` : "",
    stillPresent.length ? `${plural(stillPresent.length, "problem")} already there before this change ${stillPresent.length === 1 ? "is" : "are"} not repeated here.` : "",
  ].filter(Boolean);
  out.push("", parts.join(" "));

  out.push(...findingSections(added, project, opts));

  if (fixed.length) {
    out.push("", `<details><summary>✔ ${plural(fixed.length, "problem")} fixed by this change</summary>`, "");
    for (const f of fixed.slice(0, 200)) out.push(`- ${briefFinding(f, {})}`);
    if (fixed.length > 200) out.push(`- …and ${fixed.length - 200} more.`);
    out.push("", "</details>");
  }
  if (stillPresent.length) {
    out.push("", `<sub>Already there before this change: ${countLine(stillPresent)}. Run Seaworthy on the base branch to see them.</sub>`);
  }
  out.push("", meta(version, name, result));
  out.push(...footnotes(result));
  for (const n of opts.notes ?? []) out.push("", `> ${text(n)}`);
  return finish(out);
}

export function renderPrTerminal(result: ScanResult, project: ProjectFiles, check: PrCheck, version: string): string {
  const { added, fixed, stillPresent } = check.diff;
  const stack = result.stack.map((s) => STACK_LABELS[s]).join(", ") || "no known stack";
  const out: string[] = [""];
  out.push(`  ${pc.bold("Seaworthy")} ${pc.dim(version)}  ${pc.dim("·")}  ${basename(result.root)}  ${pc.dim("·")}  ${pc.dim(stack)}`);
  out.push(pc.dim(`  ${result.filesScanned} files, ${result.rulesRun.length} rules. Compared with ${check.ref} (${check.sha.slice(0, 7)}).`));
  out.push("");
  if (prFailed(check)) {
    out.push(`  ${pc.red(pc.bold(`✖ ${plural(added.length, "new problem")}`))}: ${countLine(added)}`);
  } else if (added.length) {
    out.push(`  ${pc.green(pc.bold("✔ No new problems"))} at or above ${check.failOn} ${pc.dim(`(${countLine(added)} new, below your threshold)`)}`);
  } else {
    out.push(`  ${pc.green(pc.bold("✔ No new problems"))} since ${check.ref}`);
  }
  out.push(`  ${pc.green(`${fixed.length} fixed`)}  ${pc.dim("·")}  ${stillPresent.length} already there`);

  for (const f of added) out.push("", ...renderFinding(f, project));
  if (fixed.length) {
    out.push("", `  ${pc.bold("Fixed")}`);
    for (const f of fixed) out.push(`    ${f.severity.padEnd(8)}  ${pc.dim(f.ruleId)}  ${f.title}  ${pc.dim(`${f.file}:${f.line}`)}`);
  }
  out.push("");
  return out.join("\n");
}

/** Machine-readable additions to the JSON report. */
export function prJson(check: PrCheck): { baseline: { ref: string; sha: string; new: Finding[]; fixed: Finding[]; alreadyThere: number } } {
  return {
    baseline: {
      ref: check.ref,
      sha: check.sha,
      new: check.diff.added,
      fixed: check.diff.fixed,
      alreadyThere: check.diff.stillPresent.length,
    },
  };
}
