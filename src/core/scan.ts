import { performance } from "node:perf_hooks";
import type { Config } from "./config.js";
import { atLeastConfidence, atLeastSeverity, compareFindings, type Finding } from "./finding.js";
import { ProjectFiles } from "./project.js";
import { detectStack, type StackFeature } from "./stack.js";
import { applySuppressions, type SuppressionProblem } from "./suppress.js";
import { excluder, walk } from "./walk.js";
import type { Rule } from "../rules/types.js";
import type { OsvResult } from "../deps/osv.js";
import type { RegistryResult } from "../deps/registry.js";

export interface ScanResult {
  root: string;
  stack: StackFeature[];
  filesScanned: number;
  skippedLarge: string[];
  rulesRun: string[];
  /** Shown findings: above the confidence floor, not suppressed, sorted worst first. */
  findings: Finding[];
  /** Findings hidden by --min-confidence. Counted so the report can say so. */
  hiddenLowConfidence: number;
  suppressed: Finding[];
  missingReason: SuppressionProblem[];
  ruleErrors: Array<{ ruleId: string; message: string }>;
  /** True if any shown finding is at or above config.failOn. */
  failed: boolean;
  durationMs: number;
}

export function scan(root: string, config: Config, rules: Rule[], extras: { osv?: OsvResult; npm?: RegistryResult } = {}): ScanResult {
  const started = performance.now();
  const { files, skippedLarge } = walk(root, config.ignore);
  const project = new ProjectFiles(root, files, excluder(config.ignore));
  const stack = detectStack(project);

  const active = rules.filter(
    (r) =>
      config.rules[r.id] !== "off" &&
      (r.appliesTo.length === 0 || r.appliesTo.some((f) => stack.has(f))),
  );

  const all: Finding[] = [];
  const ruleErrors: ScanResult["ruleErrors"] = [];
  for (const rule of active) {
    try {
      for (const raw of rule.check({ project, stack, osv: extras.osv, npm: extras.npm })) {
        all.push({
          ruleId: rule.id,
          title: raw.title ?? rule.title,
          severity: raw.severity ?? rule.severity,
          confidence: raw.confidence ?? rule.confidence,
          file: raw.file,
          line: raw.line,
          column: raw.column,
          why: raw.why,
          fix: raw.fix,
          ...(raw.fixPrompt ? { fixPrompt: raw.fixPrompt } : {}),
          ...(raw.commit ? { commit: raw.commit } : {}),
        });
      }
    } catch (err) {
      // One broken rule must never sink the whole scan; report it and carry on.
      ruleErrors.push({ ruleId: rule.id, message: (err as Error).message });
    }
  }

  const deduped = dedupe(all);
  const { kept, suppressed, missingReason } = applySuppressions(deduped, project);
  const shown = kept.filter((f) => atLeastConfidence(f.confidence, config.minConfidence));
  shown.sort(compareFindings);

  return {
    root,
    stack: [...stack],
    filesScanned: files.length,
    skippedLarge,
    rulesRun: active.map((r) => r.id),
    findings: shown,
    hiddenLowConfidence: kept.length - shown.length,
    suppressed,
    missingReason,
    ruleErrors,
    failed: shown.some((f) => atLeastSeverity(f.severity, config.failOn)),
    durationMs: Math.round(performance.now() - started),
  };
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}|${f.file}|${f.line}|${f.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
