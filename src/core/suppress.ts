import type { Finding } from "./finding.js";
import type { ProjectFiles } from "./project.js";

/**
 * Matches `seaworthy-ignore SW-A01 some reason` inside any comment style
 * (`//`, `#`, `--`, `/* *\/`, `<!-- -->`). The reason is required.
 */
const IGNORE_RE = /seaworthy-ignore\s+(SW-[A-Z]\d{2})(?:[ \t]+([^\n*]*?))?\s*(?:\*\/|-->)?\s*$/;

export interface SuppressionProblem {
  file: string;
  line: number;
  ruleId: string;
}

export interface SuppressResult {
  kept: Finding[];
  suppressed: Finding[];
  /** Ignore comments with no reason. They do not suppress anything. */
  missingReason: SuppressionProblem[];
}

/**
 * A finding is suppressed by an ignore comment for its rule on the same line or the line
 * directly above. Comments without a reason are reported, not honoured, so every
 * suppression in a codebase stays reviewable.
 */
export function applySuppressions(findings: Finding[], project: ProjectFiles): SuppressResult {
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  const missing = new Map<string, SuppressionProblem>();

  for (const f of findings) {
    const lines = project.lines(f.file);
    let hit: "ok" | "no-reason" | null = null;
    for (const ln of [f.line, f.line - 1]) {
      const m = IGNORE_RE.exec(lines[ln - 1] ?? "");
      if (m && m[1] === f.ruleId) {
        if (m[2] && m[2].trim().length > 0) {
          hit = "ok";
          break;
        }
        hit = "no-reason";
        missing.set(`${f.file}:${ln}:${f.ruleId}`, { file: f.file, line: ln, ruleId: f.ruleId });
      }
    }
    (hit === "ok" ? suppressed : kept).push(f);
  }
  return { kept, suppressed, missingReason: [...missing.values()] };
}
