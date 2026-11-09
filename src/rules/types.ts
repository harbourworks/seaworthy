import type { Confidence, Finding, Severity } from "../core/finding.js";
import type { ProjectFiles } from "../core/project.js";
import type { StackFeature } from "../core/stack.js";

export interface RuleContext {
  project: ProjectFiles;
  stack: ReadonlySet<StackFeature>;
}

/** What a rule reports. The scanner fills in the rest from the rule's metadata. */
export type RawFinding = Omit<Finding, "ruleId" | "title" | "severity" | "confidence"> & {
  title?: string;
  severity?: Severity;
  confidence?: Confidence;
};

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  /** Default confidence. A single finding can override it. */
  confidence: Confidence;
  /** Runs only when the project uses at least one of these. Empty = always runs. */
  appliesTo: StackFeature[];
  /** Longer explanation for `seaworthy explain`. */
  docs: { summary: string; bad: string; good: string };
  check(ctx: RuleContext): RawFinding[];
}
