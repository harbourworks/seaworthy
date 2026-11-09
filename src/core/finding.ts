export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = ["high", "medium", "low"] as const;
export type Confidence = (typeof CONFIDENCES)[number];

/** One problem, in one place. Every rule produces exactly this shape. */
export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Path relative to the scan root, always with forward slashes. */
  file: string;
  /** 1-based. */
  line: number;
  /** 1-based. */
  column: number;
  /** Two sentences: what is wrong and why it matters. */
  why: string;
  /** What to do about it. */
  fix: string;
  /** A paste-ready prompt for an AI coding tool, when one helps. */
  fixPrompt?: string;
}

export const severityRank = (s: Severity): number => SEVERITIES.length - SEVERITIES.indexOf(s);
export const confidenceRank = (c: Confidence): number => CONFIDENCES.length - CONFIDENCES.indexOf(c);

export function atLeastSeverity(s: Severity, threshold: Severity): boolean {
  return severityRank(s) >= severityRank(threshold);
}

export function atLeastConfidence(c: Confidence, threshold: Confidence): boolean {
  return confidenceRank(c) >= confidenceRank(threshold);
}

export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.ruleId.localeCompare(b.ruleId)
  );
}
