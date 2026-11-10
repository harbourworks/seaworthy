import { compareFindings, type Finding } from "../core/finding.js";
import type { HistoryFinding, HistoryScan } from "./history.js";

export interface Comparison {
  before: { id: number | null; timestamp: string };
  after: { id: number | null; timestamp: string };
  /** In both scans: found before, still there. */
  stillPresent: HistoryFinding[];
  /** In the earlier scan, gone from the later one. */
  fixed: HistoryFinding[];
  /** Only in the later scan. */
  added: HistoryFinding[];
}

/**
 * Compares two scans of the same project. A finding is "the same" if it has the same rule
 * and file, so editing code above it (which moves its line) doesn't make it look new. When a
 * file has several findings for one rule, they are paired in line order.
 */
export function compareScans(before: HistoryScan, after: HistoryScan): Comparison {
  const { stillPresent, fixed, added } = pair(before.findings, after.findings, (f) => `${f.rule}\u0000${f.file}`);
  const order = (fs: HistoryFinding[]) => fs.sort((x, y) => compareFindings(asFinding(x), asFinding(y)));
  return {
    before: { id: before.id, timestamp: before.timestamp },
    after: { id: after.id, timestamp: after.timestamp },
    stillPresent: order(stillPresent),
    fixed: order(fixed),
    added: order(added),
  };
}

export interface FindingDiff {
  /** Only in the later scan: what a pull request introduces. */
  added: Finding[];
  /** In the earlier scan, gone from the later one. */
  fixed: Finding[];
  /** In both (the later scan's copy, so lines are current). */
  stillPresent: Finding[];
}

/** The same matching as compareScans, on full findings (pull-request checks keep the detail). */
export function diffFindings(before: Finding[], after: Finding[]): FindingDiff {
  const { stillPresent, fixed, added } = pair(before, after, (f) => `${f.ruleId}\u0000${f.file}`);
  return { added: added.sort(compareFindings), fixed: fixed.sort(compareFindings), stillPresent: stillPresent.sort(compareFindings) };
}

function pair<T extends { line: number }>(before: T[], after: T[], key: (f: T) => string) {
  const group = (fs: T[]) => {
    const m = new Map<string, T[]>();
    for (const f of fs) {
      const k = key(f);
      m.set(k, [...(m.get(k) ?? []), f]);
    }
    for (const list of m.values()) list.sort((a, b) => a.line - b.line);
    return m;
  };
  const b = group(before);
  const a = group(after);
  const stillPresent: T[] = [];
  const fixed: T[] = [];
  const added: T[] = [];
  for (const k of new Set([...b.keys(), ...a.keys()])) {
    const was = b.get(k) ?? [];
    const now = a.get(k) ?? [];
    const both = Math.min(was.length, now.length);
    stillPresent.push(...now.slice(0, both));
    fixed.push(...was.slice(both));
    added.push(...now.slice(both));
  }
  return { stillPresent, fixed, added };
}

/** Turns live findings into the metadata-only shape history uses. */
export function toHistoryFindings(findings: Finding[]): HistoryFinding[] {
  return findings.map((f) => ({ rule: f.ruleId, file: f.file, line: f.line, severity: f.severity }));
}

const asFinding = (h: HistoryFinding): Finding =>
  ({ ruleId: h.rule, file: h.file, line: h.line, severity: h.severity }) as Finding;
