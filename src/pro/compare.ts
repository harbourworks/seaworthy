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
  const group = (fs: HistoryFinding[]) => {
    const m = new Map<string, HistoryFinding[]>();
    for (const f of fs) {
      const k = `${f.rule}\u0000${f.file}`;
      m.set(k, [...(m.get(k) ?? []), f]);
    }
    for (const list of m.values()) list.sort((a, b) => a.line - b.line);
    return m;
  };
  const b = group(before.findings);
  const a = group(after.findings);
  const stillPresent: HistoryFinding[] = [];
  const fixed: HistoryFinding[] = [];
  const added: HistoryFinding[] = [];

  for (const key of new Set([...b.keys(), ...a.keys()])) {
    const was = b.get(key) ?? [];
    const now = a.get(key) ?? [];
    const both = Math.min(was.length, now.length);
    stillPresent.push(...now.slice(0, both));
    fixed.push(...was.slice(both));
    added.push(...now.slice(both));
  }

  const order = (fs: HistoryFinding[]) => fs.sort((x, y) => compareFindings(asFinding(x), asFinding(y)));
  return {
    before: { id: before.id, timestamp: before.timestamp },
    after: { id: after.id, timestamp: after.timestamp },
    stillPresent: order(stillPresent),
    fixed: order(fixed),
    added: order(added),
  };
}

/** Turns live findings into the metadata-only shape history uses. */
export function toHistoryFindings(findings: Finding[]): HistoryFinding[] {
  return findings.map((f) => ({ rule: f.ruleId, file: f.file, line: f.line, severity: f.severity }));
}

const asFinding = (h: HistoryFinding): Finding =>
  ({ ruleId: h.rule, file: h.file, line: h.line, severity: h.severity }) as Finding;
