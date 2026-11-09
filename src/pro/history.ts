import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { SEVERITIES, type Finding, type Severity } from "../core/finding.js";

/**
 * Scan history lives in <project>/.seaworthy/history.json. It holds metadata only:
 * rule ID, file path, line, severity and time. Never code, snippets, titles or secrets.
 */
export interface HistoryFinding {
  rule: string;
  file: string;
  line: number;
  severity: Severity;
}

export interface HistoryScan {
  /** 1, 2, 3… in the order scans were recorded. */
  id: number;
  timestamp: string;
  findings: HistoryFinding[];
}

export interface HistoryFile {
  version: 1;
  scans: HistoryScan[];
}

export const HISTORY_DIR = ".seaworthy";
export const HISTORY_FILE = "history.json";
/** Oldest scans drop off after this many, so the file never grows without limit. */
export const MAX_SCANS = 500;

export function historyPath(root: string): string {
  return join(root, HISTORY_DIR, HISTORY_FILE);
}

export function loadHistory(root: string): HistoryFile {
  const p = historyPath(root);
  if (!existsSync(p)) return { version: 1, scans: [] };
  try {
    const raw = JSON.parse(readFileSync(p, "utf8")) as HistoryFile;
    if (raw?.version !== 1 || !Array.isArray(raw.scans)) return { version: 1, scans: [] };
    // Re-sanitise on read, so a hand-edited file can't smuggle anything into reports.
    return { version: 1, scans: raw.scans.filter(isScan).map(sanitiseScan) };
  } catch {
    return { version: 1, scans: [] };
  }
}

/** Appends a scan. Returns the saved scan, or null if the folder isn't writable. */
export function recordScan(root: string, findings: Finding[], now = new Date()): HistoryScan | null {
  const history = loadHistory(root);
  const scan: HistoryScan = {
    id: (history.scans.at(-1)?.id ?? 0) + 1,
    timestamp: now.toISOString(),
    findings: findings.map((f) => ({ rule: f.ruleId, file: f.file, line: f.line, severity: f.severity })),
  };
  history.scans.push(scan);
  if (history.scans.length > MAX_SCANS) history.scans.splice(0, history.scans.length - MAX_SCANS);
  try {
    const dir = join(root, HISTORY_DIR);
    mkdirSync(dir, { recursive: true });
    // Keep the folder out of git without the user having to edit their .gitignore.
    const gi = join(dir, ".gitignore");
    if (!existsSync(gi)) writeFileSync(gi, "# Created by Seaworthy: scan history stays on this machine.\n*\n");
    writeFileSync(historyPath(root), JSON.stringify(history, null, 2) + "\n");
    return scan;
  } catch {
    return null;
  }
}

export function severityCounts(findings: HistoryFinding[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
}

function isScan(s: unknown): s is HistoryScan {
  const x = s as HistoryScan;
  return !!x && typeof x.id === "number" && typeof x.timestamp === "string" && Array.isArray(x.findings);
}

function sanitiseScan(s: HistoryScan): HistoryScan {
  return {
    id: s.id,
    timestamp: s.timestamp,
    findings: s.findings
      .filter((f) => f && typeof f.rule === "string" && typeof f.file === "string" && (SEVERITIES as readonly string[]).includes(f.severity))
      .map((f) => ({
        rule: String(f.rule).slice(0, 20),
        file: String(f.file).slice(0, 500),
        line: Number.isFinite(f.line) ? Math.max(1, Math.trunc(f.line)) : 1,
        severity: f.severity,
      })),
  };
}
