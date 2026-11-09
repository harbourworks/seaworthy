import pc from "picocolors";
import { SEVERITIES, type Severity } from "../core/finding.js";
import type { Comparison } from "./compare.js";
import { severityCounts, type HistoryFile, type HistoryFinding } from "./history.js";

const SEV_COLOUR: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.red(pc.bold(s)),
  high: pc.red,
  medium: pc.yellow,
  low: pc.dim,
};

/** One line under a Pro scan: what changed since the last one. */
export function renderSinceLast(c: Comparison): string {
  if (c.fixed.length === 0 && c.added.length === 0) {
    return pc.dim(`  Since scan #${c.before.id} (${c.before.timestamp.slice(0, 10)}): no change.`);
  }
  return `  Since scan #${c.before.id} (${c.before.timestamp.slice(0, 10)}): ${pc.green(pc.bold(`${c.fixed.length} fixed`))}, ${c.added.length ? pc.red(pc.bold(`${c.added.length} new`)) : "0 new"}, ${c.stillPresent.length} still open. ${pc.dim("seaworthy compare for details")}`;
}

export function renderComparison(name: string, c: Comparison): string {
  const out = ["", `  ${pc.bold("Seaworthy compare")}  ${pc.dim("·")}  ${name}`];
  out.push(pc.dim(`  Scan #${c.before.id} (${c.before.timestamp.slice(0, 16).replace("T", " ")}) → scan #${c.after.id} (${c.after.timestamp.slice(0, 16).replace("T", " ")})`));
  out.push("");
  out.push(`  ${pc.green(pc.bold(`✔ ${c.fixed.length} fixed`))}   ${pc.red(pc.bold(`✖ ${c.added.length} new`))}   ${pc.bold(`• ${c.stillPresent.length} still open`)}`);
  const list = (label: string, fs: HistoryFinding[]) => {
    if (!fs.length) return;
    out.push("", `  ${pc.bold(label)}`);
    for (const f of fs) out.push(`    ${SEV_COLOUR[f.severity](f.severity.padEnd(8))}  ${pc.dim(f.rule)}  ${f.file}:${f.line}`);
  };
  list("Fixed", c.fixed);
  list("New", c.added);
  list("Still open", c.stillPresent);
  out.push("");
  return out.join("\n");
}

export function renderHistory(name: string, history: HistoryFile, limit = 15): string {
  const scans = history.scans.slice(-limit);
  const out = ["", `  ${pc.bold("Seaworthy history")}  ${pc.dim("·")}  ${name}  ${pc.dim(`· ${history.scans.length} scan${history.scans.length === 1 ? "" : "s"} recorded`)}`, ""];
  if (scans.length === 0) {
    out.push("  No scans recorded yet. Run seaworthy in this folder and each scan is saved here.", "");
    return out.join("\n");
  }
  const max = Math.max(1, ...scans.map((s) => s.findings.length));
  out.push(pc.dim(`  ${"Scan".padEnd(6)}${"Date".padEnd(18)}${SEVERITIES.map((s) => s.slice(0, 4).padStart(6)).join("")}  Total`));
  for (const s of scans) {
    const c = severityCounts(s.findings);
    const bar = "█".repeat(Math.round((s.findings.length / max) * 20)) || pc.green("✔");
    out.push(
      `  ${`#${s.id}`.padEnd(6)}${s.timestamp.slice(0, 16).replace("T", " ").padEnd(18)}${SEVERITIES.map((sev) => {
        const v = String(c[sev]).padStart(6);
        return c[sev] ? SEV_COLOUR[sev](v) : pc.dim(v);
      }).join("")}  ${String(s.findings.length).padStart(5)} ${pc.dim(bar)}`,
    );
  }
  const first = history.scans[0]!;
  const last = history.scans.at(-1)!;
  if (history.scans.length > 1) {
    const d = last.findings.length - first.findings.length;
    const trend = d < 0 ? pc.green(`down ${-d}`) : d > 0 ? pc.red(`up ${d}`) : "unchanged";
    out.push("", `  Since the first scan (${first.timestamp.slice(0, 10)}): ${first.findings.length} → ${last.findings.length} findings, ${trend}.`);
  }
  out.push("");
  return out.join("\n");
}
