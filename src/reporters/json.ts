import type { ScanResult } from "../core/scan.js";

/** Stable machine-readable output. Findings never contain secret values. */
export function renderJson(result: ScanResult, version: string): string {
  return JSON.stringify(
    {
      tool: "seaworthy",
      version,
      failed: result.failed,
      stack: result.stack,
      filesScanned: result.filesScanned,
      rulesRun: result.rulesRun,
      findings: result.findings,
      hiddenLowConfidence: result.hiddenLowConfidence,
      suppressed: result.suppressed.length,
      ruleErrors: result.ruleErrors,
    },
    null,
    2,
  );
}
