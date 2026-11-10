// Renders sample HTML reports from the fixture apps, for checking the report's look by eye.
// Usage: npx tsx scripts/render-sample-report.mts <outDir>
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { ProjectFiles } from "../src/core/project.js";
import { excluder, walk } from "../src/core/walk.js";
import { RULES } from "../src/rules/index.js";
import { renderHtml, type ReportProject } from "../src/pro/html.js";
import { SEAWORTHY_BRANDING } from "../src/pro/branding.js";

const out = resolve(process.argv[2] ?? "sample-reports");
mkdirSync(out, { recursive: true });
const apps = ["notes-saas", "chat-agent"].map((name) => {
  const dir = resolve("fixtures/apps", name);
  return {
    name,
    result: scan(dir, DEFAULT_CONFIG, RULES),
    project: new ProjectFiles(dir, walk(dir).files, excluder()),
  } satisfies ReportProject;
});
const when = new Date("2026-11-10T12:00:00Z");
writeFileSync(join(out, "single.html"), renderHtml({ projects: [apps[0]!], branding: SEAWORTHY_BRANDING, generatedAt: when, version: "0.2.0" }));
writeFileSync(
  join(out, "agency.html"),
  renderHtml({
    projects: apps,
    branding: { agencyName: "Northlight Studio", clientName: "Harbour Bakery Ltd", logoDataUri: null },
    generatedAt: when,
    version: "0.2.0",
  }),
);
console.log(apps.map((a) => `${a.name}: ${a.result.findings.length} findings`).join(", "));
