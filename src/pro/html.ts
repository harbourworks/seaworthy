import { SEVERITIES, type Finding, type Severity } from "../core/finding.js";
import type { ProjectFiles } from "../core/project.js";
import type { ScanResult } from "../core/scan.js";
import { STACK_LABELS } from "../core/stack.js";
import { redact } from "../rules/secrets/patterns.js";
import type { ResolvedBranding } from "./branding.js";
import type { Comparison } from "./compare.js";
import type { HistoryFinding } from "./history.js";
import { SEVERITY_MEANING, plainSummary } from "./summary.js";

export const DISCLAIMER = "Automated scan results. Not a security certification or a guarantee.";

export interface ReportProject {
  name: string;
  result: ScanResult;
  project: ProjectFiles;
  /** Before/after against the previous scan, when history is available. */
  comparison?: Comparison | null;
}

export interface ReportInput {
  projects: ReportProject[];
  branding: ResolvedBranding;
  generatedAt: Date;
  version: string;
}

/** Renders the whole report as one self-contained HTML document. */
export function renderHtml(input: ReportInput): string {
  const { projects, branding, generatedAt, version } = input;
  const combined = projects.length > 1;
  const whiteLabel = branding.agencyName !== null || branding.logoDataUri !== null;
  const all = projects.flatMap((p) => p.result.findings);
  const failed = projects.some((p) => p.result.failed);
  const title = combined ? `Security scan: ${projects.length} projects` : `Security scan: ${projects[0]?.name ?? ""}`;
  const date = generatedAt.toISOString().slice(0, 10);

  const brand = whiteLabel
    ? `${branding.logoDataUri ? `<img class="logo" src="${esc(branding.logoDataUri)}" alt="">` : ""}${branding.agencyName ? `<span class="brand-name">${esc(branding.agencyName)}</span>` : ""}`
    : `<span class="mark" aria-hidden="true">⚓</span><span class="brand-name">Seaworthy</span>`;

  const meta = [
    branding.clientName ? `Prepared for <strong>${esc(branding.clientName)}</strong>` : null,
    `${date}`,
    combined ? `${projects.length} projects` : esc(stackLine(projects[0]!.result)),
  ].filter(Boolean);

  const body = [
    `<header class="top"><div class="brand">${brand}</div><div class="meta">${meta.join(" · ")}</div></header>`,
    `<h1>${esc(title)}</h1>`,
    verdict(failed, all),
    combined ? overview(projects) : "",
    ...projects.map((p) => projectSection(p, combined)),
    footer(projects, whiteLabel, branding, version),
  ].join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<meta name="generator" content="${whiteLabel ? "" : `Seaworthy ${esc(version)}`}">
<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>
`;
}

function verdict(failed: boolean, all: Finding[]): string {
  const counts = SEVERITIES.map((s) => [s, all.filter((f) => f.severity === s).length] as const);
  const pills = counts
    .map(([s, n]) => `<span class="count sev-${s}${n === 0 ? " zero" : ""}"><b>${n}</b> ${s}</span>`)
    .join("");
  const headline = all.length === 0 ? "No problems found" : failed ? "Not ready to launch" : "No blocking problems";
  return `<section class="verdict ${failed ? "bad" : "good"}"><div class="headline">${failed ? "✖" : "✔"} ${headline}</div><div class="counts">${pills}</div></section>`;
}

function overview(projects: ReportProject[]): string {
  const rows = projects
    .map((p) => {
      const c = (s: Severity) => p.result.findings.filter((f) => f.severity === s).length;
      return `<tr><td><a href="#${anchor(p.name)}">${esc(p.name)}</a></td>${SEVERITIES.map((s) => `<td class="num sev-${s}${c(s) === 0 ? " zero" : ""}">${c(s)}</td>`).join("")}<td>${p.result.failed ? '<span class="tag bad">Not ready</span>' : '<span class="tag good">OK</span>'}</td></tr>`;
    })
    .join("");
  return `<section class="overview"><h2>Overview</h2><table><thead><tr><th>Project</th>${SEVERITIES.map((s) => `<th class="num">${s}</th>`).join("")}<th>Status</th></tr></thead><tbody>${rows}</tbody></table></section>`;
}

function projectSection(p: ReportProject, combined: boolean): string {
  const summary = plainSummary(p.name, p.result.findings).map((s) => `<p>${esc(s)}</p>`).join("");
  const parts = [
    combined ? `<h2 class="project" id="${anchor(p.name)}">${esc(p.name)} <small>${esc(stackLine(p.result))}</small></h2>` : "",
    combined ? verdict(p.result.failed, p.result.findings) : "",
    `<section class="summary"><h3>Summary</h3>${summary}</section>`,
    p.comparison ? comparisonBlock(p.comparison) : "",
    p.result.findings.length ? `<section class="findings"><h3>Findings</h3>${p.result.findings.map((f) => findingCard(f, p.project)).join("")}</section>` : "",
  ];
  return `<section class="project-block">${parts.join("")}</section>`;
}

function comparisonBlock(c: Comparison): string {
  const since = c.before.id !== null ? `scan #${c.before.id} on ${c.before.timestamp.slice(0, 10)}` : `the previous scan`;
  const list = (fs: HistoryFinding[]) =>
    fs.length ? `<ul>${fs.map((f) => `<li><span class="pill sev-${f.severity}">${f.severity}</span> <code>${esc(f.rule)}</code> ${esc(f.file)}:${f.line}</li>`).join("")}</ul>` : "";
  return `<section class="compare"><h3>Since ${esc(since)}</h3>
<div class="compare-grid">
<div class="cmp fixed"><b>${c.fixed.length}</b> fixed</div>
<div class="cmp new"><b>${c.added.length}</b> new</div>
<div class="cmp still"><b>${c.stillPresent.length}</b> still open</div>
</div>
${c.fixed.length ? `<details open><summary>Fixed</summary>${list(c.fixed)}</details>` : ""}
${c.added.length ? `<details open><summary>New</summary>${list(c.added)}</details>` : ""}
</section>`;
}

function findingCard(f: Finding, project: ProjectFiles): string {
  const lines = project.lines(f.file);
  const from = Math.max(1, f.line - 2);
  const to = Math.min(lines.length, f.line + 2);
  const code: string[] = [];
  for (let n = from; n <= to; n++) {
    const text = redact(lines[n - 1] ?? "").slice(0, 200);
    code.push(`<span class="ln${n === f.line ? " hit" : ""}"><span class="no">${n}</span>${esc(text) || " "}</span>`);
  }
  return `<article class="finding sev-border-${f.severity}">
<div class="f-head"><span class="pill sev-${f.severity}">${f.severity}</span><h4>${esc(f.title)}</h4><code class="rule">${esc(f.ruleId)}</code></div>
<div class="loc">${esc(f.file)}:${f.line}</div>
<pre class="code">${code.join("")}</pre>
<p><b>Why it matters.</b> ${esc(f.why)} <span class="muted">(${esc(cap(f.severity))}: ${esc(SEVERITY_MEANING[f.severity])}.)</span></p>
<p><b>How to fix it.</b> ${esc(f.fix)}</p>
${f.fixPrompt ? `<details><summary>Prompt for your AI coding tool</summary><pre class="prompt">${esc(f.fixPrompt)}</pre></details>` : ""}
</article>`;
}

function footer(projects: ReportProject[], whiteLabel: boolean, b: ResolvedBranding, version: string): string {
  const files = projects.reduce((n, p) => n + p.result.filesScanned, 0);
  const rules = new Set(projects.flatMap((p) => p.result.rulesRun)).size;
  const by = whiteLabel ? (b.agencyName ? `Prepared by ${esc(b.agencyName)}.` : "") : `Generated by Seaworthy ${esc(version)}.`;
  return `<footer>
<p class="disclaimer">${esc(DISCLAIMER)}</p>
<p>${files} files checked against ${rules} rules. The scan ran locally: source code was not uploaded anywhere. Secrets in code excerpts are masked. ${by}</p>
</footer>`;
}

function stackLine(r: ScanResult): string {
  return r.stack.map((s) => STACK_LABELS[s]).join(", ") || "No known stack detected";
}

const cap = (s: string) => s[0]!.toUpperCase() + s.slice(1);
const anchor = (s: string) => "p-" + s.replace(/[^A-Za-z0-9_-]+/g, "-");

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

const CSS = `
:root{--bg:#f7f8fa;--card:#fff;--ink:#14181f;--muted:#5d6675;--line:#e3e6eb;--code:#f2f4f7;
--crit:#b42318;--crit-bg:#fee4e2;--high:#c4320a;--high-bg:#ffead5;--med:#a15c07;--med-bg:#fef0c7;--low:#475467;--low-bg:#eaecf0;
--good:#067647;--good-bg:#dcfae6;--bad:#b42318;--bad-bg:#fee4e2;--accent:#1d4ed8}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--ink:#e8ebf0;--muted:#98a2b3;--line:#2a303b;--code:#11151c;
--crit:#ff8a80;--crit-bg:#3d1714;--high:#ffab70;--high-bg:#3b2010;--med:#f7c948;--med-bg:#352a0b;--low:#c0c7d2;--low-bg:#262b35;
--good:#6ce9a6;--good-bg:#0f2d1e;--bad:#ff8a80;--bad-bg:#3d1714;--accent:#8ab4ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 20px 48px}
.top{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;padding-bottom:16px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}
.mark{font-size:22px}.logo{max-height:40px;max-width:180px}
.meta{color:var(--muted);font-size:14px}
h1{font-size:28px;margin:28px 0 16px;letter-spacing:-.01em}
h2{font-size:21px;margin:36px 0 12px}h2 small{font-size:14px;color:var(--muted);font-weight:400;margin-left:6px}
h3{font-size:16px;margin:22px 0 10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
h4{margin:0;font-size:16px;flex:1}
.verdict{border-radius:12px;padding:18px 20px;margin:8px 0 8px;display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.verdict.bad{background:var(--bad-bg)}.verdict.good{background:var(--good-bg)}
.headline{font-size:20px;font-weight:700}.verdict.bad .headline{color:var(--bad)}.verdict.good .headline{color:var(--good)}
.counts{display:flex;gap:8px;flex-wrap:wrap}
.count{background:var(--card);border-radius:999px;padding:4px 12px;font-size:13px;text-transform:capitalize}
.count b{font-size:15px}.zero{opacity:.45}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}
.pill{display:inline-block;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.pill.sev-critical{background:var(--crit-bg)}.pill.sev-high{background:var(--high-bg)}.pill.sev-medium{background:var(--med-bg)}.pill.sev-low{background:var(--low-bg)}
.summary p{margin:6px 0}
.finding{background:var(--card);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:16px 18px;margin:12px 0;break-inside:avoid}
.sev-border-critical{border-left-color:var(--crit)}.sev-border-high{border-left-color:var(--high)}.sev-border-medium{border-left-color:var(--med)}.sev-border-low{border-left-color:var(--low)}
.f-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.rule{color:var(--muted);font-size:13px}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;color:var(--accent);margin:6px 0}
pre{margin:8px 0;padding:10px 0;background:var(--code);border-radius:8px;overflow-x:auto;font:12.5px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.ln{display:block;padding:0 12px;white-space:pre}.ln.hit{background:var(--crit-bg)}
.no{display:inline-block;width:3.2em;color:var(--muted);user-select:none}
.prompt{padding:10px 12px;white-space:pre-wrap}
.muted{color:var(--muted)}
details summary{cursor:pointer;color:var(--accent);font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:9px 12px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
th{color:var(--muted);font-weight:600;text-transform:capitalize}
td.num,th.num{text-align:right}
a{color:var(--accent)}
.tag{border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700}.tag.bad{background:var(--bad-bg);color:var(--bad)}.tag.good{background:var(--good-bg);color:var(--good)}
.compare-grid{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.cmp{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px}
.cmp b{font-size:20px;margin-right:4px}.cmp.fixed b{color:var(--good)}.cmp.new b{color:var(--bad)}
.compare ul{margin:6px 0 10px;padding-left:20px}.compare li{margin:3px 0;font-size:14px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
.disclaimer{font-weight:700;color:var(--ink)}
@media print{body{background:#fff}main{padding:0}.finding{border-color:#ccc}details{display:block}details>summary{display:none}}
`;
