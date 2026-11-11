import { RULES } from "../rules/index.js";
import { STACK_LABELS } from "../core/stack.js";
import type { Confidence, Severity } from "../core/finding.js";

/**
 * The rule catalogue, built from the rule definitions themselves, so docs/rules.md, the
 * website's docs page, llms.txt and the MCP server's list_rules can't drift from the code.
 *
 * COVERAGE says plainly what each rule reads and where it stops. It is written by hand,
 * because limits aren't in the code, and a test fails if a rule has no entry.
 */
export const COVERAGE: Record<string, string> = {
  "SW-S01":
    "Files as they are now, using each provider's published key format (Stripe, GitHub, OpenAI, Anthropic, Supabase, AWS, Slack, SendGrid, npm, Hugging Face, Google, private keys and database URLs). Supabase service-role JWTs are flagged; anon keys aren't. Git-ignored files are skipped, because they aren't committed. When you scan a repository's top folder, earlier versions of files in git history are checked too (newest first, up to 20,000 file versions), and a secret found only there is reported with the commit that added it.",
  "SW-S02": ".env files that git tracks or that no .gitignore covers. Templates such as .env.example and empty files are skipped.",
  "SW-S03":
    "Variables with a public prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, NUXT_PUBLIC_, GATSBY_, PUBLIC_) whose name or value is a secret, in .env files (including git-ignored ones, which still get bundled) and in code that reads them.",
  "SW-S04": "Public variables holding LLM provider keys, code that reads them, and `dangerouslyAllowBrowser`.",
  "SW-D01": "Supabase SQL migrations (`supabase/migrations/*.sql`), in order, including later `enable` and `disable`, renames and drops.",
  "SW-D02": "Policies in Supabase SQL migrations or `supabase db dump` output whose `using` or `with check` is always true or only checks that someone is logged in.",
  "SW-D03": "Firestore security rules and Realtime Database JSON rules, found directly or through firebase.json.",
  "SW-D04": "Firebase Cloud Storage rules, and Supabase buckets made public in SQL (migrations and seed.sql), supabase/config.toml or createBucket/updateBucket calls. A public bucket whose name suggests private files (invoices, documents, ID scans) is high; one with a neutral name is medium, at medium confidence; buckets for images and avatars aren't flagged.",
  "SW-D05":
    "Views and functions in the public schema of Supabase SQL migrations, replayed in order. A view without `security_invoker = true` (in `with (...)` or a later `alter view ... set`) that reads from a table with RLS enabled is high; views over tables without RLS are left to SW-D01, and dropped views or views with access revoked from anon and authenticated aren't flagged. A `security definer` function with no `set search_path`, that isn't a trigger function and whose EXECUTE isn't revoked from public, anon and authenticated, is reported at medium confidence. Functions are matched by name, not by argument types. Materialized views aren't checked.",
  "SW-P01":"Stripe webhook handlers that act on real Stripe event names without `constructEvent` or `events.retrieve`, in the file or a local helper it imports.",
  "SW-P02": "Amounts, prices and discounts in Stripe create and update calls that come from request input.",
  "SW-A01": "Next.js route handlers and server actions that change data or use an admin database client without checking who is calling.",
  "SW-A02": "Next.js handlers that read, change or delete a record by an ID from the request, through Supabase's admin client, Prisma or Drizzle, without an owner filter.",
  "SW-A03": "Next.js handlers and server actions that call paid AI models, send email or SMS, or check passwords, with no rate limiter in the handler, a local helper or middleware.",
  "SW-A04": "Wildcard or echoed origins combined with credentials, in code (`cors()`, response headers) and in nginx config.",
  "SW-A05": "SQL strings built from request input and passed to query methods.",
  "SW-L01": "System prompts or instructions built from user input, in calls to model SDKs.",
  "SW-L02": "Model output rendered as HTML, passed to `eval` or `Function`, or run as SQL.",
  "SW-L03": "Agent tools whose model-chosen arguments reach shell commands, file deletes or writes, or `eval`, with no allow-list or confirmation step.",
  "SW-L04": "MCP configs (`.cursor/mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, Windsurf) with secrets written in, or remote servers over plain HTTP or with no auth header.",
  "SW-L05":
    "`enableAllProjectMcpServers: true` in Claude Code's `.claude/settings.json` or `.claude/settings.local.json` (any folder; comments allowed), reported even before the repo has an .mcp.json. In the MCP configs SW-L04 reads, stdio servers whose launch line pipes a download into a shell (`curl` or `wget ... | sh`, `irm ... | iex`) are low severity; servers started through `bash`, `sh`, `zsh`, `cmd`, `powershell` or `pwsh` (directly or through `env`) with a run-a-command flag (`-c`, `/c`, `-Command`, `-enc`) are low severity at medium confidence. `cmd /c` that only starts one program (the usual way to run npx on Windows), shells running a script file, and unpinned `npx` or `uvx` packages aren't flagged, and other tools' trust-all settings aren't checked.",
  "SW-X01": "Direct dependencies, at the versions in your lockfile, checked against OSV (osv.dev). Sends only package names and versions; needs a connection and is skipped with `--offline`.",
  "SW-X02": "Every dependency and devDependency name in package.json, checked on the public npm registry (names only, as npm install would). Not on npm: high. First published in the last 30 days: medium, at medium confidence. Private-registry packages (.npmrc) and the project's own workspace packages are skipped; needs a connection and is skipped with `--offline`.",
  "SW-B01": "Next.js projects only. Looks for Content-Security-Policy, frame protection and HSTS in next.config, middleware, host config (vercel.json, netlify.toml, _headers, firebase.json) and nginx, Caddy, Apache or Traefik config.",
};

export interface CatalogueEntry {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** "Any project", or the stacks the rule needs (it only runs when one is detected). */
  runsOn: string;
  summary: string;
  coverage: string;
}

export function catalogue(): CatalogueEntry[] {
  return RULES.map((r) => ({
    id: r.id,
    title: r.title,
    severity: r.severity,
    confidence: r.confidence,
    runsOn: r.appliesTo.length ? r.appliesTo.map((s) => STACK_LABELS[s]).join(", ") : "Any project",
    summary: r.docs.summary,
    coverage: COVERAGE[r.id] ?? "",
  }));
}

export const READS =
  "JavaScript and TypeScript (including JSX, Vue, Svelte and Astro script blocks; test files are skipped), Supabase SQL migrations, Firebase rules, .env files, MCP configs, Claude Code project settings, lockfiles, and web server config. Files over 1 MB, build folders and anything in .gitignore are skipped, except .env files, which still get bundled into your app (SW-S03).";

export const STILL_TO_COME: string[] = [];

const SITE = "https://dynamomaritime.com";
export const LINKS = {
  site: `${SITE}/seaworthy`,
  docs: `${SITE}/seaworthy/docs`,
  npm: "https://www.npmjs.com/package/seaworthy-cli",
  source: "https://github.com/harbourworks/seaworthy",
  privacy: `${SITE}/privacy`,
  support: `${SITE}/support`,
};

/** docs/rules.md in the code repo. */
export function rulesMarkdown(): string {
  const rows = catalogue();
  const out = [
    "# Seaworthy rules",
    "",
    "<!-- Generated by `npm run docs:rules` from src/rules and src/docs/catalogue.ts. Don't edit by hand. -->",
    "",
    `Every rule Seaworthy runs, with what it reads and where it stops. A rule only runs when its stack is detected. Run \`npx seaworthy-cli explain <ID>\` for an example of the problem and the fix.`,
    "",
    `**What Seaworthy reads:** ${READS}`,
    "",
    "| ID | Rule | Severity | Runs on |",
    "| --- | --- | --- | --- |",
    ...rows.map((r) => `| [${r.id}](#${r.id.toLowerCase()}) | ${r.title} | ${r.severity} | ${r.runsOn} |`),
    "",
  ];
  for (const r of rows) {
    out.push(`## ${r.id}`, "", `**${r.title}** · ${r.severity} · runs on: ${r.runsOn}`, "", r.summary, "", `**Checks:** ${r.coverage}`, "");
  }
  if (STILL_TO_COME.length) out.push("## Not checked yet", "", ...STILL_TO_COME.map((s) => `- ${s}`), "");
  out.push("*Seaworthy catches common, serious mistakes. It is not a security audit or a guarantee.*", "");
  return out.join("\n");
}

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
/** Escapes HTML, then turns `inline code` into <code>. */
const html = (s: string) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

/** The body of the website's /seaworthy/docs page (the site's layout adds header and footer). */
export function rulesHtml(): string {
  const rows = catalogue();
  const out = [
    `<!--{"title": "Seaworthy rules: every check, and where it stops", "description": "The full list of Seaworthy's security checks for AI-built apps: secrets, Supabase and Firebase rules, auth, payments, LLM and MCP risks, dependencies and headers.", "nav": "seaworthy"}-->`,
    `<!-- Generated by npm run docs:rules in the seaworthy repo. Don't edit by hand. -->`,
    `<div class="wrap">`,
    `  <div class="page-head">`,
    `    <p class="eyebrow">Seaworthy docs</p>`,
    `    <h1>Every check, and where it stops</h1>`,
    `    <p>${rows.length} rules. Each one runs only when its stack is detected. Run <code>npx seaworthy-cli explain &lt;ID&gt;</code> for an example of the problem and the fix.</p>`,
    `  </div>`,
    `  <div class="prose">`,
    `    <p><strong>What Seaworthy reads:</strong> ${html(READS)}</p>`,
    `    <table>`,
    `      <thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Runs on</th></tr></thead>`,
    `      <tbody>`,
    ...rows.map((r) => `        <tr><td><a href="#${r.id.toLowerCase()}">${r.id}</a></td><td>${esc(r.title)}</td><td>${r.severity}</td><td>${esc(r.runsOn)}</td></tr>`),
    `      </tbody>`,
    `    </table>`,
  ];
  for (const r of rows) {
    out.push(
      `    <h2 id="${r.id.toLowerCase()}">${r.id}: ${esc(r.title)}</h2>`,
      `    <p><strong>${r.severity[0]!.toUpperCase()}${r.severity.slice(1)}</strong> · runs on: ${esc(r.runsOn)}</p>`,
      `    <p>${html(r.summary)}</p>`,
      `    <p><strong>Checks:</strong> ${html(r.coverage)}</p>`,
    );
  }
  if (STILL_TO_COME.length) {
    out.push(`    <h2 id="not-yet">Not checked yet</h2>`, `    <ul>${STILL_TO_COME.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`);
  }
  out.push(
    `    <p><em>Seaworthy catches common, serious mistakes. It is not a security audit or a guarantee.</em></p>`,
    `  </div>`,
    `</div>`,
    "",
  );
  return out.join("\n");
}

/** /llms.txt, following the llms.txt convention: H1, a blockquote summary, then sections of links. */
export function llmsTxt(): string {
  return [
    "# Seaworthy",
    "",
    "> Seaworthy is a local, pre-launch security scanner for apps built with AI coding tools. Run `npx seaworthy-cli` in a project folder. It finds leaked keys, open Supabase and Firebase rules, secrets shipped to the browser, API routes with no auth or ownership check, unverified Stripe webhooks, SQL injection, prompt injection and unsafe agent tools, and gives a fix for each. Code never leaves the machine. Made by Dynamo Maritime Ltd.",
    "",
    "## Docs",
    "",
    `- [Overview](${LINKS.site}): what it checks, plans and pricing`,
    `- [Rules](${LINKS.docs}): every check, what it reads and where it stops`,
    `- [Full docs as plain text](${"https://dynamomaritime.com"}/llms-full.txt): commands, flags, JSON output, rules and MCP setup in one file`,
    `- [npm package](${LINKS.npm}): install and run with \`npx seaworthy-cli\``,
    `- [Source](${LINKS.source}): source-available code, GitHub Actions workflow and MCP server`,
    "",
    "## Policies",
    "",
    `- [Privacy](${LINKS.privacy}): what is and isn't sent (no code, ever)`,
    `- [Support](${LINKS.support}): licence keys, CI, billing and false positives`,
    "",
  ].join("\n");
}
