import { parseArgs } from "node:util";
import { existsSync, statSync, writeFileSync } from "node:fs";
import { basename, relative, resolve, sep } from "node:path";
import pc from "picocolors";
import { ConfigError, hasBranding, loadConfig, mergeConfig, type Config } from "../core/config.js";
import { scan, type ScanResult } from "../core/scan.js";
import { ProjectFiles } from "../core/project.js";
import { excluder, walk } from "../core/walk.js";
import type { OsvResult } from "../deps/osv.js";
import { dependencyLookup } from "../deps/lookup.js";
import { renderSarif } from "../reporters/sarif.js";
import { renderMarkdown, type MarkdownOptions } from "../reporters/markdown.js";
import { BaselineError, extractBaseline } from "../core/baseline.js";
import { diffFindings } from "../pro/compare.js";
import { prFailed, prJson, renderPrMarkdown, renderPrTerminal, type PrCheck } from "../pro/pr.js";
import { initProject } from "./init.js";
import { agentTargets, writeAgentTarget } from "./agent.js";
import { FEATURE_LABELS, FEATURE_SHORT, TIER_INFO, hasFeature, priceLabel, requiredTier, type Feature, type Tier } from "../core/entitlements.js";
import { RULES, findRule } from "../rules/index.js";
import { renderTerminal } from "../reporters/terminal.js";
import { renderJson } from "../reporters/json.js";
import { VERSION } from "../version.js";
import { PORTAL_URL, PURCHASE_URL, polarSettings } from "../licensing/config.js";
import { openUrl as defaultOpenUrl } from "./open.js";
import type { LicenceProvider } from "../licensing/provider.js";
import { PolarProvider } from "../licensing/polar.js";
import { LicenceStore, userConfigDir } from "../licensing/store.js";
import { defaultMachineLabel, maskKey, resolveLicence, type LicenceStatus } from "../licensing/licence.js";
import { loadHistory, recordScan } from "../pro/history.js";
import { compareScans, type Comparison } from "../pro/compare.js";
import { discoverProjects } from "../pro/discover.js";
import { SEAWORTHY_BRANDING, resolveBranding } from "../pro/branding.js";
import { renderHtml, type ReportProject } from "../pro/html.js";
import { renderComparison, renderHistory, renderSinceLast } from "../pro/terminal.js";

export interface CliDeps {
  out: (s: string) => void;
  err: (s: string) => void;
  env: NodeJS.ProcessEnv;
  cwd: string;
  now: () => Date;
  /** Defaults to Polar. Tests pass a MockProvider. */
  provider?: LicenceProvider;
  /** Used for the OSV dependency lookup. Defaults to the global fetch; tests pass a fake. */
  fetch?: typeof fetch;
  /** A person at a terminal (not CI, not piped): links may be opened in the browser. */
  interactive?: boolean;
  /** Opens a link in the browser; false if it couldn't. Tests pass a fake. */
  openUrl?: (url: string) => boolean;
  /** Asks a yes/no question at a terminal. Absent when nobody can answer (CI, piped). */
  ask?: (question: string) => Promise<boolean>;
}

const COMMANDS = new Set(["scan", "init", "explain", "rules", "mcp", "buy", "upgrade", "login", "logout", "status", "history", "compare"]);

const HELP = `
  ${pc.bold("seaworthy")}: pre-launch security check for AI-built apps. Runs locally.

  ${pc.bold("Usage")}
    seaworthy [scan] [path]          Scan a project (default: current folder)
    seaworthy init [path]            Add a config file and a GitHub Actions workflow
      --pr                           ...that comments on pull requests with only
                                     the problems they introduce         ${pc.dim("Pro")}
      --agent                        Add a security-check step to your AI assistant's
                                     rules file (asks first; --yes to skip asking)
    seaworthy explain <rule-id>      Explain one rule and how to fix it
    seaworthy rules                  List every rule
    seaworthy mcp                    Run as an MCP server (stdio) for AI coding assistants

  ${pc.bold("Options")}
    --format terminal|json|sarif|markdown|html
                                     Output format (default: terminal; sarif is for GitHub
                                     code scanning; markdown is for CI summaries and pull
                                     request comments; html is Pro)
    --output <file>                  Where to save SARIF, Markdown or HTML (default:
                                     seaworthy.sarif, seaworthy-report.md,
                                     seaworthy-report.html)
    --fail-on critical|high|medium|low
                                     Exit 1 at or above this severity (default: high)
    --min-confidence high|medium|low Hide findings below this confidence (default: high)
    --config <file>                  Config file (default: ./seaworthy.config.json)
    --offline                        Make no network calls at all
    -h, --help    -v, --version

  ${pc.bold("Pro and Agency")}
    seaworthy buy                    See the plans and open the checkout
    seaworthy login <key>            Turn on your licence on this machine
                                     (find your key: ${PORTAL_URL})
    seaworthy logout                 Turn it off and free this machine's slot
    seaworthy status                 Show your plan and licence state
    seaworthy history [path]         Scan history and trends            ${pc.dim("Pro")}
    seaworthy compare [path]         What's fixed and new between scans ${pc.dim("Pro")}
      --from <scan#> --to <scan#>    Pick two scans (default: the last two)
    seaworthy scan --baseline <ref>  Only what's new since <ref>, e.g. a pull
                                     request against origin/main         ${pc.dim("Pro")}
    seaworthy scan <folder> --all    Every project in a folder, one report ${pc.dim("Agency")}
    --no-history                     Don't record this scan in history

  ${pc.bold("Exit codes")}  0 clean · 1 findings at or above the threshold · 2 tool error
  ${pc.dim("In CI, set SEAWORTHY_LICENCE to your key instead of running login.")}
`;

export async function run(argv: string[], deps: CliDeps): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string" },
        baseline: { type: "string" },
        output: { type: "string" },
        "fail-on": { type: "string" },
        "min-confidence": { type: "string" },
        config: { type: "string" },
        offline: { type: "boolean" },
        all: { type: "boolean" },
        "no-history": { type: "boolean" },
        label: { type: "string" },
        from: { type: "string" },
        to: { type: "string" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
        force: { type: "boolean" },
        pr: { type: "boolean" },
        "no-open": { type: "boolean" },
        agent: { type: "boolean" },
        yes: { type: "boolean", short: "y" },
      },
    });
  } catch (err) {
    deps.err(pc.red(`  ${(err as Error).message}`) + "\n  Run seaworthy --help for usage.");
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) return (deps.out(HELP), 0);
  if (values.version) return (deps.out(VERSION), 0);

  const [first, ...rest] = positionals;
  const command = first && COMMANDS.has(first) ? first : "scan";
  const args = first && COMMANDS.has(first) ? rest : positionals;

  const store = new LicenceStore(userConfigDir(deps.env));
  const provider = deps.provider ?? new PolarProvider(polarSettings(deps.env));
  const ctx: Ctx = { deps, store, provider, values };

  switch (command) {
    case "explain":
      return explain(args[0], deps);
    case "rules":
      return listRules(deps);
    case "init":
      return values.agent ? initAgent(args[0], ctx) : init(args[0], ctx);
    case "mcp": {
      // Stdio is the protocol channel: nothing else may be printed to stdout from here on.
      const { runStdio } = await import("../mcp/server.js");
      await runStdio({ cwd: deps.cwd, version: VERSION, fetch: deps.fetch });
      return 0;
    }
    case "buy":
    case "upgrade":
      return buy(ctx);
    case "login":
      return login(args[0], ctx);
    case "logout":
      return logout(ctx);
    case "status":
      return status(ctx);
    default:
      return scanCommand(command as "scan" | "history" | "compare", args[0], ctx);
  }
}

interface Ctx {
  deps: CliDeps;
  store: LicenceStore;
  provider: LicenceProvider;
  values: Record<string, string | boolean | undefined>;
}

// ── Scanning ────────────────────────────────────────────────────────────────

async function scanCommand(command: "scan" | "history" | "compare", pathArg: string | undefined, ctx: Ctx): Promise<number> {
  const { deps, values } = ctx;
  const target = resolve(deps.cwd, pathArg ?? ".");
  if (!existsSync(target) || !statSync(target).isDirectory()) {
    deps.err(pc.red(`  Not a folder: ${target}`));
    return 2;
  }

  const format = (values.format as string | undefined) ?? "terminal";
  if (!["terminal", "json", "sarif", "markdown", "html"].includes(format)) {
    deps.err(pc.red(`  --format must be terminal, json, sarif, markdown or html`));
    return 2;
  }
  const baselineRef = values.baseline as string | undefined;
  if (baselineRef !== undefined && values.all) {
    deps.err(pc.red(`  --baseline compares one project, so it can't be combined with --all.`));
    return 2;
  }

  let topConfig: Config;
  try {
    topConfig = configFor(target, values, values.config as string | undefined);
  } catch (err) {
    if (err instanceof ConfigError) return (deps.err(pc.red(`  ${err.message}`)), 2);
    throw err;
  }

  // Free users have no licence, so this makes no network call. Logged-in users are
  // checked online at most once a day; the result is cached with a 14-day offline grace.
  const licence = await resolveLicence({
    provider: ctx.provider,
    store: ctx.store,
    env: deps.env,
    now: deps.now(),
    offline: Boolean(values.offline) || topConfig.offline,
  });
  const tier = licence.tier;
  const notes: string[] = [];
  if (licence.message && licence.state !== "active") notes.push(licence.message);

  const upsells: string[] = [];
  const allow = (feature: Feature, fallback: string): boolean => {
    if (hasFeature(tier, feature)) return true;
    upsells.push(upsell(feature, fallback));
    return false;
  };

  const say = format === "json" ? deps.err : deps.out;
  const finish = (code: number) => {
    for (const n of notes) say(pc.dim(`  ${n}`));
    for (const u of upsells) say(u);
    if (notes.length || upsells.length) say("");
    return code;
  };

  // history and compare are read-only views of saved scans.
  if (command === "history" && allow("history", "Ran a normal scan instead.")) {
    deps.out(renderHistory(basename(target), loadHistory(target)));
    return finish(0);
  }
  if (command === "compare" && allow("compare", "Ran a normal scan instead.")) {
    return finish(compareCommand(target, ctx));
  }

  // Which projects to scan.
  let projects: Array<{ dir: string; name: string }>;
  const multi = Boolean(values.all) && allow("scan-all", `Scanned ${basename(target)} as a single project instead.`);
  if (multi) {
    projects = discoverProjects(target);
    if (projects.length === 0) {
      deps.err(pc.yellow(`  No projects found under ${target}. A project is a folder with package.json, supabase/, firebase.json or seaworthy.config.json.`));
      return finish(0);
    }
  } else {
    projects = [{ dir: target, name: basename(target) }];
  }

  // Without Pro this is a normal full scan, plus the one-line upsell.
  const useBaseline = baselineRef !== undefined && allow("pr-checks", "Ran a full scan instead.");
  let prCheck: PrCheck | null = null;

  const recordHistory = !values["no-history"] && hasFeature(tier, "history");
  const scanned: ReportProject[] = [];
  for (const p of projects) {
    let config: Config;
    try {
      // With --all, each project uses its own seaworthy.config.json; command-line flags still win.
      config = multi ? configFor(p.dir, values) : topConfig;
    } catch (err) {
      if (err instanceof ConfigError) {
        notes.push(`Skipped ${p.name}: ${err.message}`);
        continue;
      }
      throw err;
    }
    const osv = await dependencyLookup(p.dir, config, deps.fetch);
    const result = scan(p.dir, config, RULES, { osv });
    const label = multi ? `${p.name}: ` : "";
    if (osv?.status === "ok" && osv.checked > 0) {
      notes.push(`${label}Checked ${osv.checked} ${osv.checked === 1 ? "dependency" : "dependencies"} against OSV (osv.dev). Only package names and versions were sent.`);
    } else if (osv?.status === "offline") {
      notes.push(`${label}Dependency check skipped (offline).`);
    } else if (osv?.status === "failed") {
      notes.push(`${label}Dependency check skipped: ${osv.reason}. The rest of the scan is complete.`);
    }
    const project = new ProjectFiles(p.dir, walk(p.dir, config.ignore).files, excluder(config.ignore));
    if (useBaseline) {
      try {
        prCheck = await baselineCheck(p.dir, baselineRef!, config, result, osv, deps, notes);
      } catch (err) {
        if (!(err instanceof BaselineError)) throw err;
        deps.err(pc.red(`  ${err.message}`));
        return finish(2);
      }
    }
    let comparison: Comparison | null = null;
    if (recordHistory) {
      const previous = loadHistory(p.dir).scans.at(-1) ?? null;
      const saved = recordScan(p.dir, result.findings, deps.now());
      if (!saved) notes.push(`Couldn't save scan history in ${p.dir} (folder not writable).`);
      if (previous && saved) comparison = compareScans(previous, saved);
    }
    scanned.push({ name: multi ? p.name : basename(p.dir), result, project, comparison });
  }

  const failed = prCheck ? prFailed(prCheck) : scanned.some((s) => s.result.failed);

  if (format === "json") {
    if (prCheck) {
      const single = JSON.parse(renderJson(scanned[0]!.result, VERSION));
      deps.out(JSON.stringify({ ...single, failed, ...prJson(prCheck) }, null, 2));
    } else {
      deps.out(scanned.length === 1 && !multi ? renderJson(scanned[0]!.result, VERSION) : multiJson(scanned));
    }
    return finish(failed ? 1 : 0);
  }

  if (prCheck) {
    const s = scanned[0]!;
    deps.out(renderPrTerminal(s.result, s.project, prCheck, VERSION).replace(/\n$/, ""));
    deps.out("");
  } else {
    printTerminal(scanned, multi, deps);
  }

  if (format === "markdown") {
    const out = resolve(deps.cwd, (values.output as string | undefined) ?? "seaworthy-report.md");
    // Notes and upsells go in the summary too: in CI it is what people read.
    const mdNotes = [...notes, ...upsells].map((n) => n.replace(/\x1b\[[0-9;]*m/g, "").trim());
    const s = scanned[0]!;
    const link = multi ? undefined : githubLink(target, deps.env);
    const md = prCheck
      ? renderPrMarkdown(s.name, s.result, s.project, prCheck, VERSION, { link, notes: mdNotes })
      : renderMarkdown(scanned.map((x) => ({ name: x.name, result: x.result, project: x.project })), VERSION, { link, notes: mdNotes });
    try {
      writeFileSync(out, md);
      deps.out(`  ${pc.green("✔")} Markdown summary saved: ${pc.cyan(out)}\n`);
    } catch (err) {
      deps.err(pc.red(`  Couldn't write Markdown to ${out}: ${(err as Error).message}`));
      return finish(2);
    }
  }

  if (format === "sarif") {
    const out = resolve(deps.cwd, (values.output as string | undefined) ?? "seaworthy.sarif");
    try {
      writeFileSync(out, renderSarif(scanned.map((s) => ({ prefix: multi ? s.name : "", result: s.result })), VERSION));
      deps.out(`  ${pc.green("✔")} SARIF saved: ${pc.cyan(out)}\n`);
    } catch (err) {
      deps.err(pc.red(`  Couldn't write SARIF to ${out}: ${(err as Error).message}`));
      return finish(2);
    }
  }

  if (format === "html" && allow("html-report", "Showing terminal output instead.")) {
    let branding = SEAWORTHY_BRANDING;
    if (hasBranding(topConfig.report) && allow("white-label", "This report uses Seaworthy branding instead.")) {
      const r = resolveBranding(topConfig.report, target);
      branding = r.branding;
      notes.push(...r.warnings);
    }
    const out = resolve(deps.cwd, (values.output as string | undefined) ?? "seaworthy-report.html");
    try {
      writeFileSync(out, renderHtml({ projects: scanned, branding, generatedAt: deps.now(), version: VERSION }));
      deps.out(`  ${pc.green("✔")} HTML report saved: ${pc.cyan(out)}\n`);
    } catch (err) {
      deps.err(pc.red(`  Couldn't write the report to ${out}: ${(err as Error).message}`));
      return finish(2);
    }
  }
  return finish(failed ? 1 : 0);
}

/**
 * Scans the base ref the same way as the working tree (with the working tree's config, so a
 * pull request can't loosen its own check) and splits the findings into new, fixed and
 * already there.
 */
async function baselineCheck(
  dir: string,
  ref: string,
  config: Config,
  head: ScanResult,
  headOsv: OsvResult | undefined,
  deps: CliDeps,
  notes: string[],
): Promise<PrCheck> {
  const base = extractBaseline(dir, ref);
  try {
    const osv = await dependencyLookup(base.dir, config, deps.fetch);
    const before = scan(base.dir, config, RULES, { osv }).findings;
    const diff = diffFindings(before, head.findings);
    // If OSV answered for one side only, every dependency finding would look new.
    if (headOsv?.status === "ok" && osv?.status === "failed") {
      const isDep = (f: { ruleId: string }) => f.ruleId === "SW-X01";
      diff.stillPresent.push(...diff.added.filter(isDep));
      diff.added = diff.added.filter((f) => !isDep(f));
      notes.push(`The dependency check couldn't run on ${ref}, so dependency findings are counted as already there.`);
    }
    return { ref, sha: base.sha, diff, failOn: config.failOn };
  } finally {
    base.cleanup();
  }
}

/**
 * In GitHub Actions, links each finding to its line in the commit being checked. The
 * scanned folder may be inside the repo, so its path is prefixed.
 */
function githubLink(target: string, env: NodeJS.ProcessEnv): MarkdownOptions["link"] {
  const server = env.GITHUB_SERVER_URL;
  const repo = env.GITHUB_REPOSITORY;
  const sha = env.GITHUB_SHA;
  const workspace = env.GITHUB_WORKSPACE;
  if (!server || !repo || !sha || !/^[0-9a-f]{40,64}$/.test(sha) || !/^[\w.-]+\/[\w.-]+$/.test(repo) || !/^https:\/\/[\w.-]+$/.test(server)) {
    return undefined;
  }
  const rel = workspace ? relative(resolve(workspace), target).split(sep).join("/") : "";
  if (rel.startsWith("..")) return undefined;
  const prefix = rel ? `${rel}/` : "";
  return (file, line) => `${server}/${repo}/blob/${sha}/${(prefix + file).split("/").map(encodeURIComponent).join("/")}#L${line}`;
}

/**
 * Adds the Seaworthy step to the AI assistant files a project already has (or AGENTS.md).
 * Shows exactly what it will add, and writes nothing unless the user says yes (or --yes).
 */
async function initAgent(path: string | undefined, ctx: Ctx): Promise<number> {
  const { deps, values } = ctx;
  const dir = resolve(deps.cwd, path ?? ".");
  if (!existsSync(dir) || !statSync(dir).isDirectory()) return (deps.err(pc.red(`  Not a folder: ${dir}`)), 2);
  const { targets, already } = agentTargets(dir);
  deps.out("");
  for (const f of already) deps.out(`  ${pc.dim("•")} ${f} already mentions Seaworthy, left as it is`);
  if (targets.length === 0) return (deps.out(""), 0);

  deps.out(`  ${pc.bold("This adds a security-check step for your AI coding assistant:")}`);
  deps.out("");
  for (const t of targets) deps.out(`    ${t.mode === "create" ? "Create" : "Append to"} ${pc.cyan(t.file)}  ${pc.dim(`(read by ${t.reads})`)}`);
  deps.out("");
  for (const line of targets[0]!.content.trimEnd().split("\n")) deps.out(pc.dim(`  │ `) + line);
  deps.out("");

  let go = Boolean(values.yes);
  if (!go && deps.ask) go = await deps.ask("  Add it? [y/N] ");
  if (!go) {
    deps.out(deps.ask ? "  Nothing changed." : `  Nothing changed. Run again with --yes to add it, or copy the text above yourself.`);
    deps.out("");
    return 0;
  }
  for (const t of targets) {
    writeAgentTarget(dir, t);
    deps.out(`  ${pc.green("✔")} ${t.mode === "create" ? "Created" : "Updated"} ${t.file}`);
  }
  deps.out(pc.dim("  Commit it so everyone's assistant follows the same step."));
  deps.out("");
  return 0;
}

function init(path: string | undefined, ctx: Ctx): number {
  const { deps, values } = ctx;
  const dir = resolve(deps.cwd, path ?? ".");
  const pr = Boolean(values.pr);
  const { created, skipped } = initProject(dir, Boolean(values.force), { pr });
  deps.out("");
  for (const f of created) deps.out(`  ${pc.green("✔")} Created ${f}`);
  for (const f of skipped) deps.out(`  ${pc.dim("•")} ${f} already exists, left as it is ${pc.dim("(--force to replace)")}`);
  deps.out("");
  deps.out(`  ${pc.bold("Next")}`);
  if (pr) {
    deps.out(`    1. Add your licence key as a repository secret called SEAWORTHY_LICENCE`);
    deps.out(`       (Settings → Secrets and variables → Actions). Without it, pull requests get a full scan.`);
    deps.out(`    2. Commit both files. Each pull request then gets one comment, updated on every push,`);
    deps.out(`       with only the problems it introduces. Pushes to main go to the Security tab.`);
    deps.out(`    3. Tune what fails the build in seaworthy.config.json (failOn, rules, ignore).`);
    deps.out("");
    return 0;
  }
  deps.out(`    1. Commit both files. Every pull request and push to main is then scanned.`);
  deps.out(`    2. Findings appear in the Security tab and on pull requests (free on public repos;`);
  deps.out(`       private repos need GitHub code scanning enabled).`);
  deps.out(`    3. Tune what fails the build in seaworthy.config.json (failOn, rules, ignore).`);
  deps.out("");
  return 0;
}

function printTerminal(scanned: ReportProject[], multi: boolean, deps: CliDeps) {
  for (const s of scanned) {
    deps.out(renderTerminal(s.result, s.project, VERSION).replace(/\n$/, ""));
    if (s.comparison) deps.out(renderSinceLast(s.comparison));
    deps.out("");
  }
  if (multi) {
    const bad = scanned.filter((s) => s.result.failed).length;
    const line = bad
      ? `${pc.red(pc.bold(`✖ ${bad} of ${scanned.length} projects not seaworthy`))}: ${scanned.filter((s) => s.result.failed).map((s) => s.name).join(", ")}`
      : pc.green(pc.bold(`✔ All ${scanned.length} projects seaworthy`));
    deps.out(`  ${line}\n`);
  }
}

function compareCommand(target: string, ctx: Ctx): number {
  const { deps, values } = ctx;
  const scans = loadHistory(target).scans;
  if (scans.length < 2) {
    deps.out(`\n  Compare needs two recorded scans of this project, and there ${scans.length === 1 ? "is 1" : `are ${scans.length}`}. Run seaworthy again after making changes.\n`);
    return 0;
  }
  const pick = (v: unknown, fallback: number) => {
    if (v === undefined) return scans.at(fallback)!;
    const id = Number(String(v).replace(/^#/, ""));
    return scans.find((s) => s.id === id) ?? null;
  };
  const before = pick(values.from, -2);
  const after = pick(values.to, -1);
  if (!before || !after) {
    deps.err(pc.red(`  No scan with that number. Run seaworthy history to see them.`));
    return 2;
  }
  deps.out(renderComparison(basename(target), compareScans(before, after)));
  return 0;
}

function configFor(dir: string, values: Ctx["values"], explicit?: string): Config {
  const overrides: Record<string, unknown> = {};
  if (values["fail-on"]) overrides.failOn = values["fail-on"];
  if (values["min-confidence"]) overrides.minConfidence = values["min-confidence"];
  if (values.offline) overrides.offline = true;
  return mergeConfig(loadConfig(dir, explicit ? resolve(explicit) : undefined), overrides, "command line");
}

function multiJson(scanned: ReportProject[]): string {
  return JSON.stringify(
    {
      tool: "seaworthy",
      version: VERSION,
      failed: scanned.some((s) => s.result.failed),
      projects: scanned.map((s) => ({ name: s.name, ...JSON.parse(renderJson(s.result, VERSION)) })),
    },
    null,
    2,
  );
}

/** The single friendly line shown when a paid feature is used without the right plan. */
export function upsell(feature: Feature, fallback: string): string {
  const t = TIER_INFO[requiredTier(feature)];
  return `  ${pc.cyan("✦")} ${fallback} Seaworthy ${t.name} (${priceLabel(requiredTier(feature))}) unlocks ${featurePhrase(feature)}: ${pc.cyan(PURCHASE_URL)}`;
}

/** "HTML reports", "scan history and trends": a label that reads well mid-sentence. */
function featurePhrase(feature: Feature): string {
  const label = FEATURE_LABELS[feature];
  return /^[A-Z][a-z]/.test(label) ? label[0]!.toLowerCase() + label.slice(1) : label;
}

// ── Licence commands ────────────────────────────────────────────────────────

/** Opens a link for a person at a terminal, unless --no-open. Never in CI or when piped. */
function maybeOpen(url: string, ctx: Ctx): boolean {
  if (!ctx.deps.interactive || ctx.values["no-open"]) return false;
  return (ctx.deps.openUrl ?? defaultOpenUrl)(url);
}

/** The plans, the checkout link (opened in the browser at a terminal) and what to do after paying. */
function buy(ctx: Ctx): number {
  const { deps, store } = ctx;
  const order = (fs: readonly Feature[]) => [...fs].sort((a, b) => Number(b === "pr-checks") - Number(a === "pr-checks"));
  const proOnly = order(TIER_INFO.pro.features);
  const agencyOnly = TIER_INFO.agency.features.filter((f) => !proOnly.includes(f));
  const row = (name: string, price: string, what: string) => `  ${pc.bold(name.padEnd(8))}${price.padEnd(24)}${what}`;
  const out = ["", `  ${pc.bold("Seaworthy plans")}`, ""];
  out.push(row("Free", "£0", "every check, all free output formats, the CI workflow"));
  out.push(row("Pro", priceLabel("pro"), `+ ${proOnly.map((f) => FEATURE_SHORT[f]).join(", ")} · ${TIER_INFO.pro.machines} machines`));
  out.push(row("Agency", priceLabel("agency"), `+ ${agencyOnly.map((f) => FEATURE_SHORT[f]).join(", ")} · ${TIER_INFO.agency.machines} machines`));
  out.push("");
  const current = deps.env.SEAWORTHY_LICENCE?.trim() ? null : store.load();
  if (current && !current.problem) {
    out.push(pc.dim(`  You're logged in on this machine with Seaworthy ${TIER_INFO[current.tier].name} (${current.displayKey}).`), "");
  }
  const opened = maybeOpen(PURCHASE_URL, ctx);
  out.push(
    opened
      ? `  ${pc.green("✔")} Opened the checkout in your browser. If it didn't appear: ${pc.cyan(PURCHASE_URL)}`
      : `  ${pc.bold("Buy:")} ${pc.cyan(PURCHASE_URL)}`,
  );
  out.push(pc.dim("  Payment, tax, invoices and cancelling are handled by Polar, our merchant of record."));
  out.push("");
  out.push(`  ${pc.bold("After paying")}`);
  out.push(`    1. Get your key: ${pc.cyan(PORTAL_URL)}`);
  out.push(pc.dim("       Enter the email you bought with; the key is under your plan."));
  out.push(`    2. ${pc.cyan("seaworthy login <key>")}`);
  out.push(pc.dim("    In CI, add the key as a repository secret called SEAWORTHY_LICENCE instead."));
  out.push("");
  deps.out(out.join("\n"));
  return 0;
}

async function login(keyArg: string | undefined, ctx: Ctx): Promise<number> {
  const { deps, store, provider, values } = ctx;
  const key = keyArg?.trim();
  if (!key || /\s/.test(key) || key.length > 200) {
    const opened = !key && maybeOpen(PORTAL_URL, ctx);
    deps.err(
      [
        "",
        `  ${pc.bold("Usage:")} seaworthy login <licence-key>`,
        "",
        `  ${pc.bold("Your key")} is in the customer portal: ${pc.cyan(PORTAL_URL)}${opened ? pc.dim("  (opened in your browser)") : ""}`,
        "  Enter the email you bought with, type the code Polar emails you, and copy the key",
        "  shown under your plan. Then run seaworthy login <key>.",
        pc.dim(`  No plan yet? seaworthy buy`),
        "",
      ].join("\n"),
    );
    return 2;
  }
  if (values.offline) {
    deps.err(pc.red("  Logging in needs one online check. Run it without --offline."));
    return 2;
  }
  const label = ((values.label as string | undefined)?.trim() || defaultMachineLabel()).slice(0, 200);

  // Switching keys: free the old slot first, so it isn't left using up a machine.
  const existing = store.load();
  if (existing && existing.key !== key && existing.activationId) {
    await provider.deactivate(existing.key, existing.activationId);
  }
  if (existing && existing.key === key && existing.activationId && !existing.problem) {
    const v = await provider.validate(key, existing.activationId);
    if (v.ok) {
      store.save({ ...existing, tier: v.value.tier, displayKey: v.value.displayKey, lastValidatedAt: deps.now().toISOString() });
      deps.out(`\n  ${pc.green("✔")} Already logged in: ${pc.bold(`Seaworthy ${TIER_INFO[v.value.tier].name}`)} on ${existing.machineLabel}.\n`);
      return 0;
    }
  }

  const a = await provider.activate(key, label);
  if (!a.ok) {
    deps.err(`\n  ${pc.red("✖")} ${loginFailure(a.reason, a.detail)}\n`);
    return 1;
  }
  store.save({
    version: 1,
    key,
    activationId: a.value.activationId,
    machineLabel: label,
    tier: a.value.tier,
    displayKey: a.value.displayKey,
    lastValidatedAt: deps.now().toISOString(),
  });
  const info = TIER_INFO[a.value.tier];
  deps.out(
    [
      "",
      `  ${pc.green("✔")} Logged in: ${pc.bold(`Seaworthy ${info.name}`)} on ${label}.`,
      `  Unlocked: ${info.features.map((f) => FEATURE_LABELS[f]).join(", ")}.`,
      pc.dim(`  This key works on up to ${a.value.machineLimit ?? info.machines} machines. Saved in ${store.path}`),
      deps.env.SEAWORTHY_LICENCE ? pc.yellow("  Note: SEAWORTHY_LICENCE is set in this shell and takes priority over this login.") : "",
      "",
    ]
      .filter((l) => l !== "")
      .join("\n") + "\n",
  );
  return 0;
}

function loginFailure(reason: string, detail: string): string {
  switch (reason) {
    case "invalid":
      return `That key wasn't recognised. Check you copied all of it from the customer portal: ${PORTAL_URL}`;
    case "revoked":
      return `That key is no longer active; the subscription may have ended. Renew at ${PURCHASE_URL}.`;
    case "expired":
      return `That key has expired. Renew at ${PURCHASE_URL}.`;
    case "machine-limit":
      return `That key is already in use on as many machines as your plan allows. Run seaworthy logout on one you no longer use, or remove it in the customer portal: ${PORTAL_URL}`;
    case "not-seaworthy":
      return "That key isn't a Seaworthy licence. Check you copied the right one.";
    case "unreachable":
      return `${detail} Check your connection and try again. Scans keep working in the meantime.`;
    case "not-configured":
      return `${detail} Free scans work as normal.`;
    default:
      return detail;
  }
}

async function logout(ctx: Ctx): Promise<number> {
  const { deps, store, provider } = ctx;
  const existing = store.load();
  if (!existing) {
    deps.out("\n  You're not logged in on this machine. Seaworthy is running on the Free plan.\n");
    return 0;
  }
  let freed = true;
  if (existing.activationId && !ctx.values.offline) {
    const r = await provider.deactivate(existing.key, existing.activationId);
    freed = r.ok;
  } else if (existing.activationId) {
    freed = false;
  }
  store.clear();
  deps.out(
    `\n  ${pc.green("✔")} Logged out. Seaworthy is back on the Free plan on this machine.` +
      (freed
        ? pc.dim(`\n  This machine's slot on ${existing.displayKey} is free again.`)
        : pc.yellow(`\n  Couldn't reach the licence server to free this machine's slot. Remove "${existing.machineLabel}" in the customer portal if you need it: ${PORTAL_URL}`)) +
      "\n",
  );
  return 0;
}

async function status(ctx: Ctx): Promise<number> {
  const { deps, store, provider, values } = ctx;
  const s: LicenceStatus = await resolveLicence({
    provider,
    store,
    env: deps.env,
    now: deps.now(),
    offline: Boolean(values.offline),
    forceOnline: !values.offline,
  });
  const out: string[] = [""];
  if (s.state === "none") {
    out.push(`  ${pc.bold("Seaworthy Free")}  ${pc.dim("· every check, terminal, JSON and CI output")}`);
    out.push(`  Pro (${priceLabel("pro")}) adds ${TIER_INFO.pro.features.map(featurePhrase).join(", ")}.`);
    out.push(`  Agency (${priceLabel("agency")}) adds white-label reports and --all.`);
    out.push(`  ${pc.cyan("seaworthy buy")} to open the checkout, then ${pc.cyan("seaworthy login <key>")}.`);
    out.push("");
    deps.out(out.join("\n"));
    return 0;
  }

  const stateText: Record<string, string> = {
    active: pc.green("active"),
    grace: pc.yellow("offline grace period"),
    lapsed: pc.yellow("paused: needs an online check"),
    ended: pc.red("not active"),
    "not-configured": pc.yellow("licensing not set up in this build"),
  };
  const lic = s.licensedTier as Tier;
  const confirmed = Boolean(s.lastValidatedAt);
  const planName = confirmed ? `Seaworthy ${TIER_INFO[lic].name}` : "Seaworthy licence (not confirmed yet)";
  out.push(`  ${pc.bold(planName)}  ${pc.dim("·")}  ${stateText[s.state] ?? s.state}`);
  out.push(`  ${pc.dim("Key".padEnd(10))}${s.displayKey ?? maskKey("")}${s.source === "env" ? pc.dim("  (from SEAWORTHY_LICENCE)") : ""}`);
  if (s.source === "file") out.push(`  ${pc.dim("Machine".padEnd(10))}${s.machineLabel}`);
  if (s.lastValidatedAt) out.push(`  ${pc.dim("Checked".padEnd(10))}${s.lastValidatedAt.slice(0, 16).replace("T", " ")} UTC${s.checkedOnline ? pc.dim("  (just now)") : ""}`);
  if (s.graceEndsAt) out.push(`  ${pc.dim("Offline".padEnd(10))}keeps working until ${s.graceEndsAt.slice(0, 10)}`);
  if (confirmed) out.push(`  ${pc.dim("Plan".padEnd(10))}${TIER_INFO[lic].features.map((f) => FEATURE_LABELS[f]).join(", ")}`);
  if (confirmed && s.tier !== lic) out.push(`  ${pc.dim("Now".padEnd(10))}running as Free until this is sorted`);
  if (s.message) out.push("", `  ${s.message}`);
  out.push("");
  deps.out(out.join("\n"));
  return 0;
}

// ── Rule docs ───────────────────────────────────────────────────────────────

function explain(id: string | undefined, deps: CliDeps): number {
  const rule = id ? findRule(id) : undefined;
  if (!rule) {
    deps.err(pc.red(`  Unknown rule ${id ?? ""}. Run seaworthy rules for the list.`));
    return 2;
  }
  deps.out(
    [
      "",
      `  ${pc.bold(rule.id)}  ${pc.bold(rule.title)}  ${pc.dim(`${rule.severity}`)}`,
      "",
      `  ${rule.docs.summary}`,
      "",
      `  ${pc.red("Vulnerable")}`,
      ...rule.docs.bad.split("\n").map((l) => `    ${l}`),
      "",
      `  ${pc.green("Fixed")}`,
      ...rule.docs.good.split("\n").map((l) => `    ${l}`),
      "",
      pc.dim(`  Silence one finding with a comment: seaworthy-ignore ${rule.id} <reason>`),
      "",
    ].join("\n"),
  );
  return 0;
}

function listRules(deps: CliDeps): number {
  deps.out("");
  const width = Math.max(...RULES.map((r) => r.title.length)) + 2;
  for (const r of RULES) deps.out(`  ${pc.bold(r.id)}  ${r.title.padEnd(width)}${pc.dim(r.severity)}`);
  deps.out("");
  return 0;
}

export type { ScanResult };
