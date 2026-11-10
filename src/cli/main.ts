import { parseArgs } from "node:util";
import { existsSync, statSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import pc from "picocolors";
import { ConfigError, hasBranding, loadConfig, mergeConfig, type Config } from "../core/config.js";
import { scan, type ScanResult } from "../core/scan.js";
import { ProjectFiles } from "../core/project.js";
import { walk } from "../core/walk.js";
import { FEATURE_LABELS, TIER_INFO, hasFeature, priceLabel, requiredTier, type Feature, type Tier } from "../core/entitlements.js";
import { RULES, findRule } from "../rules/index.js";
import { renderTerminal } from "../reporters/terminal.js";
import { renderJson } from "../reporters/json.js";
import { VERSION } from "../version.js";
import { PURCHASE_URL, polarSettings } from "../licensing/config.js";
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
}

const COMMANDS = new Set(["scan", "explain", "rules", "login", "logout", "status", "history", "compare"]);

const HELP = `
  ${pc.bold("seaworthy")}: pre-launch security check for AI-built apps. Runs locally.

  ${pc.bold("Usage")}
    seaworthy [scan] [path]          Scan a project (default: current folder)
    seaworthy explain <rule-id>      Explain one rule and how to fix it
    seaworthy rules                  List every rule

  ${pc.bold("Options")}
    --format terminal|json|html      Output format (default: terminal; html is Pro)
    --output <file>                  Where to save the HTML report (default: seaworthy-report.html)
    --fail-on critical|high|medium|low
                                     Exit 1 at or above this severity (default: high)
    --min-confidence high|medium|low Hide findings below this confidence (default: high)
    --config <file>                  Config file (default: ./seaworthy.config.json)
    --offline                        Make no network calls at all
    -h, --help    -v, --version

  ${pc.bold("Pro and Agency")}  ${pc.dim(PURCHASE_URL)}
    seaworthy login <key>            Turn on your licence on this machine
    seaworthy logout                 Turn it off and free this machine's slot
    seaworthy status                 Show your plan and licence state
    seaworthy history [path]         Scan history and trends            ${pc.dim("Pro")}
    seaworthy compare [path]         What's fixed and new between scans ${pc.dim("Pro")}
      --from <scan#> --to <scan#>    Pick two scans (default: the last two)
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
  if (!["terminal", "json", "html"].includes(format)) {
    deps.err(pc.red(`  --format must be terminal, json or html`));
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
    const result = scan(p.dir, config, RULES);
    const project = new ProjectFiles(p.dir, walk(p.dir, config.ignore).files);
    let comparison: Comparison | null = null;
    if (recordHistory) {
      const previous = loadHistory(p.dir).scans.at(-1) ?? null;
      const saved = recordScan(p.dir, result.findings, deps.now());
      if (!saved) notes.push(`Couldn't save scan history in ${p.dir} (folder not writable).`);
      if (previous && saved) comparison = compareScans(previous, saved);
    }
    scanned.push({ name: multi ? p.name : basename(p.dir), result, project, comparison });
  }

  const failed = scanned.some((s) => s.result.failed);

  if (format === "json") {
    deps.out(scanned.length === 1 && !multi ? renderJson(scanned[0]!.result, VERSION) : multiJson(scanned));
    return finish(failed ? 1 : 0);
  }

  printTerminal(scanned, multi, deps);

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

async function login(keyArg: string | undefined, ctx: Ctx): Promise<number> {
  const { deps, store, provider, values } = ctx;
  const key = keyArg?.trim();
  if (!key || /\s/.test(key) || key.length > 200) {
    deps.err(pc.red("  Usage: seaworthy login <licence-key>") + pc.dim(`\n  Your key is in your purchase email. No key yet? ${PURCHASE_URL}`));
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
      return "That key wasn't recognised. Check you copied all of it from your purchase email.";
    case "revoked":
      return `That key is no longer active; the subscription may have ended. Renew at ${PURCHASE_URL}.`;
    case "expired":
      return `That key has expired. Renew at ${PURCHASE_URL}.`;
    case "machine-limit":
      return "That key is already in use on as many machines as your plan allows. Run seaworthy logout on one you no longer use, or remove it in the customer portal linked from your purchase email.";
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
        : pc.yellow(`\n  Couldn't reach the licence server to free this machine's slot. Remove "${existing.machineLabel}" in the customer portal if you need it.`)) +
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
    out.push(pc.dim(`  ${PURCHASE_URL}`));
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
