import { parseArgs } from "node:util";
import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import pc from "picocolors";
import { ConfigError, loadConfig, mergeConfig } from "../core/config.js";
import { scan } from "../core/scan.js";
import { ProjectFiles } from "../core/project.js";
import { walk } from "../core/walk.js";
import { RULES, findRule } from "../rules/index.js";
import { renderTerminal } from "../reporters/terminal.js";
import { renderJson } from "../reporters/json.js";

const VERSION = "0.1.0";

const HELP = `
  ${pc.bold("seaworthy")}: pre-launch security check for AI-built apps. Runs locally.

  ${pc.bold("Usage")}
    seaworthy [scan] [path]          Scan a project (default: current folder)
    seaworthy explain <rule-id>      Explain one rule and how to fix it
    seaworthy rules                  List every rule

  ${pc.bold("Options")}
    --format terminal|json           Output format (default: terminal)
    --fail-on critical|high|medium|low
                                     Exit 1 at or above this severity (default: high)
    --min-confidence high|medium|low Hide findings below this confidence (default: high)
    --config <file>                  Config file (default: ./seaworthy.config.json)
    -h, --help    -v, --version

  ${pc.bold("Exit codes")}  0 clean · 1 findings at or above the threshold · 2 tool error
`;

function main(argv: string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string" },
        "fail-on": { type: "string" },
        "min-confidence": { type: "string" },
        config: { type: "string" },
        offline: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (err) {
    console.error(pc.red(`  ${(err as Error).message}`) + "\n  Run seaworthy --help for usage.");
    return 2;
  }
  const { values, positionals } = parsed;
  if (values.help) return (console.log(HELP), 0);
  if (values.version) return (console.log(VERSION), 0);

  const [first, ...rest] = positionals;
  if (first === "explain") return explain(rest[0]);
  if (first === "rules") return listRules();
  const target = resolve(first === "scan" ? (rest[0] ?? ".") : (first ?? "."));

  if (!existsSync(target) || !statSync(target).isDirectory()) {
    console.error(pc.red(`  Not a folder: ${target}`));
    return 2;
  }

  let config;
  try {
    config = loadConfig(target, values.config);
    const overrides: Record<string, unknown> = {};
    if (values["fail-on"]) overrides.failOn = values["fail-on"];
    if (values["min-confidence"]) overrides.minConfidence = values["min-confidence"];
    if (values.offline) overrides.offline = true;
    config = mergeConfig(config, overrides, "command line");
  } catch (err) {
    if (err instanceof ConfigError) return (console.error(pc.red(`  ${err.message}`)), 2);
    throw err;
  }

  const format = values.format ?? "terminal";
  if (format !== "terminal" && format !== "json") {
    console.error(pc.red(`  --format must be terminal or json (markdown and sarif are coming)`));
    return 2;
  }

  const result = scan(target, config, RULES);
  if (format === "json") {
    console.log(renderJson(result, VERSION));
  } else {
    const project = new ProjectFiles(target, walk(target, config.ignore).files);
    console.log(renderTerminal(result, project, VERSION));
  }
  return result.failed ? 1 : 0;
}

function explain(id: string | undefined): number {
  const rule = id ? findRule(id) : undefined;
  if (!rule) {
    console.error(pc.red(`  Unknown rule ${id ?? ""}. Run seaworthy rules for the list.`));
    return 2;
  }
  console.log(
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

function listRules(): number {
  console.log("");
  for (const r of RULES) console.log(`  ${pc.bold(r.id)}  ${r.title.padEnd(36)} ${pc.dim(r.severity)}`);
  console.log("");
  return 0;
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (err) {
  console.error(pc.red(`  Seaworthy hit an internal error: ${(err as Error).stack ?? err}`));
  process.exitCode = 2;
}
