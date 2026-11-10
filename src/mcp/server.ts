import { existsSync, statSync } from "node:fs";
import { basename, resolve } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ConfigError, loadConfig, mergeConfig } from "../core/config.js";
import { atLeastSeverity, CONFIDENCES, SEVERITIES } from "../core/finding.js";
import { scan } from "../core/scan.js";
import { dependencyLookup } from "../deps/lookup.js";
import { catalogue, COVERAGE } from "../docs/catalogue.js";
import { findRule, RULES } from "../rules/index.js";

/**
 * Seaworthy as an MCP server, so an AI coding assistant can run a scan and read the
 * results itself. Stdio only: it runs on the user's machine like the CLI, and nothing is
 * uploaded. The tools are read-only: no history is recorded and no files are written.
 *
 * Findings are returned with their explanation and fix but never with code excerpts, so a
 * secret Seaworthy finds is never copied into the assistant's context.
 */
export interface McpDeps {
  cwd: string;
  version: string;
  /** Used for the OSV dependency lookup. Tests pass a fake. */
  fetch?: typeof fetch;
}

export function createMcpServer(deps: McpDeps): McpServer {
  const server = new McpServer({ name: "seaworthy", title: "Seaworthy", version: deps.version });

  server.registerTool(
    "scan_project",
    {
      title: "Scan a project for security problems",
      description:
        "Runs Seaworthy's pre-launch security checks on a local project folder and returns the findings as JSON, worst first. " +
        "It checks for committed secrets and keys, secrets exposed to the browser, Supabase tables without row-level security and open policies, " +
        "open Firebase rules, API routes with no auth or ownership check, unverified Stripe webhooks and client-set prices, SQL injection, " +
        "prompt injection, unsafe agent tools, MCP configs with secrets, vulnerable dependencies and missing security headers. " +
        "Each finding has a file, line, explanation and fix. Use it before a deploy, after adding auth, payments or AI features, or before making a repo public. " +
        "Code is read locally and never uploaded. The dependency check sends package names and versions to osv.dev unless offline is true.",
      inputSchema: {
        path: z.string().optional().describe("Project folder to scan, absolute or relative to the server's working directory. Default: the working directory."),
        severity: z.enum(SEVERITIES).optional().describe("Only return findings at or above this severity. Default: all severities."),
        minConfidence: z.enum(CONFIDENCES).optional().describe("Hide findings below this confidence. Default: the project's config, normally high."),
        offline: z.boolean().optional().describe("Skip the dependency check, so no network calls are made. Default: false."),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ path, severity, minConfidence, offline }) => {
      const dir = resolve(deps.cwd, path ?? ".");
      if (!existsSync(dir) || !statSync(dir).isDirectory()) return fail(`Not a folder: ${dir}`);
      let config;
      try {
        const overrides: Record<string, unknown> = {};
        if (minConfidence) overrides.minConfidence = minConfidence;
        if (offline) overrides.offline = true;
        config = mergeConfig(loadConfig(dir), overrides, "scan_project");
      } catch (err) {
        if (err instanceof ConfigError) return fail(err.message);
        throw err;
      }
      const osv = await dependencyLookup(dir, config, deps.fetch ?? fetch);
      const result = scan(dir, config, RULES, { osv });
      const findings = result.findings
        .filter((f) => !severity || atLeastSeverity(f.severity, severity))
        .map((f) => ({
          rule: f.ruleId,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          file: f.file,
          line: f.line,
          column: f.column,
          why: f.why,
          fix: f.fix,
          ...(f.fixPrompt ? { fixPrompt: f.fixPrompt } : {}),
        }));
      const notes: string[] = [];
      if (osv?.status === "ok") notes.push(`Checked ${osv.checked} dependencies against osv.dev (package names and versions only).`);
      if (osv?.status === "offline") notes.push("Dependency check skipped (offline).");
      if (osv?.status === "failed") notes.push(`Dependency check skipped: ${osv.reason}.`);
      if (result.hiddenLowConfidence) notes.push(`${result.hiddenLowConfidence} lower-confidence finding(s) hidden; pass minConfidence "medium" to see them.`);
      for (const e of result.ruleErrors) notes.push(`Rule ${e.ruleId} crashed and was skipped: ${e.message}`);
      const out = {
        project: basename(dir),
        path: dir,
        stack: result.stack,
        filesScanned: result.filesScanned,
        rulesRun: result.rulesRun,
        failOn: config.failOn,
        failed: result.failed,
        // Totals by severity, so an assistant doesn't have to count the list itself.
        counts: Object.fromEntries(SEVERITIES.map((sev) => [sev, findings.filter((f) => f.severity === sev).length])),
        findings,
        suppressed: result.suppressed.length,
        notes,
      };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], structuredContent: out };
    },
  );

  server.registerTool(
    "explain_finding",
    {
      title: "Explain a Seaworthy rule",
      description:
        "Explains one Seaworthy rule by its code (such as SW-D01): what the problem is, why it matters, an example of vulnerable code, the fixed version, and what the rule checks.",
      inputSchema: { code: z.string().describe("The rule code from a finding, such as SW-D01 or SW-P01.") },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ code }) => {
      const rule = findRule(code.trim());
      if (!rule) return fail(`Unknown rule ${code}. Call list_rules for the codes.`);
      const out = {
        code: rule.id,
        title: rule.title,
        severity: rule.severity,
        summary: rule.docs.summary,
        checks: COVERAGE[rule.id] ?? "",
        vulnerable: rule.docs.bad,
        fixed: rule.docs.good,
        silence: `Add a comment on the line or the line above: seaworthy-ignore ${rule.id} <reason>`,
      };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], structuredContent: out };
    },
  );

  server.registerTool(
    "list_rules",
    {
      title: "List Seaworthy's rules",
      description: "Lists every Seaworthy rule: code, title, severity, which stacks it runs on, and what it checks.",
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      const rules = catalogue().map((r) => ({ code: r.id, title: r.title, severity: r.severity, runsOn: r.runsOn, checks: r.coverage }));
      const out = { rules };
      return { content: [{ type: "text", text: JSON.stringify(out, null, 2) }], structuredContent: out };
    },
  );

  return server;
}

function fail(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true };
}

/** Runs the server over stdio until the client disconnects. Nothing else may write to stdout. */
export async function runStdio(deps: McpDeps): Promise<void> {
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const server = createMcpServer(deps);
  const transport = new StdioServerTransport();
  const closed = new Promise<void>((done) => {
    transport.onclose = () => done();
    process.stdin.on("end", () => done());
  });
  await server.connect(transport);
  await closed;
}
