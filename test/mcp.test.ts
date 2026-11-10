import { describe, expect, it, beforeAll, afterAll } from "vitest";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp/server.js";
import { RULES } from "../src/rules/index.js";

const FIXTURES = resolve(__dirname, "../fixtures/apps");
let work: string;
let client: Client;

/** OSV with no known vulnerabilities, so these tests never touch the network. */
const quietOsv = (async (_url: string, init?: RequestInit) =>
  new Response(JSON.stringify({ results: (JSON.parse(String(init!.body)) as { queries: unknown[] }).queries.map(() => ({})) }))) as unknown as typeof fetch;

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-mcp-"));
  cpSync(FIXTURES, join(work, "apps"), { recursive: true });
  mkdirSync(join(work, "clean"));
  writeFileSync(join(work, "clean", "index.js"), "console.log('hello');\n");
  const server = createMcpServer({ cwd: work, version: "test", fetch: quietOsv });
  const [a, b] = InMemoryTransport.createLinkedPair();
  client = new Client({ name: "test", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
});
afterAll(async () => {
  await client.close();
  rmSync(work, { recursive: true, force: true });
});

type Out = Record<string, any>;
const call = async (name: string, args: Record<string, unknown> = {}) => {
  const r = await client.callTool({ name, arguments: args });
  return r as { isError?: boolean; structuredContent?: Out; content: Array<{ type: string; text: string }> };
};

describe("MCP server", () => {
  it("offers three read-only tools with factual descriptions", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["explain_finding", "list_rules", "scan_project"]);
    for (const t of tools) {
      expect(t.annotations?.readOnlyHint).toBe(true);
      expect(t.description!.length).toBeGreaterThan(40);
    }
    const scanTool = tools.find((t) => t.name === "scan_project")!;
    expect(scanTool.description).toMatch(/never uploaded/);
    expect(scanTool.description).toMatch(/osv\.dev, and package names to the npm registry, unless offline is true/);
  });

  it("scan_project finds the planted problems, with file, line, why and fix", async () => {
    const r = await call("scan_project", { path: "apps/notes-saas" });
    expect(r.isError).toBeFalsy();
    const out = r.structuredContent!;
    expect(out.failed).toBe(true);
    expect(out.stack).toContain("supabase");
    expect(out.counts.critical).toBe(out.findings.filter((f: Out) => f.severity === "critical").length);
    expect(Object.values(out.counts as Record<string, number>).reduce((x, y) => x + y, 0)).toBe(out.findings.length);
    const d01 = out.findings.find((f: Out) => f.rule === "SW-D01");
    expect(d01).toMatchObject({ file: "supabase/migrations/0001_init.sql", line: 20, severity: "critical" });
    expect(d01.why).toBeTruthy();
    expect(d01.fix).toBeTruthy();
    expect(JSON.parse(r.content[0]!.text)).toEqual(out);
  });

  it("never returns secret values or code excerpts", async () => {
    const r = await call("scan_project", { path: "apps/notes-saas", offline: true });
    const text = JSON.stringify(r);
    const env = readFileSync(join(work, "apps/notes-saas/.env"), "utf8");
    for (const m of env.matchAll(/=(\S{20,})$/gm)) expect(text).not.toContain(m[1]!);
    expect(r.structuredContent!.notes).toContain("Dependency check skipped (offline).");
  });

  it("filters by severity, and a clean project comes back clean", async () => {
    const crit = (await call("scan_project", { path: "apps/notes-saas", severity: "critical", offline: true })).structuredContent!;
    expect(crit.findings.length).toBeGreaterThan(0);
    expect(crit.findings.every((f: Out) => f.severity === "critical")).toBe(true);
    const clean = (await call("scan_project", { path: "clean", offline: true })).structuredContent!;
    expect(clean.failed).toBe(false);
    expect(clean.findings).toEqual([]);
  });

  it("writes nothing into the scanned project", async () => {
    const before = readdirSync(join(work, "apps/notes-saas")).sort();
    await call("scan_project", { path: "apps/notes-saas", offline: true });
    expect(readdirSync(join(work, "apps/notes-saas")).sort()).toEqual(before);
    expect(existsSync(join(work, "apps/notes-saas/.seaworthy"))).toBe(false);
  });

  it("reports a bad path as a tool error, not a crash", async () => {
    const r = await call("scan_project", { path: "nope" });
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toMatch(/Not a folder/);
  });

  it("explain_finding explains a rule, and says when a code is unknown", async () => {
    const r = (await call("explain_finding", { code: "SW-P01" })).structuredContent!;
    expect(r.title).toMatch(/Stripe webhook/);
    expect(r.vulnerable).toBeTruthy();
    expect(r.fixed).toBeTruthy();
    expect(r.checks).toBeTruthy();
    const bad = await call("explain_finding", { code: "SW-ZZ9" });
    expect(bad.isError).toBe(true);
  });

  it("list_rules lists every rule", async () => {
    const r = (await call("list_rules")).structuredContent!;
    expect(r.rules.map((x: Out) => x.code)).toEqual(RULES.map((x) => x.id));
  });
});

describe("seaworthy mcp over stdio (the built CLI)", () => {
  const cli = resolve(__dirname, "../dist/cli.js");
  it.skipIf(!existsSync(cli))("answers initialize and tools/list, with nothing else on stdout", async () => {
    const child = spawn(process.execPath, [cli, "mcp"], { cwd: work, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    const send = (m: object) => child.stdin.write(JSON.stringify(m) + "\n");
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    await new Promise<void>((done, failed) => {
      const t = setTimeout(() => failed(new Error(`timed out; stdout so far: ${stdout}`)), 15000);
      child.stdout.on("data", () => {
        if (stdout.split("\n").filter(Boolean).length >= 2) (clearTimeout(t), done());
      });
    });
    child.stdin.end();
    const lines = stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
    expect(lines[0].result.serverInfo.name).toBe("seaworthy");
    expect(lines[1].result.tools).toHaveLength(3);
    await new Promise((done) => child.on("exit", done));
  }, 30000);
});
