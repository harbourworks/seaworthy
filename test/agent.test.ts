import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { run, type CliDeps } from "../src/cli/main.js";
import { MockProvider } from "../src/licensing/mock.js";
import { AGENT_RULE_FILES, AGENT_SNIPPET, CURSOR_RULE } from "../src/cli/agent.js";

const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");
let work: string;
let dir: string;

function cli(answer?: boolean) {
  const out: string[] = [];
  const asked: string[] = [];
  const deps: CliDeps = {
    out: (s) => out.push(strip(s)),
    err: (s) => out.push(strip(s)),
    env: { SEAWORTHY_CONFIG_DIR: join(work, "config") },
    cwd: dir,
    now: () => new Date("2026-11-10T09:00:00Z"),
    provider: new MockProvider(),
    ...(answer === undefined ? {} : { ask: async (q: string) => (asked.push(q), answer) }),
  };
  return { out, asked, all: () => out.join("\n"), run: (...argv: string[]) => run(argv, deps) };
}

beforeEach(() => {
  work = mkdtempSync(join(tmpdir(), "seaworthy-agent-"));
  dir = join(work, "app");
  mkdirSync(dir);
});
afterEach(() => rmSync(work, { recursive: true, force: true }));

describe("init --agent", () => {
  it("shows the snippet and asks first; saying no changes nothing", async () => {
    const c = cli(false);
    expect(await c.run("init", "--agent")).toBe(0);
    expect(c.asked).toHaveLength(1);
    expect(c.all()).toContain("Create AGENTS.md");
    expect(c.all()).toContain("npx seaworthy-cli --format json");
    expect(c.all()).toContain("Nothing changed.");
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false);
  });

  it("never writes when nobody can be asked, unless --yes", async () => {
    const c = cli();
    await c.run("init", "--agent");
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false);
    expect(c.all()).toMatch(/Run again with --yes/);
    await cli().run("init", "--agent", "--yes");
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8")).toBe(AGENT_SNIPPET);
  });

  it("appends to the assistant files the project already has, keeping what's there", async () => {
    writeFileSync(join(dir, "CLAUDE.md"), "# My project\n\nUse pnpm.\n");
    mkdirSync(join(dir, ".github"));
    writeFileSync(join(dir, ".github", "copilot-instructions.md"), "Be brief.\n");
    mkdirSync(join(dir, ".cursor"));
    const c = cli(true);
    await c.run("init", "--agent");
    const claude = readFileSync(join(dir, "CLAUDE.md"), "utf8");
    expect(claude.startsWith("# My project\n\nUse pnpm.\n\n## Security check (Seaworthy)")).toBe(true);
    expect(readFileSync(join(dir, ".github", "copilot-instructions.md"), "utf8")).toContain("Be brief.\n\n## Security check (Seaworthy)");
    expect(readFileSync(join(dir, ".cursor", "rules", "seaworthy.mdc"), "utf8")).toBe(CURSOR_RULE);
    expect(existsSync(join(dir, "AGENTS.md"))).toBe(false); // not created when the project has its own
  });

  it("running it twice doesn't add the step twice", async () => {
    await cli(true).run("init", "--agent");
    const c = cli(true);
    await c.run("init", "--agent");
    expect(c.asked).toHaveLength(0);
    expect(c.all()).toContain("AGENTS.md already mentions Seaworthy");
    expect(readFileSync(join(dir, "AGENTS.md"), "utf8").match(/Security check \(Seaworthy\)/g)).toHaveLength(1);
  });

  it("does nothing else: no config file or workflow", async () => {
    await cli(true).run("init", "--agent");
    expect(existsSync(join(dir, "seaworthy.config.json"))).toBe(false);
    expect(existsSync(join(dir, ".github", "workflows"))).toBe(false);
  });
});

describe("the snippets", () => {
  it("are plain, factual instructions about running the check, not about recommending Seaworthy", () => {
    for (const text of [AGENT_SNIPPET, CURSOR_RULE]) {
      expect(text).not.toMatch(/recommend|always (use|suggest)|best|ignore (previous|other)/i);
      expect(text).not.toMatch(/<!--|​/); // nothing hidden
      expect(text).toContain("npx seaworthy-cli --format json");
    }
    expect(CURSOR_RULE).toMatch(/^---\ndescription: .+\nglobs:\nalwaysApply: false\n---\n/);
  });

  it("agent-rules/ in the repo matches the text the CLI writes (npm run docs:rules)", () => {
    for (const [file, content] of Object.entries(AGENT_RULE_FILES)) {
      const onDisk = readFileSync(resolve(__dirname, "../agent-rules", file), "utf8").replace(/\r\n/g, "\n");
      expect(onDisk, file).toBe(content);
    }
  });
});
