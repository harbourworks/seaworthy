import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { COVERAGE, catalogue, llmsTxt, rulesHtml, rulesMarkdown } from "../src/docs/catalogue.js";
import { RULES } from "../src/rules/index.js";

describe("rule docs are built from the rules", () => {
  it("docs/rules.md is up to date (run npm run docs:rules)", () => {
    const onDisk = readFileSync(resolve(__dirname, "../docs/rules.md"), "utf8").replace(/\r\n/g, "\n");
    expect(onDisk).toBe(rulesMarkdown());
  });

  it("every rule says what it checks and where it stops, and no entry is left over", () => {
    for (const r of RULES) expect(COVERAGE[r.id], r.id).toBeTruthy();
    expect(Object.keys(COVERAGE).sort()).toEqual(RULES.map((r) => r.id).sort());
  });

  it("lists every rule exactly once, in every format", () => {
    const ids = RULES.map((r) => r.id);
    expect(catalogue().map((c) => c.id)).toEqual(ids);
    const md = rulesMarkdown();
    const html = rulesHtml();
    for (const id of ids) {
      expect(md).toContain(`## ${id}`);
      expect(html).toContain(`id="${id.toLowerCase()}"`);
    }
  });

  it("is honest about what isn't covered yet", () => {
    const md = rulesMarkdown();
    expect(md).toContain("Supabase public storage buckets are not checked yet");
    expect(md).toContain("Doesn't read git history yet");
    expect(md).toContain("## Not checked yet");
  });

  it("the HTML page escapes text and has no scripts", () => {
    const html = rulesHtml();
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain("<code>dangerouslyAllowBrowser</code>");
  });

  it("llms.txt follows the convention: H1, a blockquote summary, then link sections", () => {
    const t = llmsTxt().split("\n");
    expect(t[0]).toBe("# Seaworthy");
    expect(t[2]!.startsWith("> ")).toBe(true);
    expect(llmsTxt()).toMatch(/^## Docs$/m);
    expect(llmsTxt()).toMatch(/- \[Rules\]\(https:\/\/dynamomaritime\.com\/seaworthy\/docs\)/);
  });
});

describe("MCP Registry metadata", () => {
  it("server.json matches package.json (name, version, package)", () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8"));
    const server = JSON.parse(readFileSync(resolve(__dirname, "../server.json"), "utf8"));
    expect(server.name).toBe(pkg.mcpName);
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0]).toMatchObject({ registryType: "npm", identifier: pkg.name, version: pkg.version, transport: { type: "stdio" } });
    expect(server.packages[0].packageArguments).toEqual([{ type: "positional", value: "mcp" }]);
    expect(server.description.length).toBeLessThanOrEqual(100);
  });
});
