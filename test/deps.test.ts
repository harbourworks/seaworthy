import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { ProjectFiles } from "../src/core/project.js";
import { walk } from "../src/core/walk.js";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { RULES } from "../src/rules/index.js";
import { directDependencies } from "../src/deps/dependencies.js";
import { compareSemver, lookupAdvisories } from "../src/deps/osv.js";

function project(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), "seaworthy-deps-"));
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), c);
  }
  return { root, files: new ProjectFiles(root, walk(root).files), done: () => rmSync(root, { recursive: true, force: true }) };
}

const pkg = (deps: Record<string, string>) => JSON.stringify({ name: "app", dependencies: deps, devDependencies: { vitest: "1.0.0" } }, null, 2);

/** A fake OSV: `vulns` maps "name@version" to advisory records. Records every request. */
function fakeOsv(vulns: Record<string, object[]>) {
  const sent: Array<{ url: string; body?: unknown }> = [];
  const byId = new Map(Object.values(vulns).flat().map((v) => [(v as { id: string }).id, v]));
  const f = (async (url: string, init?: RequestInit) => {
    sent.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (url.endsWith("/querybatch")) {
      const { queries } = JSON.parse(String(init!.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      const results = queries.map((q) => ({ vulns: (vulns[`${q.package.name}@${q.version}`] ?? []).map((v) => ({ id: (v as { id: string }).id })) }));
      return new Response(JSON.stringify({ results }));
    }
    const id = decodeURIComponent(url.split("/vulns/")[1]!);
    return byId.has(id) ? new Response(JSON.stringify(byId.get(id))) : new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  return { f, sent };
}

const advisory = (id: string, severity: string, fixed: string | null, extra: object = {}) => ({
  id,
  summary: `Problem ${id}`,
  aliases: [`CVE-2024-${id.slice(-4)}`],
  database_specific: { severity },
  affected: [{ package: { name: "next", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, ...(fixed ? [{ fixed }] : [])] }] }],
  ...extra,
});

describe("direct dependencies", () => {
  it("reads exact versions from package-lock, pnpm and yarn lockfiles; skips ranges without one", () => {
    const p = project({
      "package.json": pkg({ next: "^14.1.0", react: "18.2.0" }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/next": { version: "14.1.4" }, "node_modules/react": { version: "18.2.0" } } }),
      "apps/web/package.json": pkg({ stripe: "^14.0.0" }),
      "apps/web/pnpm-lock.yaml": "importers:\n  .:\n    dependencies:\n      stripe:\n        specifier: ^14.0.0\n        version: 14.10.0\n",
      "apps/old/package.json": pkg({ lodash: "^4.17.0" }),
      "apps/old/yarn.lock": 'lodash@^4.17.0:\n  version "4.17.21"\n',
      "apps/loose/package.json": pkg({ axios: "^1.0.0", zod: "3.22.4", local: "file:../x" }),
    });
    const deps = directDependencies(p.files).map((d) => `${d.file} ${d.name}@${d.version} ${d.source}`).sort();
    p.done();
    expect(deps).toEqual([
      "apps/loose/package.json zod@3.22.4 package.json",
      "apps/old/package.json lodash@4.17.21 yarn.lock",
      "apps/web/package.json stripe@14.10.0 pnpm-lock.yaml",
      "package.json next@14.1.4 package-lock.json",
      "package.json react@18.2.0 package-lock.json",
    ]); // dev dependencies and the range-only axios are not checked
  });
});

describe("OSV lookup", () => {
  it("sends only names and versions, skips withdrawn advisories and maps severity and fixes", async () => {
    const { f, sent } = fakeOsv({
      "next@14.1.0": [
        advisory("GHSA-aaaa-0001", "CRITICAL", "14.2.25"),
        advisory("GHSA-aaaa-0002", "MODERATE", null),
        advisory("GHSA-aaaa-0003", "HIGH", "14.1.1", { withdrawn: "2025-01-01T00:00:00Z" }),
      ],
    });
    const r = await lookupAdvisories([{ name: "next", version: "14.1.0", file: "package.json", offset: 0, source: "package.json" }], f);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    const list = r.advisories.get("next@14.1.0")!;
    expect(list.map((a) => `${a.displayId} ${a.severity} ${a.fixedIn}`)).toEqual(["CVE-2024-0001 critical 14.2.25", "CVE-2024-0002 medium null"]);
    expect(sent[0]!.body).toEqual({ queries: [{ package: { name: "next", ecosystem: "npm" }, version: "14.1.0" }] });
  });
  it("reports failure instead of throwing when OSV is unreachable", async () => {
    const down = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    expect(await lookupAdvisories([{ name: "next", version: "14.1.0", file: "package.json", offset: 0, source: "package.json" }], down)).toEqual({
      status: "failed",
      reason: "couldn't reach OSV",
    });
  });
  it("compares versions, including pre-releases", () => {
    expect(["14.10.0", "14.2.0", "14.2.0-canary.1", "0", "15.0.0"].sort(compareSemver)).toEqual(["0", "14.2.0-canary.1", "14.2.0", "14.10.0", "15.0.0"]);
  });
});

describe("SW-X01 dependency with known vulnerabilities", () => {
  it("reports one finding per package, at its line, with the worst severity and the upgrade", async () => {
    const p = project({ "package.json": pkg({ next: "14.1.0", react: "18.2.0" }) });
    const { f } = fakeOsv({
      "next@14.1.0": [advisory("GHSA-aaaa-0001", "HIGH", "14.2.25"), advisory("GHSA-aaaa-0002", "CRITICAL", "15.2.3")],
    });
    const osv = await lookupAdvisories(directDependencies(p.files), f);
    const r = scan(p.root, DEFAULT_CONFIG, RULES, { osv });
    p.done();
    const x = r.findings.filter((x) => x.ruleId === "SW-X01");
    expect(x.map((y) => `${y.file}:${y.line} ${y.severity} ${y.title}`)).toEqual([
      "package.json:4 critical next 14.1.0 has 2 known vulnerabilities",
    ]);
    expect(x[0]!.fix).toContain("npm install next@15.2.3");
    expect(x[0]!.fix).toContain("to stay on 14.x, 14.2.25 fixes 1 of the 2");
  });
  it("names malicious packages as such", async () => {
    const p = project({ "package.json": pkg({ "evil-pkg": "1.0.0" }) });
    const { f } = fakeOsv({ "evil-pkg@1.0.0": [{ id: "MAL-2025-1", summary: "Malicious code in evil-pkg", affected: [] }] });
    const r = scan(p.root, DEFAULT_CONFIG, RULES, { osv: await lookupAdvisories(directDependencies(p.files), f) });
    p.done();
    expect(r.findings.filter((x) => x.ruleId === "SW-X01").map((x) => `${x.severity} ${x.title}`)).toEqual([
      "critical evil-pkg 1.0.0 is a known malicious package",
    ]);
  });
  it("reports nothing without OSV data (offline, failed or library use)", () => {
    const p = project({ "package.json": pkg({ next: "14.1.0" }) });
    const offline = scan(p.root, DEFAULT_CONFIG, RULES, { osv: { status: "offline" } });
    const none = scan(p.root, DEFAULT_CONFIG, RULES);
    p.done();
    expect([...offline.findings, ...none.findings].filter((x) => x.ruleId === "SW-X01")).toEqual([]);
  });
});
