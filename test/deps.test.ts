import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ProjectFiles } from "../src/core/project.js";
import { excluder, walk } from "../src/core/walk.js";
import { scan } from "../src/core/scan.js";
import { DEFAULT_CONFIG } from "../src/core/config.js";
import { RULES } from "../src/rules/index.js";
import { directDependencies } from "../src/deps/dependencies.js";
import { compareSemver, lookupAdvisories } from "../src/deps/osv.js";
import { declaredDependencies, lookupPackages } from "../src/deps/registry.js";

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


/** A fake npm registry. `missing` names 404; `created` gives a first-publish date (else old). Records every request. */
function fakeRegistry(opts: { missing?: string[]; created?: Record<string, string> } = {}) {
  const urls: string[] = [];
  const f = (async (url: string, init?: RequestInit) => {
    urls.push(url);
    const name = decodeURIComponent(url.replace("https://registry.npmjs.org/", ""));
    if (opts.missing?.includes(name)) return new Response('{"error":"Not found"}', { status: 404 });
    const created = opts.created?.[name];
    const abbreviated = (init?.headers as Record<string, string> | undefined)?.accept?.includes("install-v1");
    if (abbreviated) {
      return new Response(JSON.stringify({ name, versions: { "1.0.0": {} }, modified: created ?? "2019-05-01T00:00:00Z" }));
    }
    return new Response(JSON.stringify({ name, time: { created: created ?? "2019-05-01T00:00:00Z" } }));
  }) as unknown as typeof fetch;
  return { f, urls };
}

describe("SW-X02 dependency that isn't on npm, or is brand new", () => {
  it("matches the chat-agent answer key: the two invented packages, at their lines", async () => {
    const dir = resolve(__dirname, "../fixtures/apps/chat-agent");
    const files = new ProjectFiles(dir, walk(dir).files);
    const { f } = fakeRegistry({ missing: ["openai-stream-guard-utils", "react-markdown-safe-html"] });
    const npm = await lookupPackages(declaredDependencies(files).map((d) => d.name), f);
    const r = scan(dir, DEFAULT_CONFIG, RULES, { npm });
    expect(r.findings.filter((x) => x.ruleId === "SW-X02").map((x) => `${x.file}:${x.line} ${x.severity} ${x.title}`).sort()).toEqual([
      "package.json:14 high openai-stream-guard-utils isn't on npm",
      "package.json:17 high react-markdown-safe-html isn't on npm",
    ]);
  });

  it("flags a brand-new package at medium confidence (hidden by default), and not an old one", async () => {
    const recent = new Date(Date.now() - 3 * 86_400_000).toISOString();
    const p = project({ "package.json": pkg({ "fresh-thing": "1.0.0", lodash: "4.17.21" }) });
    const { f } = fakeRegistry({ created: { "fresh-thing": recent } });
    const npm = await lookupPackages(declaredDependencies(p.files).map((d) => d.name), f);
    const hidden = scan(p.root, DEFAULT_CONFIG, RULES, { npm });
    const shown = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "medium" }, RULES, { npm });
    p.done();
    expect(hidden.findings.filter((x) => x.ruleId === "SW-X02")).toEqual([]);
    expect(shown.findings.filter((x) => x.ruleId === "SW-X02").map((x) => `${x.severity} ${x.title}`)).toEqual([
      "medium fresh-thing was first published 3 days ago",
    ]);
  });

  it("checks devDependencies and npm: aliases, sends only names, and skips local, workspace and private-registry packages", async () => {
    const p = project({
      "package.json": JSON.stringify({
        name: "root",
        dependencies: {
          "@acme/internal": "1.0.0", // private scope, set in .npmrc
          shared: "*", // the project's own workspace package
          local: "file:../local",
          gitdep: "github:user/repo",
          pretty: "npm:prettier@3.0.0",
        },
        devDependencies: { "made-up-test-helper": "1.0.0" },
      }),
      "packages/shared/package.json": JSON.stringify({ name: "shared", version: "1.0.0" }),
      ".npmrc": "@acme:registry=https://npm.acme.example/\n",
    });
    const names = declaredDependencies(p.files).map((d) => d.name).sort();
    expect(names).toEqual(["made-up-test-helper", "prettier"]);
    const { f, urls } = fakeRegistry({ missing: ["made-up-test-helper"] });
    const npm = await lookupPackages(names, f);
    const r = scan(p.root, DEFAULT_CONFIG, RULES, { npm });
    p.done();
    expect(urls.every((u) => u.startsWith("https://registry.npmjs.org/"))).toBe(true);
    expect(r.findings.filter((x) => x.ruleId === "SW-X02").map((x) => x.title)).toEqual(["made-up-test-helper isn't on npm"]);
  });

  /** The names declaredDependencies() would send to the registry, for one dependency spec each. */
  const lookedUp = (deps: Record<string, string>) => {
    const p = project({ "package.json": JSON.stringify({ name: "app", dependencies: deps }) });
    const names = declaredDependencies(p.files).map((d) => d.name);
    p.done();
    return names;
  };

  it.each([
    ["../lib"],
    ["../../packages/lib"],
    ["./lib"],
    ["./"],
    ["."],
    [".."],
    ["/abs/lib"],
    ["/"],
    ["~/code/lib"],
    ["someuser/somerepo"],
    ["some-user/some.repo"],
    ["some_user/repo-name#main"],
    ["someuser/somerepo#v1.2.3"],
    ["someuser/somerepo#semver:^2.0.0"],
  ])("skips the path or GitHub-shorthand spec %j", (spec) => {
    expect(lookedUp({ "local-thing": spec })).toEqual([]);
  });

  it.each([
    ["1.0.0", "real-name"],
    ["^1.2.3", "real-name"],
    ["~1.2.3", "real-name"],
    [">=1.0.0 <2.0.0", "real-name"],
    ["1.x || 2.x", "real-name"],
    ["*", "real-name"],
    ["", "real-name"],
    ["latest", "real-name"],
    ["next", "real-name"],
    ["npm:aliased-name@1", "aliased-name"],
    ["npm:@scope/aliased-name@1", "@scope/aliased-name"],
    ["npm:@scope/aliased-name@^2.1.0", "@scope/aliased-name"],
  ])("still looks up the registry spec %j", (spec, name) => {
    expect(lookedUp({ "real-name": spec })).toEqual([name]);
  });

  it("the issue's reproduction: path, shorthand and ~/ deps are not fetched or flagged; registry specs are", async () => {
    const p = project({
      "package.json": JSON.stringify({
        name: "c1",
        dependencies: {
          "my-local-lib": "../lib",
          "my-fork": "someuser/somerepo",
          "tilde-lib": "~/code/lib",
          "made-up-thing": "^1.0.0",
          "@scope/made-up": "npm:@scope/made-up@1",
        },
      }),
    });
    const { f, urls } = fakeRegistry({ missing: ["my-local-lib", "my-fork", "tilde-lib", "made-up-thing", "@scope/made-up"] });
    const npm = await lookupPackages(declaredDependencies(p.files).map((d) => d.name), f);
    const r = scan(p.root, DEFAULT_CONFIG, RULES, { npm });
    p.done();
    expect(urls).toEqual(["https://registry.npmjs.org/made-up-thing", "https://registry.npmjs.org/@scope%2fmade-up"]);
    expect(r.findings.filter((x) => x.ruleId === "SW-X02").map((x) => x.title)).toEqual([
      "made-up-thing isn't on npm",
      "@scope/made-up isn't on npm",
    ]);
  });

  describe("fixtures", () => {
    const X02 = resolve(__dirname, "../fixtures/rules/sw-x02");
    const decoyNames = Object.keys(
      (JSON.parse(readFileSync(join(X02, "decoy/package.json"), "utf8")) as { dependencies: Record<string, string> }).dependencies,
    );
    /** Scan one fixture folder against a fake registry where the made-up name and every decoy name are missing. */
    const run = async (folder: string) => {
      const dir = join(X02, folder);
      const files = new ProjectFiles(dir, walk(dir).files);
      const { f, urls } = fakeRegistry({ missing: ["react-markdown-safe-html", ...decoyNames.filter((n) => n !== "react")] });
      const npm = await lookupPackages(declaredDependencies(files).map((d) => d.name), f);
      const r = scan(dir, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES, { npm });
      return { urls, findings: r.findings.filter((x) => x.ruleId === "SW-X02") };
    };

    it("vulnerable: the made-up package is flagged at its line, with a fix and prompt", async () => {
      const { findings } = await run("vulnerable");
      expect(findings.map((x) => `${x.file}:${x.line} ${x.severity} ${x.title}`)).toEqual([
        "package.json:6 high react-markdown-safe-html isn't on npm",
      ]);
      expect(findings[0]!.fix).toContain("Remove react-markdown-safe-html");
      expect(findings[0]!.fixPrompt).toContain("react-markdown-safe-html, which doesn't exist on npm");
    });
    it("fixed: the real package is clean", async () => {
      expect((await run("fixed")).findings).toEqual([]);
    });
    it("decoy: local, git, URL, path and GitHub-shorthand deps are neither looked up nor flagged", async () => {
      const { urls, findings } = await run("decoy");
      expect(urls).toEqual(["https://registry.npmjs.org/react"]);
      expect(findings).toEqual([]);
    });
  });

  it("a project that uses a private registry for everything is never looked up", () => {
    const p = project({ "package.json": pkg({ anything: "1.0.0" }), ".npmrc": "registry=https://npm.corp.example/\n" });
    expect(declaredDependencies(p.files)).toEqual([]);
    p.done();
  });

  describe("a project .npmrc that .gitignore lists (#32)", () => {
    const deps = { name: "c3", dependencies: { "internal-billing-sdk": "^2.0.0", "@corp/ledger": "1.0.0", lodash: "4.17.21" } };
    const names = (files: Record<string, string>) => {
      const p = project({ "package.json": JSON.stringify(deps), ...files });
      try {
        return declaredDependencies(p.files).map((d) => d.name).sort();
      } finally {
        p.done();
      }
    };

    it("control: with no .npmrc, every package is looked up", () => {
      expect(names({ ".gitignore": ".npmrc\n" })).toEqual(["@corp/ledger", "internal-billing-sdk", "lodash"]);
    });

    it("a gitignored registry= sends nothing to registry.npmjs.org", async () => {
      const found = names({ ".gitignore": ".npmrc\n", ".npmrc": "registry=https://npm.corp.example/\n" });
      expect(found).toEqual([]);
      const { f, urls } = fakeRegistry();
      await lookupPackages(found, f);
      expect(urls).toEqual([]);
    });

    it("a gitignored @scope:registry= keeps that scope private and still checks the rest", () => {
      expect(names({ ".gitignore": ".npmrc\n", ".npmrc": "@corp:registry=https://npm.corp.example/\n" })).toEqual([
        "internal-billing-sdk",
        "lodash",
      ]);
    });

    it("works for an .npmrc next to a workspace package.json, and for a glob ignore", () => {
      const p = project({
        "package.json": JSON.stringify({ name: "root", private: true }),
        "apps/web/package.json": JSON.stringify(deps),
        "apps/web/.npmrc": "@corp:registry=https://npm.corp.example/\n",
        ".gitignore": "**/.npmrc\n",
      });
      const found = declaredDependencies(p.files).map((d) => d.name).sort();
      p.done();
      expect(found).toEqual(["internal-billing-sdk", "lodash"]);
    });

    it("decoy: a gitignored token-only .npmrc does not stop public lookups", () => {
      const token = "//registry.npmjs.org/:_authToken=npm_FAKE0000000000000000000000000000fake\n";
      expect(names({ ".gitignore": ".npmrc\n", ".npmrc": token })).toEqual(["@corp/ledger", "internal-billing-sdk", "lodash"]);
    });

    it("is not added to the scanned files, so content rules never see it", () => {
      const p = project({
        "package.json": JSON.stringify(deps),
        ".gitignore": ".npmrc\n",
        ".npmrc": `registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=npm_${"aB3dE5gH7jK9mN1pQ3s" + "T5vW7yZ9bC1dE3fG5"}\n`, // fake, split so the source isn't flagged; SW-S01 flags it if the file is scanned
      });
      const r = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES, { npm: { status: "offline" } });
      const listed = p.files.files.includes(".npmrc");
      const found = declaredDependencies(p.files);
      p.done();
      expect(listed).toBe(false);
      expect(found).toEqual([]);
      expect(r.findings.filter((x) => x.file === ".npmrc")).toEqual([]);
    });

    it("never reads an .npmrc outside the scanned folder, or one the config ignores", () => {
      const outer = mkdtempSync(join(tmpdir(), "seaworthy-outer-"));
      writeFileSync(join(outer, ".npmrc"), "registry=https://npm.corp.example/\n");
      const root = join(outer, "app");
      mkdirSync(root);
      writeFileSync(join(root, "package.json"), JSON.stringify(deps));
      const all = ["@corp/ledger", "internal-billing-sdk", "lodash"];
      const lookups = (ignore: string[]) =>
        declaredDependencies(new ProjectFiles(root, walk(root, ignore).files, excluder(ignore))).map((d) => d.name).sort();
      try {
        expect(lookups([])).toEqual(all); // the parent folder's .npmrc is not read
        writeFileSync(join(root, ".gitignore"), ".npmrc\n");
        writeFileSync(join(root, ".npmrc"), "registry=https://npm.corp.example/\n");
        expect(lookups([])).toEqual([]);
        expect(lookups([".npmrc"])).toEqual(all); // the config's ignore still wins
      } finally {
        rmSync(outer, { recursive: true, force: true });
      }
    });
  });

  describe("a project .npmrc that is a symlink (#33)", () => {
    const deps = { name: "c3", dependencies: { "internal-billing-sdk": "^2.0.0", "@corp/ledger": "1.0.0", lodash: "4.17.21" } };
    const all = ["@corp/ledger", "internal-billing-sdk", "lodash"];
    /** A project in `<outer>/app` whose `.npmrc` (or `npmrcAt`) links to `target`, with `shared` files in `<outer>/shared`. */
    const linked = (opts: { target: string | ((outer: string) => string); shared?: Record<string, string>; npmrcAt?: string; pkgAt?: string; ignore?: string[] }) => {
      const outer = mkdtempSync(join(tmpdir(), "seaworthy-link-"));
      const root = join(outer, "app");
      mkdirSync(root);
      for (const [p, c] of Object.entries(opts.shared ?? {})) {
        mkdirSync(dirname(join(outer, "shared", p)), { recursive: true });
        writeFileSync(join(outer, "shared", p), c);
      }
      const pkgAt = opts.pkgAt ?? "package.json";
      mkdirSync(dirname(join(root, pkgAt)), { recursive: true });
      writeFileSync(join(root, pkgAt), JSON.stringify(deps));
      symlinkSync(typeof opts.target === "string" ? opts.target : opts.target(outer), join(root, opts.npmrcAt ?? ".npmrc"));
      const ignore = opts.ignore ?? [];
      const files = new ProjectFiles(root, walk(root, ignore).files, excluder(ignore));
      return { root, files, done: () => rmSync(outer, { recursive: true, force: true }) };
    };
    const names = (opts: Parameters<typeof linked>[0]) => {
      const p = linked(opts);
      try {
        return declaredDependencies(p.files).map((d) => d.name).sort();
      } finally {
        p.done();
      }
    };

    it("a symlink to a file with registry= sends nothing to registry.npmjs.org", async () => {
      const found = names({ target: "../shared/npmrc", shared: { npmrc: "registry=https://npm.corp.example/\n" } });
      expect(found).toEqual([]);
      const { f, urls } = fakeRegistry();
      await lookupPackages(found, f);
      expect(urls).toEqual([]);
    });

    it("a symlink with @scope:registry= keeps that scope private and still checks the rest", () => {
      expect(names({ target: "../shared/npmrc", shared: { npmrc: "@corp:registry=https://npm.corp.example/\n" } })).toEqual([
        "internal-billing-sdk",
        "lodash",
      ]);
    });

    it("works for a symlinked .npmrc next to a workspace package.json, and an absolute link", () => {
      const found = names({
        target: (outer) => join(outer, "shared", "npmrc"),
        shared: { npmrc: "@corp:registry=https://npm.corp.example/\n" },
        pkgAt: "apps/web/package.json",
        npmrcAt: "apps/web/.npmrc",
      });
      expect(found).toEqual(["internal-billing-sdk", "lodash"]);
    });

    it("a broken symlink, or one to a folder, is ignored without a crash", () => {
      expect(names({ target: "../shared/missing" })).toEqual(all);
      expect(names({ target: "../shared/dir", shared: { "dir/registry": "registry=https://npm.corp.example/\n" } })).toEqual(all);
    });

    it("decoy: a symlinked token-only .npmrc does not stop public lookups", () => {
      const token = "//registry.npmjs.org/:_authToken=npm_FAKE0000000000000000000000000000fake\n";
      expect(names({ target: "../shared/npmrc", shared: { npmrc: token } })).toEqual(all);
    });

    it("the config's ignore still wins over a symlinked .npmrc", () => {
      const shared = { npmrc: "registry=https://npm.corp.example/\n" };
      expect(names({ target: "../shared/npmrc", shared, ignore: [".npmrc"] })).toEqual(all);
    });

    it("is not added to the scanned files, so content rules never see it", () => {
      const token = `registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=npm_${"aB3dE5gH7jK9mN1pQ3s" + "T5vW7yZ9bC1dE3fG5"}\n`; // fake, split so the source isn't flagged; SW-S01 flags it if the file is scanned
      const p = linked({ target: "../shared/npmrc", shared: { npmrc: token } });
      try {
        const r = scan(p.root, { ...DEFAULT_CONFIG, minConfidence: "low" }, RULES, { npm: { status: "offline" } });
        expect(p.files.files).not.toContain(".npmrc");
        expect(declaredDependencies(p.files)).toEqual([]);
        expect(r.findings.filter((x) => x.file.includes("npmrc"))).toEqual([]);
      } finally {
        p.done();
      }
    });
  });

  it("reports nothing offline, when the registry is down, or in library use", async () => {
    const p = project({ "package.json": pkg({ ghost: "1.0.0" }) });
    const down = (async () => {
      throw new Error("ENOTFOUND");
    }) as unknown as typeof fetch;
    const failed = await lookupPackages(["ghost", "vitest"], down);
    expect(failed.status).toBe("failed");
    const runs = [scan(p.root, DEFAULT_CONFIG, RULES, { npm: { status: "offline" } }), scan(p.root, DEFAULT_CONFIG, RULES, { npm: failed }), scan(p.root, DEFAULT_CONFIG, RULES)];
    p.done();
    for (const r of runs) expect(r.findings.filter((x) => x.ruleId === "SW-X02")).toEqual([]);
  });
});
