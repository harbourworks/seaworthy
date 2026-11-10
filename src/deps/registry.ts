/**
 * Checks dependency names against the public npm registry, for SW-X02: names that don't
 * exist there (often invented by AI tools, and open to anyone who registers them) and
 * packages first published only days ago.
 *
 * Only package names are sent, to registry.npmjs.org, exactly as `npm install` would.
 * Packages that come from a private registry (set in .npmrc) and the project's own
 * workspace packages are never looked up.
 */
import { posix } from "node:path";
import type { ProjectFiles } from "../core/project.js";

const REGISTRY = "https://registry.npmjs.org";
const TIMEOUT_MS = 10_000;
const CONCURRENCY = 8;
const MAX_NAMES = 500;
/** First published within this many days counts as brand new. */
export const NEW_PACKAGE_DAYS = 30;

export interface DeclaredDependency {
  name: string;
  /** The package.json that declares it, and the offset of its name there. */
  file: string;
  offset: number;
  dev: boolean;
}

export type PackageInfo = { status: "missing" } | { status: "found"; created: string | null };

export type RegistryResult =
  | { status: "ok"; checked: number; packages: Map<string, PackageInfo> }
  | { status: "offline" }
  | { status: "failed"; reason: string };

const NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const LOCAL_SPEC = /^(file|link|workspace|portal|git|git\+[a-z]+|github|gitlab|bitbucket|https?):/;

/**
 * Every dependency and devDependency name in the project's package.json files that would be
 * fetched from the public npm registry.
 */
export function declaredDependencies(project: ProjectFiles): DeclaredDependency[] {
  const pkgFiles = project.files.filter((f) => posix.basename(f) === "package.json" && !f.includes("node_modules/"));
  const own = new Set<string>();
  for (const f of pkgFiles) {
    const name = (project.json(f) as { name?: unknown } | null)?.name;
    if (typeof name === "string") own.add(name);
  }
  const privateScopes = new Set<string>();
  let privateRegistry = false;
  for (const f of project.files.filter((f) => posix.basename(f) === ".npmrc")) {
    for (const line of (project.read(f) ?? "").split(/\r?\n/)) {
      const scoped = /^\s*(@[^:\s]+):registry\s*=/.exec(line);
      if (scoped) privateScopes.add(scoped[1]!.toLowerCase());
      else if (/^\s*registry\s*=\s*(\S+)/.test(line) && !/registry\.npmjs\.(org|com)/.test(line)) privateRegistry = true;
    }
  }
  if (privateRegistry) return []; // everything comes from somewhere else

  const out: DeclaredDependency[] = [];
  for (const file of pkgFiles) {
    const text = project.read(file);
    const pkg = project.json(file) as { dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown> } | null;
    if (!text || !pkg) continue;
    for (const [section, dev] of [["dependencies", false], ["devDependencies", true]] as const) {
      const deps = pkg[section];
      if (!deps || typeof deps !== "object") continue;
      // Find the section, so each name's offset points at the right occurrence.
      const sectionAt = text.search(new RegExp(`"${section}"\\s*:`));
      for (const [raw, spec] of Object.entries(deps)) {
        if (typeof spec !== "string" || LOCAL_SPEC.test(spec)) continue;
        // npm:real-name@version aliases fetch real-name.
        const alias = /^npm:((?:@[^/]+\/)?[^@]+)/.exec(spec);
        const name = (alias ? alias[1]! : raw).toLowerCase();
        if (!NAME.test(name) || own.has(name)) continue;
        const scope = name.startsWith("@") ? name.split("/")[0]! : null;
        if (scope && privateScopes.has(scope)) continue;
        const keyAt = text.indexOf(JSON.stringify(raw), Math.max(0, sectionAt));
        out.push({ name, file, offset: keyAt >= 0 ? keyAt + 1 : 0, dev });
      }
    }
  }
  return out;
}

export async function lookupPackages(names: string[], fetchImpl: typeof fetch = fetch, now = new Date()): Promise<RegistryResult> {
  const unique = [...new Set(names)].slice(0, MAX_NAMES);
  const packages = new Map<string, PackageInfo>();
  let failures = 0;
  const url = (name: string) => `${REGISTRY}/${name.replace("/", "%2f")}`;
  const one = async (name: string) => {
    try {
      // The abbreviated document is small; it says whether the package exists and how many versions it has.
      const r = await timed(fetchImpl, url(name), { headers: { accept: "application/vnd.npm.install-v1+json" } });
      if (r.status === 404) return void packages.set(name, { status: "missing" });
      if (!r.ok) return void failures++;
      const doc = (await r.json()) as { versions?: Record<string, unknown>; modified?: string };
      const versions = Object.keys(doc.versions ?? {}).length;
      if (versions === 0) return void packages.set(name, { status: "missing" }); // unpublished
      // Only a package with few versions, changed recently, can be brand new: fetch its full
      // document (small for such packages) for the creation date.
      const recent = doc.modified && now.getTime() - Date.parse(doc.modified) < NEW_PACKAGE_DAYS * 86_400_000;
      let created: string | null = null;
      if (versions <= 5 && recent) {
        const full = await timed(fetchImpl, url(name), {});
        if (full.ok) created = ((await full.json()) as { time?: { created?: string } }).time?.created ?? null;
      }
      packages.set(name, { status: "found", created });
    } catch {
      failures++;
    }
  };
  for (let i = 0; i < unique.length; i += CONCURRENCY) await Promise.all(unique.slice(i, i + CONCURRENCY).map(one));
  if (unique.length > 0 && failures === unique.length) return { status: "failed", reason: "the npm registry didn't answer" };
  return { status: "ok", checked: unique.length - failures, packages };
}

async function timed(fetchImpl: typeof fetch, url: string, init: RequestInit): Promise<Response> {
  return fetchImpl(url, { ...init, signal: AbortSignal.timeout(TIMEOUT_MS) });
}
