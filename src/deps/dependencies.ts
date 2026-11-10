import { posix } from "node:path";
import type { ProjectFiles } from "../core/project.js";

export interface Dependency {
  name: string;
  /** Exact installed version. */
  version: string;
  /** The package.json that declares it, and the offset of its name there. */
  file: string;
  offset: number;
  /** Where the exact version came from. */
  source: "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "package.json";
}

const EXACT = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * Direct production dependencies of every package.json in the project, with the exact
 * version installed. Versions come from the lockfile next to the package.json; without
 * one, only exactly pinned versions are used. Ranges with no lockfile are skipped rather
 * than guessed, because reporting a vulnerability in a version you don't run is noise.
 */
export function directDependencies(project: ProjectFiles): Dependency[] {
  const out: Dependency[] = [];
  const files = new Set(project.files);
  for (const pkgFile of project.files) {
    if (posix.basename(pkgFile) !== "package.json" || pkgFile.includes("node_modules/")) continue;
    const text = project.read(pkgFile);
    const pkg = project.json(pkgFile) as { dependencies?: Record<string, string> } | null;
    if (!text || !pkg?.dependencies) continue;
    const dir = posix.dirname(pkgFile);
    const at = (name: string) => (dir === "." ? name : `${dir}/${name}`);
    const lock = lockfile(project, files, at);

    for (const [name, range] of Object.entries(pkg.dependencies)) {
      if (typeof range !== "string" || /^(file|link|workspace|git|github|https?):/.test(range)) continue;
      let version = lock?.versionOf(name, range) ?? null;
      let source: Dependency["source"] = lock?.source ?? "package.json";
      if (!version && EXACT.test(range.replace(/^=/, ""))) {
        version = range.replace(/^=/, "");
        source = "package.json";
      }
      if (!version) continue;
      const offset = text.search(new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}"\\s*:`));
      out.push({ name, version, file: pkgFile, offset: Math.max(offset, 0), source });
    }
  }
  return out;
}

interface Lock {
  source: Dependency["source"];
  versionOf(name: string, range: string): string | null;
}

function lockfile(project: ProjectFiles, files: Set<string>, at: (n: string) => string): Lock | null {
  if (files.has(at("package-lock.json"))) {
    const lock = project.json(at("package-lock.json")) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    } | null;
    if (lock) {
      return {
        source: "package-lock.json",
        versionOf: (name) => lock.packages?.[`node_modules/${name}`]?.version ?? lock.dependencies?.[name]?.version ?? null,
      };
    }
  }
  if (files.has(at("pnpm-lock.yaml"))) {
    const text = project.read(at("pnpm-lock.yaml")) ?? "";
    return {
      source: "pnpm-lock.yaml",
      versionOf: (name) => {
        // importers: '.': dependencies: name: { specifier, version: 1.2.3(peer@x) } — or the older flat form.
        const esc = name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
        const m =
          new RegExp(`\\n\\s+'?${esc}'?:\\s*\\n\\s+specifier:[^\\n]*\\n\\s+version:\\s*'?([0-9][^\\s('"]*)`).exec(text) ??
          new RegExp(`\\n\\s+'?${esc}'?:\\s*'?([0-9][^\\s('"]*)`).exec(text);
        return m?.[1] ?? null;
      },
    };
  }
  if (files.has(at("yarn.lock"))) {
    const text = project.read(at("yarn.lock")) ?? "";
    return {
      source: "yarn.lock",
      versionOf: (name, range) => {
        const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
        const m = new RegExp(`(^|\\n)"?[^\\n]*${esc(name)}@(npm:)?${esc(range)}[^\\n]*:\\s*\\n\\s+version:?\\s+"?([^"\\s]+)`).exec(text);
        return m?.[3] ?? null;
      },
    };
  }
  return null;
}
