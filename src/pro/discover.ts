import { existsSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** Signs that a folder is an app worth scanning on its own. */
const PROJECT_MARKERS = ["package.json", "supabase", "firebase.json", "seaworthy.config.json"];
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "out", "coverage", "vendor", "tmp", "temp"]);

export interface DiscoveredProject {
  /** Absolute path. */
  dir: string;
  /** Path relative to the folder passed to --all, with forward slashes. "." if it is that folder. */
  name: string;
}

/**
 * Finds the projects under a folder for `scan --all`. Looks up to `maxDepth` levels down,
 * and stops descending once it finds a project, so a monorepo counts as one project with
 * its own config rather than being split up.
 */
export function discoverProjects(root: string, maxDepth = 3): DiscoveredProject[] {
  const out: DiscoveredProject[] = [];
  const isProject = (dir: string, depth: number) =>
    PROJECT_MARKERS.some((m) => {
      // The top folder's seaworthy.config.json is where an agency puts report branding for
      // the combined report; on its own it doesn't make that folder a project.
      if (depth === 0 && m === "seaworthy.config.json") return false;
      return existsSync(join(dir, m));
    });

  const visit = (dir: string, depth: number) => {
    if (isProject(dir, depth)) {
      const rel = relative(root, dir).split(sep).join("/");
      out.push({ dir, name: rel || "." });
      return;
    }
    if (depth >= maxDepth) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (!e.isDirectory() || e.name.startsWith(".") || SKIP_DIRS.has(e.name)) continue;
      visit(join(dir, e.name), depth + 1);
    }
  };

  visit(root, 0);
  return out;
}
