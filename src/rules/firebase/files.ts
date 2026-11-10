import { posix } from "node:path";
import type { ProjectFiles } from "../../core/project.js";

type Kind = "firestore" | "storage" | "database";

const DEFAULT_NAMES: Record<Kind, string> = {
  firestore: "firestore.rules",
  storage: "storage.rules",
  database: "database.rules.json",
};

/**
 * Rules files of one kind: those named in any firebase.json (paths are relative to it),
 * plus files with the default names.
 */
export function rulesFiles(project: ProjectFiles, kind: Kind): string[] {
  const out = new Set<string>();
  const present = new Set(project.files);
  for (const f of project.files) {
    if (posix.basename(f) === DEFAULT_NAMES[kind]) out.add(f);
    if (posix.basename(f) !== "firebase.json") continue;
    const cfg = project.json(f) as Record<string, unknown> | null;
    const dir = posix.dirname(f);
    for (const entry of [cfg?.[kind]].flat()) {
      const rules = (entry as { rules?: unknown } | undefined)?.rules;
      if (typeof rules !== "string") continue;
      const rel = posix.normalize(dir === "." ? rules : `${dir}/${rules}`);
      if (present.has(rel)) out.add(rel);
    }
  }
  return [...out].sort();
}
