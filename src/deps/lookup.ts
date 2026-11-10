import type { Config } from "../core/config.js";
import { ProjectFiles } from "../core/project.js";
import { excluder, walk } from "../core/walk.js";
import { directDependencies } from "./dependencies.js";
import { lookupAdvisories, type OsvResult } from "./osv.js";

/** Fetches known vulnerabilities for a project's dependencies, unless offline or SW-X01 is off. */
export async function dependencyLookup(dir: string, config: Config, fetchImpl: typeof fetch = fetch): Promise<OsvResult | undefined> {
  if (config.rules["SW-X01"] === "off") return undefined;
  if (config.offline) return { status: "offline" };
  const project = new ProjectFiles(dir, walk(dir, config.ignore).files, excluder(config.ignore));
  const list = directDependencies(project);
  if (list.length === 0) return undefined;
  return lookupAdvisories(list, fetchImpl);
}
