import type { Config } from "../core/config.js";
import { ProjectFiles } from "../core/project.js";
import { excluder, walk } from "../core/walk.js";
import { directDependencies } from "./dependencies.js";
import { lookupAdvisories, type OsvResult } from "./osv.js";
import { declaredDependencies, lookupPackages, type RegistryResult } from "./registry.js";

/** Fetches known vulnerabilities for a project's dependencies, unless offline or SW-X01 is off. */
export async function dependencyLookup(dir: string, config: Config, fetchImpl: typeof fetch = fetch): Promise<OsvResult | undefined> {
  if (config.rules["SW-X01"] === "off") return undefined;
  if (config.offline) return { status: "offline" };
  const project = new ProjectFiles(dir, walk(dir, config.ignore).files, excluder(config.ignore));
  const list = directDependencies(project);
  if (list.length === 0) return undefined;
  return lookupAdvisories(list, fetchImpl);
}

/** Checks dependency names on the npm registry (SW-X02), unless offline or the rule is off. */
export async function registryLookup(dir: string, config: Config, fetchImpl: typeof fetch = fetch): Promise<RegistryResult | undefined> {
  if (config.rules["SW-X02"] === "off") return undefined;
  if (config.offline) return { status: "offline" };
  const project = new ProjectFiles(dir, walk(dir, config.ignore).files, excluder(config.ignore));
  const names = declaredDependencies(project).map((d) => d.name);
  if (names.length === 0) return undefined;
  return lookupPackages(names, fetchImpl);
}

/** Both online checks, run together. */
export async function onlineLookups(dir: string, config: Config, fetchImpl: typeof fetch = fetch) {
  const [osv, npm] = await Promise.all([dependencyLookup(dir, config, fetchImpl), registryLookup(dir, config, fetchImpl)]);
  return { osv, npm };
}
