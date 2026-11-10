import { SEVERITIES, type Severity } from "../../core/finding.js";
import type { RawFinding, Rule } from "../types.js";
import { directDependencies } from "../../deps/dependencies.js";
import { compareSemver, depKey, type Advisory } from "../../deps/osv.js";

const rank = (s: Severity) => SEVERITIES.length - SEVERITIES.indexOf(s);

export const x01VulnerableDeps: Rule = {
  id: "SW-X01",
  title: "Dependency with known vulnerabilities",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "Checks your direct dependencies, at the exact versions in your lockfile, against OSV (osv.dev), the " +
      "open vulnerability database. Only package names and versions are sent; use --offline to skip it. " +
      "Severity follows the advisory's own rating. Development-only dependencies aren't checked.",
    bad: `"next": "14.1.0"   // has published security advisories`,
    good: `"next": "14.2.35"  // a release with the fixes (check the advisory for the exact version)`,
  },

  check({ project, osv }) {
    if (!osv || osv.status !== "ok") return [];
    const out: RawFinding[] = [];
    for (const d of directDependencies(project)) {
      const list = osv.advisories.get(depKey(d));
      if (!list?.length) continue;
      const sorted = [...list].sort((a, b) => rank(b.severity) - rank(a.severity));
      const worst = sorted[0]!.severity;
      const malicious = sorted.some((a) => a.malicious);
      const fixes = sorted.map((a) => a.fixedIn).filter((v): v is string => v !== null);
      const target = fixes.sort(compareSemver).at(-1) ?? null;
      const unfixed = sorted.filter((a) => !a.fixedIn).length;
      const n = sorted.length;
      // If fixing everything means a new major version, say what the current major line can fix.
      const major = (v: string) => v.split(".")[0];
      const sameLine = fixes.filter((f) => major(f) === major(d.version)).sort(compareSemver).at(-1) ?? null;
      const sameLineCount = sameLine ? sorted.filter((a) => a.fixedIn && compareSemver(a.fixedIn, sameLine) <= 0).length : 0;
      const stayNote =
        target && sameLine && major(target) !== major(d.version)
          ? ` That's a new major version; to stay on ${major(d.version)}.x, ${sameLine} fixes ${sameLineCount} of the ${n}.`
          : ``;
      out.push({
        file: d.file,
        ...project.position(d.file, d.offset),
        severity: worst,
        title: malicious
          ? `${d.name} ${d.version} is a known malicious package`
          : `${d.name} ${d.version} has ${n} known vulnerabilit${n === 1 ? "y" : "ies"}`,
        why:
          (malicious
            ? `OSV lists this package as malicious: installing it can run an attacker's code on your machine and in CI. `
            : `OSV lists ${n} published advisor${n === 1 ? "y" : "ies"} for ${d.name} ${d.version} (from ${d.source}). `) +
          `The worst ${n === 1 ? "is" : "include"}: ${describe(sorted.slice(0, 3))}` +
          (n > 3 ? `, and ${n - 3} more.` : `.`),
        fix: malicious
          ? `Remove ${d.name}, delete node_modules and reinstall, and rotate any secrets that were on machines where it was installed.`
          : target
            ? `Upgrade to ${d.name}@${target} or later (\`npm install ${d.name}@${target}\`), then run your tests.${stayNote}` +
              (unfixed ? ` ${unfixed} of these ${unfixed === 1 ? "has" : "have"} no fixed version yet; read ${unfixed === 1 ? "it" : "them"} to see if your app is affected.` : ``)
            : `No fixed version is published yet. Read the advisories to see if your app uses the affected feature, and watch for a release.`,
        fixPrompt: malicious
          ? `My project depends on ${d.name}, which OSV lists as a malicious package. Remove it, find a safe alternative for what it was used for, and list the secrets I should rotate.`
          : `Upgrade ${d.name} from ${d.version} to ${target ?? "the latest release"} in my project, fix anything the upgrade breaks, ` +
            `and tell me about breaking changes between those versions that affect my code.`,
      });
    }
    return out;
  },
};

function describe(list: Advisory[]): string {
  return list
    .map((a) => `${a.displayId} (${a.severity})${a.summary ? `: ${a.summary.replace(/\.$/, "")}` : ""}`)
    .join("; ");
}
