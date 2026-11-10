import type { RawFinding, Rule } from "../types.js";
import { declaredDependencies, NEW_PACKAGE_DAYS } from "../../deps/registry.js";

export const x02UnknownPackage: Rule = {
  id: "SW-X02",
  title: "Dependency that isn't on npm, or is brand new",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "AI coding tools sometimes invent package names that sound right but don't exist. Attackers watch for those " +
      "names and register them (\"slopsquatting\"), so the next install runs their code on your machine and in CI. " +
      "Seaworthy checks each dependency name against the public npm registry, sending only the names, as npm itself would. " +
      "Packages first published in the last few weeks are flagged at medium confidence, because a new package is " +
      "sometimes fine and sometimes a fresh squat. Use --offline to skip it.",
    bad: `"react-markdown-safe-html": "0.4.1"   // no such package on npm`,
    good: `"react-markdown": "9.0.1"   // the real package, checked on npmjs.com`,
  },

  check({ project, npm }) {
    if (!npm || npm.status !== "ok") return [];
    const out: RawFinding[] = [];
    for (const d of declaredDependencies(project)) {
      const info = npm.packages.get(d.name);
      if (!info) continue;
      const pos = project.position(d.file, d.offset);
      if (info.status === "missing") {
        out.push({
          file: d.file,
          ...pos,
          title: `${d.name} isn't on npm`,
          why:
            `${d.file} depends on ${d.name}, which doesn't exist on the public npm registry. If an AI tool suggested it, the name may be ` +
            `made up, and anyone can register it: the next \`npm install\` would then run whatever they publish.`,
          fix:
            `Remove ${d.name}, or replace it with the real package you meant (search npmjs.com). If it's a private package, ` +
            `add its registry to .npmrc (for example \`@your-scope:registry=https://...\`) so npm, and Seaworthy, look for it there.`,
          fixPrompt: `My package.json depends on ${d.name}, which doesn't exist on npm. Find what it was meant to do, replace it with a real, well-maintained package (or plain code), and update the imports.`,
        });
      } else if (info.created) {
        const days = Math.max(0, Math.floor((Date.now() - Date.parse(info.created)) / 86_400_000));
        if (days >= NEW_PACKAGE_DAYS) continue;
        out.push({
          file: d.file,
          ...pos,
          severity: "medium",
          confidence: "medium",
          title: `${d.name} was first published ${days === 0 ? "today" : `${days} day${days === 1 ? "" : "s"} ago`}`,
          why:
            `${d.name} is brand new on npm. That's often fine, but it's also how squatted names look: someone registers a name an ` +
            `AI tool tends to invent, and waits.`,
          fix: `Check ${d.name} on npmjs.com before keeping it: who publishes it, whether it links to a real repository, and whether it's the package you meant.`,
        });
      }
    }
    return out;
  },
};
