/**
 * Runs after the build. Lists every third-party package bundled into dist/ (from esbuild's
 * metafile) and writes their licence texts to dist/THIRD-PARTY-NOTICES.txt, as their
 * licences require. Packages installed as runtime dependencies aren't bundled, so they
 * ship their own licences. Fails the build if a bundled package has no licence file or a
 * licence that isn't on the allowed list.
 */
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const metaPath = join(root, "dist", "metafile-esm.json");
const meta = JSON.parse(readFileSync(metaPath, "utf8")) as { inputs: Record<string, unknown> };
rmSync(metaPath); // build detail, not for publishing

const ALLOWED = new Set(["MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0"]);
const packages = new Map<string, string>(); // name -> folder
for (const input of Object.keys(meta.inputs)) {
  const m = input.replace(/\\/g, "/").match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//g);
  if (!m) continue;
  const last = m.at(-1)!; // the innermost package, for nested node_modules
  const at = input.replace(/\\/g, "/").lastIndexOf(last);
  const folder = input.replace(/\\/g, "/").slice(0, at + last.length);
  const name = last.replace(/^node_modules\//, "").replace(/\/$/, "");
  packages.set(name, resolve(root, folder));
}

const out = [
  "Third-party software bundled in seaworthy-cli",
  "",
  "These packages are included in dist/ under their own licences, reproduced below.",
  "Seaworthy's own licences are in LICENSE and LICENSE-COMMERCIAL.md.",
  "",
];
const problems: string[] = [];
for (const [name, dir] of [...packages].sort(([a], [b]) => a.localeCompare(b))) {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { version: string; license?: string };
  const licence = pkg.license ?? "UNKNOWN";
  if (!ALLOWED.has(licence)) problems.push(`${name}: licence ${licence}`);
  const file = existsSync(dir) ? readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f)) : undefined;
  if (!file) problems.push(`${name}: no licence file`);
  out.push("=".repeat(78), `${name} ${pkg.version} (${licence})`, "=".repeat(78), "", file ? readFileSync(join(dir, file), "utf8").trim() : "", "");
}
if (problems.length) {
  console.error(`Third-party notices: fix these before publishing:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
writeFileSync(join(root, "dist", "THIRD-PARTY-NOTICES.txt"), out.join("\n"));
console.log(`  THIRD-PARTY-NOTICES.txt: ${packages.size} bundled packages`);
