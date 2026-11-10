/**
 * Regenerates the docs that are built from the rule definitions.
 *
 *   npm run docs:rules                               # docs/rules.md
 *   npm run docs:rules -- --site ../dynamo-website   # also the website's docs page and llms files
 *
 * A test fails if docs/rules.md is out of date, so CI catches a rule change that forgot this.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { llmsTxt, rulesHtml, rulesMarkdown } from "../src/docs/catalogue.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const write = (path: string, content: string) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
  console.log(`  wrote ${path}`);
};

const rules = rulesMarkdown();
write(join(root, "docs", "rules.md"), rules);

const i = process.argv.indexOf("--site");
if (i > 0) {
  const site = resolve(process.argv[i + 1] ?? "");
  write(join(site, "src", "pages", "seaworthy", "docs.html"), rulesHtml());
  write(join(site, "src", "static", "llms.txt"), llmsTxt());
  // The whole reference as one plain-text file: the CLI docs, then the rule catalogue.
  const cli = readFileSync(join(root, "docs", "cli.md"), "utf8");
  write(join(site, "src", "static", "llms-full.txt"), `${cli.trim()}\n\n---\n\n${rules.replace(/<!--[^>]*-->\n\n/, "")}`);
}
