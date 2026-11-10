import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ignore, { type Ignore } from "ignore";

/** Folders nobody wants scanned, whatever .gitignore says. */
const ALWAYS_SKIP = [
  ".git/",
  "node_modules/",
  ".next/",
  ".vercel/",
  ".turbo/",
  ".svelte-kit/",
  "dist/",
  "build/",
  "out/",
  "coverage/",
  ".cache/",
];

export const MAX_FILE_BYTES = 1_000_000;

export interface WalkResult {
  files: string[];
  skippedLarge: string[];
}

const toPosix = (p: string) => p.split(sep).join("/");

/**
 * Lists every file under `root` that is worth scanning, as posix paths relative to root.
 * Respects .gitignore files at any depth, plus `extraIgnore` patterns.
 *
 * Deliberately does NOT skip `.env` files that .gitignore lists: if one is present on disk
 * but ignored, it is not committed, so it is fine and we leave it alone. If it is present and
 * NOT ignored, it will be committed — exactly what rule SW-S02 is for.
 */
export function walk(root: string, extraIgnore: string[] = []): WalkResult {
  const base = ignore().add(ALWAYS_SKIP).add(extraIgnore);
  const files: string[] = [];
  const skippedLarge: string[] = [];

  const visit = (dir: string, matchers: Array<{ prefix: string; ig: Ignore }>) => {
    const local = readGitignore(dir);
    const relDir = toPosix(relative(root, dir));
    const here = local ? [...matchers, { prefix: relDir ? relDir + "/" : "", ig: local }] : matchers;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const abs = join(dir, entry.name);
      const rel = toPosix(relative(root, abs));
      const test = entry.isDirectory() ? rel + "/" : rel;

      if (base.ignores(test)) continue;
      if (here.some(({ prefix, ig }) => test.startsWith(prefix) && ig.ignores(test.slice(prefix.length)))) {
        continue;
      }

      if (entry.isDirectory()) {
        visit(abs, here);
      } else if (entry.isFile()) {
        let size = 0;
        try {
          size = statSync(abs).size;
        } catch {
          continue;
        }
        if (size > MAX_FILE_BYTES) skippedLarge.push(rel);
        else files.push(rel);
      }
    }
  };

  visit(root, []);
  return { files, skippedLarge };
}

/**
 * True for paths Seaworthy never scans whatever .gitignore says: build folders and the
 * config's `ignore` patterns. Rules that look beyond the walked files (git-tracked files,
 * git-ignored .env files) use this so they still respect the user's config.
 */
export function excluder(extraIgnore: string[] = []): (rel: string) => boolean {
  const base = ignore().add(ALWAYS_SKIP).add(extraIgnore);
  return (rel) => base.ignores(rel);
}

function readGitignore(dir: string): Ignore | null {
  const p = join(dir, ".gitignore");
  if (!existsSync(p)) return null;
  try {
    return ignore().add(readFileSync(p, "utf8"));
  } catch {
    return null;
  }
}
