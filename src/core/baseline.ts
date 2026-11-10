import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { MAX_FILE_BYTES } from "./walk.js";

export class BaselineError extends Error {}

export interface Baseline {
  /** A temporary folder holding the base ref's files, laid out like the scanned folder. */
  dir: string;
  /** The ref as given, e.g. origin/main. */
  ref: string;
  /** The commit it resolved to. */
  sha: string;
  /** The scanned folder's path inside the repo ("" at the top, else "apps/web/"). */
  prefix: string;
  cleanup: () => void;
}

/**
 * Writes the files `ref` has under the scanned folder into a temporary folder, so it can
 * be scanned exactly like the working tree.
 *
 * Nothing is checked out. Files are read straight from git's object store with `ls-tree`
 * and `cat-file`, which never run hooks, smudge filters or `core.fsmonitor`, so a repo's
 * own config can't run a command (the same rule as `git.ts`). The user's repo is never
 * changed: no worktree, no index, no refs.
 *
 * The temporary folder is itself a git repo whose index is the base tree (read through an
 * alternates link, so nothing is copied twice). Rules that ask git what is tracked, such
 * as SW-S02 for `.env` files, then get the same answer they would on a checkout.
 */
export function extractBaseline(target: string, ref: string): Baseline {
  if (!ref || ref.startsWith("-") || /[\0\n\r]/.test(ref)) {
    throw new BaselineError(`--baseline needs a git ref, such as origin/main or a commit hash.`);
  }
  const top = tryGit(target, ["rev-parse", "--show-toplevel"]);
  if (top === null) {
    throw new BaselineError(`--baseline needs a git repository, and ${target} isn't inside one (or git isn't installed).`);
  }
  const prefix = tryGit(target, ["rev-parse", "--show-prefix"]) ?? "";
  const sha = tryGit(target, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]);
  if (!sha) {
    throw new BaselineError(
      `Couldn't find ${ref} in this repository. In GitHub Actions, check out with fetch-depth: 0 so the base branch is there to compare with.`,
    );
  }
  const commonDir = tryGit(target, ["rev-parse", "--git-common-dir"]);
  if (!commonDir) throw new BaselineError(`Couldn't read the git repository at ${top}.`);
  const objects = resolve(isAbsolute(commonDir) ? commonDir : join(target, commonDir), "objects");

  // The scanned folder as it was at the base ref. It may not have existed then.
  const treeish = prefix ? `${sha}:${prefix.replace(/\/$/, "")}` : `${sha}^{tree}`;
  // (After "sha:", everything is a path, so check the object's type rather than adding ^{tree}.)
  const object = tryGit(target, ["rev-parse", "--verify", "--quiet", treeish]);
  const tree = object && tryGit(target, ["cat-file", "-t", object]) === "tree" ? object : null;

  const dir = mkdtempSync(join(tmpdir(), "seaworthy-baseline-"));
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  try {
    if (tree) {
      const entries = listBlobs(target, tree);
      writeBlobs(target, dir, entries);
      // Match the repo's hash (SHA-1, or SHA-256 for repos created that way), so read-tree can use its objects.
      const format = tryGit(target, ["rev-parse", "--show-object-format"]);
      git(dir, ["init", "--quiet", ...(format && format !== "sha1" ? [`--object-format=${format}`] : [])]);
      writeFileSync(join(dir, ".git", "objects", "info", "alternates"), objects.split(sep).join("/") + "\n");
      git(dir, ["read-tree", tree]);
    }
  } catch (err) {
    cleanup();
    if (err instanceof BaselineError) throw err;
    throw new BaselineError(`Couldn't read ${ref} from git: ${(err as Error).message.split("\n")[0]}`);
  }
  return { dir, ref, sha, prefix, cleanup };
}

interface BlobEntry {
  object: string;
  size: number;
  path: string;
}

/** Regular files in a tree, recursively. Symlinks and submodules are skipped, as the walk skips them. */
function listBlobs(cwd: string, treeish: string): BlobEntry[] {
  const out = git(cwd, ["ls-tree", "-r", "-z", "-l", "--full-tree", treeish]).toString("utf8");
  const entries: BlobEntry[] = [];
  for (const record of out.split("\0")) {
    const tab = record.indexOf("\t");
    if (tab < 0) continue;
    const [mode, type, object, size] = record.slice(0, tab).split(/\s+/);
    const path = record.slice(tab + 1);
    if (type !== "blob" || (mode !== "100644" && mode !== "100755")) continue;
    // Over the walk's size limit: it would be skipped anyway, so don't read it.
    if (Number(size) > MAX_FILE_BYTES) continue;
    entries.push({ object: object!, size: Number(size), path });
  }
  return entries;
}

/** Reads blobs with `cat-file --batch` in chunks of bounded size, and writes each one under `dir`. */
function writeBlobs(cwd: string, dir: string, entries: BlobEntry[]) {
  const root = resolve(dir);
  const CHUNK_BYTES = 32 * 1024 * 1024;
  for (let i = 0; i < entries.length; ) {
    const chunk: BlobEntry[] = [];
    let bytes = 0;
    while (i < entries.length && (chunk.length === 0 || bytes + entries[i]!.size <= CHUNK_BYTES)) {
      bytes += entries[i]!.size;
      chunk.push(entries[i++]!);
    }
    const buf = git(cwd, ["cat-file", "--batch"], chunk.map((e) => e.object).join("\n") + "\n", bytes + chunk.length * 128 + 1024);
    let at = 0;
    for (const e of chunk) {
      const nl = buf.indexOf(0x0a, at);
      const header = buf.subarray(at, nl).toString("utf8").split(" ");
      const size = Number(header[2]);
      if (header[1] !== "blob" || !Number.isFinite(size)) throw new BaselineError(`Unexpected git output reading ${e.path}.`);
      const content = buf.subarray(nl + 1, nl + 1 + size);
      at = nl + 1 + size + 1;

      // Git trees can't normally hold these, but a hand-made one could: never write outside the folder.
      const parts = e.path.split("/");
      if (parts.some((p) => p === "" || p === "." || p === ".." || p.toLowerCase() === ".git")) continue;
      const abs = resolve(root, ...parts);
      if (!abs.startsWith(root + sep)) continue;
      try {
        mkdirSync(dirname(abs), { recursive: true });
        writeFileSync(abs, content);
      } catch {
        // A name this filesystem can't hold (e.g. "aux" or "a:b" on Windows): skip that file.
      }
    }
  }
}

function git(cwd: string, args: string[], input?: string, maxBuffer = 64 * 1024 * 1024): Buffer {
  return execFileSync("git", ["-c", "core.fsmonitor=false", "-C", cwd, ...args], {
    input,
    maxBuffer,
    timeout: 120_000,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
}

function tryGit(cwd: string, args: string[]): string | null {
  try {
    return git(cwd, args).toString("utf8").trim() || null;
  } catch {
    return null;
  }
}
