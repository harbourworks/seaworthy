import { execFileSync } from "node:child_process";

/**
 * Files git tracks under `root` that match `pathspecs`, as posix paths relative to `root`.
 * Returns null when `root` is not inside a git repository or git is not installed, so
 * callers can fall back to what is on disk.
 *
 * Seaworthy is often run on repos people have just downloaded, so a repo's own config must
 * not be able to run anything: `core.fsmonitor` is the one setting that makes `ls-files`
 * execute a command, and it is forced off.
 */
export function gitTrackedFiles(root: string, pathspecs: string[]): string[] | null {
  try {
    const out = execFileSync(
      "git",
      ["-c", "core.fsmonitor=false", "-C", root, "ls-files", "-z", "--", ...pathspecs],
      { encoding: "utf8", timeout: 5000, stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
    );
    return out.split("\0").filter((p) => p.length > 0);
  } catch {
    return null;
  }
}

function git(root: string, args: string[], input?: string, maxBuffer = 256 * 1024 * 1024): Buffer {
  return execFileSync("git", ["-c", "core.fsmonitor=false", "-C", root, ...args], {
    input,
    maxBuffer,
    timeout: 60_000,
    stdio: ["pipe", "pipe", "ignore"],
    windowsHide: true,
  });
}

/** True when `root` is the top folder of a git repository that has at least one commit. */
export function isRepoTop(root: string): boolean {
  try {
    // An empty prefix means root is the top folder. (Comparing paths fails on Windows, where
    // the same folder can have a short 8.3 name and a long one.)
    if (git(root, ["rev-parse", "--show-prefix"]).toString("utf8").trim() !== "") return false;
    git(root, ["rev-parse", "--verify", "--quiet", "HEAD"]);
    return true;
  } catch {
    return false;
  }
}

export interface HistoryBlob {
  object: string;
  size: number;
  /** The path it had (the first one seen, newest commits first). */
  path: string;
}

/**
 * Every file version in the repository's history (all refs), newest first, with its path.
 * Uses rev-list and cat-file only, which never run hooks or filters. Null if git fails.
 */
export function historyBlobs(root: string): HistoryBlob[] | null {
  try {
    const objects = git(root, ["rev-list", "--all", "--objects"]).toString("utf8");
    const checked = git(root, ["cat-file", "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)"], objects).toString("utf8");
    const seen = new Set<string>();
    const out: HistoryBlob[] = [];
    for (const line of checked.split("\n")) {
      const m = /^blob ([0-9a-f]+) (\d+) (.+)$/.exec(line);
      if (!m || seen.has(m[1]!)) continue;
      seen.add(m[1]!);
      out.push({ object: m[1]!, size: Number(m[2]), path: m[3]! });
    }
    return out;
  } catch {
    return null;
  }
}

/** Blob IDs in the HEAD commit, so history scanning can skip what's checked out now. */
export function headBlobs(root: string): Set<string> {
  try {
    const out = git(root, ["ls-tree", "-r", "-z", "HEAD"]).toString("utf8");
    return new Set(out.split("\0").map((r) => r.split(/\s/)[2]).filter((x): x is string => Boolean(x)));
  } catch {
    return new Set();
  }
}

/** Reads blobs with `cat-file --batch`, in chunks of bounded size. */
export function readBlobs(root: string, blobs: HistoryBlob[], chunkBytes = 32 * 1024 * 1024): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (let i = 0; i < blobs.length; ) {
    const chunk: HistoryBlob[] = [];
    let bytes = 0;
    while (i < blobs.length && (chunk.length === 0 || bytes + blobs[i]!.size <= chunkBytes)) {
      bytes += blobs[i]!.size;
      chunk.push(blobs[i++]!);
    }
    const buf = git(root, ["cat-file", "--batch"], chunk.map((b) => b.object).join("\n") + "\n", bytes + chunk.length * 128 + 1024);
    let at = 0;
    for (const b of chunk) {
      const nl = buf.indexOf(0x0a, at);
      const size = Number(buf.subarray(at, nl).toString("utf8").split(" ")[2]);
      out.set(b.object, buf.subarray(nl + 1, nl + 1 + size));
      at = nl + 1 + size + 1;
    }
  }
  return out;
}

/** The commit (short hash and date) that first added a blob, or null. */
export function commitAdding(root: string, object: string): { commit: string; date: string } | null {
  try {
    const out = git(root, ["log", "--all", "--reverse", "--format=%h %as", `--find-object=${object}`]).toString("utf8").trim().split("\n")[0];
    const [commit, date] = (out ?? "").split(" ");
    return commit && date ? { commit, date } : null;
  } catch {
    return null;
  }
}

/** True if `commit` is already part of `ref`'s history. */
export function isAncestor(root: string, commit: string, ref: string): boolean {
  try {
    git(root, ["merge-base", "--is-ancestor", commit, ref]);
    return true;
  } catch {
    return false;
  }
}
