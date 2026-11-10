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
