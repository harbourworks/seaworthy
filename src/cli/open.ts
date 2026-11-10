import { spawn } from "node:child_process";

/**
 * Opens an https link in the default browser. Returns false if it couldn't (no desktop,
 * no opener installed), so the caller can just print the link. Never throws, never waits.
 *
 * Only https URLs are accepted, and on Windows the URL is passed to `start` without a shell
 * string being built from it, so a link can never become a command.
 */
export function openUrl(url: string, platform: NodeJS.Platform = process.platform): boolean {
  if (!/^https:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_\-./?=&%~]*$/.test(url)) return false;
  const [cmd, args] =
    platform === "win32"
      ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
      : platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  try {
    const child = spawn(cmd, args, { detached: true, stdio: "ignore", windowsHide: true });
    child.on("error", () => {});
    child.unref();
    return true;
  } catch {
    return false;
  }
}
