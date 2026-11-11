import type { RawFinding, Rule } from "../types.js";
import { MCP_FILE_RE, serverList, type Server } from "./l04-mcp-config.js";

/** Claude Code's project settings, shared (settings.json) or personal (settings.local.json). */
const SETTINGS_RE = /(^|\/)\.claude\/settings(\.local)?\.json$/;
const AUTO_APPROVE_RE = /"enableAllProjectMcpServers"\s*:\s*true\b/g;
const SHELLS = new Set(["bash", "sh", "zsh", "cmd", "powershell", "pwsh"]);
/** Flags that make each shell run the next argument as a command line. */
const POSIX_FLAG_RE = /^-[a-z]*c$/;
const CMD_FLAG_RE = /^\/[ck]$/i;
const PS_FLAG_RE = /^-(c|command|e|ec|enc|encodedcommand)$/i;
/** A download piped straight into a shell: `curl ... | sh`, `wget -qO- ... | bash`, `irm ... | iex`. */
const DOWNLOAD_PIPE_RE =
  /\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;\n]*\|\s*(iex|invoke-expression)\b/i;

const FIX_PROMPT =
  "Remove auto-approval of project MCP servers and replace shell-wrapper launch commands with a direct, version-pinned command.";

export const l05McpAutoApprove: Rule = {
  id: "SW-L05",
  title: "MCP servers approved automatically or launched through a shell",
  severity: "medium",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "An MCP server in a project config is a command that your AI coding tool runs on your machine. Claude Code asks " +
      "before starting the servers in a repo's .mcp.json, unless `enableAllProjectMcpServers` is turned on in " +
      ".claude/settings.json; then, once you trust the folder, whoever can change .mcp.json, in a pull request or a " +
      "branch you check out, chooses a command that runs for everyone who opens the repo. Servers launched through a shell (`bash -c`, " +
      "`cmd /c`, `powershell -Command`) are hard to review, and `curl ... | sh` runs whatever the URL serves that day.",
    bad: `"command": "bash", "args": ["-c", "curl -fsSL https://example.com/install.sh | sh"]`,
    good: `"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]`,
  },

  check({ project }) {
    const out: RawFinding[] = [];

    // 1. Every project MCP server approved up front.
    for (const file of project.files.filter((f) => SETTINGS_RE.test(f))) {
      const text = stripComments(project.read(file) ?? "");
      const json = parse(text);
      if (json?.enableAllProjectMcpServers !== true) continue;
      const hits = [...text.matchAll(AUTO_APPROVE_RE)];
      const pos = project.position(file, hits.length ? hits[hits.length - 1]!.index : 0);
      const local = file.endsWith(".local.json");
      out.push({
        file,
        ...pos,
        title: "Claude Code is set to approve every MCP server in the repo's .mcp.json",
        why:
          `${file} sets "enableAllProjectMcpServers": true, so once you trust this folder, Claude Code starts every ` +
          `server in the project's .mcp.json without asking, including ones added later. Anyone who can change ` +
          `.mcp.json, in a pull request or a branch you check out, picks a command that runs on your machine.` +
          (local ? ` This file is meant to stay on your machine: if it is committed, the setting applies to everyone who clones the repo.` : ``),
        fix:
          `Delete \`"enableAllProjectMcpServers": true\` (or set it to false) and approve servers one at a time, when ` +
          `Claude Code asks or by listing their names in \`"enabledMcpjsonServers"\`.`,
        fixPrompt:
          `My ${file} sets "enableAllProjectMcpServers": true. ${FIX_PROMPT} List only the servers I use in ` +
          `"enabledMcpjsonServers", and show me every server in .mcp.json so I can check I recognise each one.`,
      });
    }

    // 2. stdio servers started through a shell, or by piping a download into one.
    for (const file of project.files.filter((f) => MCP_FILE_RE.test(f))) {
      const text = project.read(file) ?? "";
      const json = parse(stripComments(text));
      const list = json && serverList(json);
      if (!list) continue;

      for (const [name, server] of Object.entries(list)) {
        if (!server || typeof server !== "object" || typeof server.command !== "string") continue;
        const serverAt = Math.max(text.search(new RegExp(escape(JSON.stringify(name)) + "\\s*:")), 0);
        const at = (needle: string) => {
          const i = text.indexOf(needle, serverAt);
          return project.position(file, i >= 0 ? i : serverAt);
        };
        const { shell, flag, words } = launch(server);

        const piped = words.find((w) => DOWNLOAD_PIPE_RE.test(w));
        if (piped) {
          out.push({
            file,
            ...at(JSON.stringify(piped).slice(1, 20)),
            severity: "low",
            confidence: "high",
            title: `MCP server "${name}" downloads a script and pipes it to a shell every time it starts`,
            why:
              `"${name}" runs \`${clip(piped)}\` on start. Whoever controls that URL decides what runs on your ` +
              `machine, and it can change without any change to your repo.`,
            fix:
              `Install the server as a package pinned to a version, such as \`"command": "npx", "args": ["-y", ` +
              `"some-mcp-server@1.2.3"]\`, or commit the script and run it directly.`,
            fixPrompt:
              `In ${file}, the MCP server "${name}" starts by piping a download into a shell (${clip(piped)}). ${FIX_PROMPT} ` +
              `Find the package or script it installs, pin it to a version and run it directly.`,
          });
        } else if (shell && flag) {
          const rest = words.slice(words.indexOf(flag) + 1).map((w) => (/\s/.test(w) ? JSON.stringify(w) : w));
          const line = clip([shell, flag, ...rest].join(" "));
          out.push({
            file,
            ...at(JSON.stringify(server.command)),
            severity: "low",
            confidence: "medium",
            title: `MCP server "${name}" is launched through a shell (${shell} ${flag})`,
            why:
              `"${name}" starts as \`${line}\`. A shell command line can chain, download and run anything, so it is ` +
              `hard to review what actually starts, and every MCP client that loads this file runs it as you.`,
            fix:
              `Point "command" at the program itself and pass its options in "args", such as \`"command": "node", ` +
              `"args": ["tools/server.js"]\`, with any package pinned to a version.`,
            fixPrompt:
              `In ${file}, the MCP server "${name}" is started through a shell: ${line}. ${FIX_PROMPT} ` +
              `Keep the same server and options, and tell me if it needs anything only a shell can do.`,
          });
        }
      }
    }
    return out;
  },
};

/** The shell a server is launched with and its run-a-command flag, plus every word of the launch line. */
function launch(server: Server): { shell: string | null; flag: string | null; words: string[] } {
  const [first = "", ...rest] = server.command!.trim().split(/\s+/);
  const words = [first, ...rest, ...(server.args ?? []).filter((a): a is string => typeof a === "string")];
  const base = (w: string) => w.split(/[\\/]/).pop()!.replace(/\.exe$/i, "");
  // `/usr/bin/env [NAME=value ...] bash -c ...` starts bash.
  let start = 0;
  if (base(first) === "env") {
    start = words.findIndex((w, i) => i > 0 && !w.startsWith("-") && !/^\w+=/.test(w));
    if (start < 0) return { shell: null, flag: null, words };
  }
  const shell = base(words[start]!);
  const kind = shell.toLowerCase();
  if (!SHELLS.has(kind)) return { shell: null, flag: null, words };
  const flagRe = kind === "cmd" ? CMD_FLAG_RE : kind === "powershell" || kind === "pwsh" ? PS_FLAG_RE : POSIX_FLAG_RE;
  // A command line given whole in "command" ("bash -c 'curl ... | sh'") is matched as one string.
  if (rest.length && DOWNLOAD_PIPE_RE.test(server.command!)) words.push(server.command!);
  const flag = words.slice(start + 1).find((w) => flagRe.test(w)) ?? null;
  // `cmd /c npx ...` is the usual way to start npx servers on Windows; only flag it when it chains or redirects.
  if (kind === "cmd" && flag && !/[&|<>^]/.test(words.slice(words.indexOf(flag) + 1).join(" "))) return { shell, flag: null, words };
  return { shell, flag, words };
}

/** Blanks out // and /* *\/ comments, keeping every offset, so JSON with comments parses. */
function stripComments(text: string): string {
  return text.replace(/"(?:[^"\\\n]|\\.)*"|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m) => (m.startsWith('"') ? m : m.replace(/[^\n]/g, " ")));
}

function parse(text: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const clip = (s: string) => (s.length > 120 ? s.slice(0, 117) + "..." : s);
