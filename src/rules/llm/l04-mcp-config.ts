import { posix } from "node:path";
import type { ProjectFiles } from "../../core/project.js";
import type { RawFinding, Rule } from "../types.js";
import { DB_URL_RE, SECRET_PATTERNS, isPlaceholder, shannonEntropy } from "../secrets/patterns.js";

/** Where MCP clients keep their server lists. */
const MCP_FILE_RE = /(^|\/)(\.cursor\/mcp\.json|\.mcp\.json|mcp\.json|\.vscode\/mcp\.json|claude_desktop_config\.json|\.windsurf\/mcp_config\.json)$/;
const SECRET_KEY_RE = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|\bPAT\b|_PAT$|CREDENTIALS?)/i;
/** References to the environment or a secret store, rather than the value itself. */
const REFERENCE_RE = /^\$\{[^}]+\}$|^\$[A-Z_][A-Z0-9_]*$|^\{\{[^}]+\}\}$|^env:|^op:\/\/|^\$\{(env|input):/i;
const LOCAL_HOST_RE = /^(localhost|127\.0\.0\.1|\[::1\]|::1|host\.docker\.internal)$/i;

interface Server {
  name: string;
  command?: string;
  args?: unknown[];
  env?: Record<string, unknown>;
  url?: string;
  headers?: Record<string, unknown>;
}

export const l04McpConfig: Rule = {
  id: "SW-L04",
  title: "MCP server config with secrets in plain text or no authentication",
  severity: "high",
  confidence: "high",
  appliesTo: ["mcp"],
  docs: {
    summary:
      "MCP config files tell your AI coding tool which servers to start and connect to. They are easy to " +
      "commit by accident, and anything written in them is readable by every tool and teammate that sees " +
      "the repo. Keep secrets in environment variables, and never connect to a remote MCP server over plain " +
      "HTTP or without authentication: whoever reaches it can drive the tools behind it.",
    bad: `"args": ["@modelcontextprotocol/server-postgres", "postgres://admin:YOUR_PASSWORD@db.internal/app"]`,
    good: `"args": ["@modelcontextprotocol/server-postgres", "\${env:DATABASE_URL}"]`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of project.files.filter((f) => MCP_FILE_RE.test(f))) {
      const text = project.read(file);
      const json = project.json(file) as Record<string, unknown> | null;
      if (!text || !json) continue;
      const list = (json.mcpServers ?? json.servers ?? json.mcp_servers) as Record<string, Server> | undefined;
      if (!list || typeof list !== "object") continue;

      for (const [name, server] of Object.entries(list)) {
        if (!server || typeof server !== "object") continue;
        const serverAt = text.indexOf(JSON.stringify(name));
        const at = (needle: string) => {
          const i = text.indexOf(needle, Math.max(serverAt, 0));
          return project.position(file, i >= 0 ? i : Math.max(serverAt, 0));
        };

        // 1. Secrets written into args or env.
        for (const arg of server.args ?? []) {
          if (typeof arg !== "string") continue;
          const kind = secretIn(arg);
          if (!kind) continue;
          out.push(secretFinding(file, at(JSON.stringify(arg).slice(1, 20)), name, `an argument`, kind));
        }
        for (const [key, value] of Object.entries(server.env ?? {})) {
          if (typeof value !== "string" || value === "" || REFERENCE_RE.test(value) || isPlaceholder(value)) continue;
          const kind = secretIn(value) ?? (SECRET_KEY_RE.test(key) && shannonEntropy(value) > 3 && value.length >= 12 ? `a ${key}` : null);
          if (!kind) continue;
          out.push(secretFinding(file, at(`"${key}"`), name, `env ${key}`, kind));
        }
        for (const [key, value] of Object.entries(server.headers ?? {})) {
          if (typeof value !== "string" || REFERENCE_RE.test(value) || /\$\{/.test(value)) continue;
          if (/authorization|token|key/i.test(key) && value.length >= 16) {
            out.push(secretFinding(file, at(`"${key}"`), name, `header ${key}`, "a credential"));
          }
        }

        // 2. Remote servers over plain HTTP, or listening on every interface, with no auth configured.
        if (typeof server.url === "string") {
          let u: URL | null = null;
          try {
            u = new URL(server.url);
          } catch {}
          if (!u) continue;
          const local = LOCAL_HOST_RE.test(u.hostname);
          const insecure = u.protocol === "http:" && !local;
          const everywhere = u.hostname === "0.0.0.0";
          const hasAuth = Object.keys(server.headers ?? {}).some((h) => /authorization|token|key/i.test(h));
          if ((insecure || everywhere) && !hasAuth) {
            out.push({
              file,
              ...at(server.url),
              title: `MCP server "${name}" is reached over ${insecure ? "plain HTTP" : "an open address"} with no authentication`,
              why:
                `"${name}" points at ${server.url}. ` +
                (insecure ? `Plain HTTP means anyone on the network path can read and change the traffic. ` : ``) +
                (everywhere ? `0.0.0.0 means the server listens on every network interface, not just this machine. ` : ``) +
                `No authentication is configured, so anyone who can reach it can call its tools as your AI assistant does.`,
              fix:
                `Run local servers on 127.0.0.1, use https:// for remote ones, and require a token: add ` +
                `\`"headers": { "Authorization": "Bearer \${env:MCP_TOKEN}" }\` and check it on the server.`,
              fixPrompt:
                `My ${file} connects to the MCP server "${name}" at ${server.url} with no authentication. Change the server ` +
                `to listen on 127.0.0.1 (or serve HTTPS if it must be remote), require a bearer token read from an ` +
                `environment variable, and update the config to send it.`,
            });
          }
        }
      }
    }
    return out;
  },
};

/** What kind of secret a string holds, if any. */
function secretIn(value: string): string | null {
  for (const m of value.matchAll(new RegExp(DB_URL_RE.source, "g"))) {
    const pw = m[2]!;
    if (!isPlaceholder(pw) && pw.length >= 4 && !REFERENCE_RE.test(pw)) return "a database password";
  }
  for (const p of SECRET_PATTERNS) {
    for (const m of value.matchAll(new RegExp(p.re.source, p.re.flags))) {
      const s = m[1]!;
      if (isPlaceholder(s)) continue;
      if (p.minEntropy && shannonEntropy(s.slice(p.prefixLength ?? 0)) < p.minEntropy) continue;
      const name = p.name.replace(/^(Live|Private) /, (w) => w.toLowerCase()); // keep brand capitals
      return `${/^[AEIOUaeiou]/.test(name) ? "an" : "a"} ${name}`;
    }
  }
  return null;
}

function secretFinding(file: string, pos: { line: number; column: number }, server: string, where: string, kind: string): RawFinding {
  return {
    file,
    ...pos,
    title: `MCP server "${server}" has ${kind} in plain text`,
    why:
      `The config for "${server}" puts ${kind} directly in ${where}. MCP config files get committed and shared, and ` +
      `every tool that reads the file can see it.`,
    fix:
      `Move it to an environment variable and reference it, such as \`\${env:DATABASE_URL}\` or \`\${env:GITHUB_TOKEN}\` ` +
      `(the syntax depends on your MCP client). It has been exposed, so rotate it.`,
    fixPrompt:
      `In ${posix.basename(file)}, the MCP server "${server}" has ${kind} written in plain text in ${where}. Replace it with a ` +
      `reference to an environment variable using my MCP client's syntax, add the variable to my .env.example, and ` +
      `remind me to rotate the old value.`,
  };
}
