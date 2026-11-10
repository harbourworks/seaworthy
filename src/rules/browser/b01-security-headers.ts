import { posix } from "node:path";
import type { ProjectFiles } from "../../core/project.js";
import type { RawFinding, Rule } from "../types.js";

const NEXT_CONFIG_RE = /(^|\/)next\.config\.(js|mjs|cjs|ts|mts)$/;
/** Other places a Next.js app can set response headers. */
const HEADER_SOURCES_RE =
  /(^|\/)(middleware\.[jt]s|src\/middleware\.[jt]s|vercel\.json|netlify\.toml|public\/_headers|_headers|firebase\.json|staticwebapp\.config\.json)$/;
/** Packages that set security headers for you. */
const HEADER_PACKAGES = ["@next-safe/middleware", "next-safe", "next-secure-headers", "helmet", "nosecone", "@nosecone/next"];

const HEADERS = {
  csp: { name: "Content-Security-Policy", re: /content-security-policy/i },
  frames: { name: "X-Frame-Options (or CSP frame-ancestors)", re: /x-frame-options|frame-ancestors/i },
  hsts: { name: "Strict-Transport-Security", re: /strict-transport-security/i },
} as const;
type HeaderKey = keyof typeof HEADERS;

export const b01SecurityHeaders: Rule = {
  id: "SW-B01",
  title: "Missing security headers",
  severity: "low",
  confidence: "high",
  appliesTo: ["nextjs"],
  docs: {
    summary:
      "A few response headers make whole classes of attack harder: Content-Security-Policy limits " +
      "which scripts can run (a second line of defence against XSS), X-Frame-Options or " +
      "frame-ancestors stops other sites framing yours to trick clicks, and Strict-Transport-Security " +
      "keeps browsers on HTTPS. They are not a fix for a real bug, which is why this is low severity, " +
      "but they are cheap to add. Some hosts add HSTS for you; `curl -I https://your-site` shows what is sent.",
    bad: `// next.config.js\nmodule.exports = { reactStrictMode: true };`,
    good:
      `// next.config.js\nmodule.exports = {\n  async headers() {\n    return [{ source: "/(.*)", headers: [\n` +
      `      { key: "Content-Security-Policy", value: "default-src 'self'; frame-ancestors 'none'" },\n` +
      `      { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },\n` +
      `      { key: "X-Frame-Options", value: "DENY" },\n    ] }];\n  },\n};`,
  },

  check({ project }) {
    if (usesHeaderPackage(project)) return [];
    const configs = project.files.filter((f) => NEXT_CONFIG_RE.test(f));
    const sources = [...configs, ...project.files.filter((f) => HEADER_SOURCES_RE.test(f))];
    const text = sources.map((f) => project.read(f) ?? "").join("\n");
    const missing = (Object.keys(HEADERS) as HeaderKey[]).filter((k) => !HEADERS[k].re.test(text));
    if (missing.length === 0) return [];

    const names = missing.map((k) => HEADERS[k].name);
    const all = missing.length === Object.keys(HEADERS).length;
    const where = configs[0] ? locateConfig(project, configs[0]) : locatePackage(project);
    if (!where) return [];
    return [
      {
        ...where,
        title: all ? "No security headers set" : `Security headers missing: ${names.join(", ")}`,
        why:
          (all
            ? `Nothing in this repo sets Content-Security-Policy, frame protection or Strict-Transport-Security`
            : `This app doesn't set ${list(names)}`) +
          (configs[0] ? `.` : `, and there is no next.config file.`) +
          ` Without them, an XSS bug has nothing to stop it, other sites can frame your pages, and browsers ` +
          `aren't told to insist on HTTPS. If your host or CDN adds them, \`curl -I\` on your site will show it.`,
        fix:
          `Add an \`async headers()\` function to ${configs[0] ?? "a new next.config.js"} that returns these for ` +
          `\`source: "/(.*)"\`: ${names.join(", ")}. Start the CSP strict, then loosen it for what your app loads.`,
        fixPrompt:
          `Add security headers to my Next.js app in ${configs[0] ?? "next.config.js"}: an async headers() function ` +
          `that sets ${names.join(", ")} on every route. Write a Content-Security-Policy that allows only what my app ` +
          `actually loads (check my code for external scripts, fonts, images and API calls), with frame-ancestors 'none'.`,
      } satisfies RawFinding,
    ];
  },
};

function usesHeaderPackage(project: ProjectFiles): boolean {
  for (const f of project.files) {
    if (posix.basename(f) !== "package.json") continue;
    const pkg = project.json(f) as Record<string, Record<string, string> | undefined> | null;
    const deps = { ...pkg?.dependencies, ...pkg?.devDependencies };
    if (HEADER_PACKAGES.some((p) => p in deps)) return true;
  }
  return false;
}

/** The line where the config object starts, so the fix lands where it belongs. */
function locateConfig(project: ProjectFiles, file: string) {
  const text = project.read(file) ?? "";
  const m = /(?:\bnextConfig\b[^=\n]*=\s*|module\.exports\s*=\s*|export\s+default\s+)(?:\w+\()?\{/.exec(text);
  return { file, ...project.position(file, m ? m.index : 0) };
}

/** No next.config at all: point at the `next` dependency. */
function locatePackage(project: ProjectFiles) {
  const file = project.files.find((f) => f === "package.json") ?? project.files.find((f) => f.endsWith("/package.json"));
  if (!file) return null;
  const text = project.read(file) ?? "";
  const i = text.search(/"next"\s*:/);
  return { file, ...project.position(file, i < 0 ? 0 : i) };
}

function list(items: string[]): string {
  return items.length <= 1 ? (items[0] ?? "") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}
