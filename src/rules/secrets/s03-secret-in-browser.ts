import type { Confidence } from "../../core/finding.js";
import type { ProjectFiles } from "../../core/project.js";
import type { RawFinding, Rule } from "../types.js";
import { JS_FILE_RE, envReads, inCode, parseJs, walkAst } from "../../core/js.js";
import { envFiles, parseEnv, publicPrefix } from "./env.js";
import { JWT_RE, SECRET_PATTERNS, decodeJwtPayload, isPlaceholder, shannonEntropy } from "./patterns.js";

/** Names that say "secret" once the public prefix is removed. */
const SECRET_NAME = /(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES_URL|MONGODB_URI|ADMIN_KEY)/;
/** Names that are public by design even though they contain a word above. */
const PUBLIC_NAME = /(PUBLISHABLE|ANON_KEY|PUBLIC_KEY|SITE_KEY|CLIENT_ID)/;
/**
 * LLM provider keys are SW-S04's job, in env files and in code, so they are reported once
 * with advice specific to them.
 */
const LLM_NAME = /(OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|GEMINI|GOOGLE_AI|PERPLEXITY|REPLICATE|TOGETHER|DEEPSEEK|XAI|OPENROUTER|FIREWORKS)/;
const LLM_PATTERN_IDS = new Set(["openai-key", "anthropic-key"]);

const CODE_FILE_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const SKIP_CODE_RE = /(^|\/)(node_modules|dist|build|\.next)\/|\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$/;
/** process.env.X, process.env["X"], import.meta.env.X, and SvelteKit's $env/static/public imports. */
const ENV_REF_RE =
  /\b(?:process\.env|import\.meta\.env)(?:\.([A-Z][A-Z0-9_]*)|\[\s*["'`]([A-Z][A-Z0-9_]*)["'`]\s*\])/g;
const SVELTE_PUBLIC_IMPORT_RE = /import\s*\{([^}]*)\}\s*from\s*["']\$env\/(?:static|dynamic)\/public["']/g;
/** Files that only ever run on the server: a public-prefixed secret here is a mistake waiting to spread. */
const SERVER_ONLY_RE =
  /(^|\/)(app\/(.*\/)?route\.[cm]?[jt]s$|pages\/api\/|server\/)|\.server\.[cm]?[jt]sx?$|(^|\/)(middleware|instrumentation)\.[jt]s$/;

export const s03SecretInBrowser: Rule = {
  id: "SW-S03",
  title: "Secret exposed to the browser",
  severity: "critical",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "Frameworks copy any variable with a public prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, " +
      "EXPO_PUBLIC_, PUBLIC_ and others) into the JavaScript that ships to every visitor. Give a " +
      "secret one of those prefixes and anyone can read it in their browser's developer tools. The " +
      "most damaging case is a Supabase service-role key, which bypasses row-level security and " +
      "reads or deletes every row in the database.",
    bad:
      `# .env.local\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJ…\n\n` +
      `// lib/supabase-browser.ts\ncreateClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!)`,
    good:
      `# .env.local\nNEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ…   # public by design\nSUPABASE_SERVICE_ROLE_KEY=eyJ…       # server only\n\n` +
      `// lib/supabase-browser.ts\ncreateClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)`,
  },

  check({ project }) {
    return [...checkEnvFiles(project), ...checkCode(project)];
  },
};

function secretName(name: string): boolean {
  const prefix = publicPrefix(name);
  if (!prefix) return false;
  const rest = name.slice(prefix.length);
  return SECRET_NAME.test(rest) && !PUBLIC_NAME.test(rest) && !LLM_NAME.test(rest);
}

/** What a public-prefixed value actually is, judged by its contents. */
function secretValue(value: string): string | null {
  if (!value || isPlaceholder(value)) return null;
  for (const m of value.matchAll(new RegExp(JWT_RE.source, "g"))) {
    if (decodeJwtPayload(m[1]!)?.role === "service_role") return "a Supabase service-role key";
  }
  for (const p of SECRET_PATTERNS) {
    if (LLM_PATTERN_IDS.has(p.id) || p.id === "private-key") continue;
    for (const m of value.matchAll(new RegExp(p.re.source, p.re.flags))) {
      const s = m[1]!;
      if (p.minEntropy && shannonEntropy(s.slice(p.prefixLength ?? 0)) < p.minEntropy) continue;
      // Keep brand capitals ("a GitHub token"); only generic leading words go lower case.
      const name = p.name.replace(/^(Live|Private) /, (w) => w.toLowerCase());
      return `${/^[aeiouAEIOU]/.test(name) ? "an" : "a"} ${name}`;
    }
  }
  return null;
}

function kindOf(name: string): string {
  return /SERVICE_ROLE/.test(name) ? "Supabase service-role key" : "secret";
}

function checkEnvFiles(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const env of envFiles(project)) {
    const text = project.read(env.path);
    if (text === null) continue;
    for (const v of parseEnv(text)) {
      const prefix = publicPrefix(v.name);
      if (!prefix) continue;
      const byValue = secretValue(v.value);
      if (!byValue && !(secretName(v.name) && v.value.length > 0)) continue;
      const what = byValue ?? `a ${kindOf(v.name)}`;
      out.push({
        file: env.path,
        ...project.position(env.path, v.offset),
        title: `Public variable ${v.name} holds ${what}`,
        why:
          `${v.name} holds ${what}, and the ${prefix} prefix tells the build to copy it into the JavaScript ` +
          `every visitor downloads. Anyone can read it in their browser.` +
          (/service-role/.test(what) || /SERVICE_ROLE/.test(v.name)
            ? ` A service-role key bypasses row-level security, so it can read and delete every row.`
            : ``),
        fix:
          `Rename it to ${v.name.slice(prefix.length)} (no prefix) and use it only in server code. ` +
          `If the site has been deployed with it, rotate the key: it is already in the shipped bundle.`,
        fixPrompt:
          `My ${env.path} sets ${v.name}, which is a secret with a public ${prefix} prefix, so it ships to the browser. ` +
          `Rename it to ${v.name.slice(prefix.length)}, move every use of it into server-only code (API routes or ` +
          `server actions), and change any browser code that used it to call that server code instead.`,
      });
    }
  }
  return out;
}

type Ref = { name: string; offset: number };

/**
 * Environment variables a file actually reads. JS and TS are parsed, so a mention in a
 * comment, a string or documentation doesn't count. Vue, Svelte and Astro files are
 * text-matched inside their script blocks only, skipping comments and strings.
 */
function envRefs(file: string, text: string): Ref[] {
  if (JS_FILE_RE.test(file)) {
    const ast = parseJs(file, text);
    if (ast) {
      const refs = envReads(ast);
      walkAst(ast, (n) => {
        if (n.type !== "ImportDeclaration" || !/^\$env\/(static|dynamic)\/public$/.test(n.source.value)) return;
        for (const s of n.specifiers) {
          if (s.type === "ImportSpecifier") {
            const name = s.imported.type === "Identifier" ? s.imported.name : s.imported.value;
            refs.push({ name, offset: s.start ?? 0 });
          }
        }
        return false;
      });
      return refs;
    }
  }
  // Script blocks (Vue, Svelte, Astro) and Astro frontmatter; the whole file if it is JS Babel couldn't parse.
  const regions: Array<[number, string]> = [];
  if (JS_FILE_RE.test(file)) regions.push([0, text]);
  else {
    for (const m of text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
      regions.push([m.index! + m[0].indexOf(">") + 1, m[1]!]);
    }
    const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
    if (fm) regions.push([fm[0].indexOf("\n") + 1, fm[1]!]);
  }
  const refs: Ref[] = [];
  for (const [base, code] of regions) {
    for (const m of code.matchAll(ENV_REF_RE)) {
      if (inCode(code, m.index!)) refs.push({ name: (m[1] ?? m[2])!, offset: base + m.index! });
    }
    for (const m of code.matchAll(SVELTE_PUBLIC_IMPORT_RE)) {
      if (!inCode(code, m.index!)) continue;
      for (const n of m[1]!.split(",")) {
        const name = n.trim().split(/\s+as\s+/)[0]!.trim();
        if (name) refs.push({ name, offset: base + m.index! + m[0].indexOf(name) });
      }
    }
  }
  return refs;
}

function checkCode(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const file of project.files) {
    if (!CODE_FILE_RE.test(file) || SKIP_CODE_RE.test(file)) continue;
    const text = project.read(file);
    if (!text || !/(?:process\.env|import\.meta\.env|\$env\/)/.test(text)) continue;
    const seen = new Set<string>();
    for (const r of envRefs(file, text)) {
      if (!secretName(r.name) || seen.has(r.name)) continue;
      seen.add(r.name);
      const prefix = publicPrefix(r.name)!;
      const serverOnly = SERVER_ONLY_RE.test(file) || /^\s*["']use server["']/m.test(text) || /from\s+["']server-only["']/.test(text);
      const clientSide = /^\s*["']use client["']/m.test(text);
      const confidence: Confidence = serverOnly && !clientSide ? "medium" : "high";
      const what = kindOf(r.name);
      out.push({
        file,
        ...project.position(file, r.offset),
        confidence,
        title: `${what[0]!.toUpperCase()}${what.slice(1)} read from public variable ${r.name}`,
        why:
          `This code reads ${r.name}. The ${prefix} prefix means the build copies the value into browser JavaScript` +
          (serverOnly && !clientSide
            ? `. This file runs on the server, but the prefix still makes the value public as soon as any browser code uses it.`
            : `, so every visitor can read the ${what}.`) +
          (/SERVICE_ROLE/.test(r.name) ? ` A service-role key bypasses row-level security entirely.` : ``),
        fix:
          `Use ${r.name.slice(prefix.length)} (no prefix) in server-only code. ` +
          (/SERVICE_ROLE/.test(r.name)
            ? `Browser code should use the anon key (NEXT_PUBLIC_SUPABASE_ANON_KEY) and rely on row-level security.`
            : `Browser code should call a server route that uses the secret, instead of holding it.`),
        fixPrompt:
          `In ${file}, my code reads ${r.name}, a secret with a public ${prefix} prefix, so it ends up in the browser bundle. ` +
          (/SERVICE_ROLE/.test(r.name)
            ? `Change browser code to use the Supabase anon key and row-level security, and move anything that truly ` +
              `needs the service-role key into server-only code that reads SUPABASE_SERVICE_ROLE_KEY.`
            : `Move the code that needs it into a server route or server action that reads ${r.name.slice(prefix.length)}, ` +
              `and have the browser call that instead.`),
      });
    }
  }
  return out;
}
