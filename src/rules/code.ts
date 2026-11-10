/**
 * Shared helpers for rules that read application code: which files count as code, where
 * code runs (server or browser), and which environment variables a file actually reads.
 */
import type { Node } from "@babel/types";
import type { ProjectFiles } from "../core/project.js";
import { JS_FILE_RE, envReads, inCode, parseJs, walkAst } from "../core/js.js";

export const CODE_FILE_RE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const SKIP_CODE_RE = /(^|\/)(node_modules|dist|build|\.next)\/|\.(test|spec)\.[cm]?[jt]sx?$|\.d\.ts$/;

/** Files that only ever run on the server. */
const SERVER_ONLY_RE =
  /(^|\/)(app\/(.*\/)?route\.[cm]?[jt]s$|pages\/api\/|server\/)|\.server\.[cm]?[jt]sx?$|(^|\/)(middleware|instrumentation)\.[jt]s$/;

/** Application code worth reading: no tests, type declarations or build output. */
export function codeFiles(project: ProjectFiles): string[] {
  return project.files.filter((f) => CODE_FILE_RE.test(f) && !SKIP_CODE_RE.test(f));
}

/** Code that runs only on the server, so it never ships to the browser by itself. */
export function isServerOnly(file: string, text: string): boolean {
  if (isClientFile(text)) return false;
  return SERVER_ONLY_RE.test(file) || /^\s*["']use server["']/m.test(text) || /from\s+["']server-only["']/.test(text);
}

/** Next.js client component, which ships to the browser. */
export function isClientFile(text: string): boolean {
  return /^\s*["']use client["']/m.test(text);
}

export type Ref = { name: string; offset: number };

/** process.env.X, process.env["X"], import.meta.env.X. */
const ENV_REF_RE =
  /\b(?:process\.env|import\.meta\.env)(?:\.([A-Z][A-Z0-9_]*)|\[\s*["'`]([A-Z][A-Z0-9_]*)["'`]\s*\])/g;
/** SvelteKit public env imports. */
const SVELTE_PUBLIC_IMPORT_RE = /import\s*\{([^}]*)\}\s*from\s*["']\$env\/(?:static|dynamic)\/public["']/g;

/**
 * The parts of a file that are code, with their offsets: the whole file for JS and TS,
 * script blocks for Vue and Svelte, script blocks and frontmatter for Astro.
 */
export function codeRegions(file: string, text: string): Array<[number, string]> {
  if (JS_FILE_RE.test(file)) return [[0, text]];
  const regions: Array<[number, string]> = [];
  for (const m of text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) {
    regions.push([m.index! + m[0].indexOf(">") + 1, m[1]!]);
  }
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (fm) regions.push([fm[0].indexOf("\n") + 1, fm[1]!]);
  return regions;
}

/** The parsed AST for JS and TS files, or null for other files and files Babel can't parse. */
export function astOf(file: string, text: string): Node | null {
  return JS_FILE_RE.test(file) ? parseJs(file, text) : null;
}

/**
 * Environment variables a file actually reads. JS and TS are parsed, so a mention in a
 * comment, a string or documentation doesn't count. Vue, Svelte and Astro files, and JS
 * that Babel can't parse, are text-matched inside their code, skipping comments and strings.
 */
export function envRefs(file: string, text: string): Ref[] {
  const ast = astOf(file, text);
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
  const refs: Ref[] = [];
  for (const [base, code] of codeRegions(file, text)) {
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

/** Quick pre-filter: does the file mention environment variables at all? */
export function mentionsEnv(text: string): boolean {
  return /(?:process\.env|import\.meta\.env|\$env\/)/.test(text);
}

const RESOLVE_EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

/**
 * Resolves a local import (`./x`, `../x`, `@/x`, `~/x`) to a scanned file, or null for
 * packages and anything not found. `@/` and `~/` are tried at the root and under `src/`,
 * which covers the Next.js, Vite and Nuxt defaults without reading tsconfig.
 */
export function resolveImport(project: ProjectFiles, fromFile: string, spec: string): string | null {
  const files = new Set(project.files);
  const dir = fromFile.includes("/") ? fromFile.slice(0, fromFile.lastIndexOf("/")) : "";
  let bases: string[];
  if (spec.startsWith("./") || spec.startsWith("../")) bases = [normalise(dir ? `${dir}/${spec}` : spec)];
  else if (spec.startsWith("@/") || spec.startsWith("~/")) bases = [spec.slice(2), `src/${spec.slice(2)}`];
  else return null;
  for (const base of bases) {
    const stem = base.replace(/\.(js|jsx|mjs|cjs)$/, ""); // TS projects import "./x.js" for "./x.ts"
    for (const ext of RESOLVE_EXTS) {
      for (const b of [base, stem]) if (files.has(b + ext)) return b + ext;
    }
  }
  return null;
}

function normalise(p: string): string {
  const out: string[] = [];
  for (const part of p.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}

/** Module specifiers a file imports (static imports, re-exports, require and dynamic import). */
export function importsOf(file: string, text: string): string[] {
  const out: string[] = [];
  const ast = astOf(file, text);
  if (ast) {
    walkAst(ast, (n) => {
      if ((n.type === "ImportDeclaration" || n.type === "ExportNamedDeclaration" || n.type === "ExportAllDeclaration") && n.source) {
        out.push(n.source.value);
      } else if (n.type === "CallExpression" && n.arguments[0]?.type === "StringLiteral") {
        const c = n.callee;
        if (c.type === "Import" || (c.type === "Identifier" && c.name === "require")) out.push(n.arguments[0].value);
      }
    });
    return out;
  }
  for (const m of text.matchAll(/\b(?:from|import|require\s*\()\s*["']([^"']+)["']/g)) out.push(m[1]!);
  return out;
}
