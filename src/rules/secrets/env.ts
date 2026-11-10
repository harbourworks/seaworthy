import { readdirSync } from "node:fs";
import { join, posix } from "node:path";
import type { ProjectFiles } from "../../core/project.js";
import { gitTrackedFiles } from "../../core/git.js";

/** `.env`, `.env.local`, `.env.production` and so on. */
const ENV_FILE_RE = /^\.env(?:\.[\w.-]+)?$/;
/** Templates are meant to be committed: `.env.example`, `.env.sample`, … */
const TEMPLATE_RE = /\.(example|sample|template|dist|defaults|schema|vault)$/i;

export function isEnvFile(path: string): boolean {
  const base = posix.basename(path);
  return ENV_FILE_RE.test(base) && !TEMPLATE_RE.test(base);
}

/**
 * Prefixes that frameworks inline into the browser bundle. Anything named with one of
 * these is public, wherever it is set.
 */
export const PUBLIC_PREFIXES = [
  "NEXT_PUBLIC_", // Next.js
  "VITE_", // Vite
  "REACT_APP_", // Create React App
  "EXPO_PUBLIC_", // Expo
  "NUXT_PUBLIC_", // Nuxt
  "GATSBY_", // Gatsby
  "PUBLIC_", // SvelteKit ($env/static/public) and Astro
] as const;

export function publicPrefix(name: string): string | null {
  return PUBLIC_PREFIXES.find((p) => name.startsWith(p)) ?? null;
}

export interface EnvVar {
  name: string;
  value: string;
  /** 1-based line. */
  line: number;
  /** File offset of the variable name. */
  offset: number;
}

/** Reads `KEY=value` lines, including `export KEY=value` and quoted values. */
export function parseEnv(text: string): EnvVar[] {
  const out: EnvVar[] = [];
  let offset = 0;
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const m = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*?)\s*$/.exec(raw.replace(/\r$/, ""));
    if (m) {
      let value = m[3]!;
      const q = value[0];
      if ((q === '"' || q === "'" || q === "`") && value.lastIndexOf(q) > 0) value = value.slice(1, value.lastIndexOf(q));
      else value = value.replace(/\s+#.*$/, "");
      out.push({ name: m[2]!, value, line: i + 1, offset: offset + m[1]!.length });
    }
    offset += raw.length + 1;
  }
  return out;
}

export interface EnvFile {
  path: string;
  /** Git tracks it: it is committed. */
  tracked: boolean;
  /** It is in the scanned files, so no .gitignore rule covers it and it would be committed. */
  unignored: boolean;
}

/**
 * Every real .env file in the project: those that would be committed (in the scan), those
 * git already tracks, and git-ignored ones on disk next to a package.json. The last group
 * matters because a `NEXT_PUBLIC_` secret is bundled for the browser even if the file
 * itself is never committed.
 */
export function envFiles(project: ProjectFiles): EnvFile[] {
  const walked = new Set(project.files.filter(isEnvFile));
  const tracked = new Set(
    (gitTrackedFiles(project.root, [":(glob)**/.env", ":(glob)**/.env.*"]) ?? []).filter(
      (f) => isEnvFile(f) && !project.isExcluded(f),
    ),
  );
  const onDisk = new Set<string>();
  const dirs = new Set(["."]);
  for (const f of project.files) if (posix.basename(f) === "package.json") dirs.add(posix.dirname(f));
  for (const dir of dirs) {
    let entries;
    try {
      entries = readdirSync(join(project.root, dir), { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile()) continue; // a Python virtualenv is often a folder called .env
      const n = e.name;
      const rel = dir === "." ? n : `${dir}/${n}`;
      if (isEnvFile(rel) && !project.isExcluded(rel)) onDisk.add(rel);
    }
  }
  const all = [...new Set([...walked, ...tracked, ...onDisk])].sort();
  return all.map((path) => ({ path, tracked: tracked.has(path), unignored: walked.has(path) }));
}

/**
 * Variable names for LLM provider keys, matched as whole `_`-separated words so that
 * `NEXT_PUBLIC_OPENAI_API_KEY` counts and `RELAXAIR_URL` doesn't. SW-S04 owns these;
 * SW-S03 skips them so each problem is reported once.
 */
export const LLM_KEY_NAME =
  /(^|_)(OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|GEMINI|GOOGLE_AI|GOOGLE_GENAI|PERPLEXITY|REPLICATE|TOGETHER|DEEPSEEK|XAI|OPENROUTER|FIREWORKS|HUGGINGFACE|HF)(_|$)/;
/** Secret patterns (see patterns.ts) that are LLM provider keys. */
export const LLM_PATTERN_IDS = new Set(["openai-key", "anthropic-key", "huggingface-token"]);
