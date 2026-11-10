import type { Confidence } from "../../core/finding.js";
import type { ProjectFiles } from "../../core/project.js";
import { inCode, walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, codeRegions, envRefs, isServerOnly } from "../code.js";
import { LLM_KEY_NAME, LLM_PATTERN_IDS, envFiles, parseEnv, publicPrefix } from "./env.js";
import { SECRET_PATTERNS, isPlaceholder, shannonEntropy } from "./patterns.js";

const PROVIDERS: Array<[RegExp, string]> = [
  [/OPENAI/, "OpenAI"],
  [/ANTHROPIC|CLAUDE/, "Anthropic"],
  [/GROQ/, "Groq"],
  [/GEMINI|GOOGLE_AI|GOOGLE_GENAI/, "Google Gemini"],
  [/MISTRAL/, "Mistral"],
  [/COHERE/, "Cohere"],
  [/PERPLEXITY/, "Perplexity"],
  [/REPLICATE/, "Replicate"],
  [/TOGETHER/, "Together AI"],
  [/DEEPSEEK/, "DeepSeek"],
  [/(^|_)XAI(_|$)/, "xAI"],
  [/OPENROUTER/, "OpenRouter"],
  [/FIREWORKS/, "Fireworks"],
  [/HUGGINGFACE|(^|_)HF(_|$)/, "Hugging Face"],
];

function providerOf(name: string): string {
  return PROVIDERS.find(([re]) => re.test(name))?.[1] ?? "LLM";
}

/** A public-prefixed variable named like an LLM key: NEXT_PUBLIC_OPENAI_API_KEY, not NEXT_PUBLIC_OPENAI_MODEL. */
function llmKeyName(name: string): string | null {
  const prefix = publicPrefix(name);
  if (!prefix) return null;
  const rest = name.slice(prefix.length);
  return LLM_KEY_NAME.test(rest) && /(KEY|TOKEN|SECRET)/.test(rest) ? providerOf(rest) : null;
}

/** The provider, if a value is an LLM key by its format. */
function llmKeyValue(value: string): string | null {
  if (!value || isPlaceholder(value)) return null;
  for (const p of SECRET_PATTERNS) {
    if (!LLM_PATTERN_IDS.has(p.id)) continue;
    for (const m of value.matchAll(new RegExp(p.re.source, p.re.flags))) {
      if (p.minEntropy && shannonEntropy(m[1]!.slice(p.prefixLength ?? 0)) < p.minEntropy) continue;
      return p.name.replace(/ (API key|token)$/, "");
    }
  }
  return null;
}

const IMPACT =
  "Anyone can copy it from the page and run their own requests on your account, so you pay for them, " +
  "up to your account's spending limit.";
const FIX =
  "Call the model from server code instead, such as an API route or server action that reads the key " +
  "from an environment variable without a public prefix. Add rate limiting and a spending limit in the " +
  "provider's dashboard, and rotate the key if this has been deployed.";
const PROMPT =
  "Move every call to the LLM provider out of browser code into a server route (for example " +
  "app/api/chat/route.ts) that reads the API key from an environment variable without a public prefix. " +
  "Have the browser call that route instead, add per-user rate limiting to it, and remove " +
  "dangerouslyAllowBrowser and any public-prefixed key variable.";

export const s04LlmKeyInClient: Rule = {
  id: "SW-S04",
  title: "LLM provider key used in client-side code",
  severity: "critical",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "Calling OpenAI, Anthropic or another model provider straight from the browser means the API " +
      "key is in the page, where anyone can copy it and spend your money. SDKs refuse to run in a " +
      "browser unless you pass `dangerouslyAllowBrowser: true`, and AI tools often add it to make an " +
      "error go away. Calls belong on the server, behind your own auth and rate limits.",
    bad:
      `// lib/openai-browser.ts, imported by a "use client" page\n` +
      `export const openai = new OpenAI({\n  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,\n  dangerouslyAllowBrowser: true,\n});`,
    good:
      `// app/api/chat/route.ts (server only)\n` +
      `const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n` +
      `export async function POST(req: Request) { /* check the user, rate-limit, then call openai */ }`,
  },

  check({ project }) {
    return [...checkEnvFiles(project), ...checkCode(project)];
  },
};

function checkEnvFiles(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const env of envFiles(project)) {
    const text = project.read(env.path);
    if (text === null) continue;
    for (const v of parseEnv(text)) {
      const prefix = publicPrefix(v.name);
      if (!prefix || !v.value) continue;
      const provider = llmKeyValue(v.value) ?? llmKeyName(v.name);
      if (!provider) continue;
      out.push({
        file: env.path,
        ...project.position(env.path, v.offset),
        title: `${provider} key in public variable ${v.name}`,
        why: `${v.name} has the public ${prefix} prefix, so the build copies the ${provider} key into the JavaScript every visitor downloads. ${IMPACT}`,
        fix: `Rename it to ${v.name.slice(prefix.length)} and use it only in server code. ${FIX}`,
        fixPrompt: `My ${env.path} sets ${v.name}, a ${provider} key with a public ${prefix} prefix. Rename it to ${v.name.slice(prefix.length)}. ${PROMPT}`,
      });
    }
  }
  return out;
}

function checkCode(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const file of codeFiles(project)) {
    const text = project.read(file);
    if (!text || !/(?:process\.env|import\.meta\.env|\$env\/|dangerouslyAllowBrowser)/.test(text)) continue;
    const serverOnly = isServerOnly(file, text);
    const confidence: Confidence = serverOnly ? "medium" : "high";
    const where = serverOnly
      ? " This file runs on the server, but the public prefix still puts the key in browser code wherever else it is used."
      : "";

    const seen = new Set<string>();
    for (const r of envRefs(file, text)) {
      const provider = llmKeyName(r.name);
      if (!provider || seen.has(r.name)) continue;
      seen.add(r.name);
      const prefix = publicPrefix(r.name)!;
      out.push({
        file,
        ...project.position(file, r.offset),
        confidence,
        title: `${provider} key read from public variable ${r.name}`,
        why: `This code reads the ${provider} key from ${r.name}. The ${prefix} prefix puts its value in the browser bundle. ${IMPACT}${where}`,
        fix: FIX,
        fixPrompt: `In ${file}, my code reads ${r.name}, a ${provider} key with a public ${prefix} prefix. ${PROMPT}`,
      });
    }

    for (const offset of allowBrowserFlags(file, text)) {
      out.push({
        file,
        ...project.position(file, offset),
        // Setting it in server-only code does nothing, so there it is a smell, not a leak.
        confidence: serverOnly ? "low" : "high",
        title: "LLM SDK told to run in the browser (dangerouslyAllowBrowser)",
        why:
          `\`dangerouslyAllowBrowser\` switches off the SDK's guard against running in a browser. Wherever this ` +
          `client is used in browser code, its API key is in the page. ${IMPACT}`,
        fix: `Remove \`dangerouslyAllowBrowser\`. ${FIX}`,
        fixPrompt: `In ${file}, an LLM SDK client is created with dangerouslyAllowBrowser: true. ${PROMPT}`,
      });
    }
  }
  return out;
}

/** Offsets of `dangerouslyAllowBrowser` set to anything but `false`. */
function allowBrowserFlags(file: string, text: string): number[] {
  if (!text.includes("dangerouslyAllowBrowser")) return [];
  const ast = astOf(file, text);
  if (ast) {
    const out: number[] = [];
    walkAst(ast, (n) => {
      if (n.type !== "ObjectProperty") return;
      const k = n.key;
      const name = k.type === "Identifier" ? k.name : k.type === "StringLiteral" ? k.value : null;
      if (name !== "dangerouslyAllowBrowser") return;
      if (n.value.type === "BooleanLiteral" && !n.value.value) return;
      out.push(n.start ?? 0);
    });
    return out;
  }
  const out: number[] = [];
  for (const [base, code] of codeRegions(file, text)) {
    for (const m of code.matchAll(/\bdangerouslyAllowBrowser\s*:\s*(?!false\b)/g)) {
      if (inCode(code, m.index!)) out.push(base + m.index!);
    }
  }
  return out;
}
