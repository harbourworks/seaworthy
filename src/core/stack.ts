import type { ProjectFiles } from "./project.js";

export type StackFeature =
  | "nextjs"
  | "react"
  | "supabase"
  | "firebase"
  | "stripe"
  | "llm"
  | "mcp";

export const STACK_LABELS: Record<StackFeature, string> = {
  nextjs: "Next.js",
  react: "React",
  supabase: "Supabase",
  firebase: "Firebase",
  stripe: "Stripe",
  llm: "LLM",
  mcp: "MCP",
};

const LLM_PACKAGES = [
  "openai",
  "@anthropic-ai/sdk",
  "ai",
  "@ai-sdk/openai",
  "@ai-sdk/anthropic",
  "@google/generative-ai",
  "@google/genai",
  "@mistralai/mistralai",
  "groq-sdk",
  "langchain",
  "@langchain/core",
  "ollama",
];

/** Works out what the project is built with, so only relevant rules run. */
export function detectStack(project: ProjectFiles): Set<StackFeature> {
  const found = new Set<StackFeature>();
  const deps = new Set<string>();

  for (const file of project.files) {
    if (file === "package.json" || file.endsWith("/package.json")) {
      const pkg = project.json(file) as Record<string, Record<string, string> | undefined> | null;
      if (!pkg) continue;
      for (const key of ["dependencies", "devDependencies", "peerDependencies"]) {
        for (const name of Object.keys(pkg[key] ?? {})) deps.add(name);
      }
    }
  }

  const has = (name: string) => deps.has(name);
  const hasPrefix = (prefix: string) => [...deps].some((d) => d.startsWith(prefix));
  const anyFile = (test: (f: string) => boolean) => project.files.some(test);

  if (has("next") || anyFile((f) => /(^|\/)next\.config\.(js|mjs|cjs|ts)$/.test(f))) found.add("nextjs");
  if (has("react")) found.add("react");
  if (hasPrefix("@supabase/") || anyFile((f) => /(^|\/)supabase\/(migrations\/|config\.toml$)/.test(f))) {
    found.add("supabase");
  }
  if (has("firebase") || has("firebase-admin") || anyFile((f) => /(^|\/)(firebase\.json|firestore\.rules|storage\.rules)$/.test(f))) {
    found.add("firebase");
  }
  if (has("stripe") || hasPrefix("@stripe/")) found.add("stripe");
  if (LLM_PACKAGES.some(has)) found.add("llm");
  if (hasPrefix("@modelcontextprotocol/") || anyFile((f) => /(^|\/)(\.cursor\/mcp\.json|\.mcp\.json|mcp\.json|\.vscode\/mcp\.json)$/.test(f))) {
    found.add("mcp");
  }
  return found;
}
