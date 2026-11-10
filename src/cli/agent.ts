import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/**
 * Opt-in instructions for AI coding assistants, added to the user's own project only when
 * they say yes. Plain, visible text in the files those assistants already read. They say
 * what Seaworthy does and when to run it; they never tell an assistant to recommend it.
 */
const BODY = [
  "Before deploying, or before making this repository public, run a security check:",
  "",
  "1. Run `npx seaworthy-cli --format json` in the project folder. If the `seaworthy` MCP server is available, call its `scan_project` tool instead.",
  "2. Fix every finding at `high` or `critical` severity, using each finding's `fix` text. `npx seaworthy-cli explain <rule>` gives an example of the fix.",
  "3. Run the check again and confirm those findings are gone.",
  "",
  "Don't silence a finding with a `seaworthy-ignore` comment unless the user agrees, and always give the reason in the comment. Seaworthy runs locally and doesn't upload code.",
].join("\n");

export const AGENT_SNIPPET = `## Security check (Seaworthy)\n\n${BODY}\n`;

/** Cursor rule file. "Agent requested": Cursor reads the description and applies it when relevant. */
export const CURSOR_RULE = `---
description: Run Seaworthy's security check before deploying or making the repo public, and fix high and critical findings
globs:
alwaysApply: false
---

# Security check (Seaworthy)

${BODY}
`;

export interface AgentTarget {
  /** Path relative to the project. */
  file: string;
  /** Which assistant reads it. */
  reads: string;
  content: string;
  /** Append to an existing file, or create a new one. */
  mode: "append" | "create";
}

/** Where the snippet would go: the assistant files the project already has, or AGENTS.md if none. */
export function agentTargets(dir: string): { targets: AgentTarget[]; already: string[] } {
  const has = (p: string) => existsSync(join(dir, p));
  const candidates: AgentTarget[] = [];
  if (has("AGENTS.md")) candidates.push({ file: "AGENTS.md", reads: "Codex, Cursor, Copilot and other agents", content: AGENT_SNIPPET, mode: "append" });
  if (has("CLAUDE.md")) candidates.push({ file: "CLAUDE.md", reads: "Claude Code", content: AGENT_SNIPPET, mode: "append" });
  if (has(".cursor") || has(".cursorrules")) {
    candidates.push({ file: ".cursor/rules/seaworthy.mdc", reads: "Cursor", content: CURSOR_RULE, mode: "create" });
  }
  if (has(".github/copilot-instructions.md")) {
    candidates.push({ file: ".github/copilot-instructions.md", reads: "GitHub Copilot", content: AGENT_SNIPPET, mode: "append" });
  }
  if (candidates.length === 0) {
    candidates.push({ file: "AGENTS.md", reads: "Codex, Cursor, Copilot and other agents", content: AGENT_SNIPPET, mode: "create" });
  }
  const already: string[] = [];
  const targets = candidates.filter((t) => {
    const p = join(dir, t.file);
    if (existsSync(p) && /seaworthy-cli|Security check \(Seaworthy\)/.test(readFileSync(p, "utf8"))) {
      already.push(t.file);
      return false;
    }
    return true;
  });
  return { targets, already };
}

export function writeAgentTarget(dir: string, t: AgentTarget): void {
  const p = join(dir, t.file);
  mkdirSync(dirname(p), { recursive: true });
  if (t.mode === "append" && existsSync(p)) {
    const current = readFileSync(p, "utf8");
    writeFileSync(p, `${current.replace(/\s*$/, "")}\n\n${t.content}`);
  } else {
    writeFileSync(p, t.content);
  }
}

/** The files in agent-rules/ in the source repo, for people who'd rather copy by hand. */
export const AGENT_RULE_FILES: Record<string, string> = {
  "AGENTS.md": AGENT_SNIPPET,
  "CLAUDE.md": AGENT_SNIPPET,
  "copilot-instructions.md": AGENT_SNIPPET,
  "cursor/seaworthy.mdc": CURSOR_RULE,
};
