import type { Node } from "@babel/types";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";
import { MODEL_OUTPUT_RE, analyseTaint, patternNames } from "../taint.js";

/** Tool names and descriptions that promise dangerous powers. */
const DANGEROUS_TOOL_RE =
  /\b(shell|bash|terminal|exec(ute)?_?(command|cmd|code)?|run_?(shell|command|cmd|code|script)|command|delete_?\w*|drop_?\w*|remove_?file|write_?file|rm_?\w*|eval|sql|raw_?query)\b|run a shell|shell command|execute (a )?command/i;
/** Signs that a person or an allow-list stands between the model and the action. */
const GUARD_RE = /\b(allow_?list|allowed(Commands|Tools|Paths)?|ALLOWED_\w+|whitelist|confirm(ation|ed)?|approv(e|al|ed)|requireApproval|needsApproval|human_?in_?the_?loop|askUser)\b/i;

type Sink = { kind: "shell" | "files" | "code"; at: Node };

export const l03DangerousAgentTool: Rule = {
  id: "SW-L03",
  title: "Agent tool with shell, file or code access and no guard",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "When you give a model a tool that runs shell commands, deletes files or executes code, the model decides " +
      "the arguments, and anyone who can influence the model's input can steer it. That includes users, and " +
      "the content of web pages, emails or documents it reads (prompt injection). Dangerous tools need an " +
      "allow-list of what they may do, a human confirmation step, or both.",
    bad: `if (call.function.name === "run_shell") {\n  const { command } = JSON.parse(call.function.arguments);\n  await exec(command);\n}`,
    good:
      `const ALLOWED = new Set(["git status", "npm test"]);\nconst { command } = JSON.parse(call.function.arguments);\n` +
      `if (!ALLOWED.has(command)) throw new Error("Command not allowed");\nawait execFile(...command.split(" "));`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text || !/(tool_calls|function\.arguments|tools\s*[:=]|\btool\s*\(|input_schema|execute\s*:)/.test(text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      if (GUARD_RE.test(text)) continue; // an allow-list or confirmation step somewhere in the file
      const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);

      // Model-chosen arguments: tool_calls / function.arguments, plus the params of AI SDK `execute` functions.
      const executeParams = new Set<string>();
      walkAst(ast, (n) => {
        if (n.type === "ObjectProperty" && n.key.type === "Identifier" && n.key.name === "execute" &&
            (n.value.type === "ArrowFunctionExpression" || n.value.type === "FunctionExpression")) {
          for (const p of n.value.params) for (const x of patternNames(p as Node)) executeParams.add(x);
        }
        if (n.type === "ObjectMethod" && n.key.type === "Identifier" && n.key.name === "execute") {
          for (const p of n.params) for (const x of patternNames(p as Node)) executeParams.add(x);
        }
      });
      const { isTainted } = analyseTaint(ast, text, { source: MODEL_OUTPUT_RE });
      const fromModel = (e: Node) => {
        if (isTainted(e)) return true;
        let hit = false;
        walkAst(e, (x) => {
          if (x.type === "Identifier" && executeParams.has(x.name)) hit = true;
        });
        return hit;
      };

      // Names that stand for exec: const run = promisify(exec), import { exec as sh }.
      const execAliases = new Set(["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "execa", "$"]);
      walkAst(ast, (n) => {
        if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init && /\bpromisify\s*\(\s*(exec|execFile|spawn)\b|^(exec|execSync|spawn)$/.test(src(n.init as Node))) {
          execAliases.add(n.id.name);
        }
        if (n.type === "ImportSpecifier" && n.imported.type === "Identifier" && execAliases.has(n.imported.name)) execAliases.add(n.local.name);
      });

      const sinks: Sink[] = [];
      walkAst(ast, (n) => {
        if (n.type !== "CallExpression") return;
        const c = n.callee;
        const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : "";
        const args = n.arguments as Node[];
        if (!args.some(fromModel)) return;
        if (execAliases.has(name) && (c.type === "Identifier" || /child_process|cp\b|childProcess/.test(src(c as Node)))) sinks.push({ kind: "shell", at: n });
        else if (/^(unlink|unlinkSync|rm|rmSync|rmdir|writeFile|writeFileSync|appendFile|rename)$/.test(name) && /\bfs\b|promises/.test(src(c as Node))) sinks.push({ kind: "files", at: n });
        else if (name === "eval" || name === "Function" || /^runIn(New|This)?Context$/.test(name)) sinks.push({ kind: "code", at: n });
      });

      // Tool definitions with dangerous names, reported where the name is given.
      const defs: Node[] = [];
      walkAst(ast, (n) => {
        if (n.type !== "ObjectProperty" || n.key.type !== "Identifier" || n.key.name !== "name" || n.value.type !== "StringLiteral") return;
        if (DANGEROUS_TOOL_RE.test(n.value.value)) defs.push(n);
      });
      // A dangerous definition alone is reported only when its arguments really reach a sink in this file.
      if (sinks.length === 0) continue;
      const power = sinks[0]!.kind === "shell" ? "run shell commands" : sinks[0]!.kind === "files" ? "change files" : "run code";

      for (const d of defs) {
        const toolName = d.type === "ObjectProperty" && d.value.type === "StringLiteral" ? d.value.value : "tool";
        out.push({
          file,
          ...project.position(file, d.start ?? 0),
          title: `Agent tool "${toolName}" can ${power} with no allow-list or confirmation`,
          why:
            `This tool lets the model ${power} on your server, and the model picks the arguments. Anyone who can ` +
            `influence what the model reads, including through prompt injection, can choose what runs.`,
          fix:
            `Remove the tool if you can. Otherwise limit it to an allow-list of exact commands or paths, run them with ` +
            `\`execFile\` (no shell), require a human to confirm each call, and keep the endpoint behind auth.`,
          fixPrompt:
            `In ${file}, the agent tool "${toolName}" lets the model ${power} with whatever arguments it chooses. Restrict it ` +
            `to an allow-list of specific operations, run commands with execFile and fixed arguments rather than a shell, ` +
            `add a confirmation step before anything destructive, and reject everything else.`,
        });
      }
      for (const s of sinks) {
        out.push({
          file,
          ...project.position(file, s.at.start ?? 0),
          title: `Model-chosen arguments reach ${s.kind === "shell" ? "a shell command" : s.kind === "files" ? "a file operation" : "code execution"}`,
          why:
            `\`${src(s.at).slice(0, 60)}\` runs with arguments the model chose, and nothing checks them against an allow-list ` +
            `or asks a person first. A prompt injection becomes code running on your server.`,
          fix: `Check the arguments against an allow-list before running anything, prefer \`execFile\` with fixed arguments over a shell, and add a confirmation step for anything destructive.`,
          fixPrompt:
            `In ${file}, \`${src(s.at).slice(0, 60)}\` executes arguments chosen by the LLM. Add an allow-list check before it ` +
            `runs, switch to execFile with fixed arguments, and make destructive actions require explicit confirmation.`,
        });
      }
    }
    return out;
  },
};
