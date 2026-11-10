import type { Confidence, Severity } from "../../core/finding.js";
import type { ProjectFiles } from "../../core/project.js";
import type { RawFinding, Rule } from "../types.js";
import { rulesFiles } from "./files.js";
import { accessOf, coversEverything, openness, parseRules, type Openness } from "./rules-parser.js";

const FIRESTORE_ROOT = /^\/databases\/\{\w+\}\/documents/;

export const d03FirebaseOpen: Rule = {
  id: "SW-D03",
  title: "Firebase database rules open to everyone",
  severity: "critical",
  confidence: "high",
  appliesTo: ["firebase"],
  docs: {
    summary:
      "Firebase apps talk to Firestore and the Realtime Database straight from the browser, so the " +
      "security rules are the only thing between your data and anyone with your (public) Firebase " +
      "config. `if true`, no condition, or Firebase's test-mode date check lets anyone read, change " +
      "and delete everything. Checking only `request.auth != null` is nearly as open, because anyone " +
      "can create an account. Rules should compare the data with the user, such as " +
      "`request.auth.uid == userId`.",
    bad: `match /{document=**} {\n  allow read, write: if true;\n}`,
    good:
      `match /notes/{noteId} {\n  allow read, update, delete: if request.auth != null && request.auth.uid == resource.data.ownerId;\n` +
      `  allow create: if request.auth != null && request.auth.uid == request.resource.data.ownerId;\n}`,
  },

  check({ project }) {
    return [...checkFirestore(project), ...checkRealtimeDatabase(project)];
  },
};

interface Verdict {
  severity: Severity;
  confidence: Confidence;
  who: string;
}

/** How bad an open rule is, given who it lets in, what it allows and how much it covers. */
export function judge(o: Openness, access: { reads: boolean; writes: boolean }, everything: boolean): Verdict | null {
  if (o.kind === "until" && o.date.getTime() <= Date.now()) return null; // expired test mode denies everyone
  const who =
    o.kind === "signed-in"
      ? "any signed-in user"
      : o.kind === "until"
        ? `anyone, until ${o.date.toISOString().slice(0, 10)}`
        : "anyone";
  if (o.kind === "signed-in") {
    if (everything) return { severity: "high", confidence: "high", who };
    // A signed-in user reading one shared collection is often by design.
    if (!access.writes) return null;
    return { severity: "high", confidence: "medium", who };
  }
  if (access.writes) return { severity: "critical", confidence: "high", who };
  // A public read of one collection (blog posts, products) is often by design.
  return { severity: "high", confidence: everything ? "high" : "medium", who };
}

function verbs(access: { reads: boolean; writes: boolean }): string {
  return access.reads && access.writes ? "read and write" : access.writes ? "write" : "read";
}

function checkFirestore(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const file of rulesFiles(project, "firestore")) {
    const text = project.read(file);
    if (!text) continue;
    const parsed = parseRules(text);
    if (parsed.service && parsed.service !== "cloud.firestore") continue;
    for (const a of parsed.allows) {
      const o = openness(a.condition);
      if (!o) continue;
      const access = accessOf(a.methods);
      const everything = coversEverything(a.path, FIRESTORE_ROOT);
      const v = judge(o, access, everything);
      if (!v) continue;
      const scope = everything ? "every document" : `documents at ${a.path.replace(FIRESTORE_ROOT, "") || "/"}`;
      const testMode = o.kind === "until";
      out.push({
        file,
        ...project.position(file, a.offset),
        severity: v.severity,
        confidence: v.confidence,
        title: testMode
          ? `Firestore is in test mode: ${scope} open to anyone until ${o.date.toISOString().slice(0, 10)}`
          : `Firestore rules let ${v.who} ${verbs(access)} ${scope}`,
        why:
          `This rule lets ${v.who} ${verbs(access)} ${scope}. Your Firebase config is in your frontend, so ` +
          `that means straight from their own browser or a script, with no app in the way.` +
          (o.kind === "signed-in" ? ` Anyone can create an account, so this is close to everyone.` : ``) +
          (testMode ? ` Test-mode rules are meant for the first days of development and then get forgotten.` : ``),
        fix:
          `Replace it with rules per collection that check the user owns the data, such as ` +
          `\`allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;\`. ` +
          `Test them in the Firebase emulator or the Rules Playground before deploying.`,
        fixPrompt:
          `My ${file} has \`allow ${a.methods.join(", ")}${a.condition ? `: if ${a.condition}` : ""};\` on ${scope}, which lets ` +
          `${v.who} ${verbs(access)} it. Rewrite the Firestore rules with a match block for each collection my app uses, ` +
          `so users can only read and write their own documents (compare request.auth.uid with an owner field), ` +
          `and deny everything else by default.`,
      });
    }
  }
  return out;
}

/** Realtime Database rules: JSON with ".read" and ".write" at any depth. */
function checkRealtimeDatabase(project: ProjectFiles): RawFinding[] {
  const out: RawFinding[] = [];
  for (const file of rulesFiles(project, "database")) {
    const text = project.read(file);
    if (!text) continue;
    let json: unknown;
    try {
      // The Realtime Database accepts comments in rules files.
      json = JSON.parse(text.replace(/\/\*[\s\S]*?\*\/|(^|[^:"\\])\/\/[^\n]*/g, "$1"));
    } catch {
      continue;
    }
    const rules = (json as { rules?: unknown })?.rules;
    if (!rules || typeof rules !== "object") continue;

    const visit = (node: Record<string, unknown>, path: string[]) => {
      for (const key of [".read", ".write"] as const) {
        const val = node[key];
        // Realtime Database rules say `auth`, where Firestore says `request.auth`.
        const cond = val === true ? "true" : typeof val === "string" ? val.replace(/\bauth\b/g, "request.auth") : null;
        const o = cond !== null ? openness(cond) : null;
        if (!o) continue;
        const access = { reads: key === ".read", writes: key === ".write" };
        const v = judge(o, access, path.length === 0);
        if (v) {
          const scope = path.length === 0 ? "the whole database" : `/${path.join("/")}`;
          out.push({
            file,
            ...project.position(file, locate(text, path, key)),
            severity: v.severity,
            confidence: v.confidence,
            title: `Realtime Database rules let ${v.who} ${verbs(access)} ${scope}`,
            why:
              `These rules let ${v.who} ${verbs(access)} ${scope}, straight from the browser.` +
              (o.kind === "signed-in" ? ` Anyone can create an account, so this is close to everyone.` : ``),
            fix:
              `Give each path rules that check the user, such as \`".write": "auth != null && auth.uid === $uid"\` ` +
              `under \`"users": { "$uid": { … } }\`.`,
            fixPrompt:
              `My ${file} lets ${v.who} ${verbs(access)} ${scope}. Rewrite the Realtime Database rules so users can ` +
              `only read and write their own data (compare auth.uid with the path's $uid), and deny everything else.`,
          });
        }
      }
      for (const [k, child] of Object.entries(node)) {
        if (!k.startsWith(".") && child && typeof child === "object") visit(child as Record<string, unknown>, [...path, k]);
      }
    };
    visit(rules as Record<string, unknown>, []);
  }
  return out;
}

/** Offset of `"key"` under the given path, found by walking the keys in order. */
function locate(text: string, path: string[], key: string): number {
  let at = text.indexOf('"rules"');
  for (const p of path) {
    const i = text.indexOf(JSON.stringify(p), at < 0 ? 0 : at);
    if (i >= 0) at = i;
  }
  const k = text.indexOf(`"${key}"`, at < 0 ? 0 : at);
  return k >= 0 ? k : Math.max(at, 0);
}
