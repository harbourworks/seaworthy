import { existsSync, statSync } from "node:fs";
import { join } from "node:path";
import ignore from "ignore";
import type { RawFinding, Rule } from "../types.js";
import { envFiles, parseEnv, publicPrefix } from "./env.js";

export const s02EnvCommitted: Rule = {
  id: "SW-S02",
  title: ".env file committed or not git-ignored",
  severity: "high",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      ".env files hold the keys your app runs on. If one is committed, everyone who can see the " +
      "repo, its forks and its history has those keys, and removing the file later does not take " +
      "them out of history. AI tools often create .env files without adding them to .gitignore. " +
      "Keep real values in .env files that git ignores, and commit a .env.example with the names only.",
    bad: `# .gitignore\nnode_modules\n.next`,
    good: `# .gitignore\nnode_modules\n.next\n.env*\n!.env.example`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    const exposed: string[] = [];

    for (const env of envFiles(project)) {
      if (!env.tracked && !env.unignored) continue; // ignored and never committed: fine
      const text = project.read(env.path);
      if (text === null) continue;
      const vars = parseEnv(text).filter((v) => v.value.length > 0);
      if (vars.length === 0) continue; // empty or names only: nothing to leak yet
      const secretLike = vars.filter((v) => !publicPrefix(v.name));
      if (env.unignored) exposed.push(env.path);

      const state = env.tracked
        ? env.unignored
          ? "is committed to git"
          : "is still committed to git, although .gitignore now lists it"
        : "is not git-ignored, so the next commit will include it";
      const holds =
        secretLike.length > 0
          ? `It sets ${count(secretLike.length, "variable")} without a public prefix, such as ${secretLike[0]!.name}, which are usually secrets.`
          : `Every value in it is public today, but the next secret added to it will be committed too.`;
      const untrack = env.tracked ? `Run \`git rm --cached ${env.path}\` and commit, then ` : "";
      out.push({
        file: env.path,
        line: 1,
        column: 1,
        title: `${env.path} ${env.tracked ? "is committed" : "is not git-ignored"}`,
        confidence: secretLike.length > 0 ? "high" : "medium",
        why:
          `${env.path} ${state}. ${holds}` +
          (env.tracked ? ` Anyone who can read the repo or its history can read the file.` : ``),
        fix:
          `${untrack}${env.tracked ? "add" : "Add"} \`.env*\` and \`!.env.example\` to .gitignore. ` +
          (env.tracked ? `The values are in git history, so rotate every secret the file holds.` : ``),
        fixPrompt:
          `My project's ${env.path} ${state}. Update .gitignore so all .env files are ignored except .env.example, ` +
          (env.tracked ? `tell me the git command to stop tracking ${env.path} without deleting it, ` : ``) +
          `and create a .env.example listing the same variable names with empty values.`,
      });
    }

    // The root .gitignore is where the missing rule belongs.
    const gitignore = ".gitignore";
    if (existsSync(join(project.root, gitignore))) {
      const ig = ignore().add(project.read(gitignore) ?? "");
      // With no .env file yet, only `.env` itself is worth advice, and not when the name is
      // taken by a folder (a Python virtualenv).
      const envIsFolder = existsSync(join(project.root, ".env")) && statSync(join(project.root, ".env")).isDirectory();
      const uncovered = exposed.length > 0 ? exposed : envIsFolder || ig.ignores(".env") ? [] : [".env"];
      if (uncovered.length > 0) {
        out.push({
          file: gitignore,
          line: 1,
          column: 1,
          title: `.gitignore does not cover ${uncovered[0]}`,
          // With no .env file yet, this is advice for later, not a leak.
          confidence: exposed.length > 0 ? "high" : "medium",
          why:
            exposed.length > 0
              ? `Nothing in your .gitignore files matches ${list(uncovered)}, so git will commit ${uncovered.length > 1 ? "them" : "it"}.`
              : `.gitignore doesn't list .env files. There isn't one yet, but the first one created will be committed.`,
          fix: `Add these two lines to .gitignore: \`.env*\` and \`!.env.example\`.`,
          fixPrompt: `Add rules to my .gitignore so every .env file is ignored except .env.example.`,
        });
      }
    }
    return out;
  },
};

function count(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

function list(items: string[]): string {
  return items.length <= 1 ? (items[0] ?? "") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
}
