import type { Rule, RawFinding } from "../types.js";
import type { ProjectFiles } from "../../core/project.js";
import { commitAdding, headBlobs, historyBlobs, isRepoTop, readBlobs } from "../../core/git.js";
import {
  DB_URL_RE,
  GOOGLE_KEY_RE,
  JWT_RE,
  SECRET_PATTERNS,
  decodeJwtPayload,
  isPlaceholder,
  shannonEntropy,
} from "./patterns.js";

/** Files that hold hashes and URLs that look like secrets but are not. */
const SKIP_FILE_RE =
  /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|composer\.lock|go\.sum)$|\.(min\.js|map|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|pdf|zip)$/i;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal", "db", "postgres", "mysql", "redis", "mongo", "database"]);

/** "a" or "an", by sound: an AWS key, an npm token, a Stripe key. */
const article = (name: string) => (/^(AWS|npm|[AEIO])/.test(name) ? "an" : "a");

const FIX_PROMPT = (what: string, file: string) =>
  `In ${file}, ${article(what)} ${what} is written directly into the code. Move it into an environment ` +
  `variable that is only read on the server (no NEXT_PUBLIC_ or VITE_ prefix), make sure .env ` +
  `files are in .gitignore, and update the code to read it from process.env. Do not print the ` +
  `key's value anywhere.`;

export const s01CommittedSecrets: Rule = {
  id: "SW-S01",
  title: "Secret committed to the repo",
  severity: "critical",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "API keys, tokens and passwords written into files that get committed. Anyone with access " +
      "to the repo, its forks or its history can use them, and bots scrape public repos for keys " +
      "within minutes of a push. Deleting the line is not enough: the key stays in git history, " +
      "so it has to be rotated.",
    bad: `const stripe = new Stripe("sk_live_…");`,
    good: `const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!); // set in your host's env settings`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    const current = new Set<string>();
    for (const file of project.files) {
      if (SKIP_FILE_RE.test(file)) continue;
      const text = project.read(file);
      if (!text) continue;
      for (const hit of scanText(file, text, (o) => project.position(file, o))) {
        out.push(hit.finding);
        current.add(hit.value);
      }
    }
    out.push(...historyFindings(project, current));
    return out;
  },
};

/** Limits that keep a history scan fast on big repositories. Newest versions come first. */
const HISTORY_MAX_BLOBS = 20_000;
const HISTORY_MAX_BYTES = 200 * 1024 * 1024;
const HISTORY_MAX_FINDINGS = 50;

/**
 * Secrets in earlier versions of files: committed, then deleted or changed, but still in
 * the repository's history for anyone with a copy. Only when scanning a repository's top
 * folder, and never for a secret that is still in the current files (that's reported above).
 */
function historyFindings(project: ProjectFiles, current: Set<string>): RawFinding[] {
  if (!isRepoTop(project.root)) return [];
  const all = historyBlobs(project.root);
  if (!all) return [];
  const head = headBlobs(project.root);
  const blobs = [];
  let bytes = 0;
  for (const b of all) {
    if (head.has(b.object) || b.size > 1_000_000 || SKIP_FILE_RE.test(b.path) || project.isExcluded(b.path)) continue;
    if (blobs.length >= HISTORY_MAX_BLOBS || bytes + b.size > HISTORY_MAX_BYTES) break;
    bytes += b.size;
    blobs.push(b);
  }
  if (blobs.length === 0) return [];
  const contents = readBlobs(project.root, blobs);

  const seen = new Set<string>(current);
  const out: RawFinding[] = [];
  for (const b of blobs) {
    const buf = contents.get(b.object);
    if (!buf || buf.includes(0)) continue; // binary
    const text = buf.toString("utf8");
    const at = lineCol(text);
    for (const hit of scanText(b.path, text, at)) {
      if (seen.has(hit.value)) continue;
      seen.add(hit.value);
      const added = commitAdding(project.root, b.object);
      if (!added) continue;
      const f = hit.finding;
      out.push({
        ...f,
        title: (f.title ?? "Secret committed").replace(/ committed$/, " in git history"),
        commit: added.commit,
        why:
          `${f.why.replace(/^This file contains/, "An earlier version of this file contained")} It was committed in ${added.commit} (${added.date}) ` +
          `and is no longer in the files, but it's still in the repository's history, so anyone with a copy of the repo can read it.`,
        fix:
          `${rotateStep(f.fix)}. Removing the file doesn't remove it from history. Rewriting history (git filter-repo) ` +
          `only helps if nobody has cloned or forked the repo yet; rotating is what makes it safe.`,
        fixPrompt: undefined,
      });
      if (out.length >= HISTORY_MAX_FINDINGS) return out;
    }
  }
  return out;
}

/** The "rotate it" step from a current-file fix, without the parts about moving it out of the file. */
function rotateStep(fix: string): string {
  const i = fix.indexOf(": it has already been exposed");
  return (i >= 0 ? fix.slice(0, i) : fix.split(/\. /)[0]!).replace(/\.$/, "");
}

/** Offset to 1-based line and column, for text that isn't a current project file. */
function lineCol(text: string): (offset: number) => { line: number; column: number } {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo]! + 1 };
  };
}

/** Every secret in one text: the finding, plus the secret's value (used only to avoid reporting it twice). */
function scanText(file: string, text: string, at: (offset: number) => { line: number; column: number }): Array<{ finding: RawFinding; value: string }> {
  const found: Array<{ finding: RawFinding; value: string }> = [];
  const out = { push: (finding: RawFinding, value: string) => found.push({ finding, value }) };

  for (const p of SECRET_PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      const secret = m[1]!;
      if (isPlaceholder(secret)) continue;
      if (p.minEntropy && shannonEntropy(secret.slice(p.prefixLength ?? 0)) < p.minEntropy) continue;

      let name = p.name;
      if (p.id === "stripe-live-secret" && (/^(sk|rk)_live_5\d/.test(secret) || /stripe/i.test(text))) {
        name = secret.startsWith("rk_") ? "Stripe live restricted key" : "Stripe live secret key";
      }
      let confidence = p.confidence;
      if (p.id === "aws-access-key" && /aws_secret_access_key|secretAccessKey|[A-Za-z0-9/+]{40}/.test(text)) {
        confidence = "high";
      }

      out.push({
        title: `${name} committed`,
        severity: p.severity,
        confidence,
        file,
        ...at(m.index! + m[0].indexOf(secret)),
        why: `This file contains ${article(name)} ${name}. Anyone who can read this repo can ${p.impact}.`,
        fix: `${p.rotate}: it has already been exposed. Then load it from a server-side environment variable instead of the file.`,
        fixPrompt: FIX_PROMPT(name, file),
      }, secret);
    }
  }

  for (const m of text.matchAll(JWT_RE)) {
    const jwt = m[1]!;
    const payload = decodeJwtPayload(jwt);
    if (!payload) continue;
    const role = payload.role;
    if (role === "anon") continue; // Supabase anon keys are public by design; RLS protects the data.
    const isServiceRole = role === "service_role";
    if (!isServiceRole && isPlaceholder(jwt)) continue;

    out.push({
      title: isServiceRole ? "Supabase service-role key committed" : "JWT committed",
      severity: isServiceRole ? "critical" : "medium",
      confidence: isServiceRole ? "high" : "medium",
      file,
      ...at(m.index!),
      why: isServiceRole
        ? "This is a Supabase service-role key: it bypasses row-level security entirely. Anyone who can read this repo can read and change every row in your database."
        : "This file contains a signed token (JWT). If it is long-lived or grants access to an API, anyone who can read this repo can use it.",
      fix: isServiceRole
        ? "Roll the JWT secret / service-role key in Supabase (Project Settings → API). Use the service-role key only in server code, from an environment variable."
        : "Check what the token grants. If it is a real credential, revoke it and load it from an environment variable.",
      fixPrompt: FIX_PROMPT(isServiceRole ? "Supabase service-role key" : "JWT", file),
    }, jwt);
  }

  for (const m of text.matchAll(DB_URL_RE)) {
    const [, , password, host] = m as unknown as [string, string, string, string];
    if (LOCAL_HOSTS.has(host.toLowerCase()) || host.endsWith(".local")) continue;
    if (isPlaceholder(password) || password.startsWith("$") || password.length < 6) continue;
    out.push({
      title: "Database password committed",
      severity: "critical",
      // A host with no dots is a Docker or internal service name, usually a development default.
      confidence: host.includes(".") ? "high" : "medium",
      file,
      ...at(m.index! + m[0].indexOf(password)),
      why: `This connection string includes the password for the database at ${host}. Anyone who can read this repo can connect to it directly, with no app or row-level security in the way.`,
      fix: "Change the database password now. Then put the connection string in a server-side environment variable.",
      fixPrompt: FIX_PROMPT("database connection string with a password", file),
    }, password);
  }

  for (const m of text.matchAll(GOOGLE_KEY_RE)) {
    const around = text.slice(Math.max(0, m.index! - 400), m.index! + 400);
    if (/authDomain|projectId|messagingSenderId|firebase/i.test(around)) continue; // Firebase web config: public.
    if (shannonEntropy(m[1]!.slice(4)) < 3) continue;
    out.push({
      title: "Google API key committed",
      severity: "high",
      confidence: "medium",
      file,
      ...at(m.index!),
      why: "This is a Google API key that is not part of a Firebase web config. If it is unrestricted or for a paid API such as Gemini, anyone who can read this repo can run up charges on it.",
      fix: "In Google Cloud Console, restrict the key to the APIs and origins it needs, or delete it and load a new one from a server-side environment variable.",
      fixPrompt: FIX_PROMPT("Google API key", file),
    }, m[1]!);
  }
  return found;
}
