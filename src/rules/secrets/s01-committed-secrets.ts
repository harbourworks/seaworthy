import type { Rule, RawFinding } from "../types.js";
import type { ProjectFiles } from "../../core/project.js";
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
    for (const file of project.files) {
      if (SKIP_FILE_RE.test(file)) continue;
      const text = project.read(file);
      if (!text) continue;
      scanFile(project, file, text, out);
    }
    return out;
  },
};

function scanFile(project: ProjectFiles, file: string, text: string, out: RawFinding[]) {
  const at = (offset: number) => project.position(file, offset);

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
      });
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
    });
  }

  for (const m of text.matchAll(DB_URL_RE)) {
    const [, , password, host] = m as unknown as [string, string, string, string];
    if (LOCAL_HOSTS.has(host.toLowerCase()) || host.endsWith(".local")) continue;
    if (isPlaceholder(password) || password.startsWith("$") || password.length < 6) continue;
    out.push({
      title: "Database password committed",
      severity: "critical",
      confidence: "high",
      file,
      ...at(m.index! + m[0].indexOf(password)),
      why: `This connection string includes the password for the database at ${host}. Anyone who can read this repo can connect to it directly, with no app or row-level security in the way.`,
      fix: "Change the database password now. Then put the connection string in a server-side environment variable.",
      fixPrompt: FIX_PROMPT("database connection string with a password", file),
    });
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
    });
  }
}
