import type { RawFinding, Rule } from "../types.js";
import { judge } from "./d03-firebase-open.js";
import { rulesFiles } from "./files.js";
import { accessOf, coversEverything, openness, parseRules } from "./rules-parser.js";
import { bucketSensitivity, publicBuckets } from "../supabase/buckets.js";

const STORAGE_ROOT = /^\/b\/\{\w+\}\/o/;

/**
 * Two halves: Cloud Storage for Firebase rules, and Supabase buckets marked public. A public
 * Supabase bucket is fine for avatars and product images, so the bucket's name decides how
 * sure the finding is.
 */
export const d04StorageOpen: Rule = {
  id: "SW-D04",
  title: "Storage open to everyone",
  severity: "high",
  confidence: "high",
  appliesTo: ["firebase", "supabase"],
  docs: {
    summary:
      "Storage rules decide who can upload, download and delete files. With no condition, `if true` " +
      "or test-mode rules, anyone can download every file (ID scans, invoices, private photos), " +
      "overwrite them, or fill your bucket and your bill. Rules should tie files to the user who owns them. " +
      "In Supabase, a bucket marked public serves every file to anyone with its URL, with no login at all: " +
      "right for avatars, wrong for invoices or documents.",
    bad: `match /{allPaths=**} {\n  allow read, write;\n}`,
    good:
      `match /users/{userId}/{allPaths=**} {\n` +
      `  allow read, write: if request.auth != null && request.auth.uid == userId;\n}`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of rulesFiles(project, "storage")) {
      const text = project.read(file);
      if (!text) continue;
      const parsed = parseRules(text);
      if (parsed.service && parsed.service !== "firebase.storage") continue;
      for (const a of parsed.allows) {
        const o = openness(a.condition);
        if (!o) continue;
        const access = accessOf(a.methods);
        const everything = coversEverything(a.path, STORAGE_ROOT);
        const v = judge(o, access, everything);
        if (!v) continue;
        const scope = everything ? "every file" : `files at ${a.path.replace(STORAGE_ROOT, "") || "/"}`;
        const verbs = access.reads && access.writes ? "download, upload and delete" : access.writes ? "upload and delete" : "download";
        out.push({
          file,
          ...project.position(file, a.offset),
          // Writes open to anyone are the worst case here too.
          severity: access.writes && o.kind !== "signed-in" ? "critical" : "high",
          confidence: v.confidence,
          title: `Storage rules let ${v.who} ${verbs} ${scope}`,
          why:
            `This rule lets ${v.who} ${verbs} ${scope} in your bucket, straight from the browser.` +
            (access.writes ? ` Anyone with write access can also replace your files or fill the bucket at your expense.` : ``) +
            (o.kind === "signed-in" ? ` Anyone can create an account, so this is close to everyone.` : ``),
          fix:
            `Keep each user's files under a path with their ID and check it: ` +
            `\`match /users/{userId}/{allPaths=**} { allow read, write: if request.auth != null && request.auth.uid == userId; }\`. ` +
            `Limit uploads with \`request.resource.size\` and \`request.resource.contentType\`.`,
          fixPrompt:
            `My ${file} has \`allow ${a.methods.join(", ")}${a.condition ? `: if ${a.condition}` : ""};\` on ${scope}. ` +
            `Rewrite the Cloud Storage rules so each user can only read and write files under users/{their uid}/, ` +
            `uploads are limited in size and type, and everything else is denied. Update my upload code to use that path.`,
        });
      }
    }
    out.push(...supabaseBuckets(project));
    return out;
  },
};

function supabaseBuckets(project: Parameters<Rule["check"]>[0]["project"]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const b of publicBuckets(project)) {
    const kind = bucketSensitivity(b.id);
    if (kind === "public") continue;
    const where = b.source === "config" ? "in supabase/config.toml" : b.source === "code" ? "in code" : "in SQL";
    out.push({
      file: b.file,
      ...project.position(b.file, b.offset),
      ...(kind === "unknown" ? { severity: "medium" as const, confidence: "medium" as const } : {}),
      title: `Supabase storage bucket "${b.id}" is public`,
      why:
        `The bucket "${b.id}" is made public ${where}. A public bucket serves every file to anyone who has its URL, with no login ` +
        `and no row-level security, and file URLs get shared, logged and guessed.` +
        (kind === "sensitive"
          ? ` Its name suggests private files, such as documents, invoices or ID scans.`
          : ` That's fine if it only holds public files such as images; not if users upload anything private to it.`),
      fix:
        `Make the bucket private (\`update storage.buckets set public = false where id = '${b.id}';\`, or \`public = false\` in config.toml), ` +
        `store each user's files under their ID (\`${b.id}/<user_id>/...\`), add storage.objects policies that check \`(storage.foldername(name))[1] = auth.uid()::text\`, ` +
        `and serve files with \`createSignedUrl()\` and a short expiry.`,
      fixPrompt:
        `My Supabase storage bucket "${b.id}" is public. Make it private, store each user's files under a folder named with their user ID, ` +
        `add storage.objects policies so users can only read and upload their own files, and change the code that shows these files to use short-lived signed URLs.`,
    });
  }
  return out;
}
