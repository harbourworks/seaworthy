import type { RawFinding, Rule } from "../types.js";
import { EXPOSED_SCHEMAS, replayMigrations } from "./migrations.js";

export const d01RlsMissing: Rule = {
  id: "SW-D01",
  title: "Table without row-level security",
  severity: "critical",
  confidence: "high",
  appliesTo: ["supabase"],
  docs: {
    summary:
      "Supabase serves every table in the public schema through its Data API, and the anon key " +
      "that calls it ships in your frontend. Without row-level security, anyone can read and " +
      "change the whole table with that key. Turning RLS on with no policies blocks all API " +
      "access until you add policies.",
    bad: `create table public.payments (id uuid primary key, user_id uuid, amount int);`,
    good:
      `create table public.payments (id uuid primary key, user_id uuid, amount int);\n` +
      `alter table public.payments enable row level security;\n` +
      `create policy "Users read own payments" on public.payments\n` +
      `  for select using (auth.uid() = user_id);`,
  },

  check({ project }) {
    const { tables } = replayMigrations(project);
    const out: RawFinding[] = [];
    for (const t of tables.values()) {
      if (t.rlsEnabled || t.temporary || t.apiRevoked || !EXPOSED_SCHEMAS.has(t.schema)) continue;
      const qualified = `${t.schema}.${t.name}`;
      if (t.rlsDynamic) {
        const where = `${t.rlsDynamic.file}:${project.position(t.rlsDynamic.file, t.rlsDynamic.offset).line}`;
        out.push({
          title: `Table ${qualified} may not have row-level security`,
          confidence: "low",
          file: t.file,
          ...project.position(t.file, t.offset),
          why:
            `${qualified} is created without row-level security, and Supabase exposes it through the Data API. ` +
            `The \`execute\` in a DO block at ${where} runs SQL that Seaworthy can't work out in advance (for example ` +
            `table names held in a variable or looked up when it runs), so it may enable row-level security on ${qualified}. ` +
            `If it doesn't, anyone with your public anon key can read, edit and delete every row.`,
          fix:
            `Check that the \`execute\` at ${where} enables row-level security on ${qualified}. If it doesn't, add a ` +
            `migration with \`alter table ${qualified} enable row level security;\` and policies for the access you want.`,
          fixPrompt:
            `In my Supabase migrations, the table ${qualified} is created without row-level security, and the \`execute\` in a DO block ` +
            `at ${where} may or may not enable it. Check whether it enables row-level security on ${qualified}. ` +
            `If it doesn't, write a new migration that runs \`alter table ${qualified} enable row level security;\` and adds ` +
            `policies so each user can only select, insert, update and delete their own rows. Don't edit existing migrations.`,
        });
        continue;
      }
      out.push({
        title: `Table ${qualified} has no row-level security`,
        file: t.file,
        ...project.position(t.file, t.offset),
        why:
          `${qualified} is created without row-level security, and Supabase exposes it through the Data API. ` +
          `Anyone with your public anon key, which is in your frontend bundle, can read, edit and delete every row.`,
        fix:
          `Add a migration with \`alter table ${qualified} enable row level security;\`, then add policies ` +
          `for the access you actually want, such as \`using (auth.uid() = user_id)\`.`,
        fixPrompt:
          `In my Supabase migrations, the table ${qualified} is created without row-level security. ` +
          `Write a new migration that runs \`alter table ${qualified} enable row level security;\` and adds ` +
          `policies so each user can only select, insert, update and delete their own rows. Don't edit existing migrations.`,
      });
    }
    return out;
  },
};
