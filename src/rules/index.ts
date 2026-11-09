import type { Rule } from "./types.js";
import { s01CommittedSecrets } from "./secrets/s01-committed-secrets.js";
import { d01RlsMissing } from "./supabase/d01-rls-missing.js";

export const RULES: Rule[] = [s01CommittedSecrets, d01RlsMissing];

export function findRule(id: string): Rule | undefined {
  const want = id.trim().toUpperCase();
  return RULES.find((r) => r.id === want);
}
