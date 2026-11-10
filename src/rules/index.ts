import type { Rule } from "./types.js";
import { s01CommittedSecrets } from "./secrets/s01-committed-secrets.js";
import { s02EnvCommitted } from "./secrets/s02-env-committed.js";
import { s03SecretInBrowser } from "./secrets/s03-secret-in-browser.js";
import { s04LlmKeyInClient } from "./secrets/s04-llm-key-in-client.js";
import { d01RlsMissing } from "./supabase/d01-rls-missing.js";
import { d02PolicyAllowsAll } from "./supabase/d02-policy-allows-all.js";
import { d03FirebaseOpen } from "./firebase/d03-firebase-open.js";
import { d04StorageOpen } from "./firebase/d04-storage-open.js";
import { p01WebhookUnverified } from "./payments/p01-webhook-unverified.js";

export const RULES: Rule[] = [s01CommittedSecrets, s02EnvCommitted, s03SecretInBrowser, s04LlmKeyInClient, d01RlsMissing, d02PolicyAllowsAll, d03FirebaseOpen, d04StorageOpen, p01WebhookUnverified];

export function findRule(id: string): Rule | undefined {
  const want = id.trim().toUpperCase();
  return RULES.find((r) => r.id === want);
}
