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
import { b01SecurityHeaders } from "./browser/b01-security-headers.js";
import { a05SqlInjection } from "./injection/a05-sql-injection.js";
import { l01PromptInjection } from "./llm/l01-prompt-injection.js";
import { l02ModelOutputSink } from "./llm/l02-model-output-sink.js";

export const RULES: Rule[] = [s01CommittedSecrets, s02EnvCommitted, s03SecretInBrowser, s04LlmKeyInClient, d01RlsMissing, d02PolicyAllowsAll, d03FirebaseOpen, d04StorageOpen, p01WebhookUnverified, a05SqlInjection, l01PromptInjection, l02ModelOutputSink, b01SecurityHeaders];

export function findRule(id: string): Rule | undefined {
  const want = id.trim().toUpperCase();
  return RULES.find((r) => r.id === want);
}
