import type { Confidence, Severity } from "../../core/finding.js";

/**
 * Secret formats, written from each provider's published token format.
 * Each pattern's first capture group is the secret itself (what gets redacted).
 */
export interface SecretPattern {
  id: string;
  /** Human name, e.g. "Stripe live secret key". */
  name: string;
  re: RegExp;
  severity: Severity;
  confidence: Confidence;
  /** Length of the fixed prefix, excluded from the entropy check. */
  prefixLength?: number;
  /** Minimum Shannon entropy (bits per char) of the random part. Filters placeholders. */
  minEntropy?: number;
  /** What an attacker gets. Finishes the sentence "Anyone who can read this repo can ..." */
  impact: string;
  /** Where to revoke it. */
  rotate: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "private-key",
    name: "Private key",
    re: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)/g,
    severity: "critical",
    confidence: "high",
    impact: "impersonate whatever this key signs for, such as a server, a deploy or an app",
    rotate: "Generate a new key pair and remove this one wherever it is trusted",
  },
  {
    id: "stripe-live-secret",
    name: "Live secret key (Stripe or Clerk)",
    re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 8,
    minEntropy: 3,
    impact: "act as your account: for Stripe, charge cards, issue refunds and read customer data",
    rotate: "Roll the key in the provider's dashboard (Stripe: Developers → API keys)",
  },
  {
    id: "stripe-webhook-secret",
    name: "Stripe webhook signing secret",
    re: /\b(whsec_[0-9a-zA-Z]{24,})\b/g,
    severity: "high",
    confidence: "high",
    prefixLength: 6,
    minEntropy: 3,
    impact: "forge webhook events your app trusts, such as a payment that never happened",
    rotate: "Roll the signing secret for the endpoint in Stripe (Developers → Webhooks)",
  },
  {
    id: "github-token",
    name: "GitHub token",
    re: /\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 4,
    minEntropy: 3,
    impact: "read and possibly write your repositories with the token owner's access",
    rotate: "Revoke it at github.com/settings/tokens (or the app's settings)",
  },
  {
    id: "anthropic-key",
    name: "Anthropic API key",
    re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 14,
    minEntropy: 3,
    impact: "run up usage on your Anthropic account",
    rotate: "Delete the key in the Anthropic Console and create a new one",
  },
  {
    id: "openai-key",
    name: "OpenAI API key",
    re: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 8,
    minEntropy: 3,
    impact: "run up usage on your OpenAI account",
    rotate: "Revoke the key at platform.openai.com/api-keys and create a new one",
  },
  {
    id: "supabase-secret-key",
    name: "Supabase secret key",
    re: /\b(sb_secret_[A-Za-z0-9_-]{20,})/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 10,
    minEntropy: 3,
    impact: "read and change every row in your database, bypassing row-level security",
    rotate: "Revoke it in Supabase (Project Settings → API keys) and create a new one",
  },
  {
    id: "aws-access-key",
    name: "AWS access key ID",
    re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
    severity: "high",
    confidence: "medium",
    prefixLength: 4,
    minEntropy: 2.5,
    impact: "use your AWS account if the matching secret key is also exposed",
    rotate: "Deactivate and delete the key in AWS IAM, then create a new one",
  },
  {
    id: "slack-token",
    name: "Slack token",
    re: /\b(xox[baprs]-[0-9A-Za-z-]{20,})/g,
    severity: "high",
    confidence: "high",
    prefixLength: 5,
    minEntropy: 3,
    impact: "read or post messages in your Slack workspace",
    rotate: "Revoke it in the Slack app's settings (OAuth & Permissions)",
  },
  {
    id: "sendgrid-key",
    name: "SendGrid API key",
    re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    severity: "high",
    confidence: "high",
    prefixLength: 3,
    minEntropy: 3,
    impact: "send email as you, which is useful for phishing your own users",
    rotate: "Delete the key in SendGrid (Settings → API Keys)",
  },
  {
    id: "npm-token",
    name: "npm access token",
    re: /\b(npm_[A-Za-z0-9]{36})\b/g,
    severity: "critical",
    confidence: "high",
    prefixLength: 4,
    minEntropy: 3,
    impact: "publish packages under your name, which is a supply-chain attack on everyone who installs them",
    rotate: "Revoke it at npmjs.com → Access Tokens",
  },
  {
    id: "huggingface-token",
    name: "Hugging Face token",
    re: /\b(hf_[A-Za-z]{34})\b/g,
    severity: "high",
    confidence: "high",
    prefixLength: 3,
    minEntropy: 3,
    impact: "use your Hugging Face account and any private models or datasets",
    rotate: "Revoke it at huggingface.co/settings/tokens",
  },
];

/** JWTs get decoded, not just matched: a Supabase anon key is meant to be public. */
export const JWT_RE = /\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g;

/** `scheme://user:password@host`. Group 1 = whole URL, group 2 = password, group 3 = host. */
export const DB_URL_RE =
  /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:/@'"`]+:([^\s@'"`]+)@([^\s/:'"`?]+)[^\s'"`]*)/g;

/** Google API keys: Firebase web config keys are public by design; others (Gemini) are not. */
export const GOOGLE_KEY_RE = /\b(AIza[0-9A-Za-z_-]{35})\b/g;

const PLACEHOLDER_RE = /x{4,}|X{4,}|example|EXAMPLE|your[_-]?|YOUR[_-]?|placeholder|PLACEHOLDER|dummy|DUMMY|changeme|CHANGEME|<[^>]*>|\$\{|\{\{|\*{4,}|\.{3}/;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Decodes the payload of a JWT without verifying it. Returns null if it is not a JWT. */
export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const part = jwt.split(".")[1];
  if (!part) return null;
  try {
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const v = JSON.parse(json);
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Replaces anything secret-shaped in a line with a masked version. Used by every reporter. */
export function redact(line: string): string {
  const mask = (s: string) => (s.length <= 12 ? "•".repeat(s.length) : s.slice(0, 8) + "•".repeat(8) + s.slice(-2));
  let out = line;
  for (const p of SECRET_PATTERNS) {
    out = out.replace(new RegExp(p.re.source, p.re.flags), (m, g1: string) =>
      p.id === "private-key" ? m : m.replace(g1, mask(g1)),
    );
  }
  out = out.replace(new RegExp(JWT_RE.source, "g"), (m) => m.slice(0, 12) + "•".repeat(8));
  out = out.replace(new RegExp(DB_URL_RE.source, "g"), (m, _u: string, pw: string) => m.replace(":" + pw + "@", ":" + "•".repeat(8) + "@"));
  out = out.replace(new RegExp(GOOGLE_KEY_RE.source, "g"), (m) => mask(m));
  return out;
}
