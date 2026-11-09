import type { Tier } from "../core/entitlements.js";

/**
 * Where people buy a licence. One constant, because the domain is not registered yet.
 * Change it here and every message, report and doc string follows.
 */
export const PURCHASE_URL = "https://seaworthy.sh/pricing";

/**
 * Polar settings for each server. These IDs are public (they ship in the CLI) and are
 * deliberately NOT overridable from the environment: if they were, anyone could point the
 * CLI at their own Polar organisation and mint themselves an Agency key.
 *
 * The all-zero IDs are placeholders until the Polar organisation and products exist.
 * While they are placeholders, `seaworthy login` explains that licensing is not set up in
 * this build rather than calling Polar.
 */
export interface PolarSettings {
  apiBase: string;
  organizationId: string;
  /** Licence-key benefit ID → tier. One licence-key benefit per tier. */
  benefits: Record<string, Exclude<Tier, "free">>;
}

const PLACEHOLDER = "00000000-0000-0000-0000-000000000000";

export const POLAR_SERVERS: Record<"production" | "sandbox", PolarSettings> = {
  production: {
    apiBase: "https://api.polar.sh",
    organizationId: PLACEHOLDER,
    benefits: {
      // "<pro licence-key benefit id>": "pro",
      // "<agency licence-key benefit id>": "agency",
    },
  },
  sandbox: {
    apiBase: "https://sandbox-api.polar.sh",
    organizationId: PLACEHOLDER,
    benefits: {},
  },
};

/** SEAWORTHY_POLAR_SERVER=sandbox switches to Polar's sandbox, for testing a real purchase flow. */
export function polarSettings(env: NodeJS.ProcessEnv = process.env): PolarSettings {
  return env.SEAWORTHY_POLAR_SERVER === "sandbox" ? POLAR_SERVERS.sandbox : POLAR_SERVERS.production;
}

export function isConfigured(s: PolarSettings): boolean {
  return s.organizationId !== PLACEHOLDER && Object.keys(s.benefits).length > 0;
}

/** How long a successful validation keeps working with no network. */
export const OFFLINE_GRACE_DAYS = 14;
/** How long a successful validation is trusted before checking again online. */
export const REVALIDATE_AFTER_HOURS = 24;
/** Network timeout for licence calls. A slow licence server must never hang a scan. */
export const LICENCE_TIMEOUT_MS = 8000;
