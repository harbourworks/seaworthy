import type { Tier } from "../core/entitlements.js";

/**
 * Where people buy a licence: Polar's hosted checkout, which offers Pro monthly, Pro yearly
 * and Agency. One constant, so when a pricing page exists, changing it here moves every
 * message, report and doc string.
 */
export const PURCHASE_URL = "https://buy.polar.sh/polar_cl_kHaCRzNrtLS4EE3Pm5WcMzQDgJRB6Fsxd5mim4NgS4x";

/**
 * Where customers find their licence key: Polar's customer portal for Dynamo Maritime. They
 * enter the email they bought with, Polar emails a sign-in code, and the key is under the
 * plan's benefits. It also manages machines, invoices and cancelling.
 */
export const PORTAL_URL = "https://polar.sh/dynamo-maritime/portal";

/**
 * Polar settings for each server. These IDs are public (they ship in the CLI) and are
 * deliberately NOT overridable from the environment: if they were, anyone could point the
 * CLI at their own Polar organisation and mint themselves an Agency key.
 *
 * Production holds Dynamo Maritime's real Polar organisation (set up 10 November 2026).
 * The sandbox still has placeholders; while a server has them, `seaworthy login` explains
 * that licensing is not set up rather than calling Polar.
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
    organizationId: "a4a6a28a-20f3-4b1f-9211-7eccab46ff92",
    benefits: {
      // Pro monthly and Pro yearly share this licence-key benefit (2 activations).
      "298917da-ddc9-4565-a713-2ea855db464f": "pro",
      // Agency (10 activations).
      "c23b4b3d-8dcf-4ec3-a4b1-aefd5f810ea7": "agency",
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
