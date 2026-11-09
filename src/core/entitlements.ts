/**
 * The ONLY place tiers map to features. Everything else asks this file.
 *
 * Free is never blocked or degraded: every check, every free output format and the
 * normal exit code work the same with or without a licence. Paid features add things.
 */

export const TIERS = ["free", "pro", "agency"] as const;
export type Tier = (typeof TIERS)[number];

export type Feature =
  | "html-report" // --format html: a self-contained, Seaworthy-branded report
  | "history" // scan history and trends (.seaworthy/history.json)
  | "compare" // before/after comparison of two scans
  | "white-label" // agency logo, agency name and client name on reports
  | "scan-all"; // scan --all: every project in a folder, one combined report

export interface TierInfo {
  name: string;
  /** Price in whole pounds per year; 0 for Free. */
  pricePerYearGbp: number;
  /** Machines one key can be activated on at once. */
  machines: number;
  features: readonly Feature[];
}

const PRO_FEATURES: readonly Feature[] = ["html-report", "history", "compare"];

export const TIER_INFO: Record<Tier, TierInfo> = {
  free: { name: "Free", pricePerYearGbp: 0, machines: 0, features: [] },
  pro: { name: "Pro", pricePerYearGbp: 99, machines: 2, features: PRO_FEATURES },
  agency: {
    name: "Agency",
    pricePerYearGbp: 349,
    machines: 10,
    features: [...PRO_FEATURES, "white-label", "scan-all"],
  },
};

export const FEATURE_LABELS: Record<Feature, string> = {
  "html-report": "HTML reports",
  history: "Scan history and trends",
  compare: "Before/after comparison",
  "white-label": "White-label reports",
  "scan-all": "Scanning every project in a folder (--all)",
};

export function hasFeature(tier: Tier, feature: Feature): boolean {
  return TIER_INFO[tier].features.includes(feature);
}

/** The cheapest tier that unlocks a feature. */
export function requiredTier(feature: Feature): Exclude<Tier, "free"> {
  return hasFeature("pro", feature) ? "pro" : "agency";
}

export function tierRank(tier: Tier): number {
  return TIERS.indexOf(tier);
}
