import { hostname } from "node:os";
import type { Tier } from "../core/entitlements.js";
import { OFFLINE_GRACE_DAYS, PORTAL_URL, PURCHASE_URL, REVALIDATE_AFTER_HOURS } from "./config.js";
import type { FailureReason, LicenceProvider } from "./provider.js";
import type { LicenceRecord, LicenceStore } from "./store.js";

const DAY = 86_400_000;
const HOUR = 3_600_000;

export type LicenceState =
  /** No licence on this machine: Free. */
  | "none"
  /** Confirmed by the licence server recently. */
  | "active"
  /** Server unreachable, but confirmed within the last 14 days, so the paid tier still works. */
  | "grace"
  /** Server unreachable for more than 14 days: back to Free until it can check. */
  | "lapsed"
  /** The server says the key is no longer good. */
  | "ended"
  /** Licensing not available in this build. */
  | "not-configured";

export interface LicenceStatus {
  /** The tier to use for this run. */
  tier: Tier;
  /** The tier the key is for, even if it is not usable right now. */
  licensedTier: Tier;
  state: LicenceState;
  source: "none" | "file" | "env";
  displayKey?: string;
  machineLabel?: string;
  lastValidatedAt?: string;
  graceEndsAt?: string;
  /** One line worth telling the user, if anything is wrong. */
  message?: string;
  checkedOnline: boolean;
}

export interface ResolveOptions {
  provider: LicenceProvider;
  store: LicenceStore;
  env?: NodeJS.ProcessEnv;
  now?: Date;
  /** --offline: never call the licence server; use the cache and grace period. */
  offline?: boolean;
  /** `seaworthy status`: always check online, even if the cache is fresh. */
  forceOnline?: boolean;
}

export function defaultMachineLabel(): string {
  const platform = { win32: "Windows", darwin: "macOS", linux: "Linux" }[process.platform as string] ?? process.platform;
  return `${hostname() || "unknown machine"} (${platform})`;
}

/**
 * Works out which tier this run gets. Never throws, and never calls the network unless a
 * licence exists: Free users' scans make no licence calls at all.
 */
export async function resolveLicence(opts: ResolveOptions): Promise<LicenceStatus> {
  const env = opts.env ?? process.env;
  const now = opts.now ?? new Date();

  const envKey = env.SEAWORTHY_LICENCE?.trim();
  let source: LicenceStatus["source"];
  let record: LicenceRecord | null;
  if (envKey) {
    source = "env";
    record = opts.store.loadEnvCache(envKey) ?? {
      version: 1,
      key: envKey,
      activationId: null,
      machineLabel: "CI",
      tier: "pro",
      displayKey: maskKey(envKey),
      lastValidatedAt: new Date(0).toISOString(),
    };
    // In CI each run is a fresh machine, so the key is validated without creating an
    // activation (which would use up a machine slot every run). A pinned activation can be
    // supplied with SEAWORTHY_ACTIVATION_ID if the product requires one.
    record.activationId = env.SEAWORTHY_ACTIVATION_ID?.trim() || null;
    if (record.problem && !opts.forceOnline && !isFresh(record, now)) delete record.problem;
  } else {
    source = "file";
    record = opts.store.load();
    if (!record) return { tier: "free", licensedTier: "free", state: "none", source: "none", checkedOnline: false };
  }

  const base = {
    licensedTier: record.tier,
    source,
    displayKey: record.displayKey,
    machineLabel: record.machineLabel,
    lastValidatedAt: validTime(record.lastValidatedAt, now) ? record.lastValidatedAt : undefined,
  };
  const save = (r: LicenceRecord) => (source === "env" ? opts.store.saveEnvCache(r) : opts.store.save(r));

  // A key the server already rejected stays rejected until the user logs in again (or `status` rechecks).
  if (record.problem && !opts.forceOnline) {
    return { ...base, tier: "free", state: "ended", message: problemMessage(record.problem), checkedOnline: false };
  }

  if (!opts.forceOnline && isFresh(record, now)) {
    return { ...base, tier: record.tier, state: "active", checkedOnline: false };
  }
  if (opts.offline) return graceOrLapsed(record, base, now, false, "You're offline (--offline).");

  const v = await opts.provider.validate(record.key, record.activationId);
  if (v.ok) {
    const updated: LicenceRecord = {
      ...record,
      tier: v.value.tier,
      displayKey: v.value.displayKey,
      lastValidatedAt: now.toISOString(),
    };
    delete updated.problem;
    save(updated);
    return {
      ...base,
      licensedTier: updated.tier,
      displayKey: updated.displayKey,
      lastValidatedAt: updated.lastValidatedAt,
      tier: updated.tier,
      state: "active",
      checkedOnline: true,
    };
  }

  if (v.reason === "unreachable") return graceOrLapsed(record, base, now, true, v.detail);
  if (v.reason === "not-configured") {
    return { ...base, tier: "free", state: "not-configured", message: v.detail, checkedOnline: false };
  }

  const problem = toProblem(v.reason);
  save({ ...record, problem });
  return { ...base, tier: "free", state: "ended", message: problemMessage(problem), checkedOnline: true };
}

function graceOrLapsed(
  record: LicenceRecord,
  base: Omit<LicenceStatus, "tier" | "state" | "checkedOnline">,
  now: Date,
  checkedOnline: boolean,
  why: string,
): LicenceStatus {
  const last = validTime(record.lastValidatedAt, now) ? Date.parse(record.lastValidatedAt) : 0;
  const graceEnds = last + OFFLINE_GRACE_DAYS * DAY;
  if (last > 0 && now.getTime() <= graceEnds) {
    const until = new Date(graceEnds).toISOString();
    return {
      ...base,
      tier: record.tier,
      state: "grace",
      graceEndsAt: until,
      message: `${why} Your licence keeps working offline until ${until.slice(0, 10)}.`,
      checkedOnline,
    };
  }
  return {
    ...base,
    tier: "free",
    state: "lapsed",
    message:
      last > 0
        ? `${why} The licence hasn't been confirmed for over ${OFFLINE_GRACE_DAYS} days, so paid features are paused until Seaworthy can check it online.`
        : `${why} Paid features will turn on once Seaworthy can confirm your licence online.`,
    checkedOnline,
  };
}

function isFresh(record: LicenceRecord, now: Date): boolean {
  if (!validTime(record.lastValidatedAt, now)) return false;
  return now.getTime() - Date.parse(record.lastValidatedAt) < REVALIDATE_AFTER_HOURS * HOUR;
}

/** Rejects unparseable times and times in the future (a wound-back clock or an edited file). */
function validTime(iso: string, now: Date): boolean {
  const t = Date.parse(iso);
  return Number.isFinite(t) && t > 0 && t <= now.getTime() + 5 * 60_000;
}

function toProblem(reason: FailureReason): NonNullable<LicenceRecord["problem"]> {
  if (reason === "expired") return "expired";
  if (reason === "activation-removed") return "activation-removed";
  if (reason === "not-seaworthy" || reason === "invalid") return "not-seaworthy";
  return "revoked";
}

export function problemMessage(problem: NonNullable<LicenceRecord["problem"]>): string {
  switch (problem) {
    case "revoked":
      return `Your Seaworthy licence is no longer active; the subscription may have ended. Renew at ${PURCHASE_URL}, then run seaworthy login <key>.`;
    case "expired":
      return `Your Seaworthy licence has expired. Renew at ${PURCHASE_URL}, then run seaworthy login <key>.`;
    case "activation-removed":
      return `This machine was removed from your licence. Run seaworthy login <key> to add it back (your key: ${PORTAL_URL}).`;
    case "not-seaworthy":
      return "That key isn't a Seaworthy licence. Check you copied the right one, then run seaworthy login <key>.";
  }
}

/** Shows enough of a key to recognise it, never enough to use it. */
export function maskKey(key: string): string {
  return key.length <= 6 ? "****" : `****-${key.slice(-6).toUpperCase()}`;
}
