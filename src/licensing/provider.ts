import type { Tier } from "../core/entitlements.js";

/**
 * Everything Seaworthy needs from a payment provider. Polar is the real one; MockProvider is
 * for tests. Implementations send only the licence key, the machine label and the IDs the
 * provider issued. They never see code, findings or file names.
 */
export interface LicenceProvider {
  readonly name: string;
  /** Registers this machine against the key. */
  activate(key: string, machineLabel: string): Promise<ProviderResult<Activation>>;
  /** Checks the key (and this machine's activation) is still good. */
  validate(key: string, activationId: string | null): Promise<ProviderResult<Validation>>;
  /** Frees this machine's slot. */
  deactivate(key: string, activationId: string): Promise<ProviderResult<null>>;
}

export interface Activation {
  activationId: string;
  tier: Exclude<Tier, "free">;
  /** Masked key safe to show, e.g. `****-E304DA`. */
  displayKey: string;
  machineLimit: number | null;
}

export interface Validation {
  tier: Exclude<Tier, "free">;
  displayKey: string;
  /** Only set for one-off (non-subscription) keys. */
  expiresAt: string | null;
}

export type FailureReason =
  /** Key does not exist or was mistyped. */
  | "invalid"
  /** Key was revoked or disabled, or its subscription ended. */
  | "revoked"
  /** One-off key past its expiry date. */
  | "expired"
  /** Every machine slot is in use. */
  | "machine-limit"
  /** This machine's activation was removed (for example from the customer portal). */
  | "activation-removed"
  /** A real key, but not one of ours (wrong organisation or an unknown product). */
  | "not-seaworthy"
  /** No network, timeout or a server error: says nothing about the key itself. */
  | "unreachable"
  /** The licence server is not configured in this build. */
  | "not-configured";

export type ProviderResult<T> = { ok: true; value: T } | { ok: false; reason: FailureReason; detail: string };

export const ok = <T>(value: T): ProviderResult<T> => ({ ok: true, value });
export const fail = <T>(reason: FailureReason, detail: string): ProviderResult<T> => ({ ok: false, reason, detail });
