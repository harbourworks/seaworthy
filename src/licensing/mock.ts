import { randomUUID } from "node:crypto";
import type { Tier } from "../core/entitlements.js";
import { TIER_INFO } from "../core/entitlements.js";
import { fail, ok, type Activation, type LicenceProvider, type ProviderResult, type Validation } from "./provider.js";

interface MockKey {
  tier: Exclude<Tier, "free">;
  state: "granted" | "revoked";
  activations: Map<string, string>; // activationId -> label
  limit: number;
  /** Simulates a key from someone else's Polar organisation. */
  foreign?: boolean;
  expiresAt?: string | null;
}

/**
 * In-memory licence server for tests and offline development. Behaves like Polar's
 * customer-portal endpoints: per-key activation limits, revocation, and 404-style failures.
 */
export class MockProvider implements LicenceProvider {
  readonly name = "Mock";
  readonly keys = new Map<string, MockKey>();
  /** Every call made, so tests can assert exactly what would have been sent. */
  readonly calls: Array<{ op: string; key: string; label?: string; activationId?: string | null }> = [];
  /** Set to true to simulate no network. */
  offline = false;

  addKey(key: string, tier: Exclude<Tier, "free">, opts: Partial<Pick<MockKey, "foreign" | "expiresAt" | "limit">> = {}): this {
    this.keys.set(key, {
      tier,
      state: "granted",
      activations: new Map(),
      limit: opts.limit ?? TIER_INFO[tier].machines,
      foreign: opts.foreign,
      expiresAt: opts.expiresAt ?? null,
    });
    return this;
  }

  revoke(key: string): void {
    const k = this.keys.get(key);
    if (k) k.state = "revoked";
  }

  async activate(key: string, label: string): Promise<ProviderResult<Activation>> {
    this.calls.push({ op: "activate", key, label });
    if (this.offline) return fail("unreachable", "The licence server could not be reached.");
    const k = this.keys.get(key);
    if (!k) return fail("invalid", "License key not found.");
    if (k.state !== "granted") return fail("revoked", "License key is revoked.");
    if (k.activations.size >= k.limit) return fail("machine-limit", "License key activation limit reached.");
    const id = randomUUID();
    k.activations.set(id, label);
    const v = await this.validate(key, id);
    if (!v.ok) {
      k.activations.delete(id);
      return v;
    }
    return ok({ activationId: id, tier: v.value.tier, displayKey: v.value.displayKey, machineLimit: k.limit });
  }

  async validate(key: string, activationId: string | null): Promise<ProviderResult<Validation>> {
    this.calls.push({ op: "validate", key, activationId });
    if (this.offline) return fail("unreachable", "The licence server could not be reached.");
    const k = this.keys.get(key);
    if (!k || k.state !== "granted") return fail("revoked", "Polar no longer accepts this key.");
    if (activationId && !k.activations.has(activationId)) return fail("activation-removed", "This machine's activation was removed.");
    if (k.foreign) return fail("not-seaworthy", "This key belongs to a different Polar organisation.");
    if (k.expiresAt && Date.parse(k.expiresAt) < Date.now()) return fail("expired", "This key has expired.");
    return ok({ tier: k.tier, displayKey: `****-${key.slice(-6).toUpperCase()}`, expiresAt: k.expiresAt ?? null });
  }

  async deactivate(key: string, activationId: string): Promise<ProviderResult<null>> {
    this.calls.push({ op: "deactivate", key, activationId });
    if (this.offline) return fail("unreachable", "The licence server could not be reached.");
    this.keys.get(key)?.activations.delete(activationId);
    return ok(null);
  }
}
