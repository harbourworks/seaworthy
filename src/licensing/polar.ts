import { LICENCE_TIMEOUT_MS, isConfigured, type PolarSettings } from "./config.js";
import { fail, ok, type Activation, type LicenceProvider, type ProviderResult, type Validation } from "./provider.js";
import { VERSION } from "../version.js";

type Fetch = typeof fetch;

interface HttpResult {
  status: number;
  body: Record<string, unknown> | null;
}

/**
 * Polar licence keys, through the customer-portal endpoints. Polar documents these as
 * needing no authentication and being safe for public clients such as a CLI:
 *   POST /v1/customer-portal/license-keys/activate   { key, organization_id, label }
 *   POST /v1/customer-portal/license-keys/validate   { key, organization_id, activation_id? }
 *   POST /v1/customer-portal/license-keys/deactivate { key, organization_id, activation_id }
 *
 * Notes from Polar's docs (checked 9 November 2026):
 * - A validated key's `status` is always "granted". Revoked, disabled and expired keys, and
 *   keys whose subscription has ended, come back as 404, not as a different status.
 * - Subscription keys have no `expires_at`; one-off keys may have one.
 * - activate returns 403 when the key is revoked/disabled/expired or at its activation limit.
 */
export class PolarProvider implements LicenceProvider {
  readonly name = "Polar";

  constructor(
    private readonly settings: PolarSettings,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  async activate(key: string, machineLabel: string): Promise<ProviderResult<Activation>> {
    if (!isConfigured(this.settings)) return notConfigured();
    const res = await this.post("activate", {
      key,
      organization_id: this.settings.organizationId,
      label: machineLabel.slice(0, 200),
    });
    if ("error" in res) return res.error;

    if (res.status === 200 && res.body) {
      const activationId = str(res.body.id);
      const lk = (res.body.license_key ?? {}) as Record<string, unknown>;
      if (!activationId) return fail("unreachable", "Polar returned an activation with no ID.");
      // Validate straight away: that is where organisation, product and expiry get checked.
      const v = await this.validate(key, activationId);
      if (!v.ok) {
        if (v.reason === "not-seaworthy") await this.deactivate(key, activationId); // don't burn a slot
        return v;
      }
      return ok({
        activationId,
        tier: v.value.tier,
        displayKey: v.value.displayKey,
        machineLimit: typeof lk.limit_activations === "number" ? lk.limit_activations : null,
      });
    }
    if (res.status === 403) {
      const detail = detailOf(res.body);
      return /limit/i.test(detail)
        ? fail("machine-limit", detail)
        : fail("revoked", detail || "Polar refused this key: it is revoked, disabled or expired.");
    }
    if (res.status === 404 || res.status === 422) return fail("invalid", detailOf(res.body) || "Polar doesn't recognise this key.");
    return unexpected(res);
  }

  async validate(key: string, activationId: string | null): Promise<ProviderResult<Validation>> {
    if (!isConfigured(this.settings)) return notConfigured();
    const body: Record<string, string> = { key, organization_id: this.settings.organizationId };
    if (activationId) body.activation_id = activationId;
    const res = await this.post("validate", body);
    if ("error" in res) return res.error;

    if (res.status === 200 && res.body) {
      const b = res.body;
      if (str(b.organization_id) !== this.settings.organizationId) {
        return fail("not-seaworthy", "This key belongs to a different Polar organisation.");
      }
      const tier = this.settings.benefits[str(b.benefit_id) ?? ""];
      if (!tier) return fail("not-seaworthy", "This key is for a product that isn't a Seaworthy plan.");
      if (b.status !== undefined && b.status !== "granted") {
        return fail("revoked", `Polar reports this key as ${String(b.status)}.`);
      }
      const expiresAt = str(b.expires_at);
      if (expiresAt && Date.parse(expiresAt) < Date.now()) return fail("expired", `This key expired on ${expiresAt.slice(0, 10)}.`);
      return ok({ tier, displayKey: str(b.display_key) ?? "****", expiresAt });
    }
    if (res.status === 404) {
      // 404 means either the key is no longer valid, or this machine's activation is gone.
      // Re-checking the key alone tells the two apart.
      if (activationId) {
        const keyOnly = await this.validate(key, null);
        if (keyOnly.ok) return fail("activation-removed", "This machine's activation was removed.");
        if (keyOnly.reason === "unreachable") return keyOnly;
      }
      return fail("revoked", "Polar no longer accepts this key: the subscription may have ended, or the key was revoked.");
    }
    if (res.status === 422) return fail("invalid", "That doesn't look like a valid licence key.");
    return unexpected(res);
  }

  async deactivate(key: string, activationId: string): Promise<ProviderResult<null>> {
    if (!isConfigured(this.settings)) return notConfigured();
    const res = await this.post("deactivate", {
      key,
      organization_id: this.settings.organizationId,
      activation_id: activationId,
    });
    if ("error" in res) return res.error;
    if (res.status === 204 || res.status === 200 || res.status === 404) return ok(null); // 404: already gone
    return unexpected(res);
  }

  private async post(
    action: "activate" | "validate" | "deactivate",
    body: Record<string, unknown>,
  ): Promise<HttpResult | { error: ProviderResult<never> }> {
    const url = `${this.settings.apiBase}/v1/customer-portal/license-keys/${action}`;
    try {
      const r = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", "user-agent": `seaworthy-cli/${VERSION}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(LICENCE_TIMEOUT_MS),
      });
      let parsed: Record<string, unknown> | null = null;
      if (r.status !== 204) {
        try {
          const j = await r.json();
          parsed = typeof j === "object" && j !== null ? (j as Record<string, unknown>) : null;
        } catch {
          parsed = null;
        }
      }
      return { status: r.status, body: parsed };
    } catch (err) {
      const e = err as Error;
      const why = e.name === "TimeoutError" || e.name === "AbortError" ? "timed out" : "could not be reached";
      return { error: fail("unreachable", `The licence server ${why}.`) };
    }
  }
}

const str = (v: unknown): string | null => (typeof v === "string" && v.length > 0 ? v : null);

function detailOf(body: Record<string, unknown> | null): string {
  const d = body?.detail;
  return typeof d === "string" ? d : "";
}

function notConfigured<T>(): ProviderResult<T> {
  return fail("not-configured", "Licensing isn't set up in this build of Seaworthy yet.");
}

function unexpected<T>(res: HttpResult): ProviderResult<T> {
  // 5xx, 429 and anything unexpected says nothing about the key, so treat it like no network.
  return fail("unreachable", `The licence server returned an unexpected response (HTTP ${res.status}).`);
}
