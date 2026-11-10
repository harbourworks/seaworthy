import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TIER_INFO, hasFeature, requiredTier, TIERS, type Feature } from "../src/core/entitlements.js";
import { MockProvider } from "../src/licensing/mock.js";
import { LicenceStore, userConfigDir } from "../src/licensing/store.js";
import { resolveLicence } from "../src/licensing/licence.js";
import { PolarProvider } from "../src/licensing/polar.js";
import { POLAR_SERVERS, PURCHASE_URL, isConfigured, type PolarSettings } from "../src/licensing/config.js";

const DAY = 86_400_000;
const PRO_KEY = "SEAWORTHY-TEST-PRO-0001";
const AGENCY_KEY = "SEAWORTHY-TEST-AGENCY-0001";

describe("entitlements", () => {
  it("matches the tier table exactly", () => {
    const features = (t: (typeof TIERS)[number]) => [...TIER_INFO[t].features].sort();
    expect(features("free")).toEqual([]);
    expect(features("pro")).toEqual(["compare", "history", "html-report", "pr-checks"]);
    expect(features("agency")).toEqual(["compare", "history", "html-report", "pr-checks", "scan-all", "white-label"]);
    expect([TIER_INFO.pro.pricePerYearGbp, TIER_INFO.agency.pricePerYearGbp]).toEqual([99, 349]);
    expect(TIER_INFO.pro.pricePerMonthGbp).toBe(12);
    expect(TIER_INFO.agency.pricePerMonthGbp).toBeUndefined();
    expect([TIER_INFO.pro.machines, TIER_INFO.agency.machines]).toEqual([2, 10]);
  });
  it("names the cheapest tier for each feature", () => {
    const want: Record<Feature, string> = { "html-report": "pro", history: "pro", compare: "pro", "pr-checks": "pro", "white-label": "agency", "scan-all": "agency" };
    for (const [f, t] of Object.entries(want)) expect(requiredTier(f as Feature)).toBe(t);
    expect(hasFeature("free", "html-report")).toBe(false);
  });
});

describe("licence resolution", () => {
  let dir: string;
  let store: LicenceStore;
  let provider: MockProvider;
  const now = new Date("2026-11-10T09:00:00Z");

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "seaworthy-lic-"));
    store = new LicenceStore(dir);
    provider = new MockProvider().addKey(PRO_KEY, "pro").addKey(AGENCY_KEY, "agency");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  const loginAs = async (key: string, at = now) => {
    const a = await provider.activate(key, "test-machine");
    if (!a.ok) throw new Error(a.detail);
    store.save({ version: 1, key, activationId: a.value.activationId, machineLabel: "test-machine", tier: a.value.tier, displayKey: a.value.displayKey, lastValidatedAt: at.toISOString() });
    provider.calls.length = 0;
  };

  it("no licence: Free, and no network call at all", async () => {
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "free", state: "none" });
    expect(provider.calls).toEqual([]);
  });

  it("fresh cache (under 24h): uses it without calling the server", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 3_600_000));
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "pro", state: "active", checkedOnline: false });
    expect(provider.calls).toEqual([]);
  });

  it("stale cache: validates online with only the key and activation ID", async () => {
    await loginAs(AGENCY_KEY, new Date(now.getTime() - 2 * DAY));
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "agency", state: "active", checkedOnline: true });
    expect(provider.calls).toHaveLength(1);
    expect(Object.keys(provider.calls[0]!).sort()).toEqual(["activationId", "key", "op"]);
    expect(store.load()!.lastValidatedAt).toBe(now.toISOString());
  });

  it("offline within 14 days: keeps the paid tier (grace)", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 10 * DAY));
    provider.offline = true;
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "pro", state: "grace" });
    expect(s.graceEndsAt!.slice(0, 10)).toBe("2026-11-14");
  });

  it("offline beyond 14 days: back to Free until it can check (lapsed)", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 15 * DAY));
    provider.offline = true;
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "free", licensedTier: "pro", state: "lapsed" });
  });

  it("--offline never calls the server, and grace still applies", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 3 * DAY));
    const s = await resolveLicence({ provider, store, env: {}, now, offline: true });
    expect(s).toMatchObject({ tier: "pro", state: "grace" });
    expect(provider.calls).toEqual([]);
  });

  it("revoked key (subscription ended): Free, remembered, with a renew message", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 2 * DAY));
    provider.revoke(PRO_KEY);
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s).toMatchObject({ tier: "free", state: "ended" });
    expect(s.message).toMatch(/no longer active/);
    expect(store.load()!.problem).toBe("revoked");
    provider.calls.length = 0;
    const again = await resolveLicence({ provider, store, env: {}, now });
    expect(again.tier).toBe("free");
    expect(provider.calls).toEqual([]); // doesn't hammer the server once it knows
  });

  it("a removed activation is reported as such", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 2 * DAY));
    const rec = store.load()!;
    await provider.deactivate(PRO_KEY, rec.activationId!);
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s.state).toBe("ended");
    expect(s.message).toMatch(/removed from your licence/);
  });

  it("a clock or file set in the future is not trusted", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() + 30 * DAY));
    provider.offline = true;
    const s = await resolveLicence({ provider, store, env: {}, now });
    expect(s.tier).toBe("free");
  });

  it("SEAWORTHY_LICENCE wins over the saved login and never creates an activation", async () => {
    await loginAs(PRO_KEY, new Date(now.getTime() - 2 * DAY));
    const s = await resolveLicence({ provider, store, env: { SEAWORTHY_LICENCE: AGENCY_KEY }, now });
    expect(s).toMatchObject({ tier: "agency", source: "env", state: "active" });
    expect(provider.calls.map((c) => c.op)).toEqual(["validate"]);
    expect(provider.calls[0]!.activationId).toBeNull();
    // The CI cache never holds the raw key.
    expect(readFileSync(join(dir, "env-licence-cache.json"), "utf8")).not.toContain(AGENCY_KEY);
  });

  it("a key from another organisation is rejected", async () => {
    provider.addKey("SEAWORTHY-FOREIGN-0001", "agency", { foreign: true });
    const a = await provider.activate("SEAWORTHY-FOREIGN-0001", "m");
    expect(a).toMatchObject({ ok: false, reason: "not-seaworthy" });
  });

  it("enforces machine limits: Pro 2, Agency 10", async () => {
    for (let i = 0; i < 2; i++) expect((await provider.activate(PRO_KEY, `m${i}`)).ok).toBe(true);
    expect(await provider.activate(PRO_KEY, "m3")).toMatchObject({ ok: false, reason: "machine-limit" });
    for (let i = 0; i < 10; i++) expect((await provider.activate(AGENCY_KEY, `m${i}`)).ok).toBe(true);
    expect(await provider.activate(AGENCY_KEY, "m11")).toMatchObject({ ok: false, reason: "machine-limit" });
  });

  it("stores the licence in the user config folder, never a project", () => {
    expect(userConfigDir({ APPDATA: "C:\\Users\\x\\AppData\\Roaming" }, "win32")).toMatch(/AppData[\\/]Roaming[\\/]seaworthy$/);
    expect(userConfigDir({ XDG_CONFIG_HOME: "/home/x/.config" }, "linux")).toBe(join("/home/x/.config", "seaworthy"));
    expect(userConfigDir({ SEAWORTHY_CONFIG_DIR: "/tmp/sw" }, "linux")).toBe("/tmp/sw");
    expect(existsSync(join(process.cwd(), "licence.json"))).toBe(false);
  });
});

describe("PolarProvider (fake fetch, no network)", () => {
  const ORG = "11111111-1111-4111-8111-111111111111";
  const PRO_BENEFIT = "22222222-2222-4222-8222-222222222222";
  const AGENCY_BENEFIT = "33333333-3333-4333-8333-333333333333";
  const settings: PolarSettings = { apiBase: "https://polar.test", organizationId: ORG, benefits: { [PRO_BENEFIT]: "pro", [AGENCY_BENEFIT]: "agency" } };

  type Reply = { status: number; body?: unknown };
  function fakeFetch(replies: Reply[]) {
    const sent: Array<{ url: string; body: Record<string, unknown> }> = [];
    const f = (async (url: string, init: RequestInit) => {
      sent.push({ url, body: JSON.parse(String(init.body)) });
      const r = replies.shift() ?? { status: 500 };
      return new Response(r.status === 204 ? null : JSON.stringify(r.body ?? {}), { status: r.status });
    }) as unknown as typeof fetch;
    return { f, sent };
  }
  const validated = (over: Record<string, unknown> = {}) => ({
    status: 200,
    body: { id: "k1", organization_id: ORG, benefit_id: PRO_BENEFIT, status: "granted", display_key: "****-E304DA", expires_at: null, ...over },
  });

  it("login: activates with key, organisation and label, then validates with the activation ID", async () => {
    const { f, sent } = fakeFetch([{ status: 200, body: { id: "act-1", license_key: { limit_activations: 2 } } }, validated()]);
    const r = await new PolarProvider(settings, f).activate("POLAR-KEY", "laptop (macOS)");
    expect(r).toEqual({ ok: true, value: { activationId: "act-1", tier: "pro", displayKey: "****-E304DA", machineLimit: 2 } });
    expect(sent[0]).toEqual({ url: "https://polar.test/v1/customer-portal/license-keys/activate", body: { key: "POLAR-KEY", organization_id: ORG, label: "laptop (macOS)" } });
    expect(sent[1]).toEqual({ url: "https://polar.test/v1/customer-portal/license-keys/validate", body: { key: "POLAR-KEY", organization_id: ORG, activation_id: "act-1" } });
  });

  it("derives the tier from benefit_id", async () => {
    const { f } = fakeFetch([validated({ benefit_id: AGENCY_BENEFIT })]);
    expect(await new PolarProvider(settings, f).validate("K", "a")).toMatchObject({ ok: true, value: { tier: "agency" } });
  });

  it("rejects another organisation's key and unknown products", async () => {
    const a = fakeFetch([validated({ organization_id: "99999999-9999-4999-8999-999999999999" })]);
    expect(await new PolarProvider(settings, a.f).validate("K", "a")).toMatchObject({ ok: false, reason: "not-seaworthy" });
    const b = fakeFetch([validated({ benefit_id: "44444444-4444-4444-8444-444444444444" })]);
    expect(await new PolarProvider(settings, b.f).validate("K", "a")).toMatchObject({ ok: false, reason: "not-seaworthy" });
  });

  it("a not-ours key is deactivated straight away so it doesn't use a slot", async () => {
    const { f, sent } = fakeFetch([{ status: 200, body: { id: "act-9", license_key: {} } }, validated({ organization_id: "x" }), { status: 204 }]);
    expect(await new PolarProvider(settings, f).activate("K", "m")).toMatchObject({ ok: false, reason: "not-seaworthy" });
    expect(sent.map((s) => s.url.split("/").pop())).toEqual(["activate", "validate", "deactivate"]);
  });

  it("404 on validate: revoked when the key itself fails, activation-removed when only the activation does", async () => {
    const gone = fakeFetch([{ status: 404, body: { error: "ResourceNotFound" } }, { status: 404 }]);
    expect(await new PolarProvider(settings, gone.f).validate("K", "a")).toMatchObject({ ok: false, reason: "revoked" });
    const removed = fakeFetch([{ status: 404 }, validated()]);
    expect(await new PolarProvider(settings, removed.f).validate("K", "a")).toMatchObject({ ok: false, reason: "activation-removed" });
  });

  it("maps activation errors: limit, revoked and unknown keys", async () => {
    const lim = fakeFetch([{ status: 403, body: { error: "NotPermitted", detail: "License key has reached its activation limit." } }]);
    expect(await new PolarProvider(settings, lim.f).activate("K", "m")).toMatchObject({ ok: false, reason: "machine-limit" });
    const rev = fakeFetch([{ status: 403, body: { error: "NotPermitted", detail: "License key is revoked." } }]);
    expect(await new PolarProvider(settings, rev.f).activate("K", "m")).toMatchObject({ ok: false, reason: "revoked" });
    const unk = fakeFetch([{ status: 404, body: { error: "ResourceNotFound" } }]);
    expect(await new PolarProvider(settings, unk.f).activate("K", "m")).toMatchObject({ ok: false, reason: "invalid" });
  });

  it("server errors and network failures count as unreachable, never as a bad key", async () => {
    const s5 = fakeFetch([{ status: 503 }]);
    expect(await new PolarProvider(settings, s5.f).validate("K", "a")).toMatchObject({ ok: false, reason: "unreachable" });
    const boom = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    expect(await new PolarProvider(settings, boom).validate("K", "a")).toMatchObject({ ok: false, reason: "unreachable" });
  });

  it("treats an expired one-off key as expired", async () => {
    const { f } = fakeFetch([validated({ expires_at: "2020-01-01T00:00:00Z" })]);
    expect(await new PolarProvider(settings, f).validate("K", "a")).toMatchObject({ ok: false, reason: "expired" });
  });

  it("refuses to call Polar while the build has placeholder IDs", async () => {
    const { f, sent } = fakeFetch([]);
    const p = new PolarProvider({ apiBase: "https://polar.test", organizationId: "00000000-0000-0000-0000-000000000000", benefits: {} }, f);
    expect(await p.activate("K", "m")).toMatchObject({ ok: false, reason: "not-configured" });
    expect(sent).toEqual([]);
  });
});

describe("production Polar config", () => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  it("is set up with real IDs for both paid tiers", () => {
    const p = POLAR_SERVERS.production;
    expect(isConfigured(p)).toBe(true);
    expect(p.organizationId).toMatch(UUID);
    for (const id of Object.keys(p.benefits)) expect(id).toMatch(UUID);
    expect(Object.values(p.benefits).sort()).toEqual(["agency", "pro"]);
    expect(p.apiBase).toBe("https://api.polar.sh");
  });
  it("points purchases at Polar's checkout", () => {
    expect(PURCHASE_URL).toMatch(/^https:\/\/buy\.polar\.sh\//);
  });
});
