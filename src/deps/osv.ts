/**
 * Looks up known vulnerabilities on OSV (osv.dev), the free, open vulnerability database.
 * Only package names and versions are sent: never code, file names or findings.
 */
import type { Severity } from "../core/finding.js";
import type { Dependency } from "./dependencies.js";

const API = "https://api.osv.dev/v1";
const TIMEOUT_MS = 10_000;
const DETAIL_CONCURRENCY = 8;

export interface Advisory {
  id: string;
  /** A CVE or GHSA ID people will recognise, if OSV has one. */
  displayId: string;
  summary: string;
  severity: Severity;
  /** The lowest version that fixes it for the installed version, if there is one. */
  fixedIn: string | null;
  malicious: boolean;
}

export type OsvResult =
  | { status: "ok"; checked: number; advisories: Map<string, Advisory[]> }
  | { status: "offline" }
  | { status: "failed"; reason: string };

export const depKey = (d: { name: string; version: string }) => `${d.name}@${d.version}`;

export async function lookupAdvisories(deps: Dependency[], fetchImpl: typeof fetch = fetch): Promise<OsvResult> {
  const unique = [...new Map(deps.map((d) => [depKey(d), d])).values()];
  if (unique.length === 0) return { status: "ok", checked: 0, advisories: new Map() };
  try {
    const ids = new Map<string, string[]>();
    for (let i = 0; i < unique.length; i += 500) {
      const batch = unique.slice(i, i + 500);
      const res = await timed(fetchImpl, `${API}/querybatch`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: batch.map((d) => ({ package: { name: d.name, ecosystem: "npm" }, version: d.version })) }),
      });
      if (!res.ok) return { status: "failed", reason: `OSV answered ${res.status}` };
      const body = (await res.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
      batch.forEach((d, j) => ids.set(depKey(d), (body.results?.[j]?.vulns ?? []).map((v) => v.id)));
    }

    // Fetch each advisory's details once, a few at a time.
    const allIds = [...new Set([...ids.values()].flat())];
    const details = new Map<string, OsvVuln>();
    for (let i = 0; i < allIds.length; i += DETAIL_CONCURRENCY) {
      await Promise.all(
        allIds.slice(i, i + DETAIL_CONCURRENCY).map(async (id) => {
          const r = await timed(fetchImpl, `${API}/vulns/${encodeURIComponent(id)}`, {});
          if (r.ok) details.set(id, (await r.json()) as OsvVuln);
        }),
      );
    }

    const advisories = new Map<string, Advisory[]>();
    for (const d of unique) {
      const list: Advisory[] = [];
      for (const id of ids.get(depKey(d)) ?? []) {
        const v = details.get(id);
        if (!v || v.withdrawn) continue;
        list.push(toAdvisory(v, d));
      }
      if (list.length) advisories.set(depKey(d), list);
    }
    return { status: "ok", checked: unique.length, advisories };
  } catch (err) {
    return { status: "failed", reason: (err as Error).name === "AbortError" ? "OSV didn't answer in time" : "couldn't reach OSV" };
  }
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  withdrawn?: string;
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
    database_specific?: { severity?: string };
  }>;
}

function toAdvisory(v: OsvVuln, d: Dependency): Advisory {
  const malicious = v.id.startsWith("MAL-");
  const raw = (v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity ?? "").toUpperCase();
  const severity: Severity = malicious
    ? "critical"
    : raw === "CRITICAL" ? "critical" : raw === "HIGH" ? "high" : raw === "LOW" ? "low" : "medium";
  const displayId = v.aliases?.find((a) => a.startsWith("CVE-")) ?? (v.id.startsWith("GHSA-") ? v.id : v.aliases?.find((a) => a.startsWith("GHSA-")) ?? v.id);
  return {
    id: v.id,
    displayId,
    summary: (v.summary ?? v.details ?? "").split("\n")[0]!.trim(),
    severity,
    fixedIn: fixedVersion(v, d),
    malicious,
  };
}

/** The `fixed` event of the range that contains the installed version. */
function fixedVersion(v: OsvVuln, d: Dependency): string | null {
  for (const a of v.affected ?? []) {
    if (a.package?.name && a.package.name !== d.name) continue;
    for (const r of a.ranges ?? []) {
      if (r.type !== "SEMVER" && r.type !== "ECOSYSTEM") continue;
      let introduced: string | null = null;
      for (const e of r.events) {
        if (e.introduced !== undefined) introduced = e.introduced;
        if (e.fixed !== undefined && introduced !== null) {
          if (compareSemver(d.version, introduced) >= 0 && compareSemver(d.version, e.fixed) < 0) return e.fixed;
          introduced = null;
        }
      }
    }
  }
  return null;
}

/** Compares semver strings; "0" (OSV's "from the start") sorts first. Pre-releases sort before releases. */
export function compareSemver(a: string, b: string): number {
  const parse = (s: string) => {
    const [main, pre] = s.split("-", 2) as [string, string | undefined];
    return { nums: main.split(".").map((x) => parseInt(x, 10) || 0), pre };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (x.pre && !y.pre) return -1;
  if (!x.pre && y.pre) return 1;
  return (x.pre ?? "").localeCompare(y.pre ?? "", undefined, { numeric: true });
}

async function timed(fetchImpl: typeof fetch, url: string, init: RequestInit): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    return await fetchImpl(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}
