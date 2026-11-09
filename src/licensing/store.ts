import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { Tier } from "../core/entitlements.js";

/** What is saved on this machine after `seaworthy login`. Never stored inside a project. */
export interface LicenceRecord {
  version: 1;
  key: string;
  activationId: string | null;
  machineLabel: string;
  tier: Exclude<Tier, "free">;
  displayKey: string;
  /** Last time the licence server confirmed the key. Drives the offline grace period. */
  lastValidatedAt: string;
  /** Set when the server says the key is no longer good, so we stop offering paid features. */
  problem?: "revoked" | "expired" | "activation-removed" | "not-seaworthy";
}

/** The per-user config folder: %APPDATA%\seaworthy, ~/Library/Application Support/seaworthy or ~/.config/seaworthy. */
export function userConfigDir(env: NodeJS.ProcessEnv = process.env, platform = process.platform): string {
  if (env.SEAWORTHY_CONFIG_DIR) return env.SEAWORTHY_CONFIG_DIR;
  if (platform === "win32") return join(env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "seaworthy");
  if (platform === "darwin") return join(homedir(), "Library", "Application Support", "seaworthy");
  return join(env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "seaworthy");
}

export class LicenceStore {
  constructor(readonly dir: string) {}

  get path(): string {
    return join(this.dir, "licence.json");
  }

  load(): LicenceRecord | null {
    return readJson<LicenceRecord>(this.path, (r) => r.version === 1 && typeof r.key === "string");
  }

  save(record: LicenceRecord): void {
    writeJson(this.dir, this.path, record);
  }

  clear(): void {
    rmSync(this.path, { force: true });
  }

  /** Validation cache for a key supplied through SEAWORTHY_LICENCE (CI). Keyed by a hash, not the key. */
  loadEnvCache(key: string): LicenceRecord | null {
    const all = readJson<Record<string, LicenceRecord>>(this.envCachePath, () => true) ?? {};
    const rec = all[hashKey(key)];
    return rec ? { ...rec, key } : null;
  }

  saveEnvCache(record: LicenceRecord): void {
    const all = readJson<Record<string, LicenceRecord>>(this.envCachePath, () => true) ?? {};
    all[hashKey(record.key)] = { ...record, key: "" }; // never write the raw key to disk
    writeJson(this.dir, this.envCachePath, all);
  }

  private get envCachePath(): string {
    return join(this.dir, "env-licence-cache.json");
  }
}

const hashKey = (key: string) => createHash("sha256").update(key).digest("hex").slice(0, 32);

function readJson<T>(path: string, valid: (v: T) => boolean): T | null {
  if (!existsSync(path)) return null;
  try {
    const v = JSON.parse(readFileSync(path, "utf8")) as T;
    return v && typeof v === "object" && valid(v) ? v : null;
  } catch {
    return null; // a corrupt file is treated as "not logged in", never as a crash
  }
}

function writeJson(dir: string, path: string, value: unknown): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  // 0600: the key is a credential. (Windows ignores the mode; the folder is per-user anyway.)
  writeFileSync(path, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
}
