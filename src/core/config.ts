import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIDENCES, SEVERITIES, type Confidence, type Severity } from "./finding.js";

export interface Config {
  /** Exit non-zero when any finding is at or above this severity. */
  failOn: Severity;
  /** Hide findings below this confidence. */
  minConfidence: Confidence;
  /** Extra gitignore-style patterns to skip. */
  ignore: string[];
  /** Turn individual rules off: { "SW-B01": "off" }. */
  rules: Record<string, "off" | "on">;
  /** Never make network calls. */
  offline: boolean;
}

export const DEFAULT_CONFIG: Config = {
  failOn: "high",
  minConfidence: "high",
  ignore: [],
  rules: {},
  offline: false,
};

export const CONFIG_FILE = "seaworthy.config.json";

export class ConfigError extends Error {}

export function loadConfig(root: string, explicitPath?: string): Config {
  const path = explicitPath ?? join(root, CONFIG_FILE);
  if (!existsSync(path)) {
    if (explicitPath) throw new ConfigError(`Config file not found: ${explicitPath}`);
    return { ...DEFAULT_CONFIG };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    throw new ConfigError(`Could not parse ${path}: ${(err as Error).message}`);
  }
  return mergeConfig(DEFAULT_CONFIG, raw, path);
}

export function mergeConfig(base: Config, raw: unknown, source = "config"): Config {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError(`${source} must be a JSON object`);
  }
  const r = raw as Record<string, unknown>;
  const out: Config = { ...base, ignore: [...base.ignore], rules: { ...base.rules } };

  if (r.failOn !== undefined) out.failOn = oneOf(r.failOn, SEVERITIES, "failOn", source);
  if (r.minConfidence !== undefined) {
    out.minConfidence = oneOf(r.minConfidence, CONFIDENCES, "minConfidence", source);
  }
  if (r.offline !== undefined) {
    if (typeof r.offline !== "boolean") throw new ConfigError(`${source}: offline must be true or false`);
    out.offline = r.offline;
  }
  if (r.ignore !== undefined) {
    if (!Array.isArray(r.ignore) || !r.ignore.every((p) => typeof p === "string")) {
      throw new ConfigError(`${source}: ignore must be a list of patterns`);
    }
    out.ignore.push(...r.ignore);
  }
  if (r.rules !== undefined) {
    if (typeof r.rules !== "object" || r.rules === null) {
      throw new ConfigError(`${source}: rules must be an object like { "SW-B01": "off" }`);
    }
    for (const [id, v] of Object.entries(r.rules)) {
      if (v !== "off" && v !== "on") throw new ConfigError(`${source}: rules.${id} must be "on" or "off"`);
      out.rules[id] = v;
    }
  }
  return out;
}

function oneOf<T extends string>(v: unknown, allowed: readonly T[], key: string, source: string): T {
  if (typeof v === "string" && (allowed as readonly string[]).includes(v)) return v as T;
  throw new ConfigError(`${source}: ${key} must be one of ${allowed.join(", ")}`);
}
