import { existsSync, readFileSync, statSync } from "node:fs";
import { extname, resolve } from "node:path";
import type { ReportBranding } from "../core/config.js";

export interface ResolvedBranding {
  /** null = Seaworthy's own branding. */
  agencyName: string | null;
  clientName: string | null;
  /** data: URI, so the report stays a single self-contained file. */
  logoDataUri: string | null;
}

export const SEAWORTHY_BRANDING: ResolvedBranding = { agencyName: null, clientName: null, logoDataUri: null };

const LOGO_TYPES: Record<string, string> = {
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
};
export const MAX_LOGO_BYTES = 512 * 1024;

/**
 * Reads white-label settings. The logo is embedded as a data URI inside an <img>; browsers
 * don't run scripts in SVGs loaded that way, so an SVG logo can't inject code.
 */
export function resolveBranding(b: ReportBranding, baseDir: string): { branding: ResolvedBranding; warnings: string[] } {
  const warnings: string[] = [];
  let logoDataUri: string | null = null;
  if (b.logo) {
    const path = resolve(baseDir, b.logo);
    const type = LOGO_TYPES[extname(path).toLowerCase()];
    if (!type) warnings.push(`Logo ${b.logo} must be a PNG, JPEG, WebP or SVG file, so the report has no logo.`);
    else if (!existsSync(path)) warnings.push(`Logo ${b.logo} wasn't found, so the report has no logo.`);
    else if (statSync(path).size > MAX_LOGO_BYTES) warnings.push(`Logo ${b.logo} is over 512 KB, so the report has no logo.`);
    else logoDataUri = `data:${type};base64,${readFileSync(path).toString("base64")}`;
  }
  return {
    branding: { agencyName: b.agencyName ?? null, clientName: b.clientName ?? null, logoDataUri },
    warnings,
  };
}
