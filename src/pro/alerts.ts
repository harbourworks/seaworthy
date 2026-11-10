import { atLeastSeverity, SEVERITIES, type Finding, type Severity } from "../core/finding.js";
import { isAddress, parseSmtpUrl, sendMail, SmtpError, type SmtpConfig } from "./smtp.js";

/**
 * Alerts for scheduled scans (Pro). Destinations come from environment variables, which in
 * CI are repository secrets: a Slack incoming webhook, any https webhook, or email through
 * the user's own SMTP server. Nothing is sent anywhere else, and nothing is sent unless
 * `--notify` is given.
 *
 * Alerts carry rule, title, severity, file and line only: never code, excerpts or secrets.
 */
export const NOTIFY_ON = ["new", "failing", "always"] as const;
export type NotifyOn = (typeof NOTIFY_ON)[number];

export interface AlertInput {
  project: string;
  version: string;
  failOn: Severity;
  findings: Finding[];
  /** Findings that weren't in the last recorded scan. Null when there's no earlier scan. */
  added: Finding[] | null;
  fixedCount: number;
  /** owner/repo in GitHub Actions. */
  repository?: string;
  /** Link to this workflow run, in GitHub Actions. */
  runUrl?: string;
}

export interface Destinations {
  slack?: string;
  webhook?: string;
  email?: { smtp: SmtpConfig; from: string; to: string[] };
}

export class AlertConfigError extends Error {}

/** Reads destinations from the environment. Throws AlertConfigError if one is set up wrongly. */
export function destinationsFromEnv(env: NodeJS.ProcessEnv): Destinations {
  const d: Destinations = {};
  const https = (name: string, v: string) => {
    let u: URL;
    try {
      u = new URL(v);
    } catch {
      throw new AlertConfigError(`${name} isn't a valid URL.`);
    }
    if (u.protocol !== "https:") throw new AlertConfigError(`${name} must be an https:// URL.`);
    return u.toString();
  };
  if (env.SEAWORTHY_SLACK_WEBHOOK?.trim()) d.slack = https("SEAWORTHY_SLACK_WEBHOOK", env.SEAWORTHY_SLACK_WEBHOOK.trim());
  if (env.SEAWORTHY_WEBHOOK_URL?.trim()) d.webhook = https("SEAWORTHY_WEBHOOK_URL", env.SEAWORTHY_WEBHOOK_URL.trim());
  if (env.SEAWORTHY_SMTP_URL?.trim()) {
    let smtp: SmtpConfig;
    try {
      smtp = parseSmtpUrl(env.SEAWORTHY_SMTP_URL.trim());
    } catch (e) {
      throw new AlertConfigError((e as Error).message);
    }
    const to = (env.SEAWORTHY_EMAIL_TO ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    if (to.length === 0 || !to.every(isAddress)) throw new AlertConfigError("SEAWORTHY_EMAIL_TO must be one or more email addresses, separated by commas.");
    const from = env.SEAWORTHY_EMAIL_FROM?.trim() || smtp.user || "";
    if (!isAddress(from)) throw new AlertConfigError("Set SEAWORTHY_EMAIL_FROM to the address to send from (or use your email address as the SMTP username).");
    d.email = { smtp, from, to };
  }
  return d;
}

export function hasDestination(d: Destinations): boolean {
  return Boolean(d.slack || d.webhook || d.email);
}

/** In GitHub Actions, the repository and a link to this run. */
export function githubContext(env: NodeJS.ProcessEnv): { repository?: string; runUrl?: string } {
  const repo = env.GITHUB_REPOSITORY;
  if (!repo || !/^[\w.-]+\/[\w.-]+$/.test(repo)) return {};
  const server = env.GITHUB_SERVER_URL ?? "";
  const run = env.GITHUB_RUN_ID ?? "";
  return { repository: repo, ...(/^https:\/\/[\w.-]+$/.test(server) && /^\d+$/.test(run) ? { runUrl: `${server}/${repo}/actions/runs/${run}` } : {}) };
}

const blocking = (fs: Finding[], failOn: Severity) => fs.filter((f) => atLeastSeverity(f.severity, failOn));

/** Whether this scan should alert, and which findings to list. */
export function decide(input: AlertInput, on: NotifyOn): { send: boolean; listed: Finding[]; kind: "new" | "failing" | "clean" } {
  const failing = blocking(input.findings, input.failOn);
  // With no earlier scan to compare with, everything that fails counts as new.
  const added = blocking(input.added ?? input.findings, input.failOn);
  if (added.length) return { send: true, listed: added, kind: "new" };
  if (on === "new") return { send: false, listed: [], kind: failing.length ? "failing" : "clean" };
  if (failing.length) return { send: true, listed: failing, kind: "failing" };
  return { send: on === "always", listed: [], kind: "clean" };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const counts = (fs: Finding[]) =>
  SEVERITIES.map((s) => [s, fs.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");

export interface AlertMessage {
  title: string;
  lines: string[];
  more: number;
  footer: string;
}

export function alertMessage(input: AlertInput, decision: ReturnType<typeof decide>, max = 10): AlertMessage {
  const where = input.repository ?? input.project;
  const title =
    decision.kind === "new"
      ? `Seaworthy: ${plural(decision.listed.length, "new problem")} in ${where} (${counts(decision.listed)})`
      : decision.kind === "failing"
        ? `Seaworthy: ${where} is not seaworthy (${counts(decision.listed)})`
        : `Seaworthy: no problems at or above ${input.failOn} in ${where}`;
  const lines = decision.listed.slice(0, max).map((f) => `${f.severity.toUpperCase()}  ${f.title}  ${f.file}:${f.line}  ${f.ruleId}`);
  const extra = [
    input.fixedCount ? `${plural(input.fixedCount, "problem")} fixed since the last scan.` : "",
    input.runUrl ? `Details: ${input.runUrl}` : "",
  ].filter(Boolean);
  return {
    title,
    lines: [...lines, ...extra],
    more: Math.max(0, decision.listed.length - max),
    footer: `Sent by Seaworthy ${input.version}. Alerts never include code or secrets.`,
  };
}

const slackEscape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function slackPayload(m: AlertMessage): unknown {
  const body = [...m.lines, ...(m.more ? [`…and ${m.more} more.`] : [])].map(slackEscape).join("\n").slice(0, 2900);
  return {
    text: m.title,
    blocks: [
      { type: "section", text: { type: "mrkdwn", text: `*${slackEscape(m.title)}*` } },
      ...(body ? [{ type: "section", text: { type: "mrkdwn", text: body } }] : []),
      { type: "context", elements: [{ type: "mrkdwn", text: slackEscape(m.footer) }] },
    ],
  };
}

export function webhookPayload(input: AlertInput, decision: ReturnType<typeof decide>, m: AlertMessage): unknown {
  return {
    tool: "seaworthy",
    version: input.version,
    project: input.project,
    repository: input.repository ?? null,
    runUrl: input.runUrl ?? null,
    title: m.title,
    reason: decision.kind,
    failOn: input.failOn,
    counts: Object.fromEntries(SEVERITIES.map((s) => [s, input.findings.filter((f) => f.severity === s).length])),
    fixedSinceLastScan: input.fixedCount,
    findings: decision.listed.slice(0, 50).map((f) => ({ rule: f.ruleId, title: f.title, severity: f.severity, file: f.file, line: f.line })),
  };
}

export function emailText(m: AlertMessage): string {
  return [m.title, "", ...m.lines, ...(m.more ? [`…and ${m.more} more.`] : []), "", m.footer, ""].join("\n");
}

/** Sends to every destination. Returns one line per destination saying what happened. */
export async function sendAlerts(
  d: Destinations,
  input: AlertInput,
  decision: ReturnType<typeof decide>,
  deps: { fetch: typeof fetch; sendMail?: typeof sendMail; now?: Date },
): Promise<Array<{ ok: boolean; message: string }>> {
  const m = alertMessage(input, decision);
  const results: Array<{ ok: boolean; message: string }> = [];
  const post = async (name: string, url: string, body: unknown) => {
    try {
      const r = await deps.fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": `seaworthy/${input.version}` },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
      });
      results.push(r.ok ? { ok: true, message: `Alert sent to ${name}.` } : { ok: false, message: `${name} refused the alert (HTTP ${r.status}).` });
    } catch (e) {
      results.push({ ok: false, message: `Couldn't reach ${name}: ${(e as Error).message}` });
    }
  };
  if (d.slack) await post("Slack", d.slack, slackPayload(m));
  if (d.webhook) await post("the webhook", d.webhook, webhookPayload(input, decision, m));
  if (d.email) {
    try {
      await (deps.sendMail ?? sendMail)(d.email.smtp, { from: d.email.from, to: d.email.to, subject: m.title, text: emailText(m) }, { now: deps.now });
      results.push({ ok: true, message: `Alert emailed to ${d.email.to.join(", ")}.` });
    } catch (e) {
      results.push({ ok: false, message: e instanceof SmtpError ? e.message : `Sending email failed: ${(e as Error).message}` });
    }
  }
  return results;
}
