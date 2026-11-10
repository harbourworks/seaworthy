import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type ConnectionOptions, type TLSSocket } from "node:tls";
import { randomBytes } from "node:crypto";

/**
 * Just enough SMTP to send one plain-text email through the user's own mail server, so
 * email alerts need no third-party service and no dependency.
 *
 * Credentials only ever travel encrypted: smtps:// uses TLS from the start, and smtp://
 * requires the server to offer STARTTLS (and refuses to send otherwise). Certificates are
 * verified. Header values are stripped of line breaks, so nothing can inject headers.
 */
export interface SmtpConfig {
  /** TLS from the first byte (smtps://, usually port 465). Otherwise STARTTLS is required. */
  secure: boolean;
  host: string;
  port: number;
  user?: string;
  pass?: string;
}

export interface MailMessage {
  from: string;
  to: string[];
  subject: string;
  text: string;
}

export class SmtpError extends Error {}

const ADDRESS = /^[^\s<>@,;:"]+@[^\s<>@,;:"]+\.[^\s<>@,;:"]+$/;

/** smtps://user:pass@smtp.example.com:465 or smtp://user:pass@smtp.example.com:587 */
export function parseSmtpUrl(url: string): SmtpConfig {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new SmtpError("SEAWORTHY_SMTP_URL isn't a valid URL. Use smtps://user:password@smtp.example.com:465 (or smtp://... :587 for STARTTLS).");
  }
  if (u.protocol !== "smtps:" && u.protocol !== "smtp:") throw new SmtpError("SEAWORTHY_SMTP_URL must start with smtps:// or smtp://.");
  if (!u.hostname) throw new SmtpError("SEAWORTHY_SMTP_URL has no server name.");
  const secure = u.protocol === "smtps:";
  return {
    secure,
    host: u.hostname,
    port: u.port ? Number(u.port) : secure ? 465 : 587,
    ...(u.username ? { user: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { pass: decodeURIComponent(u.password) } : {}),
  };
}

export function isAddress(s: string): boolean {
  return ADDRESS.test(s);
}

interface Reply {
  code: number;
  lines: string[];
}

/** Reads SMTP replies (including multi-line ones) from a socket that may be upgraded to TLS. */
class Wire {
  private buf = "";
  private current: string[] = [];
  private replies: Reply[] = [];
  private waiting: Array<{ ok: (r: Reply) => void; fail: (e: Error) => void }> = [];
  private error: Error | null = null;
  socket!: Socket | TLSSocket;

  attach(socket: Socket | TLSSocket) {
    this.socket = socket;
    socket.setEncoding("utf8");
    socket.on("data", (d: string) => this.onData(d));
    socket.on("error", (e) => this.onError(e));
    socket.on("close", () => this.onError(new SmtpError("The mail server closed the connection.")));
  }

  private onData(d: string) {
    this.buf += d;
    let nl: number;
    while ((nl = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, nl).replace(/\r$/, "");
      this.buf = this.buf.slice(nl + 1);
      this.current.push(line);
      if (/^\d{3}(?: |$)/.test(line)) {
        const reply = { code: Number(line.slice(0, 3)), lines: this.current.map((l) => l.slice(4)) };
        this.current = [];
        const w = this.waiting.shift();
        if (w) w.ok(reply);
        else this.replies.push(reply);
      }
    }
  }

  private onError(e: Error) {
    if (this.error) return;
    this.error = e;
    for (const w of this.waiting.splice(0)) w.fail(e);
  }

  /** Stops listening to the plain socket before it's wrapped in TLS. */
  detach() {
    this.socket.removeAllListeners("data");
    this.socket.removeAllListeners("error");
    this.socket.removeAllListeners("close");
    this.buf = "";
  }

  read(): Promise<Reply> {
    const r = this.replies.shift();
    if (r) return Promise.resolve(r);
    if (this.error) return Promise.reject(this.error);
    return new Promise((ok, fail) => this.waiting.push({ ok, fail }));
  }

  write(s: string) {
    this.socket.write(s);
  }
}

/** Sends one email. Throws SmtpError with a plain-English reason on any failure. */
export async function sendMail(
  cfg: SmtpConfig,
  msg: MailMessage,
  opts: { timeoutMs?: number; tls?: ConnectionOptions; now?: Date } = {},
): Promise<void> {
  if (!isAddress(msg.from)) throw new SmtpError(`The sender address "${msg.from}" isn't a valid email address.`);
  if (msg.to.length === 0 || !msg.to.every(isAddress)) throw new SmtpError("SEAWORTHY_EMAIL_TO must be one or more valid email addresses, separated by commas.");
  const timeoutMs = opts.timeoutMs ?? 20_000;
  const wire = new Wire();

  const open = (): Promise<Socket | TLSSocket> =>
    new Promise((ok, fail) => {
      const s = cfg.secure
        ? tlsConnect({ host: cfg.host, port: cfg.port, servername: cfg.host, ...opts.tls }, () => ok(s))
        : netConnect({ host: cfg.host, port: cfg.port }, () => ok(s));
      s.once("error", (e) => fail(new SmtpError(`Couldn't connect to ${cfg.host}:${cfg.port}: ${e.message}`)));
    });

  const expect = async (codes: number[], what: string) => {
    const r = await wire.read();
    if (!codes.includes(r.code)) throw new SmtpError(`The mail server refused ${what}: ${r.code} ${r.lines.join(" ").slice(0, 200)}`);
    return r;
  };
  const say = async (line: string, codes: number[], what: string) => {
    wire.write(line + "\r\n");
    return expect(codes, what);
  };

  const run = async () => {
    wire.attach(await open());
    await expect([220], "the connection");
    let caps = (await say("EHLO seaworthy", [250], "EHLO")).lines.map((l) => l.toUpperCase());

    if (!cfg.secure) {
      if (!caps.some((c) => c.startsWith("STARTTLS"))) {
        throw new SmtpError(`${cfg.host} doesn't offer STARTTLS, so Seaworthy won't send your password unencrypted. Use smtps:// (port 465) if the server supports it.`);
      }
      await say("STARTTLS", [220], "STARTTLS");
      wire.detach();
      const plain = wire.socket;
      const secured: TLSSocket = await new Promise((ok, fail) => {
        const t = tlsConnect({ socket: plain, servername: cfg.host, ...opts.tls }, () => ok(t));
        t.once("error", (e) => fail(new SmtpError(`TLS with ${cfg.host} failed: ${e.message}`)));
      });
      wire.attach(secured);
      caps = (await say("EHLO seaworthy", [250], "EHLO")).lines.map((l) => l.toUpperCase());
    }

    if (cfg.user) {
      const auth = caps.find((c) => c.startsWith("AUTH")) ?? "";
      if (/\bPLAIN\b/.test(auth) || !/\bLOGIN\b/.test(auth)) {
        const token = Buffer.from(`\0${cfg.user}\0${cfg.pass ?? ""}`).toString("base64");
        await say(`AUTH PLAIN ${token}`, [235], "the username or password");
      } else {
        await say("AUTH LOGIN", [334], "login");
        await say(Buffer.from(cfg.user).toString("base64"), [334], "the username");
        await say(Buffer.from(cfg.pass ?? "").toString("base64"), [235], "the username or password");
      }
    }

    await say(`MAIL FROM:<${msg.from}>`, [250], "the sender address");
    for (const to of msg.to) await say(`RCPT TO:<${to}>`, [250, 251], `the recipient ${to}`);
    await say("DATA", [354], "the message");
    wire.write(formatMessage(msg, opts.now ?? new Date()));
    await expect([250], "the message");
    wire.write("QUIT\r\n");
  };

  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      run(),
      new Promise<never>((_, fail) => {
        timer = setTimeout(() => fail(new SmtpError(`The mail server at ${cfg.host} didn't answer within ${Math.round(timeoutMs / 1000)} seconds.`)), timeoutMs);
      }),
    ]);
  } catch (err) {
    throw err instanceof SmtpError ? err : new SmtpError(`Sending email failed: ${(err as Error).message}`);
  } finally {
    clearTimeout(timer);
    wire.socket?.destroy();
  }
}

const oneLine = (s: string) => s.replace(/[\r\n]+/g, " ").trim();

/** RFC 5322 message, with a base64 UTF-8 body, ending in the DATA terminator. */
export function formatMessage(msg: MailMessage, now: Date): string {
  const subject = /^[\x20-\x7e]*$/.test(oneLine(msg.subject))
    ? oneLine(msg.subject)
    : `=?UTF-8?B?${Buffer.from(oneLine(msg.subject)).toString("base64")}?=`;
  const domain = msg.from.split("@")[1] ?? "seaworthy.local";
  const body = Buffer.from(msg.text.replace(/\r?\n/g, "\r\n")).toString("base64").replace(/.{1,76}/g, "$&\r\n");
  return [
    `From: Seaworthy <${oneLine(msg.from)}>`,
    `To: ${msg.to.map(oneLine).join(", ")}`,
    `Subject: ${subject}`,
    `Date: ${now.toUTCString().replace(/GMT$/, "+0000")}`,
    `Message-ID: <${randomBytes(12).toString("hex")}@${oneLine(domain)}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: base64",
    "",
    body + ".\r\n",
  ].join("\r\n");
}
