import type { Node } from "@babel/types";
import type { ProjectFiles } from "../../core/project.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, importsOf, resolveImport } from "../code.js";

/** Event types a Stripe webhook handler branches on. */
// Only real Stripe event endings, so that i18n keys such as "invoice.total" don't count.
const EVENT_SOURCE =
  String.raw`(checkout\.session|customer\.subscription|customer|invoice|payment_intent|payment_method|charge|` +
  String.raw`subscription_schedule|setup_intent|price|product)\.(created|updated|deleted|completed|expired|succeeded|` +
  String.raw`failed|paid|payment_failed|payment_succeeded|payment_action_required|finalized|upcoming|canceled|processing|` +
  String.raw`requires_action|refunded|captured|trial_will_end|paused|resumed|attached|detached|voided|` +
  String.raw`marked_uncollectible|async_payment_succeeded|async_payment_failed|dispute\.created)`;
const STRIPE_EVENT_RE = new RegExp(`^${EVENT_SOURCE}$`);
const STRIPE_EVENT_TEXT_RE = new RegExp(`["'\`]${EVENT_SOURCE}["'\`]`);
/** Ways a handler proves the event came from Stripe. */
const VERIFIES_RE = /\bconstructEvent(Async)?\s*\(|\bwebhooks\.signature\b|\bevents\.retrieve\s*\(/;
const WEBHOOK_PATH_RE = /(^|\/)[^/]*webhook[^/]*(\/|\.)/i;

export const p01WebhookUnverified: Rule = {
  id: "SW-P01",
  title: "Stripe webhook does not verify the signature",
  severity: "critical",
  confidence: "high",
  appliesTo: ["stripe"],
  docs: {
    summary:
      "Your webhook URL is public, so anyone can send it a request that looks like a Stripe event. " +
      "If the handler trusts the body without checking Stripe's signature, a single fake " +
      "`checkout.session.completed` gives someone a paid plan for free. Stripe signs every event; " +
      "`stripe.webhooks.constructEvent` checks that signature against your endpoint's secret.",
    bad: `export async function POST(req: Request) {\n  const event = JSON.parse(await req.text());\n  if (event.type === "checkout.session.completed") { /* upgrade the user */ }\n}`,
    good:
      `export async function POST(req: Request) {\n  const sig = req.headers.get("stripe-signature")!;\n` +
      `  const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET!);\n` +
      `  if (event.type === "checkout.session.completed") { /* upgrade the user */ }\n}`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text) continue;
      const handler = analyse(file, text);
      if (!handler.handlesStripeEvents) continue;
      if (VERIFIES_RE.test(text) || helperVerifies(project, file, text)) continue;
      const inWebhookPath = WEBHOOK_PATH_RE.test(file);
      out.push({
        file,
        ...project.position(file, handler.bodyOffset ?? handler.eventOffset),
        // Event names alone could be a test helper or a shared type; a webhook path settles it.
        confidence: inWebhookPath || handler.bodyOffset !== null ? "high" : "medium",
        why:
          `This handler acts on Stripe events (such as "${handler.example}") from the request body without ` +
          `checking Stripe's signature. Anyone who finds the URL can send a fake event, for example a completed ` +
          `checkout, and your app will treat it as a real payment.`,
        fix:
          `Read the raw body with \`await req.text()\`, then verify it: ` +
          `\`stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature")!, process.env.STRIPE_WEBHOOK_SECRET!)\`. ` +
          `Return 400 if it throws, and use the event it returns instead of the parsed body.`,
        fixPrompt:
          `In ${file}, my Stripe webhook handler parses the request body and trusts it without verifying Stripe's ` +
          `signature. Change it to read the raw body with req.text(), verify it with stripe.webhooks.constructEvent ` +
          `using the stripe-signature header and STRIPE_WEBHOOK_SECRET, return a 400 response if verification fails, ` +
          `and use only the verified event.`,
      });
    }
    return out;
  },
};

interface Analysis {
  handlesStripeEvents: boolean;
  example: string;
  /** Where the body is parsed: JSON.parse(…), req.json(), req.body. */
  bodyOffset: number | null;
  eventOffset: number;
}

function analyse(file: string, text: string): Analysis {
  const none = { handlesStripeEvents: false, example: "", bodyOffset: null, eventOffset: 0 };
  const ast = astOf(file, text);
  if (!ast) {
    const m = STRIPE_EVENT_TEXT_RE.exec(text);
    if (!m) return none;
    const body = /JSON\.parse\s*\(|\b(req|request)\.json\s*\(|\breq\.body\b/.exec(text);
    return { handlesStripeEvents: true, example: m[0].slice(1, -1), bodyOffset: body?.index ?? null, eventOffset: m.index };
  }
  let example = "";
  let eventOffset = 0;
  let bodyOffset: number | null = null;
  walkAst(ast, (n: Node) => {
    if (n.type === "StringLiteral" && STRIPE_EVENT_RE.test(n.value) && !example) {
      example = n.value;
      eventOffset = n.start ?? 0;
    }
    if (bodyOffset === null && n.type === "CallExpression") {
      const c = n.callee;
      // JSON.parse(…)
      if (c.type === "MemberExpression" && c.object.type === "Identifier" && c.object.name === "JSON" &&
          c.property.type === "Identifier" && c.property.name === "parse") bodyOffset = n.start ?? null;
      // req.json() / request.json()
      if (c.type === "MemberExpression" && c.property.type === "Identifier" && c.property.name === "json" &&
          c.object.type === "Identifier" && /^(req|request)$/.test(c.object.name)) bodyOffset = n.start ?? null;
    }
    // req.body (Express, pages/api)
    if (bodyOffset === null && n.type === "MemberExpression" && n.object.type === "Identifier" &&
        /^(req|request)$/.test(n.object.name) && n.property.type === "Identifier" && n.property.name === "body") {
      bodyOffset = n.start ?? null;
    }
  });
  // Without event names, a JSON.parse is just a JSON.parse.
  return { handlesStripeEvents: example !== "", example, bodyOffset, eventOffset };
}

/** The handler may verify in a local helper: follow its local imports one level. */
function helperVerifies(project: ProjectFiles, file: string, text: string): boolean {
  for (const spec of importsOf(file, text)) {
    const target = resolveImport(project, file, spec);
    if (target && VERIFIES_RE.test(project.read(target) ?? "")) return true;
  }
  return false;
}
