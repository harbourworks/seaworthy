import type { Node } from "@babel/types";
import type { Confidence } from "../../core/finding.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";
import { REQUEST_INPUT_RE, analyseTaint } from "../taint.js";

/** Stripe calls that decide what a customer pays. */
const STRIPE_CREATE_RE =
  /\b(checkout\.sessions|paymentIntents|prices|invoiceItems|paymentLinks|subscriptions|subscriptionItems|setupIntents|charges|coupons)\.(create|update)\b/;
/** Fields that set the amount itself. */
const AMOUNT_KEYS = new Set(["unit_amount", "unit_amount_decimal", "amount", "amount_off", "percent_off", "application_fee_amount"]);
/** Fields that pick one of your prices: client choice is sometimes deliberate. */
const PRICE_KEYS = new Set(["price", "coupon", "promotion_code"]);

export const p02ClientPrice: Rule = {
  id: "SW-P02",
  title: "Price or amount taken from the client",
  severity: "high",
  confidence: "high",
  appliesTo: ["stripe"],
  docs: {
    summary:
      "Anything the browser sends can be edited. If your checkout takes the amount from the request, a " +
      "customer can change it and buy your Pro plan for 1p. Look the price up on the server from something " +
      "the customer is allowed to choose, such as a plan name, and use Stripe Price IDs you created.",
    bad: `const { plan, amount } = await req.json();\nstripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: amount, … } }] });`,
    good:
      `const PRICES = { pro: "price_1Pro…", team: "price_1Team…" };\nconst { plan } = await req.json();\n` +
      `const price = PRICES[plan];\nif (!price) return new Response("Unknown plan", { status: 400 });\n` +
      `stripe.checkout.sessions.create({ line_items: [{ price, quantity: 1 }], … });`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text || !STRIPE_CREATE_RE.test(text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);
      const { isTainted } = analyseTaint(ast, text, {
        source: REQUEST_INPUT_RE,
        allParams: /^\s*["']use server["']/m.test(text),
        routeParams: true,
      });
      /** Request input reaching a value, except through a lookup in your own table (PRICES[plan]). */
      const reaches = (e: Node): boolean => {
        if (e.type === "LogicalExpression") return reaches(e.left as Node) || reaches(e.right as Node);
        if (e.type === "ConditionalExpression") return reaches(e.consequent as Node) || reaches(e.alternate as Node);
        if (e.type === "MemberExpression" && e.computed && !isTainted(e.object as Node)) return false;
        // Number(amount), parseInt(amount), Math.round(amount * 100): still the client's number.
        return isTainted(e);
      };
      /** Where the value was read from the request, for the "why". */
      const sourceLine = (e: Node): number | null => {
        const name = e.type === "Identifier" ? e.name : null;
        if (!name) return null;
        const m = new RegExp(`\\b${name}\\b[^;\\n]*=\\s*(await\\s+)?[^;\\n]*(req|request|searchParams|formData)`).exec(text) ??
          new RegExp(`\\{[^}]*\\b${name}\\b[^}]*\\}\\s*=\\s*(await\\s+)?[^;\\n]*(req|request|formData)`).exec(text);
        return m ? project.position(file, m.index).line : null;
      };

      walkAst(ast, (n) => {
        if (n.type !== "CallExpression" || !STRIPE_CREATE_RE.test(src(n.callee as Node))) return;
        walkAst(n, (p) => {
          if (p.type !== "ObjectProperty") return;
          const key = p.key.type === "Identifier" ? p.key.name : p.key.type === "StringLiteral" ? p.key.value : "";
          const amount = AMOUNT_KEYS.has(key);
          if (!amount && !PRICE_KEYS.has(key)) return;
          const value = p.value as Node;
          if (!reaches(value)) return;
          const confidence: Confidence = amount ? "high" : "medium";
          const from = sourceLine(value);
          out.push({
            file,
            ...project.position(file, p.start ?? 0),
            confidence,
            title: amount ? `Stripe ${key} comes from the request` : `Stripe ${key} is chosen by the client`,
            why: amount
              ? `\`${key}\` is set from \`${src(value)}\`, which the browser sends${from ? ` (read on line ${from})` : ""}. Anyone can edit ` +
                `the request and pay whatever they like, down to the smallest amount Stripe allows.`
              : `The client picks the Stripe ${key} (\`${src(value)}\`${from ? `, read on line ${from}` : ""}). Unless you check it ` +
                `against the ones on offer, a customer can pick any active ${key} in your Stripe account, including ` +
                `cheaper or internal ones.`,
            fix: amount
              ? `Don't take amounts from the client. Look the price up on the server, for example ` +
                `\`const price = PRICES[plan]\` mapping each plan to a Stripe Price ID, and pass \`{ price, quantity: 1 }\`.`
              : `Map what the customer chooses to your own list on the server, such as \`PRICES[plan]\`, and reject anything not in it.`,
            fixPrompt:
              `In ${file}, the Stripe ${key} comes from the request (\`${src(value)}\`). Change the checkout so the server ` +
              `decides the price: accept only a plan identifier from the client, map it to a Stripe Price ID in a server-side ` +
              `table, return 400 for unknown plans, and never use an amount or ${key} sent by the browser.`,
          });
        });
        return false;
      });
    }
    return out;
  },
};
