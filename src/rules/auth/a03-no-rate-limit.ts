import type { ProjectFiles } from "../../core/project.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles, importsOf, resolveImport } from "../code.js";
import { APP_ROUTE_RE, PAGES_API_RE, handlers, routeUrl } from "./a01-no-auth-check.js";

/** What makes an endpoint worth abusing, and what it costs you. */
const COSTLY: Array<{ re: RegExp; what: string }> = [
  {
    re: /\b(chat\.completions|completions|responses|messages|embeddings|images)\.(create|generate)\s*\(|\b(generateText|streamText|generateObject|streamObject|generateImage)\s*\(|\bgenerateContent(Stream)?\s*\(/,
    what: "calls a paid AI model, so anyone can run up your bill by calling it in a loop",
  },
  {
    re: /\b(emails?|mail)\.send\s*\(|\bsendMail\s*\(|\bsgMail\.send\s*\(|\bresend\.\w+\.send\s*\(|\bpostmark|\bsendEmail\s*\(/,
    what: "sends email, so anyone can use it to spam people from your domain and burn your sending reputation",
  },
  { re: /\btwilio\b[\s\S]*\bmessages\.create\s*\(|\bsendSms\s*\(|\bverify\.v2\b/, what: "sends SMS, which costs money per message and is a favourite for fraud" },
  {
    re: /\b(bcrypt|bcryptjs|argon2)\.(compare|verify)\s*\(|\bverifyPassword\s*\(/,
    what: "checks passwords, so without a limit anyone can try thousands of guesses",
  },
];
/** Rate limiting in code: libraries and the usual helper names. */
const LIMITER_RE =
  /\b(ratelimit|rateLimit|rateLimiter|RateLimiter|limiter|throttle|slowDown)\b|@upstash\/ratelimit|rate-limiter-flexible|express-rate-limit|\baj\.protect\s*\(|@arcjet|\bslidingWindow\s*\(|\bfixedWindow\s*\(|\btokenBucket\s*\(/i;

export const a03NoRateLimit: Rule = {
  id: "SW-A03",
  title: "Costly or sensitive endpoint with no rate limit",
  severity: "medium",
  confidence: "high",
  appliesTo: ["nextjs"],
  docs: {
    summary:
      "Endpoints that call paid AI models, send email or SMS, or check passwords are the ones attackers " +
      "script: a loop of requests can cost you hundreds of pounds overnight or crack a weak password. A rate " +
      "limit per user or IP stops that. Checks that need a login still need a limit, because accounts are free.",
    bad: `export async function POST(req) {\n  const { message } = await req.json();\n  return Response.json(await openai.chat.completions.create({ … }));\n}`,
    good:
      `const ratelimit = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(20, "1 m") });\n` +
      `export async function POST(req) {\n  const { success } = await ratelimit.limit(userId ?? ip);\n` +
      `  if (!success) return new Response("Too many requests", { status: 429 });\n  …\n}`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    if (middlewareLimits(project)) return out;
    for (const file of codeFiles(project)) {
      const appRoute = APP_ROUTE_RE.test(file);
      const pagesApi = PAGES_API_RE.test(file);
      const text = project.read(file);
      if (!text) continue;
      const serverActions = !appRoute && !pagesApi && /^\s*["']use server["']/m.test(text);
      if (!appRoute && !pagesApi && !serverActions) continue;
      if (!COSTLY.some((c) => c.re.test(text))) continue;
      if (LIMITER_RE.test(text) || helpersLimit(project, file, text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const url = routeUrl(file);
      for (const h of handlers(ast, appRoute, pagesApi)) {
        const body = text.slice(h.fn.start ?? 0, h.fn.end ?? 0);
        const cost = COSTLY.find((c) => c.re.test(body));
        if (!cost) continue;
        const label = serverActions ? `Server action ${h.name}` : `${h.method ?? "Handler"} ${url ?? file}`;
        out.push({
          file,
          ...project.position(file, h.at),
          title: `${label} has no rate limit`,
          why: `This ${serverActions ? "action" : "endpoint"} ${cost.what}. Nothing limits how often one user or IP address can call it.`,
          fix:
            `Add a per-user or per-IP limit before the expensive work, for example with @upstash/ratelimit ` +
            `(\`Ratelimit.slidingWindow(20, "1 m")\`), and return 429 when it's exceeded. Also set a spending cap ` +
            `with your AI, email or SMS provider.`,
          fixPrompt:
            `In ${file}, the ${serverActions ? `server action ${h.name}` : `${h.method ?? ""} handler`.trim()} ${cost.what}, and it has no ` +
            `rate limit. Add rate limiting keyed by the signed-in user's ID (or the client IP if there is no user), ` +
            `return 429 with a Retry-After header when exceeded, using a store that works on serverless (such as ` +
            `Upstash Redis), and tell me what spending cap to set with the provider.`,
        });
      }
    }
    return out;
  },
};

/** Middleware that rate-limits covers every route it runs on. */
function middlewareLimits(project: ProjectFiles): boolean {
  const file = project.files.find((f) => /^(src\/)?middleware\.[cm]?[jt]s$/.test(f));
  return !!file && LIMITER_RE.test(project.read(file) ?? "");
}

/** A local module the route imports does the limiting (for example lib/ratelimit.ts). */
function helpersLimit(project: ProjectFiles, file: string, text: string): boolean {
  for (const spec of importsOf(file, text)) {
    const target = resolveImport(project, file, spec);
    if (target && LIMITER_RE.test(project.read(target) ?? "")) return true;
  }
  return false;
}
