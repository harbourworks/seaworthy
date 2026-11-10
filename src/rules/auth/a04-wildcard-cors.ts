import type { Node } from "@babel/types";
import type { Confidence } from "../../core/finding.js";
import { walkAst } from "../../core/js.js";
import type { RawFinding, Rule } from "../types.js";
import { astOf, codeFiles } from "../code.js";

const ORIGIN_KEY = /^access-control-allow-origin$/i;
const CREDS_KEY = /^access-control-allow-credentials$/i;

export const a04WildcardCors: Rule = {
  id: "SW-A04",
  title: "CORS lets any site make credentialed requests",
  severity: "medium",
  confidence: "high",
  appliesTo: [],
  docs: {
    summary:
      "CORS decides which other websites can call your API from a visitor's browser. Allowing every origin " +
      "is fine for a public API with no logins. Combined with credentials (cookies or auth headers), it lets " +
      "any website the user visits act as them. Browsers refuse `*` with credentials, so the usual next step " +
      "is echoing back the request's Origin header, which does exactly that.",
    bad: `"Access-Control-Allow-Origin": "*",\n"Access-Control-Allow-Credentials": "true",`,
    good: `const ALLOWED = ["https://app.example.com"];\nconst origin = req.headers.get("origin");\nif (origin && ALLOWED.includes(origin)) headers.set("Access-Control-Allow-Origin", origin);`,
  },

  check({ project }) {
    const out: RawFinding[] = [];
    for (const file of codeFiles(project)) {
      const text = project.read(file);
      if (!text || !/access-control-allow-origin|\bcors\s*\(/i.test(text)) continue;
      const ast = astOf(file, text);
      if (!ast) continue;
      const src = (n: Node) => text.slice(n.start ?? 0, n.end ?? 0);
      const credentials = /access-control-allow-credentials["'`]?\s*[:,]\s*["'`]?true/i.test(text);
      const report = (at: Node, kind: "wildcard" | "reflect" | "cors-pkg", confidence: Confidence) =>
        out.push({
          file,
          ...project.position(file, at.start ?? 0),
          confidence,
          title:
            kind === "reflect"
              ? "CORS echoes back any origin, with credentials"
              : kind === "cors-pkg"
                ? "cors() allows every origin, with credentials"
                : "Wildcard CORS with credentials",
          why:
            kind === "reflect"
              ? `This copies the request's Origin header into Access-Control-Allow-Origin and allows credentials, so any ` +
                `website a signed-in user visits can call this API as them and read the answers.`
              : `This allows every origin and also allows credentials. Browsers reject that exact pair, so it either ` +
                `breaks or gets "fixed" by echoing the Origin back, which lets any website call this API as a signed-in user.`,
          fix:
            `List the origins that may call this API, such as \`["https://yourapp.com"]\`, and only set ` +
            `Access-Control-Allow-Origin when the request's Origin is on that list. Drop credentials if you don't need cookies cross-site.`,
          fixPrompt:
            `In ${file}, CORS allows any origin together with credentials. Replace it with an allow-list of my app's own ` +
            `origins: set Access-Control-Allow-Origin to the request's Origin only when it's on the list, add Vary: Origin, ` +
            `and keep credentials only if cross-site cookies are really needed.`,
        });

      walkAst(ast, (n) => {
        // Header objects and headers.set(...) calls.
        if (n.type === "ObjectProperty") {
          const key = n.key.type === "StringLiteral" ? n.key.value : n.key.type === "Identifier" ? n.key.name : "";
          if (ORIGIN_KEY.test(key) && credentials) {
            const v = n.value as Node;
            if (v.type === "StringLiteral" && v.value === "*") report(n, "wildcard", "high");
            else if (/origin/i.test(src(v)) && /headers\.get|headers\[|req\.headers|request\.headers/.test(src(v))) report(n, "reflect", "high");
          }
          return;
        }
        if (n.type === "CallExpression") {
          const c = n.callee;
          const name = c.type === "Identifier" ? c.name : c.type === "MemberExpression" && c.property.type === "Identifier" ? c.property.name : "";
          const [a0, a1] = n.arguments as Node[];
          if ((name === "set" || name === "setHeader" || name === "append" || name === "header") && a0?.type === "StringLiteral" && ORIGIN_KEY.test(a0.value) && a1 && credentials) {
            if (a1.type === "StringLiteral" && a1.value === "*") report(n, "wildcard", "high");
            else if (/origin/i.test(src(a1)) && /headers/.test(src(a1))) report(n, "reflect", "high");
          }
          // cors({ origin: true | "*", credentials: true }) from the cors package.
          if (name === "cors" && a0?.type === "ObjectExpression") {
            const get = (k: string) => {
              const p = a0.properties.find((x) => x.type === "ObjectProperty" && x.key.type === "Identifier" && x.key.name === k);
              return p && p.type === "ObjectProperty" ? (p.value as Node) : null;
            };
            const origin = get("origin");
            const creds = get("credentials");
            const anyOrigin = origin && ((origin.type === "BooleanLiteral" && origin.value) || (origin.type === "StringLiteral" && origin.value === "*"));
            if (anyOrigin && creds?.type === "BooleanLiteral" && creds.value) report(n, "cors-pkg", "high");
          }
        }
      });
    }
    return out;
  },
};
