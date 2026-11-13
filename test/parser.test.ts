import { describe, expect, it } from "vitest";
import type { Node } from "@babel/types";
import { parseJs, walkAst } from "../src/core/js.js";

/** Node types in a parsed file, in walk order. */
const types = (ast: Node | null) => {
  const out: string[] = [];
  if (ast) walkAst(ast, (n) => void out.push(n.type));
  return out;
};

describe("parseJs: class accessor fields", () => {
  const cls = "class Store {\n  accessor count = 0;\n  static accessor #hidden = 1;\n}\n";

  it("parses an accessor field in a .ts file", () => {
    const ast = parseJs("lib/store.ts", cls + "interface Opts { dangerouslyAllowBrowser: boolean }\n");
    expect(ast).not.toBeNull();
    expect(types(ast)).toContain("ClassAccessorProperty");
    expect(types(ast)).toContain("TSInterfaceDeclaration");
  });
  it.each(["a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.mts", "a.cts", "a.tsx"])("parses one in %s", (file) => {
    expect(types(parseJs(file, cls))).toContain("ClassAccessorProperty");
  });
  it("parses a typed accessor in .tsx alongside JSX", () => {
    const ast = parseJs("a.tsx", "class S { accessor n: number = 0 }\nexport const A = () => <p>{new S().n}</p>;\n");
    expect(types(ast)).toEqual(expect.arrayContaining(["ClassAccessorProperty", "JSXElement"]));
  });
  it("still treats `accessor` as a plain name where it is one", () => {
    const ast = parseJs(
      "a.ts",
      "const accessor = 1;\nclass A { accessor; accessor = 2; accessor() { return accessor; } }\n",
    );
    expect(types(ast)).not.toContain("ClassAccessorProperty");
    expect(types(ast).filter((t) => t === "ClassProperty")).toHaveLength(2);
    expect(types(ast)).toContain("ClassMethod");
  });
});
