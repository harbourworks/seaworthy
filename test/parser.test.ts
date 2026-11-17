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

describe("parseJs: decorators", () => {
  const mobx = "class Settings { @observable accessor busy = false; }\nexport interface Opts { dangerouslyAllowBrowser: boolean }\n";
  const angular =
    "@Component({ selector: 'app-chat', template: '<p>{{ name }}</p>' })\n" +
    "export class ChatComponent {\n  @Input() name: string = '';\n  @Output() sent = new EventEmitter<string>();\n" +
    "  constructor(@Inject(API) private api: Api) {}\n  @HostListener('click', ['$event']) onClick(e: Event) {}\n}\n";
  const decorators = (ast: Node | null) => types(ast).filter((t) => t === "Decorator").length;

  it("parses a decorated accessor field next to an interface (the MobX and Lit pattern)", () => {
    const ast = parseJs("src/store.ts", mobx);
    expect(ast).not.toBeNull();
    expect(types(ast)).toEqual(expect.arrayContaining(["Decorator", "ClassAccessorProperty", "TSInterfaceDeclaration"]));
  });
  it("parses Angular-style class, member and parameter decorators", () => {
    expect(decorators(parseJs("src/chat.component.ts", angular))).toBe(5);
  });
  it.each(["a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.mts", "a.cts", "a.tsx"])("parses decorators in %s", (file) => {
    const ast = parseJs(file, "@sealed\nclass S {\n  @observable accessor n = 0;\n  @action.bound inc() { this.n++; }\n}\n");
    expect(decorators(ast)).toBe(3);
    expect(types(ast)).toContain("ClassAccessorProperty");
  });
  it("parses decorators before or after `export`", () => {
    expect(decorators(parseJs("a.ts", "@dec export class A {}\n@dec export default class B {}\n"))).toBe(2);
    expect(decorators(parseJs("a.ts", "export @dec class A { @dec accessor x = 1 }\n"))).toBe(2);
    expect(decorators(parseJs("a.tsx", "export default @dec class A {}\nexport const C = () => <p>hi</p>;\n"))).toBe(1);
  });
  it("leaves `@` in JSX text and strings alone", () => {
    const ast = parseJs("a.tsx", "export const A = () => <p>email me @ home, '@dec'</p>;\nconst s = '@x';\n");
    expect(decorators(ast)).toBe(0);
    expect(types(ast)).toContain("JSXElement");
  });
  it("still returns null for a file that isn't code", () => {
    expect(parseJs("a.ts", "@@@ {{{ not code")).toBeNull();
  });
});
