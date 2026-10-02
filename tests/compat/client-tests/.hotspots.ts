import { parse } from "@babel/parser";
const files = process.argv.slice(2);
let total = 0;
for (const file of files) {
  const src = await Bun.file(file).text();
  const ast = parse(src, { sourceType: "module", plugins: ["typescript"] });
  const out: string[] = [];
  const text = (n: any) => src.slice(n.start, n.end);
  const fnStack: Map<string, number[]>[] = [new Map()];
  const depth = (n: any): number => n?.type === "ConditionalExpression" ? 1 + Math.max(depth(n.consequent), depth(n.alternate)) : 0;
  const memberDepth = (n: any): number => {
    let d = 0;
    while (n && (n.type === "MemberExpression" || n.type === "TSNonNullExpression" || n.type === "OptionalMemberExpression")) { if (n.type !== "TSNonNullExpression") d++; n = n.type === "TSNonNullExpression" ? n.expression : n.object; }
    return n?.type === "Identifier" ? d : 0;
  };
  const walk = (n: any, parent: any) => {
    if (!n || typeof n.type !== "string") return;
    const isFn = /Function|ArrowFunction/.test(n.type);
    if (isFn) fnStack.push(new Map());
    if (n.type === "ConditionalExpression" && parent?.type !== "ConditionalExpression" && depth(n) >= 3) out.push(`${n.loc.start.line}: nested ternary depth ${depth(n)}`);
    if (n.type === "ImportExpression" || (n.type === "CallExpression" && n.callee.type === "Import")) out.push(`${n.loc.start.line}: dynamic import`);
    if ((n.type === "MemberExpression" || n.type === "OptionalMemberExpression") && n.object.type === "AwaitExpression") out.push(`${n.loc.start.line}: (await …).${text(n.property)}`);
    if ((n.type === "MemberExpression" || n.type === "TSNonNullExpression") && !["MemberExpression", "TSNonNullExpression", "OptionalMemberExpression"].includes(parent?.type) && memberDepth(n) >= 3) {
      const t = text(n).replace(/\s+/g, "");
      const m = fnStack.at(-1)!; m.set(t, [...(m.get(t) ?? []), n.loc.start.line]);
    }
    for (const k of Object.keys(n)) { if (["loc","leadingComments","trailingComments","innerComments","extra"].includes(k)) continue; const v = n[k]; if (Array.isArray(v)) v.forEach((c) => walk(c, n)); else if (v && typeof v === "object") walk(v, n); }
    if (isFn) { for (const [t, lines] of fnStack.pop()!) if (lines.length >= 3) out.push(`${lines[0]}: ${t} x${lines.length}`); }
  };
  walk(ast.program, null);
  for (const [t, lines] of fnStack[0]!) if (lines.length >= 3) out.push(`${lines[0]}: ${t} x${lines.length}`);
  if (out.length) { total += out.length; console.log(`== ${file} (${out.length})`); for (const o of out.sort((a, b) => parseInt(a) - parseInt(b))) console.log("  " + o); }
}
console.error("TOTAL", total);
