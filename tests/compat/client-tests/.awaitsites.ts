import { parse } from "@babel/parser";
const counts = new Map<string, number>();
for (const file of process.argv.slice(2)) {
  const src = await Bun.file(file).text();
  const ast = parse(src, { sourceType: "module", plugins: ["typescript"] });
  const walk = (n: any) => {
    if (!n || typeof n.type !== "string") return;
    if ((n.type === "MemberExpression" || n.type === "OptionalMemberExpression") && n.object.type === "AwaitExpression") {
      let c = n.object.argument; while (c?.type === "TSNonNullExpression") c = c.expression;
      const callee = c?.type === "CallExpression" ? src.slice(c.callee.start, c.callee.end).replace(/\s+/g, "") : c?.type;
      const key = `${callee} .${src.slice(n.property.start, n.property.end)}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    for (const k of Object.keys(n)) { if (["loc","leadingComments","trailingComments","innerComments","extra"].includes(k)) continue; const v = n[k]; if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === "object") walk(v); }
  };
  walk(ast.program);
}
for (const [k, v] of [...counts].sort((a, b) => b[1] - a[1]).slice(0, 45)) console.log(v, k);
