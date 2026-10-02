import { parse } from "@babel/parser";
import { createInstrumenter } from "istanbul-lib-instrument";
import { readFile, readdir, rm } from "node:fs/promises";
import { join, relative } from "node:path";
import { digest, filesUnder, upstreamPin, writeJSON } from "./common";
import { upstreamSource, verifiedPublishedRoots } from "./source";

type Node = {
  type: string;
  start: number;
  end: number;
  loc?: { start: { line: number } };
  [key: string]: unknown;
};
export type Source = {
  id: string;
  package: string;
  path: string;
  origin: "published" | "repository";
  sha256: string;
};
export type Surface = {
  id: string;
  source: string;
  kind:
    | "package"
    | "source-file"
    | "export"
    | "option"
    | "upstream-test"
    | "test-file"
    | "branch"
    | "function"
    | "unmeasured-control-flow";
  name: string;
  line: number;
  start?: number;
  end?: number;
  snippetHash?: string;
  dynamic?: boolean;
};
export type SourceMutation = {
  id: string;
  source: string;
  sourceHash: string;
  start: number;
  end: number;
  original: string;
  replacement: string;
  operator: "negate-condition" | "boundary" | "omit-effect";
  line: number;
};
export type Inventory = {
  schemaVersion: 1;
  version: string;
  commit: string;
  digest: string;
  sources: Source[];
  surfaces: Surface[];
  mutations: SourceMutation[];
};

function node(value: unknown): value is Node {
  return (
    !!value &&
    typeof value === "object" &&
    "type" in value &&
    typeof value.type === "string"
  );
}
function children(value: Node): Node[] {
  return Object.entries(value)
    .filter(
      ([key]) =>
        ![
          "loc",
          "comments",
          "leadingComments",
          "trailingComments",
          "innerComments",
          "extra",
        ].includes(key),
    )
    .flatMap(([, child]) =>
      Array.isArray(child) ? child.filter(node) : node(child) ? [child] : [],
    );
}
function named(value: unknown): string | undefined {
  if (!node(value)) return;
  if (value.type === "Identifier") return String(value.name);
  if (value.type === "StringLiteral") return String(value.value);
}
function ast(source: string, types: boolean): Node {
  return parse(source, {
    sourceType: "module",
    plugins: types ? ["typescript", "jsx"] : [],
    errorRecovery: false,
  }) as unknown as Node;
}
function surface(
  source: Source,
  text: string,
  value: Node,
  kind: Surface["kind"],
  name: string,
): Surface {
  return {
    id: `${source.id}#${kind}:${value.start}:${value.end}:${name}`,
    source: source.id,
    kind,
    name,
    line: value.loc?.start.line ?? 1,
    start: value.start,
    end: value.end,
    snippetHash: digest(text.slice(value.start, value.end)),
  };
}

/** Extract from upstream alone. Test templates stay templates; no guessed parameter expansion. */
export function sourceSurfaces(source: Source, text: string): Surface[] {
  const root = ast(text, /\.[cm]?tsx?$/.test(source.path));
  const result: Surface[] = [];
  const bindings = new Map<string, "suite" | "case">();
  const modifiers = new Set([
    "each",
    "for",
    "runIf",
    "skipIf",
    "skip",
    "only",
    "todo",
    "concurrent",
    "sequential",
    "fails",
  ]);
  function testRoot(
    value: unknown,
    scope: ReadonlyMap<string, "suite" | "case">,
  ): "suite" | "case" | undefined {
    if (!node(value)) return;
    if (value.type === "Identifier") return scope.get(String(value.name));
    if (
      value.type === "MemberExpression" &&
      !value.computed &&
      modifiers.has(named(value.property) ?? "")
    )
      return testRoot(value.object, scope);
    if (value.type === "CallExpression") return testRoot(value.callee, scope);
    if (value.type === "TaggedTemplateExpression")
      return testRoot(value.tag, scope);
  }
  const program = root.program as Node;
  for (const value of program.body as Node[]) {
    if (
      value.type === "ImportDeclaration" &&
      node(value.source) &&
      ["vitest", "bun:test", "node:test"].includes(String(value.source.value))
    ) {
      for (const specifier of value.specifiers as Node[]) {
        const imported = named(specifier.imported),
          local = named(specifier.local);
        if (
          local &&
          imported &&
          ["test", "it", "describe", "suite"].includes(imported)
        )
          bindings.set(
            local,
            ["describe", "suite"].includes(imported) ? "suite" : "case",
          );
      }
    }
  }
  function options(value: Node, parent: string) {
    // Callback arguments describe hook context, not additional configuration keys.
    if (
      [
        "TSFunctionType",
        "TSMethodSignature",
        "TSCallSignatureDeclaration",
        "TSConstructorType",
      ].includes(value.type)
    )
      return;
    if (value.type === "TSPropertySignature") {
      const name =
        named(value.key) ??
        text.slice((value.key as Node).start, (value.key as Node).end);
      parent = `${parent}.${name}`;
      result.push(surface(source, text, value, "option", parent));
    }
    for (const child of children(value)) options(child, parent);
  }
  function visit(
    value: Node,
    scope: Map<string, "suite" | "case">,
    suites: string[],
  ) {
    let nested = suites;
    if (
      [
        "FunctionDeclaration",
        "FunctionExpression",
        "ArrowFunctionExpression",
      ].includes(value.type)
    ) {
      scope = new Map(scope);
      for (const param of (value.params as Node[]) ?? []) {
        const name = named(param);
        if (name) scope.delete(name);
      }
    }
    if (value.type === "BlockStatement") scope = new Map(scope);
    if (value.type === "VariableDeclarator" && named(value.id)) {
      const name = named(value.id)!;
      const init = value.init;
      const extended =
        node(init) &&
        init.type === "CallExpression" &&
        node(init.callee) &&
        init.callee.type === "MemberExpression" &&
        named(init.callee.property) === "extend"
          ? testRoot(init.callee.object, scope)
          : undefined;
      scope.delete(name);
      if (extended) scope.set(name, extended);
    }
    if (value.type === "CallExpression") {
      const kind = testRoot(value.callee, scope),
        args = value.arguments as Node[];
      const title = args[0];
      const callback = args.some((arg) =>
        ["ArrowFunctionExpression", "FunctionExpression"].includes(arg.type),
      );
      const deferred = text
        .slice((value.callee as Node).start, (value.callee as Node).end)
        .endsWith(".todo");
      if (
        kind &&
        title &&
        (callback || deferred) &&
        ![
          "ObjectExpression",
          "ArrayExpression",
          "ArrowFunctionExpression",
        ].includes(title.type)
      ) {
        const name =
          title.type === "StringLiteral"
            ? String(title.value)
            : text.slice(title.start, title.end);
        if (kind === "case")
          result.push({
            ...surface(
              source,
              text,
              value,
              "upstream-test",
              [...suites, name].join(" > "),
            ),
            dynamic:
              title.type !== "StringLiteral" ||
              (value.callee as Node).type !== "Identifier",
          });
        else nested = [...suites, name];
      }
    }
    if (
      ["TSTypeAliasDeclaration", "TSInterfaceDeclaration"].includes(
        value.type,
      ) &&
      /(?:Options|Config)$/.test(named(value.id) ?? "")
    ) {
      options(value, named(value.id)!);
    }
    if (value.type === "ExportNamedDeclaration") {
      if (node(value.declaration)) {
        const declaration = value.declaration;
        const declarations =
          declaration.type === "VariableDeclaration"
            ? (declaration.declarations as Node[])
            : [declaration];
        for (const item of declarations) {
          const name = named(item.id);
          if (name) result.push(surface(source, text, item, "export", name));
        }
      }
      for (const specifier of (value.specifiers as Node[]) ?? []) {
        const name = named(specifier.exported);
        if (name) result.push(surface(source, text, specifier, "export", name));
      }
    }
    if (value.type === "ExportAllDeclaration")
      result.push(
        surface(source, text, value, "export", `* from ${named(value.source)}`),
      );
    if (value.type === "ExportDefaultDeclaration")
      result.push(surface(source, text, value, "export", "default"));
    for (const child of children(value)) visit(child, scope, nested);
  }
  visit(root, bindings, []);
  return result;
}

export function runtimeEvidence(source: Source, text: string) {
  const instrumenter = createInstrumenter({
    esModules: true,
    compact: true,
    coverageVariable: "__compatCoverage",
  });
  instrumenter.instrumentSync(text, source.id);
  const coverage = instrumenter.lastFileCoverage();
  const surfaces: Surface[] = [];
  for (const [id, branch] of Object.entries(coverage.branchMap)) {
    branch.locations.forEach((location, arm) =>
      surfaces.push({
        id: `${source.id}#branch:${id}:${arm}`,
        source: source.id,
        kind: "branch",
        name: `${branch.type} arm ${arm}`,
        line: location.start?.line ?? branch.loc.start.line,
      }),
    );
  }
  for (const [id, fn] of Object.entries(coverage.fnMap))
    surfaces.push({
      id: `${source.id}#function:${id}`,
      source: source.id,
      kind: "function",
      name: fn.name,
      line: fn.loc.start.line,
    });
  const mutations: SourceMutation[] = [];
  function add(
    value: Node,
    operator: SourceMutation["operator"],
    replacement: string,
  ) {
    const original = text.slice(value.start, value.end);
    mutations.push({
      id: `${source.id}#${operator}:${value.start}:${value.end}`,
      source: source.id,
      sourceHash: source.sha256,
      start: value.start,
      end: value.end,
      original,
      replacement,
      operator,
      line: value.loc?.start.line ?? 1,
    });
  }
  function visit(value: Node) {
    if (
      [
        "OptionalMemberExpression",
        "OptionalCallExpression",
        "ForStatement",
        "ForOfStatement",
        "ForInStatement",
        "WhileStatement",
        "DoWhileStatement",
        "CatchClause",
      ].includes(value.type)
    )
      surfaces.push(
        surface(source, text, value, "unmeasured-control-flow", value.type),
      );
    if (
      ["IfStatement", "ConditionalExpression"].includes(value.type) &&
      node(value.test)
    )
      add(
        value.test,
        "negate-condition",
        `!(${text.slice(value.test.start, value.test.end)})`,
      );
    if (
      value.type === "BinaryExpression" &&
      ["<", "<=", ">", ">="].includes(String(value.operator)) &&
      node(value.left) &&
      node(value.right)
    ) {
      const changed = { "<": "<=", "<=": "<", ">": ">=", ">=": ">" }[
        String(value.operator)
      ]!;
      add(
        value,
        "boundary",
        `(${text.slice(value.left.start, value.left.end)}) ${changed} (${text.slice(value.right.start, value.right.end)})`,
      );
    }
    if (
      value.type === "AwaitExpression" &&
      node(value.argument) &&
      value.argument.type === "CallExpression" &&
      node(value.argument.callee) &&
      value.argument.callee.type === "MemberExpression"
    ) {
      const effect = named(value.argument.callee.property) ?? "";
      if (/^(?:delete|update|create|consume|send|revoke)/.test(effect))
        add(value, "omit-effect", "undefined");
    }
    // Delivery callbacks are frequently passed to runInBackgroundOrAwait.
    if (
      value.type === "CallExpression" &&
      node(value.callee) &&
      value.callee.type === "MemberExpression" &&
      /^send/.test(named(value.callee.property) ?? "")
    )
      add(value, "omit-effect", "undefined");
    for (const child of children(value)) visit(child);
  }
  visit(ast(text, false));
  return { surfaces, mutations };
}

async function buildInventory(): Promise<Inventory> {
  const sources: Source[] = [],
    surfaces: Surface[] = [],
    mutations: SourceMutation[] = [];
  for (const { name, root } of await verifiedPublishedRoots()) {
    const text = await readFile(join(root, "package.json"), "utf8");
    const manifest: Source = {
      id: `npm:${name}/package.json`,
      package: name,
      path: "package.json",
      origin: "published",
      sha256: digest(text),
    };
    sources.push(manifest);
    const exports = (JSON.parse(text) as { exports?: unknown }).exports;
    if (exports && typeof exports === "object")
      for (const path of Object.keys(exports))
        surfaces.push({
          id: `${manifest.id}#export:${path}`,
          source: manifest.id,
          kind: "export",
          name: path,
          line: 1,
        });
    for (const path of (await filesUnder(join(root, "dist"))).filter((path) =>
      /\.(?:mjs|d\.mts)$/.test(path),
    )) {
      const text = await readFile(path, "utf8"),
        relativePath = relative(root, path).replaceAll("\\", "/");
      const source: Source = {
        id: `npm:${name}/${relativePath}`,
        package: name,
        path: relativePath,
        origin: "published",
        sha256: digest(text),
      };
      sources.push(source);
      surfaces.push(...sourceSurfaces(source, text));
      if (path.endsWith(".mjs")) {
        const evidence = runtimeEvidence(source, text);
        surfaces.push(...evidence.surfaces);
        mutations.push(...evidence.mutations);
      }
    }
  }
  const repository = await upstreamSource();
  try {
    for (const entry of (
      await readdir(join(repository, "packages"), { withFileTypes: true })
    ).sort((a, b) => a.name.localeCompare(b.name))) {
      if (!entry.isDirectory()) continue;
      const root = join(repository, "packages", entry.name);
      const metadataPath = join(root, "package.json"),
        metadataText = await readFile(metadataPath, "utf8");
      const metadata = JSON.parse(metadataText) as { name: string };
      const pkg: Source = {
        id: `git:packages/${entry.name}/package.json`,
        package: metadata.name,
        path: `packages/${entry.name}/package.json`,
        origin: "repository",
        sha256: digest(metadataText),
      };
      sources.push(pkg);
      surfaces.push({
        id: `${pkg.id}#package`,
        source: pkg.id,
        kind: "package",
        name: metadata.name,
        line: 1,
      });
      // All repository packages enter the denominator, including uninstalled plugins/adapters.
      for (const path of (await filesUnder(root)).filter((path) =>
        /\.[cm]?[jt]sx?$/.test(path),
      )) {
        const text = await readFile(path, "utf8"),
          relativePath = relative(repository, path).replaceAll("\\", "/");
        const source: Source = {
          id: `git:${relativePath}`,
          package: metadata.name,
          path: relativePath,
          origin: "repository",
          sha256: digest(text),
        };
        sources.push(source);
        const isTest = /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(path);
        const kind = isTest ? "test-file" : "source-file";
        surfaces.push({
          id: `${source.id}#${kind}`,
          source: source.id,
          kind,
          name: relativePath,
          line: 1,
        });
        surfaces.push(
          ...sourceSurfaces(source, text).filter(
            (record) => !isTest || record.kind === "upstream-test",
          ),
        );
      }
    }
  } finally {
    await rm(repository, { recursive: true, force: true });
  }
  sources.sort((a, b) => a.id.localeCompare(b.id));
  surfaces.sort((a, b) => a.id.localeCompare(b.id));
  mutations.sort((a, b) => a.id.localeCompare(b.id));
  const seen = new Set<string>();
  const duplicates = surfaces
    .filter((value) => seen.has(value.id) || !seen.add(value.id))
    .map((value) => value.id);
  if (duplicates.length)
    throw new Error(
      `Duplicate upstream surface identity: ${duplicates.slice(0, 5).join(", ")}`,
    );
  const identity = {
    version: upstreamPin.version,
    commit: upstreamPin.commit,
    sources,
    surfaces,
    mutations,
    instrumentation: "istanbul-lib-instrument@6.0.3:__compatCoverage",
  };
  return {
    schemaVersion: 1,
    version: upstreamPin.version,
    commit: upstreamPin.commit,
    digest: digest(JSON.stringify(identity)),
    sources,
    surfaces,
    mutations,
  };
}

export async function writeInventory(path: string) {
  const inventory = await buildInventory();
  await writeJSON(path, inventory);
  return inventory;
}
