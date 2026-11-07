import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

assert.equal(process.version, "v26.13.0");
assert.equal(process.versions.v8, "14.6.202.34-node.40");
assert.equal(process.versions.icu, "78.3");
assert.equal(Intl.DateTimeFormat().resolvedOptions().locale, "en-US");
const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");

function* permutations(values) {
  if (!values.length) {
    yield [];
    return;
  }
  for (let i = 0; i < values.length; ++i) {
    for (const tail of permutations(values.filter((_, j) => i !== j))) {
      yield [values[i], ...tail];
    }
  }
}

let seed = 0x53728a41;
function shuffled(values) {
  const rows = [...values];
  for (let i = rows.length - 1; i > 0; --i) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const j = seed % (i + 1);
    [rows[i], rows[j]] = [rows[j], rows[i]];
  }
  return rows;
}

const inputs = [];
for (const values of [[2, 10, "10", "2"], [2, 10, "2", true]]) {
  for (const ids of permutations(values)) {
    inputs.push({ name: `permutation-${inputs.length}`, ids });
  }
}
for (const length of [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 31, 32, 63, 64, 65, 127, 128, 129, 257, 1024]) {
  const ids = Array.from({ length }, (_, i) => i % 2 ? String((i + 1) / 2) : i / 2 + 1);
  if (length) ids[0] = true;
  if (length > 32) {
    ids[1] = "é";
    ids[3] = "e\u0301";
    ids[5] = "É";
    ids[7] = "a";
    ids[9] = "A";
  }
  inputs.push({ name: `shuffled-${length}`, ids: shuffled(ids) });
}
for (const [a, b] of [[64, 256], [256, 64], [256, 768], [768, 256]]) {
  inputs.push({
    name: `runs-${a}-${b}`,
    ids: [
      ...Array.from({ length: a }, (_, i) => String(1000 + i)),
      ...Array.from({ length: b }, (_, i) => i + 1),
    ],
  });
}
for (const [a, b] of [[64, 256], [256, 64]]) {
  inputs.push({
    name: `numeric-runs-${a}-${b}`,
    ids: [
      ...Array.from({ length: a }, (_, i) => 10000 + i),
      ...Array.from({ length: b }, (_, i) => i + 1),
    ],
  });
}
inputs.push({
  name: "numeric-left-gallop",
  ids: [
    ...Array.from({ length: 65 }, (_, i) => 10 + i), 400,
    1, ...Array.from({ length: 251 }, (_, i) => 100 + i),
  ],
});
inputs.push({
  name: "numeric-right-gallop",
  ids: [
    ...Array.from({ length: 71 }, (_, i) => 30 + i),
    ...Array.from({ length: 301 }, (_, i) => 1000 + i),
    1, 2, ...Array.from({ length: 30 }, (_, i) => 101 + i),
  ],
});
inputs.push({
  name: "boolean-text-exponent-ties",
  ids: [true, "true", "True", 2, 10, "10", "2", 1e30, "1e+30", -1e30, "-1e+30", 1e-30, "1e-30", "😀", "é", "e\u0301"],
});
const cases = [];
for (const input of inputs) {
  assert.equal(new Set(input.ids).size, input.ids.length);
  const rows = input.ids.map((id, i) => ({
    id, name: String(i), email: `${i}@${i % 3 === 0 ? "keep" : "other"}.fixture.test`,
    emailVerified: false, createdAt: new Date(0), updatedAt: new Date(0),
  }));
  const adapter = memoryAdapter({ user: rows })({ advanced: { database: { generateId: false } } });
  const output = { ...input };
  for (const filtered of [false, true]) {
    const where = filtered ? [{ field: "email", operator: "contains", value: "@keep." }] : [];
    for (const direction of ["asc", "desc"]) {
      const result = await adapter.findMany({
        model: "user", sortBy: { field: "id", direction }, where, limit: rows.length + 1,
      });
      assert.equal(result.length, await adapter.count({ model: "user", where }));
      output[`${filtered ? "filtered_" : ""}${direction}`] = result.map(row => Number(row.name));
    }
  }
  cases.push(output);
}
const document = {
  node: process.version, v8: process.versions.v8, icu: process.versions.icu,
  locale: Intl.DateTimeFormat().resolvedOptions().locale, better_auth: pkg.version, cases,
};
const text = JSON.stringify(document).replaceAll('},{"name":', '},\n{"name":');
await writeFile(new URL("../../../crates/core/src/store/memory_user_sort_cases.json", import.meta.url), text + "\n");
console.log(`Wrote ${cases.length} actual Better Auth cases (${inputs.reduce((sum, c) => sum + c.ids.length, 0)} physical rows)`);
