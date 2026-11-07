import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { memoryAdapter } from "../reference-server/node_modules/@better-auth/memory-adapter/dist/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/memory-adapter/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const cases = [];
const inputs = [
  ["absent", undefined], ["undefined", undefined], ["null", null],
  ["false", false], ["zero", 0], ["empty", ""], ["string", "supplied"],
  ["object", { nested: [null, false, "supplied"] }],
];
for (const creation of [false, true]) {
  for (const required of [false, true]) {
    for (const hasDefault of [false, true]) {
      for (const onUpdate of [false, true]) {
        for (const transform of [false, true]) {
          for (const [kind, input] of inputs) {
            const events = [];
            const observed = [];
            const field = { type: "string", required };
            if (hasDefault) field.defaultValue = () => { events.push("default"); return "default"; };
            if (onUpdate) field.onUpdate = () => { events.push("update"); return "updated"; };
            if (transform) field.transform = { input: async value => {
              events.push("input");
              observed.push({ undefined: value === undefined, value: value === undefined ? null : value });
              return value;
            } };
            const database = { user: creation ? [] : [{ id: "user", marker: "stored" }] };
            const adapter = memoryAdapter(database)({
              advanced: { database: { generateId: false } },
              user: { additionalFields: { marker: field } },
            });
            const data = kind === "absent" ? {} : { marker: input };
            if (creation) {
              await adapter.create({ model: "user", data: { id: "user", ...data }, forceAllowId: true });
            } else {
              await adapter.update({ model: "user", where: [{ field: "id", value: "user" }], update: data });
            }
            assert.equal(database.user.length, 1);
            const row = database.user[0];
            cases.push({
              creation, required, has_default: hasDefault, on_update: onUpdate, transform,
              kind, input: input === undefined ? null : input,
              present: Object.hasOwn(row, "marker"),
              expected: row.marker === undefined ? null : row.marker,
              events, observed,
            });
          }
        }
      }
    }
  }
}
assert.equal(cases.length, 256);
await writeFile(new URL("../../../crates/core/src/field_policy_undefined_cases.json", import.meta.url),
  JSON.stringify({ better_auth: pkg.version, cases }).replaceAll('},{"creation":', '},\n{"creation":') + "\n");
console.log(`${cases.length} adapter-input cases from Better Auth ${pkg.version}`);
