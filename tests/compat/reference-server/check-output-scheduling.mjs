import assert from "node:assert/strict";
import { createAdapterFactory } from "@better-auth/core/db/adapter";

// Execute the installed factory, rather than reimplementing its promise wrappers.
// A held callback is released only after the actual aggregate has rejected.
for (const [fieldCount, blockHidden] of [[3, false], [8, false], [3, true]]) {
  const events = [];
  const completion = Object.fromEntries(["normal", "slow"].map(row => [row, Promise.withResolvers()]));
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const names = ["label", "hidden", "omitted", "four", "five", "six", "seven", "eight"].slice(0, fieldCount);
  const fields = Object.fromEntries(names.map(field => [field, {
    type: "string",
    transform: { output: async value => {
      events.push({ row: value, field, phase: "start" });
      await Promise.resolve();
      if (value === "reject") throw new Error("application output failed");
      if (value === "slow" || (blockHidden && value === "normal" && field === "hidden")) await held;
      events.push({ row: value, field, phase: "finish" });
      if (field === names.at(-1)) completion[value].resolve();
      return value;
    } },
  }]));
  const adapter = createAdapterFactory({
    config: { adapterId: "output-scheduling-characterization" },
    adapter: () => ({ findMany: async () => ["normal", "reject", "slow"].map(row => ({ id: row, ...Object.fromEntries(names.map(field => [field, row])) })) }),
  })({ session: { additionalFields: fields } });
  await assert.rejects(adapter.findMany({ model: "session" }), /application output failed/);
  const atRejection = events.slice();
  const normalFinished = atRejection.filter(event => event.row === "normal" && event.phase === "finish");
  assert.equal(atRejection.filter(event => event.row === "slow" && event.phase === "finish").length, 0);
  if (fieldCount === 3 && !blockHidden) assert.equal(normalFinished.length, fieldCount);
  else assert.ok(normalFinished.length < fieldCount);
  release();
  await Promise.all(Object.values(completion).map(row => row.promise));
  for (const row of ["normal", "slow"]) assert.equal(events.filter(event => event.row === row && event.phase === "finish").length, fieldCount);
  console.log(JSON.stringify({ fieldCount, blockHidden, atRejection, afterRelease: events }));
}
