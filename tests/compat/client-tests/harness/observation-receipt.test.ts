import { expect, test } from "bun:test";

import {
  parseObservationReceipt,
  serializeObservationReceipt,
} from "../support/observation-receipt";

test("paired observation receipts preserve BigInt type and exact values without tag collisions or live mutation", () => {
  const ordinary = {
    scenarioName: "ordinary receipt",
    ts: {
      observation: {
        text: "18446744073709551615",
        nested: { bigintEncoding: { version: 1, paths: [["ts"]] } },
      },
      traces: [],
    },
    rust: { observation: [null, true, 17, "-9007199254740993"], traces: [] },
  };
  expect(serializeObservationReceipt(ordinary)).toBe(JSON.stringify(ordinary, null, 2));
  expect(parseObservationReceipt(serializeObservationReceipt(ordinary))).toEqual(ordinary);
  const shared = { signed: -9007199254740993n };
  const receipt = {
    scenarioName: "typed paired receipt",
    ts: {
      observation: {
        "literal.key/with~punctuation": [0n, 18446744073709551615n, shared],
        "": -1n,
        ...ordinary.ts.observation,
      },
    },
    rust: {
      observation: {
        shared,
        huge: 1234567890123456789012345678901234567890n,
        marker: { type: "bigint", value: "-9007199254740993" },
      },
    },
  };
  const original = structuredClone(receipt);
  const encoded = serializeObservationReceipt(receipt);
  expect(receipt).toEqual(original);
  expect(receipt.ts.observation["literal.key/with~punctuation"][2]).toBe(shared);
  expect(receipt.rust.observation.shared).toBe(shared);
  const decoded = parseObservationReceipt(encoded) as typeof receipt;
  expect(decoded).toEqual(original);
  expect(typeof decoded.ts.observation["literal.key/with~punctuation"][0]).toBe("bigint");
  expect(decoded.ts.observation["literal.key/with~punctuation"][1]).toBe(18446744073709551615n);
  expect(typeof decoded.rust.observation.shared.signed).toBe("bigint");
  expect(decoded.rust.observation.shared.signed).toBe(-9007199254740993n);
  expect(decoded.rust.observation.huge).toBe(1234567890123456789012345678901234567890n);
  expect(typeof decoded.ts.observation.text).toBe("string");
  expect(decoded.rust.observation.marker).toEqual({ type: "bigint", value: "-9007199254740993" });

  // Independently authored receipt, rather than encoder-produced expectations.
  const persisted = {
    scenarioName: "independent receipt",
    ts: { observation: ["-18446744073709551616", "18446744073709551615"] },
    rust: JSON.parse('{"__proto__":{"own":"9007199254740993"}}'),
    bigintEncoding: {
      version: 1,
      paths: [
        ["ts", "observation", "0"],
        ["rust", "__proto__", "own"],
      ],
    },
  };
  const restored = parseObservationReceipt(JSON.stringify(persisted)) as {
    ts: { observation: unknown[] };
    rust: Record<string, { own: bigint }>;
  };
  expect(restored.ts.observation).toEqual([-18446744073709551616n, "18446744073709551615"]);
  expect(Object.getPrototypeOf(restored.rust)).toBe(Object.prototype);
  expect(restored.rust["__proto__"]!.own).toBe(9007199254740993n);
  for (const encoding of [
    null,
    { version: 2, paths: [["ts"]] },
    { version: 1, paths: [] },
    { version: 1, paths: [["ts", "observation", "0"]], extra: true },
    ...[
      [],
      ["scenarioName"],
      ["bigintEncoding", "version"],
      ["ts", "missing"],
      ["ts", "constructor"],
      ["ts", "__proto__"],
      ["ts", "observation", "01"],
      ["ts", "observation", "length"],
      ["ts", "observation", 0],
    ].map((path) => ({ version: 1, paths: [path] })),
    {
      version: 1,
      paths: [
        ["ts", "observation", "0"],
        ["ts", "observation", "0"],
      ],
    },
    {
      version: 1,
      paths: [
        ["ts", "observation", "0"],
        ["rust", "__proto__", "missing"],
      ],
    },
  ]) {
    expect(() =>
      parseObservationReceipt(JSON.stringify({ ...persisted, bigintEncoding: encoding })),
    ).toThrow("Invalid observation receipt BigInt encoding");
  }
  for (const value of ["-0", "01", "+1", "1.0", "1e3", " 1", "", 1, null, {}, ["1"]]) {
    expect(() =>
      parseObservationReceipt(JSON.stringify({ ...persisted, ts: { observation: [value] } })),
    ).toThrow("Invalid observation receipt BigInt encoding");
  }
});
