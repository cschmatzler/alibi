import { expect, test } from "bun:test";
import { readdir } from "node:fs/promises";

/**
 * Scenario files that compare the runtimes without `compatScenario`, and why.
 * Such a file skips the trace comparator, the oracle checks, capability
 * evidence and assurance registration, so each one must be listed here.
 */
const DIRECT_DUAL_RUNTIME_TESTS: Record<string, string> = {
  "plugins/siwe/runtime-body.test.ts":
    "Bun exposes enumerable stream/blob methods to upstream's body validator; the diagnostic text legitimately differs per runtime and is asserted literally for each",
};

const root = new URL("../tests/", import.meta.url);

async function scenarioFiles() {
  const entries = await readdir(root, { recursive: true });
  return entries.filter((entry) => entry.endsWith(".test.ts")).sort();
}

test("every scenario file registers through compatScenario", async () => {
  const bypassing: string[] = [];

  for (const file of await scenarioFiles()) {
    const source = await Bun.file(new URL(file, root)).text();
    const registers = /\bcompatScenario\s*\(/.test(source);
    // A bare bun:test `test` runs without comparing the two runtimes.
    const importsTest = /import\s*\{[^}]*\btest\b[^}]*\}\s*from\s*"bun:test"/.test(source);
    const skips = /\b(?:test|describe|it)\.(?:skip|only|todo|if|skipIf|todoIf)\b/.test(source);

    if (skips || ((!registers || importsTest) && !(file in DIRECT_DUAL_RUNTIME_TESTS))) {
      bypassing.push(file);
    }
  }

  expect(bypassing).toEqual([]);
});

test("every listed direct test still exists and still bypasses the comparator", async () => {
  const files = await scenarioFiles();
  for (const file of Object.keys(DIRECT_DUAL_RUNTIME_TESTS)) {
    expect(files).toContain(file);
    const source = await Bun.file(new URL(file, root)).text();
    expect(source).not.toMatch(/\bcompatScenario\s*\(/);
  }
});
