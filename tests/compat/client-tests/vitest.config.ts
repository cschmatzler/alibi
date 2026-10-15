import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "harness/**/*.test.ts",
      "tests/**/*.test.ts",
      "browser/**/*.test.ts",
      "environment/**/*.test.ts",
      "process-proofs/**/*.test.ts",
    ],
    // Fixtures and comparison windows are process-owned, not safe to share
    // between concurrent files or scenarios.
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
