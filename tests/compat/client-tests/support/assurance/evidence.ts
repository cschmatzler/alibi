import { appendFileSync, readFileSync } from "node:fs";
import { z } from "zod";
import { localURL } from "./common";

export const coverageSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: z.string(),
    version: z.string(),
    inventoryDigest: z.string(),
    scenario: z.string(),
    hits: z.record(z.string(), z.number().int().nonnegative()),
    loaded: z.array(z.string()),
    mutation: z.string().nullable(),
    mutationHits: z.number().int().nonnegative(),
  })
  .strict();
export type ScenarioCoverage = z.infer<typeof coverageSchema>;
export type ScenarioOutcome = {
  name: string;
  status: "passed" | "failed";
  failure?:
    | "comparison"
    | "assertion"
    | "model"
    | "invalid-sequence"
    | "scenario"
    | "infrastructure";
  signature?: string;
  paths?: string[];
  phase?: "TS" | "Rust";
  reproduction?: unknown;
  coverage: Partial<Record<"TS" | "Rust", ScenarioCoverage>>;
};
let phase: { name: string; label: "TS" | "Rust" } | undefined;
export function setAssurancePhase(name: string, label: "TS" | "Rust") {
  phase = { name, label };
}
export function assurancePhase() {
  return phase;
}
const bridgeSchema = z
  .object({
    runId: z.string(),
    inventoryDigest: z.string(),
    url: z.string(),
    token: z.string(),
  })
  .strict();

/** One append-only, run-owned journal. Failed scenarios never produce positive evidence. */
export function assuranceEvent(event: Record<string, unknown>) {
  const path = process.env.COMPAT_ASSURANCE_EVENTS;
  if (!path) return;
  if (!process.env.COMPAT_ASSURANCE_RUN_ID)
    throw new Error("Assurance events require a run identity");
  appendFileSync(
    path,
    JSON.stringify({ ...event, runId: process.env.COMPAT_ASSURANCE_RUN_ID }) +
      "\n",
    { mode: 0o600 },
  );
}
export async function scenarioCoverage(
  operation: "begin" | "end",
  label: "TS" | "Rust",
  scenario: string,
): Promise<ScenarioCoverage | undefined> {
  const path =
    process.env[
      label === "TS"
        ? "COMPAT_ASSURANCE_LEFT_BRIDGE"
        : "COMPAT_ASSURANCE_RIGHT_BRIDGE"
    ];
  if (!path) return;
  const bridge = bridgeSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  if (bridge.runId !== process.env.COMPAT_ASSURANCE_RUN_ID)
    throw new Error("Stale assurance coverage bridge");
  const url = new URL(`/${operation}`, localURL(bridge.url));
  const response = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${bridge.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ scenario }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok)
    throw new Error(
      `Reference coverage ${operation} failed: ${response.status}`,
    );
  const value: unknown = await response.json();
  if (operation === "begin") return;
  const coverage = coverageSchema.parse(value);
  if (
    coverage.runId !== bridge.runId ||
    coverage.inventoryDigest !== bridge.inventoryDigest ||
    coverage.scenario !== scenario
  )
    throw new Error("Reference coverage provenance mismatch");
  return coverage;
}
