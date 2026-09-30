import { z } from "zod";
import { mkdir } from "node:fs/promises";
import type { TraceEntry } from "./trace";

/** Validated, committed route and scenario requirements. */
export const inventorySchema = z.object({ upstreamVersion: z.literal("1.7.6"), capabilities: z.array(z.object({
  route: z.string(), implemented: z.boolean(), upstream: z.boolean(),
  evidence: z.object({ success: z.string().nullable(), rejection: z.string().nullable(), authorization: z.string().nullable(), state: z.string().nullable() }),
})) });
/** Independent evidence categories; none implies complete endpoint coverage. */
export type EvidenceKind = "success" | "rejection" | "authorization" | "state";
const inventory = inventorySchema.parse(await Bun.file(new URL("../../capabilities.json", import.meta.url)).json());

/** Persist evidence only after both runtime comparisons pass. */
export async function recordCoverage(scenario: string, traces: readonly TraceEntry[], stateTransitions: readonly string[]) {
  if (process.env.COMPAT_COVERAGE !== "1") return;
  const observations = new Map<string, Map<EvidenceKind, Set<string>>>();
  for (const trace of traces) {
    const path = new URL(trace.path, "http://compat.local").pathname.replace(/^\/api\/auth/, "");
    if (!trace.path.startsWith("/api/auth/")) continue;
    const route = inventory.capabilities.find(entry => entry.route === `${trace.method} ${path}`)?.route ?? inventory.capabilities.find(entry => {
      const [method, pattern] = entry.route.split(" ");
      return method === trace.method && pattern !== undefined && pattern.split("/").length === path.split("/").length && pattern.split("/").every((part, i) => part === "{}" || part === path.split("/")[i]);
    })?.route ?? `${trace.method} ${path}`;
    const kinds: EvidenceKind[] = [];
    if (trace.responseStatus >= 200 && trace.responseStatus < 400) kinds.push("success");
    if (trace.responseStatus >= 400 && trace.responseStatus < 500) kinds.push("rejection");
    if ([401, 403].includes(trace.responseStatus)) kinds.push("authorization");
    if (stateTransitions.includes(route)) kinds.push("state");
    const record = observations.get(route) ?? new Map<EvidenceKind, Set<string>>();
    for (const kind of kinds) { const scenarios = record.get(kind) ?? new Set<string>(); scenarios.add(scenario); record.set(kind, scenarios); }
    observations.set(route, record);
  }
  const output = Object.fromEntries([...observations].sort().map(([route, kinds]) => [route, Object.fromEntries([...kinds].map(([kind, names]) => [kind, [...names].sort()]))]));
  const directory = new URL("../artifacts/evidence/", import.meta.url);
  await mkdir(directory, { recursive: true });
  await Bun.write(new URL(`${Bun.hash(scenario)}.json`, directory), JSON.stringify(output, null, 2));
}
