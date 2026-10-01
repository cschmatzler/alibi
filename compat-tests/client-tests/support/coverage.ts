import { z } from "zod";
import { mkdir } from "node:fs/promises";
import type { TraceEntry } from "./trace";

/** One category can require several independent configuration or lifecycle scenarios. */
const requirementSchema = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]).nullable();

/** Validated, committed route and scenario requirements. */
export const inventorySchema = z.object({ upstreamVersion: z.literal("1.7.6"), capabilities: z.array(z.object({
  route: z.string(), implemented: z.boolean(), upstream: z.boolean(),
  evidence: z.object({ success: requirementSchema, rejection: requirementSchema, authorization: requirementSchema, state: requirementSchema }).strict(),
}).strict()) }).strict();
/** Independent evidence categories; none implies complete endpoint coverage. */
export type EvidenceKind = "success" | "rejection" | "authorization" | "state";
const inventory = inventorySchema.parse(await Bun.file(new URL("../../capabilities.json", import.meta.url)).json());

/** Collect route evidence without conflating it with complete parity. */
export function collectCoverage(scenario: string, traces: readonly TraceEntry[], stateTransitions: readonly string[], baseURL?: string) {
  const observations = new Map<string, Map<EvidenceKind, Set<string>>>();
  for (const trace of traces) {
    const pathname = new URL(trace.path, "http://compat.local").pathname;
    const prefix = pathname.match(/^(?:\/__test\/profiles\/[a-z0-9-]+)?\/api\/auth(?=\/)/)?.[0];
    if (!prefix) continue;
    const path = pathname.slice(prefix.length);
    const route = inventory.capabilities.find(entry => entry.route === `${trace.method} ${path}`)?.route ?? inventory.capabilities.find(entry => {
      const [method, pattern] = entry.route.split(" ");
      return method === trace.method && pattern !== undefined && pattern.split("/").length === path.split("/").length && pattern.split("/").every((part, i) => part === "{}" || part === path.split("/")[i]);
    })?.route ?? `${trace.method} ${path}`;
    const kinds: EvidenceKind[] = [];
    let rejectedCallback = false;
    if (baseURL && trace.method === "GET" && /^\/callback\/[^/]+$/.test(path) && trace.responseStatus === 302) {
      try {
        const base = new URL(baseURL), location = new URL(trace.responseHeaders.location ?? "", base);
        const errors = location.searchParams.getAll("error");
        rejectedCallback = !!trace.responseHeaders.location && location.origin === base.origin
          && !location.username && !location.password && !location.href.includes("#") && location.pathname === `${prefix}/error`
          && errors.length === 1 && ["email_does_not_match", "unable_to_get_user_info", "state_mismatch"].includes(errors[0]!);
      } catch { /* Malformed locations cannot supply callback admission evidence. */ }
    }
    // These measured Source errors use the default OAuth error channel. Owners
    // still prove their actual denial and unchanged state; arbitrary configured
    // application callbacks are not generally inferable from transport alone.
    if (rejectedCallback) kinds.push("rejection", "authorization");
    else if (trace.responseStatus >= 200 && trace.responseStatus < 400) kinds.push("success");
    if (trace.responseStatus >= 400 && trace.responseStatus < 500) kinds.push("rejection");
    if ([401, 403].includes(trace.responseStatus)) kinds.push("authorization");
    if (stateTransitions.includes(route)) kinds.push("state");
    const record = observations.get(route) ?? new Map<EvidenceKind, Set<string>>();
    for (const kind of kinds) { const scenarios = record.get(kind) ?? new Set<string>(); scenarios.add(scenario); record.set(kind, scenarios); }
    observations.set(route, record);
  }
  return Object.fromEntries([...observations].sort().map(([route, kinds]) => [route, Object.fromEntries([...kinds].map(([kind, names]) => [kind, [...names].sort()]))]));
}

/** Persist evidence only after both runtime comparisons pass. */
export async function recordCoverage(scenario: string, traces: readonly TraceEntry[], stateTransitions: readonly string[], baseURL?: string) {
  if (process.env.COMPAT_COVERAGE !== "1") return;
  const output = collectCoverage(scenario, traces, stateTransitions, baseURL);
  const directory = new URL("../artifacts/evidence/", import.meta.url);
  await mkdir(directory, { recursive: true });
  await Bun.write(new URL(`${Bun.hash(scenario)}.json`, directory), JSON.stringify(output, null, 2));
}
