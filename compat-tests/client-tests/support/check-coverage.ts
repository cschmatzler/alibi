import { readdir } from "node:fs/promises";
import { z } from "zod";
import { inventorySchema } from "./coverage";

const inventoryURL = new URL("../../capabilities.json", import.meta.url);
const inventory = inventorySchema.parse(await Bun.file(inventoryURL).json());
// Prevent a dependency update from silently keeping an obsolete oracle label.
for (const project of ["client-tests", "reference-server"]) {
  for (const name of ["better-auth", "@better-auth/passkey", "@better-auth/api-key"]) {
    const metadata = await Bun.file(new URL(`../../${project}/node_modules/${name}/package.json`, import.meta.url)).json();
    z.object({ version: z.literal(inventory.upstreamVersion) }).parse(metadata);
  }
}
const routesSchema = z.array(z.string());
const upstream = new Set(routesSchema.parse(await Bun.file(new URL("../../../coverage/upstream-routes.json", import.meta.url)).json()));
const runtime = new Set(routesSchema.parse(await Bun.file(new URL("../../../coverage/runtime-routes.json", import.meta.url)).json()));
const evidenceSchema = z.record(z.string(), z.partialRecord(z.enum(["success", "rejection", "authorization", "state"]), z.array(z.string())));
const directory = new URL("../artifacts/evidence/", import.meta.url);
const evidence = new Map<string, Map<string, Set<string>>>();
for (const file of await readdir(directory)) {
  if (!file.endsWith(".json")) continue;
  const observation = evidenceSchema.parse(await Bun.file(new URL(file, directory)).json());
  for (const [route, kinds] of Object.entries(observation)) {
    const merged = evidence.get(route) ?? new Map<string, Set<string>>();
    for (const [kind, names] of Object.entries(kinds)) {
      const scenarios = merged.get(kind) ?? new Set<string>();
      for (const name of names) scenarios.add(name);
      merged.set(kind, scenarios);
    }
    evidence.set(route, merged);
  }
}
await Bun.write(new URL("../artifacts/capability-evidence.json", import.meta.url), JSON.stringify(Object.fromEntries([...evidence].sort().map(([route, kinds]) => [route, Object.fromEntries([...kinds].map(([kind, scenarios]) => [kind, [...scenarios].sort()]))])), null, 2) + "\n");
const kinds = ["success", "rejection", "authorization", "state"] as const;
const actual = new Set([...upstream, ...runtime]);
const declared = new Set(inventory.capabilities.map(entry => entry.route));
if (declared.size !== inventory.capabilities.length) throw new Error("Duplicate committed capability routes");
const missing: string[] = [];
// Regeneration may discover routes and fill empty evidence, but never discard a
// committed requirement because the scenario disappeared or sorted differently.
for (const entry of inventory.capabilities) {
  if (!actual.has(entry.route)) missing.push(`Committed capability route disappeared: ${entry.route}`);
  for (const kind of kinds) {
    const requirement = entry.evidence[kind];
    const required = typeof requirement === "string" ? [requirement] : requirement ?? [];
    for (const scenario of required) {
      if (!evidence.get(entry.route)?.get(kind)?.has(scenario)) missing.push(`${entry.route}: missing ${kind} (${scenario})`);
    }
  }
}
if (missing.length) throw new Error(`Capability evidence disappeared:\n${missing.join("\n")}`);
if (process.env.BETTER_AUTH_UPDATE_CAPABILITIES === "1") {
  const previous = new Map(inventory.capabilities.map(entry => [entry.route, entry]));
  const capabilities = [...actual].sort().map(route => ({
    route, upstream: upstream.has(route), implemented: runtime.has(route),
    evidence: Object.fromEntries(kinds.map(kind => [kind, previous.get(route)?.evidence[kind] ?? [...(evidence.get(route)?.get(kind) ?? [])].sort().at(0) ?? null])),
  }));
  await Bun.write(inventoryURL, JSON.stringify({ upstreamVersion: "1.7.6", capabilities }, null, 2) + "\n");
  console.log(`Updated ${capabilities.length} capability records. Review every changed requirement.`);
} else {
  if (declared.size !== actual.size || [...actual].some(route => !declared.has(route))) throw new Error("Capability route inventory differs; explicitly regenerate and review it.");
  for (const entry of inventory.capabilities) {
    if (entry.implemented !== runtime.has(entry.route) || entry.upstream !== upstream.has(entry.route)) missing.push(`${entry.route}: implementation/upstream declaration differs`);
  }
  if (missing.length) throw new Error(`Capability evidence disappeared:\n${missing.join("\n")}`);
  console.log(`Capability inventory: ${inventory.capabilities.length} routes; ${inventory.capabilities.filter(entry => !entry.implemented).length} unimplemented; ${inventory.capabilities.filter(entry => entry.implemented && !entry.evidence.success).length} implemented without successful scenario evidence.`);
}
