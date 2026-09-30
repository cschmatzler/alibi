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
if (process.env.BETTER_AUTH_UPDATE_CAPABILITIES === "1") {
  const capabilities = [...new Set([...upstream, ...runtime])].sort().map(route => ({
    route, upstream: upstream.has(route), implemented: runtime.has(route),
    evidence: Object.fromEntries(kinds.map(kind => [kind, [...(evidence.get(route)?.get(kind) ?? [])].sort().at(0) ?? null])),
  }));
  await Bun.write(inventoryURL, JSON.stringify({ upstreamVersion: "1.7.6", capabilities }, null, 2) + "\n");
  console.log(`Updated ${capabilities.length} capability records. Review every changed requirement.`);
} else {
  const declared = new Set(inventory.capabilities.map(entry => entry.route));
  const actual = new Set([...upstream, ...runtime]);
  if (declared.size !== inventory.capabilities.length || declared.size !== actual.size || [...actual].some(route => !declared.has(route))) throw new Error("Capability route inventory differs; explicitly regenerate and review it.");
  const missing: string[] = [];
  for (const entry of inventory.capabilities) {
    if (entry.implemented !== runtime.has(entry.route) || entry.upstream !== upstream.has(entry.route)) missing.push(`${entry.route}: implementation/upstream declaration differs`);
    for (const kind of kinds) {
      const required = entry.evidence[kind];
      if (required && !evidence.get(entry.route)?.get(kind)?.has(required)) missing.push(`${entry.route}: missing ${kind} (${required})`);
    }
  }
  if (missing.length) throw new Error(`Capability evidence disappeared:\n${missing.join("\n")}`);
  console.log(`Capability inventory: ${inventory.capabilities.length} routes; ${inventory.capabilities.filter(entry => !entry.implemented).length} unimplemented; ${inventory.capabilities.filter(entry => entry.implemented && !entry.evidence.success).length} implemented without successful scenario evidence.`);
}
