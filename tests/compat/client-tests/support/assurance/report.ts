import { z } from "zod";
import { digest, upstreamPin } from "./common";
import { coverageSchema } from "./evidence";
import type { Inventory, Surface } from "./inventory";
import {
  type Campaign,
  classifyMutation,
  cleanSuite,
  type Mutation,
  matchingSuites,
} from "./mutations";
import { type SuiteResult, suiteSchema } from "./processes";
import { wireMutationSchema } from "./wire";

const reason = z.string().min(12);
export const policySchema = z
  .object({
    schemaVersion: z.literal(1),
    upstreamVersion: z.literal(upstreamPin.version),
    commit: z.literal(upstreamPin.commit),
    excludedPackages: z.array(z.object({ package: z.string(), reason }).strict()),
    excludedSurfaces: z.array(z.object({ id: z.string(), reason }).strict()),
    equivalentMutations: z.array(z.object({ id: z.string(), reason }).strict()),
    contracts: z.array(
      z
        .object({
          id: z.string(),
          claim: reason,
          upstream: z
            .array(
              z
                .object({
                  source: z.string(),
                  kind: z.enum([
                    "package",
                    "source-file",
                    "export",
                    "option",
                    "upstream-test",
                    "test-file",
                    "branch",
                    "function",
                    "unmeasured-control-flow",
                  ]),
                  name: z.string(),
                })
                .strict(),
            )
            .min(1),
          scenarios: z.array(z.string()).min(1),
          mutations: z.array(z.string()).min(1),
        })
        .strict(),
    ),
  })
  .strict();
export type Policy = z.infer<typeof policySchema>;
export const campaignSchema = z
  .object({
    schemaVersion: z.literal(1),
    runId: z.string(),
    inventoryDigest: z.string(),
    baseline: suiteSchema,
    confirmation: suiteSchema.optional(),
    universe: z.array(z.string()),
    selected: z.array(z.string()),
    results: z.array(
      z
        .object({
          id: z.string(),
          kind: z.enum(["wire", "source"]),
          status: z.enum(["killed", "survived", "not-reached", "no-change", "inconclusive"]),
          killingScenarios: z.array(z.string()),
          reason: z.string().optional(),
          execution: suiteSchema.optional(),
        })
        .strict(),
    ),
    notRun: z.array(z.string()),
    errors: z.array(z.string()),
  })
  .strict();
export const controlsSchema = z
  .object({
    runId: z.string(),
    harnessDigest: z.string(),
    code: z.number().int(),
    timedOut: z.boolean(),
  })
  .strict();
export const executionSchema = z
  .object({
    suite: suiteSchema,
    campaign: campaignSchema.optional(),
    controls: controlsSchema,
    mode: z.enum(["parity", "reference-only"]),
    candidate: z
      .object({
        executable: z.string(),
        sha256: z.string(),
        sourceDigest: z.string(),
      })
      .strict()
      .optional(),
  })
  .strict();

/** This is a gap report, not a weighted score that can hide missing evidence. */
export function assuranceReport(
  inventory: Inventory,
  rawPolicy: unknown,
  suite: SuiteResult,
  campaign: Campaign | undefined,
  mode: "parity" | "reference-only",
  controls?: z.infer<typeof controlsSchema>,
) {
  suite = suiteSchema.parse(suite);
  if (campaign) campaign = campaignSchema.parse(campaign);
  const policy = policySchema.parse(rawPolicy),
    errors: string[] = [];
  if (
    !controls ||
    controls.runId !== suite.runId ||
    controls.harnessDigest !== suite.harnessDigest ||
    controls.code !== 0 ||
    controls.timedOut
  )
    errors.push("Missing, stale or failing harness negative controls");
  const sources = new Map(inventory.sources.map((source) => [source.id, source]));
  const surfaces = new Map(inventory.surfaces.map((surface) => [surface.id, surface]));
  const excluded = new Set(policy.excludedPackages.map((item) => item.package));
  const explicitlyExcluded = new Set(policy.excludedSurfaces.map((item) => item.id));
  for (const id of explicitlyExcluded)
    if (!surfaces.has(id)) errors.push(`Unknown excluded surface: ${id}`);
  const excludedSurfaces = inventory.surfaces.filter(
    (surface) =>
      excluded.has(sources.get(surface.source)!.package) || explicitlyExcluded.has(surface.id),
  );
  const excludedIds = new Set(excludedSurfaces.map((surface) => surface.id));
  const included = inventory.surfaces.filter((surface) => !excludedIds.has(surface.id));
  const mutationIds = new Set(inventory.mutations.map((mutation) => mutation.id));
  const equivalent = new Set(policy.equivalentMutations.map((item) => item.id));
  for (const id of equivalent)
    if (!mutationIds.has(id) && !campaign?.universe.includes(id))
      errors.push(`Unknown equivalent mutation: ${id}`);
  if (
    inventory.version !== upstreamPin.version ||
    inventory.commit !== upstreamPin.commit ||
    suite.inventoryDigest !== inventory.digest
  )
    errors.push("Source inventory or execution evidence is stale");
  if (!cleanSuite(suite)) errors.push("Compatibility execution was incomplete or had failures");
  if (mode === "reference-only")
    errors.push("Two upstream fixtures validate the harness; they do not establish Rust parity");
  const hits = new Set<string>();
  for (const outcome of suite.outcomes) {
    if (outcome.status !== "passed") continue;
    const parsed = coverageSchema.safeParse(outcome.coverage.TS);
    if (!parsed.success) {
      errors.push(`${outcome.name}: missing valid upstream branch evidence`);
      continue;
    }
    const coverage = parsed.data;
    if (
      coverage.runId !== suite.runId ||
      coverage.inventoryDigest !== inventory.digest ||
      coverage.version !== inventory.version ||
      coverage.scenario !== outcome.name ||
      coverage.mutation !== null ||
      !coverage.loaded.length ||
      coverage.loaded.some((id) => !sources.has(id))
    ) {
      errors.push(`${outcome.name}: mismatched upstream branch evidence`);
      continue;
    }
    for (const [id, count] of Object.entries(coverage.hits)) {
      if (!surfaces.has(id)) errors.push(`Unknown coverage surface: ${id}`);
      else if (count > 0) hits.add(id);
    }
  }
  const candidates = new Map<string, Mutation>(
    inventory.mutations.map((mutation) => [mutation.id, { ...mutation, kind: "source" }]),
  );
  // The candidate artifact cannot shrink the independently established denominator.
  if (campaign)
    for (const raw of campaign.baseline.wireCandidates) {
      const candidate = wireMutationSchema.parse(raw);
      candidates.set(candidate.id, candidate);
    }
  const equalSet = (left: string[], right: string[]) =>
    new Set(left).size === left.length &&
    JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
  let campaignValid =
    !!campaign &&
    campaign.inventoryDigest === inventory.digest &&
    campaign.runId === suite.runId &&
    cleanSuite(campaign.baseline) &&
    matchingSuites(suite, campaign.baseline) &&
    !!campaign.confirmation &&
    cleanSuite(campaign.confirmation) &&
    matchingSuites(suite, campaign.confirmation) &&
    !campaign.errors.length;
  if (campaign) {
    if (
      !equalSet(campaign.universe, [...candidates.keys()]) ||
      !equalSet(
        campaign.results.map((result) => result.id),
        campaign.selected,
      ) ||
      !equalSet(
        campaign.notRun,
        [...candidates.keys()].filter((id) => !campaign.selected.includes(id)),
      ) ||
      campaign.selected.some((id) => !candidates.has(id))
    )
      campaignValid = false;
    for (const result of campaign.results) {
      const candidate = candidates.get(result.id);
      if (!candidate || (!result.execution && result.status !== "inconclusive")) {
        campaignValid = false;
        continue;
      }
      if (result.execution) {
        const actual = classifyMutation(candidate, campaign.baseline, result.execution);
        if (
          actual.status !== result.status ||
          !equalSet(actual.killingScenarios, result.killingScenarios)
        )
          campaignValid = false;
      }
    }
  }
  if (campaign && !campaignValid)
    errors.push(
      "Mutation campaign did not have matching provenance and clean baseline/confirmation",
    );
  const detections = new Map(
    campaignValid
      ? campaign!.results
          .filter((result) => result.status === "killed")
          .map((result) => [result.id, result.killingScenarios])
      : [],
  );
  const mapped = new Set<string>(),
    owners = new Map<string, string>();
  const contracts = policy.contracts.map((contract) => {
    const gaps: string[] = [],
      anchors: string[] = [];
    if (owners.has(contract.id)) errors.push(`Duplicate contract identity: ${contract.id}`);
    owners.set(contract.id, contract.claim);
    for (const selector of contract.upstream) {
      const matches = inventory.surfaces.filter(
        (surface) =>
          surface.source === selector.source &&
          surface.kind === selector.kind &&
          surface.name === selector.name,
      );
      if (matches.length !== 1) {
        gaps.push(
          `Upstream selector resolves to ${matches.length} records: ${JSON.stringify(selector)}`,
        );
        continue;
      }
      const id = matches[0]!.id;
      if (excludedIds.has(id)) gaps.push(`Contract refers to excluded surface: ${id}`);
      mapped.add(id);
      anchors.push(id);
    }
    for (const name of contract.scenarios)
      if (!suite.outcomes.some((outcome) => outcome.name === name && outcome.status === "passed"))
        gaps.push(`Missing successful scenario: ${name}`);
    for (const id of contract.mutations) {
      if (!mutationIds.has(id) && !campaign?.universe.includes(id))
        gaps.push(`Unknown required mutation: ${id}`);
      else if (!detections.get(id)?.some((name) => contract.scenarios.includes(name)))
        gaps.push(`Required mutation has no detection by its contract owner: ${id}`);
    }
    return {
      ...contract,
      anchors,
      status: gaps.length ? "unproven" : "proven",
      gaps,
    };
  });
  const summarize = (kind: Surface["kind"]) => {
    const all = included.filter((surface) => surface.kind === kind);
    return {
      total: all.length,
      reached: all.filter((surface) => hits.has(surface.id)).length,
      missing: all.filter((surface) => !hits.has(surface.id)).map((surface) => surface.id),
    };
  };
  const semantic = included.filter((surface) => !["branch", "function"].includes(surface.kind));
  const unmapped = semantic
    .filter((surface) => !mapped.has(surface.id))
    .map((surface) => surface.id);
  const branches = summarize("branch"),
    functions = summarize("function");
  const unresolvedMutations = [...candidates]
    .filter(
      ([id, candidate]) =>
        !equivalent.has(id) &&
        !detections.has(id) &&
        !(
          candidate.kind === "source" && excluded.has(sources.get(candidate.source)?.package ?? "")
        ),
    )
    .map(([id]) => id);
  const complete =
    !!campaign &&
    campaignValid &&
    errors.length === 0 &&
    unmapped.length === 0 &&
    !branches.missing.length &&
    !functions.missing.length &&
    contracts.every((contract) => contract.status === "proven") &&
    unresolvedMutations.length === 0;
  return {
    schemaVersion: 1,
    runId: suite.runId,
    version: inventory.version,
    commit: inventory.commit,
    inventoryDigest: inventory.digest,
    policyDigest: digest(JSON.stringify(policy)),
    mode,
    controls,
    status: complete ? "complete-within-declared-scope" : "incomplete",
    errors,
    summary: {
      scenarios: suite.outcomes.length,
      passed: suite.outcomes.filter((outcome) => outcome.status === "passed").length,
      upstreamSurfaces: inventory.surfaces.length,
      excludedSurfaces: excludedSurfaces.length,
      unmapped: unmapped.length,
      branchArms: branches.total,
      reachedBranchArms: branches.reached,
      functions: functions.total,
      reachedFunctions: functions.reached,
      contracts: contracts.length,
      provenContracts: contracts.filter((contract) => contract.status === "proven").length,
      mutationDetections: detections.size,
      unresolvedMutations: unresolvedMutations.length,
    },
    contracts,
    branches,
    functions,
    unmapped,
    unresolvedMutations,
    exclusions: {
      packages: policy.excludedPackages,
      surfaces: policy.excludedSurfaces,
      equivalentMutations: policy.equivalentMutations,
      affectedSurfaces: excludedSurfaces.map((surface) => surface.id),
    },
  };
}
