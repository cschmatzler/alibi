import { readFileSync } from "node:fs";
import {
  executeGenerated,
  generateCase,
  generatedCaseSchema,
} from "../../support/assurance/generated";
import { compatScenario } from "../../support/scenario";

const replay = process.env.COMPAT_ASSURANCE_REPLAY;
const seeds = (process.env.COMPAT_ASSURANCE_SEEDS ?? "1,12648430").split(",").map(Number);
const steps = Number(process.env.COMPAT_ASSURANCE_STEPS ?? "12");
const profiles = (
  process.env.COMPAT_ASSURANCE_PROFILES ?? "default,session-no-refresh,session-deferred"
)
  .split(",")
  .map((profile) => generatedCaseSchema.shape.profile.parse(profile));
const cases = replay
  ? [generatedCaseSchema.parse(JSON.parse(readFileSync(replay, "utf8")))]
  : seeds.flatMap((seed) => profiles.map((profile) => generateCase(seed, steps, profile)));

for (const generated of cases) {
  compatScenario(
    `generated lifecycle seed ${generated.seed} profile ${generated.profile}`,
    (ctx) => executeGenerated(ctx, generated),
    [],
    120_000,
    {},
    generated,
  );
}
