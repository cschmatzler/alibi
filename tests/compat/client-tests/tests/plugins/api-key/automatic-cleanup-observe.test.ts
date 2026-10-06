import { compatScenario } from "../../../support/scenario";
import { cleanupObserver } from "./automatic-cleanup-shared";

compatScenario(
  "api-key automatic middleware observe admits one concurrent cleanup and retains both credential owners",
  (ctx) => cleanupObserver(ctx, "observe"),
  ["GET /get-session"],
  30_000,
);
