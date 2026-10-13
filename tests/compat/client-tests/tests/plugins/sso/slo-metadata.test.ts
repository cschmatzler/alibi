import { compatScenario } from "../../../support/scenario";
import { samlMetadataFlow } from "./metadata-flow";
compatScenario("SLO-enabled metadata publishes both actual logout bindings", (ctx) =>
  samlMetadataFlow(ctx, true),
);
