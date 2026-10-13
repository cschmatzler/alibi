import { compatScenario } from "../../../support/scenario";
import { samlMetadataFlow } from "./metadata-flow";
compatScenario(
  "SSO service-provider metadata publishes registered authority and ACS policy",
  (ctx) => samlMetadataFlow(ctx, false),
);
