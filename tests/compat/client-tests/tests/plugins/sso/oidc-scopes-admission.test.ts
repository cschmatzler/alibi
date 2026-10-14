import { compatScenario } from "../../../support/scenario";
import { mappingAdmissionFlow } from "./mapping-admission-flow";
compatScenario(
  "OIDC scopes admission validates string arrays before registration and updates",
  (ctx) => mappingAdmissionFlow(ctx, false, true),
);
