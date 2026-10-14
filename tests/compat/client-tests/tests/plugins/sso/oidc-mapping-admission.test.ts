import { compatScenario } from "../../../support/scenario";
import { mappingAdmissionFlow } from "./mapping-admission-flow";
compatScenario(
  "OIDC mapping admission validates identity fields before registration and updates",
  (ctx) => mappingAdmissionFlow(ctx),
);
