import { compatScenario } from "../../../support/scenario";
import { samlMetadataAdmissionFlow } from "./metadata-admission-flow";
compatScenario(
  "SAML SP metadata validates declared fields before registration or update and drops unknown fields",
  (ctx) => samlMetadataAdmissionFlow(ctx, false),
);
