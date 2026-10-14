import { compatScenario } from "../../../support/scenario";
import { samlMetadataAdmissionFlow } from "./metadata-admission-flow";
compatScenario(
  "SAML IdP metadata validates declared fields and service URLs before durable provider mutations",
  (ctx) => samlMetadataAdmissionFlow(ctx, true),
);
