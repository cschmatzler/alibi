import { compatScenario } from "../../../support/scenario";
import { idpInitiatedFlow } from "./idp-initiated-flow";
compatScenario(
  "SAML IdP-initiated admission requires opt-in, trusted signatures and fresh assertions",
  (ctx) => idpInitiatedFlow(ctx),
);
