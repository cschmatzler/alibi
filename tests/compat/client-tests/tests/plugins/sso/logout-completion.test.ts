import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("SAML logout completion retires correlation and rejects external relay", (ctx) =>
  samlLogoutFlow(ctx, true),
);
