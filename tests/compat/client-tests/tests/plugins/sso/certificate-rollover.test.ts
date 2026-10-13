import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("SAML rollover accepts a later trusted certificate for login and logout", (ctx) =>
  samlLogoutFlow(ctx, true, true, true),
);
