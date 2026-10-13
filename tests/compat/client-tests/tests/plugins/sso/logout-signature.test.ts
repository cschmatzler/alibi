import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("Required SAML logout signatures preserve proof until trusted completion", (ctx) =>
  samlLogoutFlow(ctx, true, true),
);
