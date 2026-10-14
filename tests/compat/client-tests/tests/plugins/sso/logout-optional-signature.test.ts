import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("SSO optional XML signature preserves disabled logout response checking", (ctx) =>
  samlLogoutFlow(ctx, true, false, false, "post-optional-signature"),
);
compatScenario("SSO optional XML signature preserves disabled IdP logout request checking", (ctx) =>
  idpLogoutFlow(ctx, "ignored", true),
);
