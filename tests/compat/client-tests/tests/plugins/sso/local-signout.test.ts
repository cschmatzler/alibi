import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario(
  "SSO server sign-out retires SAML tracking while preserving unrelated sessions",
  (ctx) => samlLogoutFlow(ctx, false, false, false, "local-api"),
);
compatScenario(
  "SSO HTTP sign-out retires SAML tracking while preserving unrelated sessions",
  (ctx) => samlLogoutFlow(ctx, false, false, false, "local-http"),
);

compatScenario("SSO sign-out preserves tracking when SAML single logout is disabled", (ctx) =>
  samlLogoutFlow(ctx, false, false, false, "local-disabled"),
);
