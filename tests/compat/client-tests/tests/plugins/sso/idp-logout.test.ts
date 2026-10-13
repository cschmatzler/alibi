import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
compatScenario("IdP logout retires matching sessions and preserves mismatched indexes", (ctx) =>
  idpLogoutFlow(ctx, false),
);
