import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
compatScenario(
  "IdP logout HTTP form accepts external origin and retires matching sessions",
  (ctx) => idpLogoutFlow(ctx, false, true),
);
