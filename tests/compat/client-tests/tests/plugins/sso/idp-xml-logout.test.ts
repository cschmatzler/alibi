import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("IdP XML logout uses XML services and trusted response signatures", (ctx) =>
  samlLogoutFlow(ctx, true, true, false, "xml-idp"),
);
compatScenario("IdP XML HTTP logout uses XML services and trusted request signatures", (ctx) =>
  idpLogoutFlow(ctx, "xml-idp", true),
);
