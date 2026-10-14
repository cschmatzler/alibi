import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("Custom SP XML drives logout request issuer and NameID format", (ctx) =>
  samlLogoutFlow(ctx, true, false, false, "custom-sp"),
);
compatScenario("Custom SP XML drives IdP logout response issuer", (ctx) =>
  idpLogoutFlow(ctx, "custom-sp", true),
);
