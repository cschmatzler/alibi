import { compatScenario } from "../../../support/scenario";
import { idpLogoutFlow } from "./idp-logout-flow";
compatScenario("IdP logout requires a trusted signature before session retirement", (ctx) =>
  idpLogoutFlow(ctx, "required"),
);
