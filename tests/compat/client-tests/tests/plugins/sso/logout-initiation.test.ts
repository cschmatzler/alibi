import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("SAML logout uses ACS session indexes and retires the actual session", (ctx) =>
  samlLogoutFlow(ctx, false),
);
