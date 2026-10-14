import { compatScenario } from "../../../support/scenario";
import { samlLogoutFlow } from "./logout-flow";
compatScenario("SSO GET logout ignores optional query signature and retires real proof", (ctx) =>
  samlLogoutFlow(ctx, true, false, false, "redirect"),
);
