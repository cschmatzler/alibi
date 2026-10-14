import { compatScenario } from "../../../support/scenario";
import { idpInitiatedFlow } from "./idp-initiated-flow";
for (const global of ["relative", "absolute", "unsafe"] as const) {
  compatScenario(
    `SAML global ${global} callback honors provider precedence and trusted fallbacks`,
    (ctx) => idpInitiatedFlow(ctx, global),
  );
}
