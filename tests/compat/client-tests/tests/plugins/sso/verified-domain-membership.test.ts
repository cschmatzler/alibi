import { compatScenario } from "../../../support/scenario";
import { socialDomainMembershipFlow } from "./domain-membership-flow";
compatScenario(
  "Verified SSO domains assign social users while unverified and ambiguous identities remain unassigned",
  (ctx) => socialDomainMembershipFlow(ctx, false),
);
compatScenario(
  "Verified SSO domains assign HTTP social users while unverified and ambiguous identities remain unassigned",
  (ctx) => socialDomainMembershipFlow(ctx, true),
);
