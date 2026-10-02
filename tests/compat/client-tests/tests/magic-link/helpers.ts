import { createAuthClient } from "better-auth/client";
import { magicLinkClient as officialMagicLinkClient } from "better-auth/client/plugins";
import { z } from "zod";
import { fixtureValue, type ScenarioContext } from "../../support/verification";

const delivery = z.object({ url: z.string(), token: z.string(), metadata: z.unknown() });

export function magicLinkClient(ctx: ScenarioContext, actor = "primary") {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [officialMagicLinkClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor).fetch },
  });
}

export async function readMagicLink(ctx: ScenarioContext, email: string) {
  const parsed = delivery.safeParse(await fixtureValue(ctx, "/__test/magic-link", { email }));
  if (!parsed.success)
    throw new Error("Successful link issuance must deliver the actual URL and token");
  return parsed.data;
}
