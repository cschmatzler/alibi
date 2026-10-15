import { expect } from "vitest";
import { z } from "zod";

import { cacheReceipt } from "./compact-cache-receipt";
import type { ScenarioContext } from "./verification";

export const revocationObservation = z.object({
  result: z
    .object({
      ok: z.boolean(),
      status: z.number().optional(),
      body: z
        .object({ code: z.string().optional(), message: z.string().optional() })
        .passthrough()
        .optional(),
      value: z
        .object({
          response: z.object({ status: z.boolean() }),
          headers: z.record(z.string(), z.string()),
        })
        .optional(),
    })
    .passthrough(),
  events: z.array(
    z
      .object({
        stage: z.string(),
        path: z.string().nullable(),
        request: z.unknown(),
        session: z
          .object({ user: z.object({ id: z.string() }) })
          .passthrough()
          .nullable(),
      })
      .passthrough(),
  ),
});
export async function issueSession(
  ctx: ScenarioContext,
  name: string,
  email: string,
  signIn = false,
) {
  let headers = new Headers();
  const actor = ctx.actor(name, "server-dispatch-cache");
  const fetchOptions = {
    onSuccess({ response }: { response: Response }) {
      headers = new Headers(response.headers);
    },
  };
  const result = signIn
    ? await actor.client.signIn.email({
        email,
        password: "Correct-Horse-Password-205",
        fetchOptions,
      })
    : await actor.client.signUp.email({
        name,
        email,
        password: "Correct-Horse-Password-205",
        fetchOptions,
      });
  expect(result.error).toBeNull();
  const cookie = headers
    .getSetCookie()
    .map((raw) => raw.split(";")[0])
    .join("; ");
  expect(cookie).toContain("better-auth.session_data=");
  return {
    result,
    headers: { cookie },
    publication: {
      body: result.data,
      headers: Object.fromEntries(
        [...headers].filter(([name]) => !["date", "content-length"].includes(name)),
      ),
      ...(await cacheReceipt(headers)),
    },
  };
}
