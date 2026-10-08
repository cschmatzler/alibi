import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { oneTimeTokenClient } from "better-auth/client/plugins";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "OTT new-session header callbacks reject after real authentication commits",
  async (ctx) => {
    const profile = "ott-custom-header";
    function actor(name: string) {
      return {
        client: createAuthClient({
          baseURL: `${ctx.baseURL}/__test/profiles/${profile}/api/auth`,
          plugins: [oneTimeTokenClient()],
          fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
        }),
      };
    }
    async function control(mode?: string) {
      const response = await fetch(`${ctx.baseURL}/__test/one-time-token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation: "callbacks", profile, ...(mode ? { mode } : {}) }),
      });
      expect(response.status).toBe(200);
      return response.json() as Promise<{
        events: {
          stage: string;
          userId?: string;
          session?: { id: string; token: string; userId: string; expiresAt: string };
          request?: { path: string; method: string; marker: string };
        }[];
      }>;
    }
    const foreign = await ctx.actor("ott-foreign").client.signUp.email({
      email: ctx.uniqueEmail("ott-foreign"),
      password: "password123",
      name: "Foreign OTT",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    async function proofs() {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      const state = (await response.json()) as Record<string, Record<string, unknown>[]>;
      return state.verification ?? state.verifications;
    }
    const observations = [];
    const mismatches = [];
    for (const endpoint of ["signup", "signin"] as const) {
      for (const stage of ["generate", "hash"] as const) {
        for (const kind of ["ordinary", "veto"] as const) {
          const label = `${endpoint}-${stage}-${kind}`;
          const email = ctx.uniqueEmail(label);
          const owner = actor(label);
          await control("success");
          if (endpoint === "signin") {
            const registered = await owner.client.signUp.email({
              email,
              password: "password123",
              name: "OTT Header Owner",
            });
            expect(registered.error).toBeNull();
          }
          const proofsBefore = await proofs();
          await control(`${stage}-${kind}`);
          let transport: { status: number; body: string; ott: string | null } | undefined;
          const options = {
            headers: { "x-ott-marker": label },
            async onResponse({ response }: { response: Response }) {
              transport = {
                status: response.status,
                body: await response.clone().text(),
                ott: response.headers.get("set-ott"),
              };
            },
          };
          const failed =
            endpoint === "signup"
              ? await owner.client.signUp.email(
                  { email, password: "password123", name: "OTT Header Owner" },
                  options,
                )
              : await owner.client.signIn.email({ email, password: "password123" }, options);
          const receipt = await control();
          expect(receipt.events.map((event) => event.stage)).toEqual(
            stage === "generate" ? ["generate"] : ["generate", "hash"],
          );
          const generated = receipt.events[0]!;
          expect(generated.request).toEqual({
            path: endpoint === "signup" ? "/sign-up/email" : "/sign-in/email",
            method: "POST",
            marker: label,
          });
          const state = (await ctx.readUserState({ userId: generated.userId! })) as {
            user: { id: string; email: string };
            accounts: { providerId: string; userId: string }[];
            sessions: { id: string; token: string; userId: string; expiresAt: string }[];
          };
          expect(state.user.email).toBe(email);
          expect(state.accounts).toContainEqual(
            expect.objectContaining({ providerId: "credential", userId: generated.userId }),
          );
          expect(state.sessions).toHaveLength(endpoint === "signup" ? 1 : 2);
          expect(state.sessions).toContainEqual(expect.objectContaining(generated.session!));
          expect(await proofs()).toEqual(proofsBefore);
          expect(transport?.ott).toBeNull();
          expect(failed.data).toBeNull();
          expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
          const expectedStatus = kind === "ordinary" ? 500 : 403;
          if (
            transport?.status !== expectedStatus ||
            (kind === "ordinary"
              ? transport.body !== ""
              : transport.body !==
                JSON.stringify({ code: "OTT_VETO", message: "OTT callback veto" }))
          ) {
            mismatches.push({ label, transport });
          }
          await control("success");
          let token: string | null = null;
          const restored = await owner.client.signIn.email(
            { email, password: "password123" },
            {
              onResponse({ response }) {
                token = response.headers.get("set-ott");
              },
            },
          );
          expect(restored.error).toBeNull();
          expect(restored.data?.user.id).toBe(generated.userId);
          expect(token as string | null).toMatch(/^ott-header-token-\d+$/);
          const pending = await ctx.readVerificationState({
            identifier: `one-time-token:digest-${token}`,
          });
          expect(pending).toMatchObject([{ value: restored.data!.token }]);
          const consumed = await actor(`consumer-${label}`).client.oneTimeToken.verify({
            token: token!,
          });
          expect(consumed.error).toBeNull();
          expect(consumed.data?.session.token).toBe(restored.data!.token);
          const replay = await actor(`consumer-${label}`).client.oneTimeToken.verify({
            token: token!,
          });
          expect(replay.error?.status).toBe(400);
          observations.push({
            label,
            failed: ctx.snapshot(failed),
            transport,
            receipt,
            state,
            restored: ctx.snapshot(restored),
            consumed: ctx.snapshot(consumed),
            replay: ctx.snapshot(replay),
          });
        }
      }
    }
    expect(mismatches).toEqual([]);
    return { foreign: ctx.snapshot(foreign), observations };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);
