import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";
import { readOtp } from "./helpers";

compatScenario(
  "OTP email change hook failures retain consumed proofs and stage-specific mailbox commits",
  async (ctx) => {
    const observations = [];
    const mismatches = [];
    const control = async (stage?: string, error = "ordinary") => {
      const response = await fetch(
        `${ctx.baseURL}/__test/email-change-hooks`,
        stage
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ stage, error }),
            }
          : undefined,
      );
      expect(response.status).toBe(200);
      return (await response.json()) as {
        events: {
          stage: string;
          user: { id: string; email: string; emailVerified: boolean };
          request: unknown;
        }[];
      };
    };
    const foreign = await ctx.actor("hook-foreign").client.signUp.email({
      email: ctx.uniqueEmail("hook-foreign"),
      password: "password123",
      name: "Foreign Hook Owner",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await readUserState(ctx, foreign.data!.user.id);
    for (const stage of ["before", "after"] as const) {
      for (const error of ["ordinary", "coded"] as const) {
        const name = `change-${stage}-${error}`;
        const actor = ctx.actor(name, "otp-change-hooks");
        const email = ctx.uniqueEmail(name);
        const target = ctx.uniqueEmail(`${name}-target`);
        const marker = `${name}-marker`;
        await control("none");
        const signup = await actor.client.signUp.email({
          email,
          password: "password123",
          name: "Hook Owner",
        });
        expect(signup.error).toBeNull();
        const userId = signup.data!.user.id;
        const before = await readUserState(ctx, userId);
        const issued = await actor.client.emailOtp.requestEmailChange({ newEmail: target });
        expect(issued.error).toBeNull();
        const otp = await readOtp(ctx, target, "change-email");
        const identifier = `change-email-otp-${email}-${target}`;
        expect(await ctx.readVerificationState({ identifier })).toHaveLength(1);
        await control(stage, error);
        let cookies: string[] = [];
        const failed = await actor.client.emailOtp.changeEmail(
          { newEmail: target, otp },
          {
            headers: { "x-email-change-marker": marker },
            onResponse: ({ response }) => {
              cookies = response.headers.getSetCookie();
            },
          },
        );
        expect(failed.data).toBeNull();
        expect(failed.error?.status).toBe(error === "coded" ? 403 : 500);
        expect(cookies).toEqual([]);
        expect(await ctx.readVerificationState({ identifier })).toEqual([]);
        const committed = await readUserState(ctx, userId);
        expect(committed.sessions).toEqual(before.sessions);
        expect(committed.accounts).toEqual(before.accounts);
        expect(committed.user).toEqual(
          stage === "before"
            ? before.user
            : { ...before.user!, email: target, emailVerified: true },
        );
        const events = (await control()).events;
        expect(events.map((row) => row.stage)).toEqual(
          stage === "before" ? ["before"] : ["before", "after"],
        );
        for (const event of events) {
          expect(event.user).toEqual({
            id: userId,
            email: event.stage === "before" ? email : target,
            emailVerified: event.stage === "before" ? false : true,
          });
          const expectedRequest = {
            path: "/__test/profiles/otp-change-hooks/api/auth/email-otp/change-email",
            method: "POST",
            marker,
          };
          if (JSON.stringify(event.request) !== JSON.stringify(expectedRequest)) {
            mismatches.push({ stage, error, event });
          }
        }
        if (error === "coded") {
          expect(failed.error).toMatchObject({
            code: "EMAIL_CHANGE_HOOK_VETO",
            message: "Application verification hook rejected",
          });
        } else if (
          JSON.stringify(failed.error) !==
          JSON.stringify({ status: 500, statusText: "Internal Server Error" })
        ) {
          mismatches.push({ stage, error, failure: failed.error });
        }
        const authority = await actor.client.getSession();
        expect(authority.data?.session.id).toBe(before.sessions[0]!.id);
        expect(authority.data?.user.email).toBe(stage === "before" ? email : target);
        expect(authority.data?.session.token).toBe(signup.data!.token!);
        expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(foreignBefore);
        const replay = await actor.client.emailOtp.changeEmail({ newEmail: target, otp });
        expect(replay.error?.status).toBe(400);
        expect(await readUserState(ctx, userId)).toEqual(committed);
        const replayEvents = (await control()).events;
        expect(replayEvents).toEqual(events);
        await control("none");
        const recoveryTarget = ctx.uniqueEmail(`${name}-recovery`);
        const reissued = await actor.client.emailOtp.requestEmailChange({
          newEmail: recoveryTarget,
        });
        expect(reissued.error).toBeNull();
        const fresh = await readOtp(ctx, recoveryTarget, "change-email");
        const recovered = await actor.client.emailOtp.changeEmail(
          { newEmail: recoveryTarget, otp: fresh },
          { headers: { "x-email-change-marker": `${marker}-recovery` } },
        );
        expect(recovered.error).toBeNull();
        expect((await actor.client.getSession()).data?.user).toMatchObject({
          id: userId,
          email: recoveryTarget,
          emailVerified: true,
        });
        expect(
          await ctx.readVerificationState({
            identifier: `change-email-otp-${stage === "before" ? email : target}-${recoveryTarget}`,
          }),
        ).toEqual([]);
        expect((await readUserState(ctx, userId)).sessions).toEqual(before.sessions);
        observations.push({
          stage,
          error,
          signup,
          issued,
          failed,
          committed,
          events,
          authority,
          replay,
          reissued,
          recovered,
          recoveryEvents: await control(),
        });
      }
    }
    expect((await ctx.actor("hook-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    expect(mismatches).toEqual([]);
    return ctx.snapshot({ foreign, observations });
  },
  ["POST /email-otp/request-email-change", "POST /email-otp/change-email"],
);
