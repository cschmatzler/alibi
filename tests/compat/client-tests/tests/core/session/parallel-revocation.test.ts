import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

compatScenario(
  "revoke-other-sessions launches every sibling deletion and retains independent work after rejection",
  async (ctx) => {
    const profile = "session-adapter-failure";
    const control = async (
      operation: string,
      tokens?: { heldToken: string; rejectToken: string },
    ) => {
      const response = await fetch(`${ctx.baseURL}/__test/session-adapter-failure`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ operation, ...tokens }),
      });
      expect(response.status).toBe(200);
      return (await response.json()) as { events: { stage: string; token: string }[] };
    };
    const pauseUntil = async (predicate: () => Promise<boolean>, milliseconds = 750) => {
      const deadline = Date.now() + milliseconds;
      while (Date.now() < deadline) {
        if (await predicate()) return true;
        await Bun.sleep(10);
      }
      return false;
    };
    const foreign = await ctx
      .actor("parallel-foreign")
      .client.signUp.email({
        email: ctx.uniqueEmail("parallel-foreign"),
        password: "password123",
        name: "Foreign Revocation Owner",
      });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const email = ctx.uniqueEmail("parallel-owner");
    const owner = ctx.actor("parallel-owner", profile);
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Parallel Revocation Owner",
    });
    expect(signup.error).toBeNull();
    const browsers = [];
    for (let index = 0; index < 3; index++) {
      const actor = ctx.actor(`parallel-sibling-${index}`, profile);
      const signedIn = await actor.client.signIn.email({ email, password: "password123" });
      expect(signedIn.error).toBeNull();
      browsers.push({ actor, signedIn });
    }
    const before = await readUserState(ctx, signup.data!.user.id);
    expect(before.sessions).toHaveLength(4);
    const list = await owner.client.listSessions();
    const siblings = list.data!.filter((row) => row.token !== signup.data!.token);
    expect(siblings).toHaveLength(3);
    const [held, rejected, completed] = siblings;
    await control("arm", { heldToken: held!.token, rejectToken: rejected!.token });
    let settled = false;
    const pending = owner.client.revokeOtherSessions().then((result) => {
      settled = true;
      return result;
    });
    const launched = await pauseUntil(
      async () =>
        (await control("read")).events.filter((row) => row.stage === "started").length === 3,
    );
    const launchState = await control("read");
    if (launched)
      expect(
        launchState.events
          .filter((row) => row.stage === "started")
          .map((row) => row.token)
          .sort(),
      ).toEqual(siblings.map((row) => row.token).sort());
    await control("reject");
    const rejectedWhileHeld = await pauseUntil(async () => settled);
    if (launched)
      await pauseUntil(async () =>
        (await control("read")).events.some(
          (row) => row.stage === "completed" && row.token === completed!.token,
        ),
      );
    const beforeRelease = await readUserState(ctx, signup.data!.user.id);
    const eventsBeforeRelease = await control("read");
    const retainedBeforeRelease = beforeRelease.sessions.map((row) => row.token).sort();
    const expectedBeforeRelease = [signup.data!.token!, held!.token, rejected!.token].sort();
    await control("release");
    const failed = await Promise.race([
      pending,
      Bun.sleep(5000).then(() => {
        throw new Error(
          "Sibling revocation did not complete after releasing the real adapter gate",
        );
      }),
    ]);
    await pauseUntil(async () =>
      (await control("read")).events.some(
        (row) => row.stage === "completed" && row.token === held!.token,
      ),
    );
    const final = await readUserState(ctx, signup.data!.user.id);
    const eventsAfterRelease = await control("read");
    expect(failed.data).toBeNull();
    expect(failed.error?.status).toBe(500);
    expect(final.user).toEqual(before.user);
    expect(final.accounts).toEqual(before.accounts);
    expect(final.sessions.find((row) => row.token === signup.data!.token)).toEqual(
      before.sessions.find((row) => row.token === signup.data!.token),
    );
    expect(final.sessions.find((row) => row.token === rejected!.token)).toEqual(
      before.sessions.find((row) => row.token === rejected!.token),
    );
    expect(final.sessions.find((row) => row.token === held!.token)).toBeUndefined();
    expect((await owner.client.getSession()).data?.user.id).toBe(signup.data!.user.id);
    expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
    expect((await ctx.actor("parallel-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    await control("restore");
    const surviving = browsers.find((row) => row.signedIn.data!.token === rejected!.token)!;
    expect((await surviving.actor.client.getSession()).data?.user.id).toBe(signup.data!.user.id);
    const recovery = await owner.client.revokeOtherSessions();
    expect(recovery.data).toEqual({ status: true });
    expect(
      (await readUserState(ctx, signup.data!.user.id)).sessions.map((row) => row.token),
    ).toEqual([signup.data!.token!]);
    const mismatches = [];
    if (!launched)
      mismatches.push({
        contract: "all sibling deletes started while first is held",
        events: launchState,
      });
    if (!rejectedWhileHeld)
      mismatches.push({ contract: "rejection completes before held deletion is released" });
    if (JSON.stringify(retainedBeforeRelease) !== JSON.stringify(expectedBeforeRelease))
      mismatches.push({
        contract: "independent completed deletion commits before release",
        retainedBeforeRelease,
      });
    if (final.sessions.some((row) => row.token === completed!.token))
      mismatches.push({
        contract: "all successful sibling deletions remain committed after rejection",
      });
    if (
      JSON.stringify(failed.error) !==
      JSON.stringify({ status: 500, statusText: "Internal Server Error" })
    )
      mismatches.push({ contract: "bare ordinary storage rejection", error: failed.error });
    expect(mismatches).toEqual([]);
    return ctx.snapshot({
      foreign,
      signup,
      list,
      launchState,
      beforeRelease,
      eventsBeforeRelease,
      failed,
      final,
      eventsAfterRelease,
      recovery,
    });
  },
  ["POST /revoke-other-sessions"],
);
