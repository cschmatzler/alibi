import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";

// Unauthenticated callers must receive identical values, statuses and cookie
// attributes on the session surface. Both runtimes are compared literally
// through the official client; this replaces the former shape-only wire
// smoke checks with full value comparison.
compatScenario("guest session surface returns identical empty reads and sign-out", async (ctx) => {
  const guest = ctx.actor("guest");
  const session = await guest.client.getSession();
  const sessions = await guest.client.listSessions();
  const signOut = await guest.client.signOut();
  const sessionAgain = await guest.client.getSession();
  expect(session.data).toBeNull();
  expect(sessions.error).toMatchObject({ status: 401 });
  expect(signOut.data).toMatchObject({ success: true });
  expect(sessionAgain.data).toBeNull();
  return {
    session: ctx.snapshot(session),
    sessions: ctx.snapshot(sessions),
    signOut: ctx.snapshot(signOut),
    sessionAgain: ctx.snapshot(sessionAgain),
  };
});

compatScenario(
  "sign-out with a foreign or malformed session cookie is rejected identically",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const email = ctx.uniqueEmail("guest-surface");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Guest Surface",
    });
    expect(signup.error).toBeNull();
    const forged = await ctx.rawRequest({
      actor: "forger",
      path: "/api/auth/sign-out",
      method: "POST",
      headers: { cookie: "better-auth.session_token=not-a-real-token.not-a-real-signature" },
      json: {},
    });
    const unsigned = await ctx.rawRequest({
      actor: "forger",
      path: "/api/auth/list-sessions",
      method: "GET",
      headers: { cookie: `better-auth.session_token=${signup.data?.token ?? ""}` },
    });
    const ownerStill = await owner.client.getSession();
    expect(ownerStill.data?.user.email).toBe(email);
    return {
      signup: ctx.snapshot(signup),
      forged: ctx.snapshot(forged),
      unsigned: ctx.snapshot(unsigned),
      ownerStill: ctx.snapshot(ownerStill),
    };
  },
);
