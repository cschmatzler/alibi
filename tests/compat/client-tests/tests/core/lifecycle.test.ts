import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";

const control = z.object({
  events: z.array(
    z.object({
      stage: z.string(),
      path: z.string(),
      status: z.number().optional(),
      header: z.string().nullable().optional(),
      cookieCount: z.number().optional(),
    }),
  ),
  state: z
    .object({
      userId: z.string().nullable(),
      accounts: z.array(z.object({ id: z.string(), userId: z.string(), providerId: z.string() })),
      sessions: z.array(z.object({ id: z.string(), userId: z.string(), token: z.string() })),
    })
    .nullable(),
});

compatScenario(
  "core response hooks see endpoint failures and preserve issued session cookies",
  async (ctx) => {
    await ctx.rawRequest({ path: "/__test/lifecycle" });
    const actor = ctx.actor();
    const email = ctx.uniqueEmail("lifecycle-session");
    const signup = await actor.client.signUp.email(
      { email, password: "password123", name: "Lifecycle User" },
      {
        headers: { "x-parity-lifecycle": "reject" },
      },
    );
    expect(signup.error?.status).toBe(403);
    expect(signup.error?.message).toBe("fixture after rejection");
    const issued = control.parse(
      (await ctx.rawRequest({ path: `/__test/lifecycle?email=${encodeURIComponent(email)}` })).body,
    );
    expect(issued.events).toEqual([
      { stage: "before", path: "/sign-up/email" },
      { stage: "after", path: "/sign-up/email", status: 200 },
      { stage: "observe", path: "/sign-up/email", status: 403, header: "visible", cookieCount: 2 },
    ]);
    if (!issued.state?.userId) throw new Error("Signup must persist before its after hook rejects");
    expect(issued.state.accounts).toHaveLength(1);
    expect(issued.state.accounts[0]?.providerId).toBe("credential");
    expect(issued.state.accounts[0]?.userId).toBe(issued.state.userId);
    expect(issued.state.sessions).toHaveLength(1);
    expect(issued.state.sessions[0]?.userId).toBe(issued.state.userId);
    const current = await actor.client.getSession();
    expect(current.error).toBeNull();
    expect(current.data?.user.id).toBe(issued.state.userId);
    expect(current.data?.session.token).toBe(issued.state.sessions[0]?.token);
    const invalid = await actor.client.signIn.email(
      { email, password: "incorrect-password" },
      {
        headers: { "x-parity-lifecycle": "trace" },
      },
    );
    expect(invalid.error?.status).toBe(401);
    const rejected = control.parse(
      (await ctx.rawRequest({ path: `/__test/lifecycle?email=${encodeURIComponent(email)}` })).body,
    );
    expect(rejected.events).toEqual([
      { stage: "before", path: "/sign-in/email" },
      { stage: "after", path: "/sign-in/email", status: 401 },
      { stage: "observe", path: "/sign-in/email", status: 401, header: "visible", cookieCount: 1 },
    ]);
    expect(rejected.state).toEqual(issued.state);
    const credentialActor = ctx.actor("credential-login");
    const credentialLogin = await credentialActor.client.signIn.email({
      email,
      password: "password123",
    });
    expect(credentialLogin.error).toBeNull();
    expect(credentialLogin.data?.user.id).toBe(issued.state.userId);
    expect(credentialLogin.data?.token).toBeString();
    expect(credentialLogin.data?.token).not.toBe(issued.state.sessions[0]?.token);
    const credentialSession = await credentialActor.client.getSession();
    expect(credentialSession.data?.session.token).toBe(credentialLogin.data?.token);
    expect(credentialSession.data?.user.id).toBe(issued.state.userId);
    return { signup, issued, current, invalid, rejected, credentialLogin, credentialSession };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);

compatScenario(
  "core before responses stop endpoint writes and unknown routes cannot run hooks",
  async (ctx) => {
    await ctx.rawRequest({ path: "/__test/lifecycle" });
    const actor = ctx.actor();
    const email = ctx.uniqueEmail("lifecycle-stop");
    const stopped = await actor.client.signUp.email(
      { email, password: "password123", name: "Stopped User" },
      {
        headers: { "x-parity-lifecycle": "stop" },
      },
    );
    expect(stopped.error).toBeNull();
    const stoppedData: unknown = stopped.data;
    expect(stoppedData).toEqual({ stopped: true });
    const prevented = control.parse(
      (await ctx.rawRequest({ path: `/__test/lifecycle?email=${encodeURIComponent(email)}` })).body,
    );
    expect(prevented.events).toEqual([{ stage: "before", path: "/sign-up/email" }]);
    expect(prevented.state).toEqual({ userId: null, accounts: [], sessions: [] });
    const unknown = await ctx.rawRequest({
      path: "/api/auth/unregistered-lifecycle",
      headers: { "x-parity-lifecycle": "stop" },
    });
    const wrongMethod = await ctx.rawRequest({
      path: "/api/auth/ok",
      method: "POST",
      json: {},
      headers: { "x-parity-lifecycle": "trace" },
    });
    expect(unknown).toEqual({ status: 404, location: null, body: null });
    expect(wrongMethod).toEqual({ status: 404, location: null, body: null });
    const absent = control.parse((await ctx.rawRequest({ path: "/__test/lifecycle" })).body);
    expect(absent.events).toEqual([]);
    const okResponse = await actor.fetch("/api/auth/ok", {
      headers: { "x-parity-lifecycle": "trace" },
    });
    expect(okResponse.status).toBe(200);
    const ok: unknown = await okResponse.json();
    expect(ok).toEqual({ ok: true });
    expect(okResponse.headers.get("x-lifecycle-observed")).toBe("visible");
    const observed = control.parse((await ctx.rawRequest({ path: "/__test/lifecycle" })).body);
    expect(observed.events).toEqual([
      { stage: "before", path: "/ok" },
      { stage: "after", path: "/ok", status: 200 },
      { stage: "observe", path: "/ok", status: 200, header: "visible", cookieCount: 1 },
    ]);
    return { stopped, prevented, unknown, wrongMethod, absent, ok, observed };
  },
  ["POST /sign-up/email"],
);
