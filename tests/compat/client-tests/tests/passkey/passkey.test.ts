import { expect } from "bun:test";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { Authenticator } from "../../support/authenticator";
import { compatScenario } from "../../support/scenario";

function passkeyActor(ctx: Parameters<Parameters<typeof compatScenario>[1]>[0], name = "primary") {
  const actor = ctx.actor(name);
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [passkeyClient()],
    fetchOptions: {
      customFetchImpl: actor.fetch,
    },
  });
}

compatScenario(
  "passkey client surface matches TS for options and management errors",
  async (ctx) => {
    const actor = ctx.actor("primary");
    const passkey = passkeyActor(ctx, "primary");
    const email = ctx.uniqueEmail("passkey-passkey");

    const signup = await actor.client.signUp.email({
      email,
      password: "password123",
      name: "Passkey Passkey",
    });

    const registerOptions = await passkey.$fetch("/passkey/generate-register-options", {
      method: "GET",
      query: {
        name: "Laptop Passkey",
        authenticatorAttachment: "cross-platform",
      },
      throw: false,
    });

    const authenticateOptions = await passkey.$fetch("/passkey/generate-authenticate-options", {
      method: "GET",
      throw: false,
    });

    const listPasskeys = await passkey.$fetch("/passkey/list-user-passkeys", {
      method: "GET",
      throw: false,
    });

    const deleteMissing = await passkey.$fetch("/passkey/delete-passkey", {
      method: "POST",
      body: {
        id: "missing-passkey-id",
      },
      throw: false,
    });

    const updateMissing = await passkey.$fetch("/passkey/update-passkey", {
      method: "POST",
      body: {
        id: "missing-passkey-id",
        name: "Renamed Passkey",
      },
      throw: false,
    });

    return {
      signup: ctx.snapshot(signup),
      registerOptions: ctx.snapshot(registerOptions),
      authenticateOptions: ctx.snapshot(authenticateOptions),
      listPasskeys: ctx.snapshot(listPasskeys),
      deleteMissing: ctx.snapshot(deleteMissing),
      updateMissing: ctx.snapshot(updateMissing),
    };
  },
);

compatScenario(
  "passkey registration authentication ownership and deletion round trip",
  async (ctx) => {
    const owner = ctx.actor("owner");
    const attacker = ctx.actor("attacker");
    const email = ctx.uniqueEmail("passkey-owner");
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Passkey Owner",
    });
    expect(signup.error).toBeNull();

    const user = z.object({ user: z.object({ id: z.string() }) }).parse(signup.data).user;
    const authenticator = new Authenticator();
    const options = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/generate-register-options",
    });
    expect(options.status).toBe(200);

    const response = authenticator.register(options.body, ctx.baseURL);
    const registration = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/verify-registration",
      method: "POST",
      json: { response, name: "Laptop" },
    });
    expect(registration.status).toBe(200);

    const passkey = z
      .object({ id: z.string(), userId: z.string(), credentialID: z.string(), counter: z.number() })
      .parse(registration.body);
    expect(passkey.userId).toBe(user.id);
    expect(passkey.counter).toBe(0);
    expect(passkey.credentialID).toBe(response.id);

    const attackerSignup = await attacker.client.signUp.email({
      email: ctx.uniqueEmail("passkey-attacker"),
      password: "password123",
      name: "Other User",
    });
    expect(attackerSignup.error).toBeNull();

    const forbiddenDelete = await ctx.rawRequest({
      actor: "attacker",
      path: "/api/auth/passkey/delete-passkey",
      method: "POST",
      json: { id: passkey.id },
    });
    expect(forbiddenDelete.status).toBe(401);

    const forbiddenUpdate = await ctx.rawRequest({
      actor: "attacker",
      path: "/api/auth/passkey/update-passkey",
      method: "POST",
      json: { id: passkey.id, name: "Hijacked" },
    });
    expect(forbiddenUpdate.status).toBe(401);

    const renamed = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/update-passkey",
      method: "POST",
      json: { id: passkey.id, name: "Renamed" },
    });
    expect(renamed.status).toBe(200);

    const listed = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/list-user-passkeys",
    });
    expect(
      z
        .array(z.object({ name: z.string() }))
        .parse(listed.body)
        .map((key) => key.name),
    ).toEqual(["Renamed"]);

    await owner.client.signOut();
    expect((await owner.client.getSession()).data).toBeNull();

    const authOptions = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/generate-authenticate-options",
    });
    expect(authOptions.status).toBe(200);

    const assertion = authenticator.authenticate(authOptions.body, ctx.baseURL);
    const authentication = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/verify-authentication",
      method: "POST",
      json: { response: assertion },
    });
    expect(authentication.status).toBe(200);

    const session = await owner.client.getSession();
    expect(session.data?.user.id).toBe(user.id);

    const afterLogin = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/list-user-passkeys",
    });
    expect(
      z
        .array(z.object({ counter: z.number() }))
        .parse(afterLogin.body)
        .map((key) => key.counter),
    ).toEqual([1]);

    const replay = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/verify-authentication",
      method: "POST",
      json: { response: assertion },
    });
    expect(replay.status).toBeGreaterThanOrEqual(400);

    const deleted = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/delete-passkey",
      method: "POST",
      json: { id: passkey.id },
    });
    expect(deleted.status).toBe(200);

    const empty = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/list-user-passkeys",
    });
    expect(empty.body).toEqual([]);

    return {
      registration,
      renamed,
      authentication,
      session: ctx.snapshot(session),
      forbiddenDelete,
      forbiddenUpdate,
      replay,
      deleted,
    };
  },
  [
    "POST /passkey/verify-registration",
    "POST /passkey/verify-authentication",
    "POST /passkey/update-passkey",
    "POST /passkey/delete-passkey",
    "POST /sign-out",
  ],
);
