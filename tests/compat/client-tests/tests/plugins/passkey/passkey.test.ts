import { expect } from "bun:test";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { Authenticator } from "../../../support/authenticator";
import { compatScenario } from "../../../support/scenario";

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
    let ownerCookie = "";
    const signup = await owner.client.signUp.email({
      email,
      password: "password123",
      name: "Passkey Owner",
      fetchOptions: {
        onSuccess({ response }) {
          ownerCookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
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

    let attackerCookie = "";
    const attackerSignup = await attacker.client.signUp.email({
      email: ctx.uniqueEmail("passkey-attacker"),
      password: "password123",
      name: "Other User",
      fetchOptions: {
        onSuccess({ response }) {
          attackerCookie = response.headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(attackerSignup.error).toBeNull();

    async function serverDelete(body: unknown, cookie?: string) {
      const response = await owner.fetch(`${ctx.baseURL}/__test/server-api/passkey-delete`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ body, ...(cookie ? { headers: { cookie } } : {}) }),
      });
      expect(response.headers.get("set-cookie")).toBeNull();
      const text = await response.text();
      return { status: response.status, body: text ? JSON.parse(text) : null, absent: text === "" };
    }
    const forbiddenDelete = await serverDelete({ id: passkey.id }, attackerCookie);
    expect(forbiddenDelete.status).toBe(401);
    expect(forbiddenDelete.absent).toBe(true);
    const malformedDelete = await serverDelete({ id: 42 }, ownerCookie);
    expect(malformedDelete.status).toBe(400);
    expect(malformedDelete.body.code).toBe("VALIDATION_ERROR");
    const guestDelete = await serverDelete({ id: passkey.id });
    expect(guestDelete.status).toBe(401);
    expect(guestDelete.body.code).toBe("UNAUTHORIZED");
    const missingDelete = await serverDelete({ id: "missing-passkey" }, ownerCookie);
    expect(missingDelete.status).toBe(404);
    expect(missingDelete.body.code).toBe("PASSKEY_NOT_FOUND");
    const emptyDelete = await serverDelete({ id: "" }, ownerCookie);
    expect(emptyDelete.status).toBe(400);
    expect(emptyDelete.body.message).toBe("Missing required parameter: id");
    const emptyHttpDelete = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/delete-passkey",
      method: "POST",
      json: { id: "" },
    });
    expect(emptyHttpDelete.status).toBe(400);
    expect(emptyHttpDelete.body).toEqual(emptyDelete.body);
    const retained = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/list-user-passkeys",
    });
    expect(retained.body).toMatchObject([
      { id: passkey.id, userId: user.id, credentialID: passkey.credentialID, name: "Laptop" },
    ]);

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
      json: { id: passkey.id, name: " \uFEFF\u00A0Renamed\u2028\t " },
    });
    expect(renamed.status).toBe(200);

    async function serverList(cookie?: string) {
      const response = await owner.fetch(`${ctx.baseURL}/__test/server-api/passkey-list`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          body: { userId: attackerSignup.data!.user.id },
          ...(cookie ? { headers: { cookie } } : {}),
        }),
      });
      expect(response.headers.get("set-cookie")).toBeNull();
      return { status: response.status, body: (await response.json()) as any };
    }
    const guestList = await serverList();
    expect(guestList.status).toBe(401);
    expect(guestList.body.code).toBe("UNAUTHORIZED");
    const foreignList = await serverList(attackerCookie);
    expect(foreignList.status).toBe(200);
    expect(foreignList.body).toEqual([]);
    const listed = await serverList(ownerCookie);
    expect(listed.status).toBe(200);
    expect(listed.body).toMatchObject([
      { id: passkey.id, userId: user.id, credentialID: passkey.credentialID },
    ]);
    expect(
      z
        .array(z.object({ name: z.string() }))
        .parse(listed.body)
        .map((key) => key.name),
    ).toEqual(["Renamed"]);

    const rejectedLabels = [];
    for (const name of [" \t\n", "\uFEFF\u00A0", "\u2028\u2029"]) {
      const rejected = await ctx.rawRequest({
        actor: "owner",
        path: "/api/auth/passkey/update-passkey",
        method: "POST",
        json: { id: passkey.id, name },
      });
      expect(rejected.status).toBe(400);
      const unchanged = await ctx.rawRequest({
        actor: "owner",
        path: "/api/auth/passkey/list-user-passkeys",
      });
      expect(unchanged.body).toEqual(listed.body);
      rejectedLabels.push(rejected);
    }

    await owner.client.signOut();
    expect((await owner.client.getSession()).data).toBeNull();

    const authOptions = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/generate-authenticate-options",
    });
    expect(authOptions.status).toBe(200);

    const assertion = authenticator.authenticate(authOptions.body, ctx.baseURL);
    const authenticationResponse = await owner.fetch(
      `${ctx.baseURL}/api/auth/passkey/verify-authentication`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ response: assertion }),
      },
    );
    ownerCookie = authenticationResponse.headers
      .getSetCookie()
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const authentication = {
      status: authenticationResponse.status,
      location: authenticationResponse.headers.get("location"),
      body: await authenticationResponse.json(),
    };
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

    const deleted = await serverDelete(
      { id: passkey.id, userId: attackerSignup.data!.user.id },
      ownerCookie,
    );
    expect(deleted.status).toBe(200);
    expect(deleted.body).toEqual({ status: true });
    const deleteReplay = await serverDelete({ id: passkey.id }, ownerCookie);
    expect(deleteReplay.status).toBe(404);
    expect(deleteReplay.body.code).toBe("PASSKEY_NOT_FOUND");

    const empty = await ctx.rawRequest({
      actor: "owner",
      path: "/api/auth/passkey/list-user-passkeys",
    });
    expect(empty.body).toEqual([]);

    return {
      registration,
      renamed,
      rejectedLabels,
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
