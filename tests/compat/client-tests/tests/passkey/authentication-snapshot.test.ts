import { expect } from "bun:test";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import { Authenticator } from "../../support/authenticator";
import { compatScenario } from "../../support/scenario";

compatScenario(
  "passkey signed backup state changes advance verified counters while preserving registration snapshots and foreign owners",
  async (ctx) => {
    const owner = ctx.actor("snapshot-owner");
    const foreign = ctx.actor("snapshot-foreign");
    const client = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [passkeyClient()],
      fetchOptions: { customFetchImpl: owner.fetch },
    });
    const foreignSignup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("snapshot-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(foreignSignup.error).toBeNull();

    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("snapshot-owner"),
      name: "Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const device = new Authenticator();
    const options = await client.$fetch("/passkey/generate-register-options", { method: "GET" });
    expect(options.error).toBeNull();

    const registered = await client.$fetch("/passkey/verify-registration", {
      method: "POST",
      body: {
        response: device.register(options.data, ctx.baseURL, { backupEligible: true }),
        name: "Owned device",
      },
    });
    expect(registered.error).toBeNull();

    const schema = z.array(
      z
        .object({
          id: z.string(),
          userId: z.string(),
          credentialID: z.string(),
          counter: z.number(),
          deviceType: z.string(),
          backedUp: z.boolean(),
        })
        .passthrough(),
    );
    const initial = await client.$fetch("/passkey/list-user-passkeys", { method: "GET" });
    const initialRow = schema.parse(initial.data)[0]!;
    expect(initialRow).toMatchObject({
      userId: signup.data!.user.id,
      counter: 0,
      deviceType: "multiDevice",
      backedUp: false,
    });

    const signout = await owner.client.signOut();
    expect(signout.error).toBeNull();

    const before = await ctx.readUserState({ userId: signup.data!.user.id });
    expect(before).toMatchObject({ sessions: [] });

    const foreignBefore = await ctx.readUserState({ userId: foreignSignup.data!.user.id });
    const authentications = [];

    for (const counter of [1, 2]) {
      const challenge = await client.$fetch("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(challenge.error).toBeNull();

      const assertion = device.authenticate(challenge.data, ctx.baseURL, {
        backupEligible: true,
        backedUp: true,
      });
      const result = await client.$fetch("/passkey/verify-authentication", {
        method: "POST",
        body: { response: assertion },
      });
      expect(result.error).toBeNull();
      expect(result.data).toMatchObject({
        user: { id: signup.data!.user.id },
        session: { userId: signup.data!.user.id },
      });

      const listed = await client.$fetch("/passkey/list-user-passkeys", { method: "GET" });
      expect(listed.error).toBeNull();

      const row = schema.parse(listed.data)[0]!;
      expect(row).toMatchObject({
        id: initialRow.id,
        userId: initialRow.userId,
        credentialID: initialRow.credentialID,
        counter,
        deviceType: "multiDevice",
        backedUp: false,
      });

      const stored = await ctx.readUserState({ userId: signup.data!.user.id });
      expect(stored).toMatchObject({
        user: { id: signup.data!.user.id },
        sessions: [{ userId: signup.data!.user.id }],
      });
      expect(await ctx.readUserState({ userId: foreignSignup.data!.user.id })).toEqual(
        foreignBefore,
      );

      authentications.push({ challenge, result, listed, stored });

      if (counter === 1) {
        const out = await owner.client.signOut();
        expect(out.error).toBeNull();
        authentications.push({ signout: out });
      }
    }

    const current = await owner.client.getSession();
    expect(current.data?.user.id).toBe(signup.data!.user.id);

    return {
      signup,
      foreignSignup,
      options,
      registered,
      initial,
      signout,
      before,
      foreignBefore,
      authentications,
      current,
      foreignAfter: await ctx.readUserState({ userId: foreignSignup.data!.user.id }),
    };
  },
  ["POST /passkey/verify-authentication", "GET /passkey/list-user-passkeys"],
);
