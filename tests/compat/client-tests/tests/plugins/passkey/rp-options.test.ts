import { expect } from "bun:test";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";

import { Authenticator } from "../../../support/authenticator";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const mode of ["options", "listed-origin", "foreign-origin", "null-origin"] as const) {
  compatScenario(
    `passkey RP configuration ${mode} governs real registration and authentication`,
    async (ctx) => {
      const profile =
        mode === "options"
          ? "passkey-rp-options"
          : mode === "null-origin"
            ? "passkey-origin-null"
            : "passkey-origin-list";
      const actor = ctx.actor("owner", profile);
      const client = createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [passkeyClient()],
        fetchOptions: { customFetchImpl: actor.fetch },
      });
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail("rp-owner"),
        password: "password123",
        name: "RP Owner",
      });
      expect(signup.error).toBeNull();
      const options = await client.$fetch<any>("/passkey/generate-register-options", {
        method: "GET",
      });
      expect(options.error).toBeNull();
      if (mode === "options") {
        expect(options.data!.rp.name).toBe("Configured ceremony RP");
        expect(options.data!.authenticatorSelection).toMatchObject({
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
          authenticatorAttachment: "platform",
        });
      }
      const device = new Authenticator();
      const origin =
        mode === "options"
          ? ctx.baseURL
          : mode === "listed-origin"
            ? "http://localhost:4444"
            : "http://localhost:5555";
      const response = device.register(options.data, origin);
      const registered = await client.$fetch<any>("/passkey/verify-registration", {
        method: "POST",
        body: { response, name: "Configured RP key" },
      });
      if (mode === "foreign-origin" || mode === "null-origin") {
        expect(registered.error!.status).toBe(500);
        expect(
          (await client.$fetch("/passkey/list-user-passkeys", { method: "GET" })).data,
        ).toEqual([]);
        expect((await actor.client.getSession()).data!.user.id).toBe(signup.data!.user.id);
        return ctx.snapshot({ signup, options, registered });
      }
      expect(registered.error).toBeNull();
      expect(registered.data!.userId).toBe(signup.data!.user.id);
      await client.signOut();
      const auth = await client.$fetch<any>("/passkey/generate-authenticate-options", {
        method: "GET",
      });
      expect(auth.error).toBeNull();
      const authenticated = await client.$fetch<any>("/passkey/verify-authentication", {
        method: "POST",
        body: { response: device.authenticate(auth.data, origin) },
      });
      expect(authenticated.error).toBeNull();
      expect((await actor.client.getSession()).data!.user.id).toBe(signup.data!.user.id);
      return ctx.snapshot({ signup, options, registered, auth, authenticated });
    },
    [
      "GET /passkey/generate-register-options",
      "POST /passkey/verify-registration",
      "POST /passkey/verify-authentication",
    ],
  );
}
