import { expect } from "bun:test";

import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";

import { Authenticator } from "../../../support/authenticator";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
for (const mode of ["static", "resolver", "coded", "ordinary"] as const) {
  compatScenario(
    `passkey ${mode} extension inputs reach registration and authentication options`,
    async (ctx) => {
      const profile = `passkey-extensions-${mode}` as const;
      const actor = ctx.actor("owner", profile);
      const client = createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [passkeyClient()],
        fetchOptions: { customFetchImpl: actor.fetch },
      });
      const signup = await client.signUp.email({
        email: ctx.uniqueEmail("extensions-owner"),
        password: "password123",
        name: "Extensions Owner",
      });
      expect(signup.error).toBeNull();
      const state = async () =>
        (
          await ctx.rawRequest({
            path: `/__test/passkey-state?userId=${encodeURIComponent(signup.data!.user.id)}`,
          })
        ).body;
      const before = await state();
      const options = await client.$fetch<any>("/passkey/generate-register-options", {
        method: "GET",
        headers: { "x-extension-marker": "registration-marker" },
      });
      const auth = await client.$fetch<any>("/passkey/generate-authenticate-options", {
        method: "GET",
        headers: { "x-extension-marker": "authentication-marker" },
      });
      if (mode === "coded" || mode === "ordinary") {
        expect(options.error?.status).toBe(mode === "coded" ? 403 : 500);
        expect(auth.error?.status).toBe(mode === "coded" ? 403 : 500);
        if (mode === "coded") {
          expect(options.error).toMatchObject({
            code: "EXTENSIONS_DENIED",
            message: "Application extensions rejected",
          });
          expect(auth.error).toMatchObject({
            code: "EXTENSIONS_DENIED",
            message: "Application extensions rejected",
          });
        }
        expect(await state()).toEqual(before);
        expect((await actor.client.getSession()).data!.user.id).toBe(signup.data!.user.id);
        return ctx.snapshot({ signup, before, options, auth });
      }
      expect(options.error).toBeNull();
      expect(auth.error).toBeNull();
      // SimpleWebAuthn always forces credProps; another field observes resolver input.
      expect(options.data!.extensions).toEqual(
        mode === "static" ? { credProps: true } : { credProps: true, minPinLength: true },
      );
      expect(auth.data!.extensions).toEqual({
        appid:
          mode === "static"
            ? "https://extensions.fixture.test/static"
            : "https://extensions.fixture.test/authentication-marker/generate-authenticate-options",
      });
      const registration = await client.$fetch<any>("/passkey/generate-register-options", {
        method: "GET",
        headers: { "x-extension-marker": "registration-marker" },
      });
      expect(registration.data!.extensions).toEqual(options.data!.extensions);
      const device = new Authenticator();
      const registered = await client.$fetch<any>("/passkey/verify-registration", {
        method: "POST",
        body: { response: device.register(registration.data, ctx.baseURL), name: "Extensions key" },
      });
      expect(registered.error).toBeNull();
      expect(registered.data!.userId).toBe(signup.data!.user.id);
      await client.signOut();
      const freshAuth = await client.$fetch<any>("/passkey/generate-authenticate-options", {
        method: "GET",
        headers: { "x-extension-marker": "authentication-marker" },
      });
      expect(freshAuth.data!.extensions).toEqual(auth.data!.extensions);
      const signedIn = await client.$fetch<any>("/passkey/verify-authentication", {
        method: "POST",
        body: { response: device.authenticate(freshAuth.data, ctx.baseURL) },
      });
      expect(signedIn.error).toBeNull();
      expect((await actor.client.getSession()).data!.user.id).toBe(signup.data!.user.id);
      return ctx.snapshot({
        signup,
        before,
        options,
        auth,
        registered,
        freshAuth,
        signedIn,
        after: await state(),
      });
    },
    ["GET /passkey/generate-register-options", "GET /passkey/generate-authenticate-options"],
  );
}
