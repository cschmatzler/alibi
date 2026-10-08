import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { multiSessionClient } from "better-auth/client/plugins";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

type Profile =
  | "bearer-default"
  | "bearer-signed"
  | "bearer-composition"
  | "bearer-renamed-cookie"
  | "bearer-secure-cookie";

function client(ctx: ScenarioContext, profile: Profile, actor: string) {
  return createAuthClient({
    baseURL: `${ctx.baseURL}${authProfilePath(profile)}`,
    plugins: [multiSessionClient(), apiKeyClient()],
    fetchOptions: { customFetchImpl: ctx.actor(actor, profile).fetch },
  });
}

function receipt(response: Response) {
  return {
    token: response.headers.get("set-auth-token"),
    expose: response.headers.get("access-control-expose-headers"),
  };
}

for (const profile of ["bearer-default", "bearer-signed", "bearer-composition"] as const) {
  compatScenario(
    `bearer ${profile} preserves signed issuance header precedence and physical session lifecycle`,
    async (ctx) => {
      const owner = client(ctx, profile, "bearer-owner");
      const foreign = client(ctx, profile, "bearer-foreign");
      let issued: ReturnType<typeof receipt> | undefined;
      let foreignIssued: ReturnType<typeof receipt> | undefined;
      const first = await owner.signUp.email(
        {
          email: ctx.uniqueEmail("bearer-owner"),
          name: "Owner",
          password: "password123",
        },
        {
          onResponse({ response }) {
            issued = receipt(response);
          },
        },
      );
      const other = await foreign.signUp.email(
        {
          email: ctx.uniqueEmail("bearer-foreign"),
          name: "Foreign",
          password: "password123",
        },
        {
          onResponse({ response }) {
            foreignIssued = receipt(response);
          },
        },
      );
      expect(first.error).toBeNull();
      expect(other.error).toBeNull();

      if (!first.data?.token || !other.data?.token || !issued?.token || !foreignIssued?.token) {
        throw new Error("real signed session issuance required");
      }

      const token = first.data.token;
      const signed = issued.token;
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      const paddingChar = signed.at(-2);

      if (!paddingChar || !signed.endsWith("=")) {
        throw new Error("actual padded HMAC required");
      }

      const aliasChar = alphabet[alphabet.indexOf(paddingChar) + 1];

      if (!aliasChar) {
        throw new Error("HMAC padding alias required");
      }

      const alias = `${signed.slice(0, -2)}${aliasChar}=`;
      expect(decodeURIComponent(signed).split(".")[0]).toBe(token);
      expect(issued.expose?.split(", ")).toContain("set-auth-token");

      if (profile === "bearer-signed") {
        expect(issued.expose).toBe("X-First, X-Second, set-auth-token");
      }

      const ownerState = await ctx.readUserState({ userId: first.data.user.id });
      const foreignState = await ctx.readUserState({ userId: other.data.user.id });
      const results = [];

      for (const [index, [authorization, expected]] of (
        [
          [undefined, null],
          ["Basic anything", null],
          ["Bearer ", null],
          ["Bearer missing-session", null],
          ["Bearer invalid.signature", null],
          [`Bearer ${token}`, profile === "bearer-signed" ? null : first.data.user.id],
          [`bEaReR   ${signed}  `, first.data.user.id],
          [`Bearer ${encodeURIComponent(signed)}`, first.data.user.id],
          [`Bearer ${alias}`, first.data.user.id],
          [`Bearer ${foreignIssued.token}`, other.data.user.id],
          [`Bearer ${token}.%ZZ`, null],
          [`Bearer ${signed.slice(0, -3)}xxx`, null],
          [`Bearer ${signed}.extra`, null],
        ] as [string | undefined, string | null][]
      ).entries()) {
        const selected = client(ctx, profile, `bearer-visitor-${index}`);
        const result = await selected.getSession({
          fetchOptions: { headers: authorization ? { authorization } : {} },
        });
        expect(result.error).toBeNull();
        expect(result.data?.user.id ?? null).toBe(expected);
        expect(await ctx.readUserState({ userId: first.data.user.id })).toEqual(ownerState);
        expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignState);

        results.push(result);
      }

      // Exercise a session-gated endpoint as well as get-session's nullable response.
      const protectedUnsigned = await client(ctx, profile, "protected-unsigned").listSessions({
        fetchOptions: { headers: { authorization: `Bearer ${token}` } },
      });
      if (profile === "bearer-signed") {
        expect(protectedUnsigned.error).toMatchObject({ status: 401 });
      } else {
        expect(protectedUnsigned.error).toBeNull();
        expect(protectedUnsigned.data).toContainEqual(
          expect.objectContaining({ userId: first.data.user.id }),
        );
      }
      const protectedSigned = await client(ctx, profile, "protected-signed").listSessions({
        fetchOptions: { headers: { authorization: `Bearer ${signed}` } },
      });
      expect(protectedSigned.error).toBeNull();
      expect(protectedSigned.data).toContainEqual(
        expect.objectContaining({ userId: first.data.user.id }),
      );

      // A valid header replaces a foreign browser cookie; rejected signatures leave it intact.
      const precedence = await foreign.getSession({
        fetchOptions: { headers: { authorization: `Bearer ${signed}` } },
      });
      expect(precedence.data?.user.id).toBe(first.data.user.id);

      const ignored = await foreign.getSession({
        fetchOptions: { headers: { authorization: "Bearer invalid.signature" } },
      });
      expect(ignored.data?.user.id).toBe(other.data.user.id);

      const composition: unknown[] = [];

      if (profile === "bearer-composition") {
        const key = await owner.apiKey.create({ name: "bearer-composition" });
        expect(key.error).toBeNull();

        if (!key.data?.key) {
          throw new Error("real API key required");
        }

        let virtualHeaders: ReturnType<typeof receipt> | undefined;
        const virtual = await client(ctx, profile, "bearer-api-key").getSession({
          fetchOptions: {
            headers: { "x-api-key": key.data.key, authorization: `Bearer ${signed}` },
            onResponse({ response }) {
              virtualHeaders = receipt(response);
            },
          },
        });
        expect(virtual.data?.user.id).toBe(first.data.user.id);
        expect(virtual.data?.session.token).toBe(key.data.key);
        expect(virtualHeaders?.token).toBeNull();
        expect(await ctx.readUserState({ userId: first.data.user.id })).toEqual(ownerState);

        const list = await owner.multiSession.listDeviceSessions({
          fetchOptions: { headers: { authorization: `Bearer ${signed}` } },
        });
        expect(list.error).toBeNull();
        expect(list.data).toHaveLength(1);
        expect(list.data?.[0]?.user.id).toBe(first.data.user.id);

        composition.push(virtual, virtualHeaders, list);
      }

      let signoutHeaders: ReturnType<typeof receipt> | undefined;
      const signout = await client(ctx, profile, "bearer-revoker").signOut({
        fetchOptions: {
          headers: { authorization: `Bearer ${signed}` },
          onResponse({ response }) {
            signoutHeaders = receipt(response);
          },
        },
      });
      expect(signout.error).toBeNull();
      expect(signoutHeaders?.token).toBeNull();

      if (profile === "bearer-signed") {
        expect(signoutHeaders?.expose).toBe("X-First, X-First, X-Second");
      }

      const revoked = await foreign.getSession({
        fetchOptions: { headers: { authorization: `Bearer ${signed}` } },
      });
      expect(revoked.data).toBeNull();
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignState);

      const gone = await ctx.readUserState({ userId: first.data.user.id });
      const second = await owner.signIn.email(
        { email: first.data.user.email, password: "password123" },
        {
          onResponse({ response }) {
            issued = receipt(response);
          },
        },
      );
      expect(second.error).toBeNull();

      if (!second.data?.token || !issued?.token) {
        throw new Error("second genuine session required");
      }

      const expired = await ctx.rawRequest({
        path: "/__test/expire-session",
        method: "POST",
        json: {
          token: second.data.token,
          expiresAt: "2000-01-01T00:00:00.000Z",
        },
      });
      expect(expired.status).toBe(200);

      const expiredRead = await client(ctx, profile, "bearer-expired").getSession({
        fetchOptions: { headers: { authorization: `Bearer ${issued.token}` } },
      });
      expect(expiredRead.data).toBeNull();
      expect(await ctx.readUserState({ userId: other.data.user.id })).toEqual(foreignState);

      return {
        first,
        other,
        signed,
        issued,
        results,
        protectedUnsigned: ctx.snapshot(protectedUnsigned),
        protectedSigned: ctx.snapshot(protectedSigned),
        precedence,
        ignored,
        composition,
        signout,
        signoutHeaders,
        revoked,
        gone,
        second,
        expired,
        expiredRead,
        final: await ctx.readUserState({ userId: first.data.user.id }),
        foreignState,
      };
    },
    ["POST /sign-up/email", "POST /sign-in/email", "GET /get-session", "POST /sign-out"],
  );
}

for (const profile of ["bearer-renamed-cookie", "bearer-secure-cookie"] as const) {
  compatScenario(
    `bearer configured cookies: ${profile} selects the actual owner and issuance receipt`,
    async (ctx) => {
      const owner = client(ctx, profile, "configured-owner");
      const foreign = client(ctx, profile, "configured-foreign");
      const cookieName =
        profile === "bearer-renamed-cookie"
          ? "configured-bearer-token"
          : "__Secure-bearer-app.session_token";
      let issued: { token: string | null; expose: string | null; cookies: string[] } | undefined;
      let foreignIssued: typeof issued;
      function capture(response: Response) {
        return { ...receipt(response), cookies: response.headers.getSetCookie() };
      }
      const first = await owner.signUp.email(
        {
          email: ctx.uniqueEmail("configured-bearer"),
          name: "Configured Bearer",
          password: "password123",
        },
        {
          onResponse({ response }) {
            issued = capture(response);
          },
        },
      );
      const other = await foreign.signUp.email(
        {
          email: ctx.uniqueEmail("configured-bearer-foreign"),
          name: "Foreign Bearer",
          password: "password123",
        },
        {
          onResponse({ response }) {
            foreignIssued = capture(response);
          },
        },
      );
      expect(first.error).toBeNull();
      expect(other.error).toBeNull();
      for (const delivered of [issued!, foreignIssued!]) {
        expect(delivered.token).toBeTruthy();
        const sessionCookies = delivered.cookies.filter((cookie) =>
          cookie.startsWith(`${cookieName}=`),
        );
        expect(sessionCookies).toHaveLength(1);
        const rawValue = sessionCookies[0]!.split(";", 1)[0]!.slice(cookieName.length + 1);
        expect(decodeURIComponent(rawValue)).toBe(delivered.token!);
        expect(delivered.expose?.split(", ")).toContain("set-auth-token");
        expect(
          delivered.cookies.some((cookie) =>
            /^(?:__Secure-)?better-auth\.session_token=/.test(cookie),
          ),
        ).toBe(false);
        if (profile === "bearer-secure-cookie") expect(sessionCookies[0]).toContain("Secure");
      }
      const ownerId = first.data!.user.id;
      const foreignId = other.data!.user.id;
      expect((await owner.getSession()).data?.user.id).toBe(ownerId);
      expect((await foreign.getSession()).data?.user.id).toBe(foreignId);
      const before = await ctx.readUserState({ userId: ownerId });
      const foreignBefore = await ctx.readUserState({ userId: foreignId });
      const results = [];
      for (const authorization of [`Bearer ${issued!.token}`, `Bearer ${first.data!.token}`]) {
        const fresh = client(ctx, profile, `configured-fresh-${results.length}`);
        const current = await fresh.getSession({ fetchOptions: { headers: { authorization } } });
        expect(current.data?.user.id).toBe(ownerId);
        const protectedCall = await fresh.listSessions({
          fetchOptions: { headers: { authorization } },
        });
        expect(protectedCall.error).toBeNull();
        expect(protectedCall.data?.map((session) => session.userId)).toEqual([ownerId]);
        const precedence = await foreign.getSession({
          fetchOptions: { headers: { authorization } },
        });
        expect(precedence.data?.user.id).toBe(ownerId);
        const invalid = await foreign.getSession({
          fetchOptions: { headers: { authorization: "Bearer invalid.signature" } },
        });
        expect(invalid.data?.user.id).toBe(foreignId);
        expect(await ctx.readUserState({ userId: ownerId })).toEqual(before);
        expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
        results.push({ current, protectedCall, precedence, invalid });
      }
      let signedOut: ReturnType<typeof capture> | undefined;
      const signOut = await client(ctx, profile, "configured-signout").signOut(
        {},
        {
          headers: { authorization: `Bearer ${issued!.token}` },
          onResponse({ response }) {
            signedOut = capture(response);
          },
        },
      );
      expect(signOut.error).toBeNull();
      expect(signedOut?.token).toBeNull();
      expect(
        signedOut?.cookies.some(
          (cookie) => cookie.startsWith(`${cookieName}=`) && /Max-Age=0/i.test(cookie),
        ),
      ).toBe(true);
      expect(
        ((await ctx.readUserState({ userId: ownerId })) as { sessions: unknown[] }).sessions,
      ).toEqual([]);
      expect((await owner.getSession()).data).toBeNull();
      expect((await foreign.getSession()).data?.user.id).toBe(foreignId);
      expect(await ctx.readUserState({ userId: foreignId })).toEqual(foreignBefore);
      return ctx.snapshot({ first, other, issued, foreignIssued, results, signOut, signedOut });
    },
    ["GET /get-session", "GET /list-sessions", "POST /sign-out"],
  );
}
