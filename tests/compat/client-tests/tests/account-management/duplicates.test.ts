import { expect } from "bun:test";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { authProfilePath } from "../../support/profiles";
type Row = Record<string, unknown>;
type State = {
  users: Row[];
  accounts: Row[];
  sessions: Row[];
  receipts: Row[];
};
const fixture = "social-gitlab-issuer";
async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({
    path: "/__test/social-provider/duplicate-state",
  });
  expect(response.status).toBe(200);
  return response.body as State;
}
function observed(value: State) {
  return {
    ...value,
    accounts: value.accounts.map((row) => {
      if (typeof row.password !== "string") return row;
      expect(row.password).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
      const [salt, key] = row.password.split(":");
      return {
        ...row,
        password: {
          token: row.password,
          salt: { token: salt, length: 32 },
          derivedKey: { token: key, length: 128 },
          encoding: "hex-lower",
        },
      };
    }),
    receipts: value.receipts.map((receipt) => {
      const body = receipt.body as Row | null;
      return {
        ...receipt,
        body:
          typeof body?.code_verifier === "string"
            ? {
                ...body,
                code_verifier: {
                  token: body.code_verifier,
                  length: body.code_verifier.length,
                },
              }
            : body,
      };
    }),
  };
}
function rows(value: State) {
  const { receipts, ...stored } = value;
  return stored;
}
async function complete(
  actor: ReturnType<ScenarioContext["actor"]>,
  url: string,
) {
  const issued = new URL(url).searchParams.get("state");
  expect(issued).toBeTruthy();
  const response = await actor.fetch(
    `${authProfilePath(fixture)}/callback/gitlab?${new URLSearchParams({ state: issued!, code: "fixture-code" })}`,
    { redirect: "manual" },
  );
  return {
    status: response.status,
    location: response.headers.get("location"),
    body: await response.text(),
  };
}
async function setup(ctx: ScenarioContext) {
  const owner = ctx.actor("owner", fixture),
    foreign = ctx.actor("foreign", fixture);
  const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("owner"),
      name: "Owner",
      password: "password123",
    }),
    other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("foreign"),
      name: "Foreign",
      password: "password123",
    });
  expect(signup.error).toBeNull();
  expect(other.error).toBeNull();
  const profile = {
    id: 912345,
    email: signup.data!.user.email,
    name: "Owner",
    email_verified: true,
    state: "active",
  };
  const configured = await ctx.rawRequest({
    path: "/__test/social-provider/profile",
    method: "POST",
    json: profile,
  });
  expect(configured.status).toBe(200);
  const link = await owner.client.linkSocial({
    provider: "gitlab",
    callbackURL: "/duplicate-done",
    disableRedirect: true,
  });
  expect(link.error).toBeNull();
  const linked = await complete(owner, link.data!.url!);
  expect(linked).toMatchObject({ status: 302, location: "/duplicate-done" });
  const before = await state(ctx),
    account = before.accounts.find(
      (row) =>
        row.userId === signup.data!.user.id && row.providerId === "gitlab",
    )!;
  expect(account).toBeTruthy();
  return {
    owner,
    foreign,
    signup,
    other,
    configured,
    link,
    linked,
    before,
    account,
  };
}
for (const ownership of ["same", "foreign"] as const)
  compatScenario(
    `duplicate OAuth ${ownership} owner keys reject global callbacks while row-id lifecycle remains scoped`,
    async (ctx) => {
      const s = await setup(ctx);
      const foreignExtra = await ctx.seedOAuthAccount({
        email: ctx.uniqueEmail("foreign"),
        providerId: "mock",
        accountId: "foreign-extra-identity",
        accessToken: "foreign-extra-access",
        refreshToken: null,
      });
      s.before = await state(ctx);
      const foreignBefore = await ctx.readUserState({
        userId: s.other.data!.user.id,
      });
      const duplicate = await ctx.rawRequest({
        path: "/__test/social-provider/duplicate-account",
        method: "POST",
        json: {
          accountId: s.account.id,
          userId:
            ownership === "same"
              ? s.signup.data!.user.id
              : s.other.data!.user.id,
        },
      });
      expect(duplicate.status).toBe(200);
      const duplicateId = (duplicate.body as Row).accountId;
      const before = await state(ctx);
      expect(before.accounts).toHaveLength(s.before.accounts.length + 1);
      expect(
        before.accounts.find((row) => row.id === duplicateId),
      ).toMatchObject({
        providerId: "gitlab",
        accountId: s.account.accountId,
        userId:
          ownership === "same" ? s.signup.data!.user.id : s.other.data!.user.id,
      });
      const listed = await s.owner.client.listAccounts();
      expect(listed.error).toBeNull();
      expect(listed.data!.map((row) => row.id)).toEqual(
        before.accounts
          .filter((row) => row.userId === s.signup.data!.user.id)
          .map((row) => String(row.id)),
      );
      const guest = ctx.actor("guest", fixture),
        signin = await guest.client.signIn.social({
          provider: "gitlab",
          callbackURL: "/duplicate-done",
          errorCallbackURL: "/caller-error",
          disableRedirect: true,
        });
      expect(signin.error).toBeNull();
      const denied = await complete(guest, signin.data!.url!);
      expect(denied).toEqual({
        status: 302,
        location: `${ctx.baseURL}${authProfilePath(fixture)}/error?error=internal_server_error`,
        body: "",
      });
      const afterDenied = await state(ctx);
      expect(rows(afterDenied)).toEqual(rows(before));
      expect(afterDenied.receipts).toHaveLength(before.receipts.length + 2);
      const guestSession = await guest.client.getSession();
      expect(guestSession.data).toBeNull();
      const linking = await s.owner.client.linkSocial({
        provider: "gitlab",
        callbackURL: "/duplicate-done",
        errorCallbackURL: "/caller-link-error",
        disableRedirect: true,
      });
      expect(linking.error).toBeNull();
      const deniedLink = await complete(s.owner, linking.data!.url!);
      expect(deniedLink).toEqual({ status: 500, location: null, body: "" });
      const afterLink = await state(ctx);
      expect(rows(afterLink)).toEqual(rows(before));
      const access = await s.owner.client.getAccessToken({
        accountId: String(s.account.id),
      });
      expect(access.error).toBeNull();
      expect(access.data?.accessToken).toBe("fixture-gitlab-access");
      const foreignRefresh = await s.foreign.client.refreshToken({
        accountId: String(s.account.id),
      });
      expect(foreignRefresh.error).toMatchObject({
        status: 400,
        code: "ACCOUNT_NOT_FOUND",
      });
      const foreignUnlink = await s.foreign.client.unlinkAccount({
        accountId: String(s.account.id),
      });
      expect(foreignUnlink.error).toMatchObject({
        status: 400,
        code: "ACCOUNT_NOT_FOUND",
      });
      expect(rows(await state(ctx))).toEqual(rows(before));
      const refresh = await s.owner.client.refreshToken({
        accountId: String(s.account.id),
      });
      expect(refresh.error).toBeNull();
      const refreshed = await state(ctx);
      expect(refreshed.accounts.find((row) => row.id === duplicateId)).toEqual(
        before.accounts.find((row) => row.id === duplicateId),
      );
      expect(
        refreshed.accounts.find((row) => row.id === s.account.id),
      ).toMatchObject({
        accessToken: "fixture-gitlab-refreshed-access",
        refreshToken: "fixture-gitlab-refreshed-refresh",
      });
      expect(refreshed.users).toEqual(before.users);
      expect(refreshed.sessions).toEqual(before.sessions);
      const unlink = await s.owner.client.unlinkAccount({
        accountId: String(s.account.id),
      });
      expect(unlink.data).toEqual({ status: true });
      const after = await state(ctx);
      expect(after.accounts).toEqual(
        refreshed.accounts.filter((row) => row.id !== s.account.id),
      );
      expect(after.users).toEqual(before.users);
      expect(after.sessions).toEqual(before.sessions);
      if (ownership === "same")
        expect(
          await ctx.readUserState({ userId: s.other.data!.user.id }),
        ).toEqual(foreignBefore);
      return {
        signup: ctx.snapshot(s.signup),
        other: ctx.snapshot(s.other),
        configured: s.configured,
        link: ctx.snapshot(s.link),
        linked: s.linked,
        original: observed(s.before),
        duplicate,
        before: observed(before),
        listed: ctx.snapshot(listed),
        signin: ctx.snapshot(signin),
        denied,
        afterDenied: observed(afterDenied),
        guestSession: ctx.snapshot(guestSession),
        linking: ctx.snapshot(linking),
        deniedLink,
        afterLink: observed(afterLink),
        access: ctx.snapshot(access),
        foreignRefresh: ctx.snapshot(foreignRefresh),
        foreignUnlink: ctx.snapshot(foreignUnlink),
        refresh: ctx.snapshot(refresh),
        refreshed: observed(refreshed),
        unlink: ctx.snapshot(unlink),
        after: observed(after),
        foreignExtra: { id: foreignExtra },
        foreignBefore,
        foreignAfter: await ctx.readUserState({
          userId: s.other.data!.user.id,
        }),
      };
    },
    [
      "POST /sign-in/social",
      "POST /link-social",
      "GET /list-accounts",
      "POST /refresh-token",
      "POST /unlink-account",
    ],
  );

compatScenario(
  "duplicate canonical credentials keep the first scoped physical row authoritative for sign-in",
  async (ctx) => {
    const owner = ctx.actor("owner", fixture),
      foreign = ctx.actor("foreign", fixture),
      signup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("owner"),
        name: "Credential Owner",
        password: "password123",
      }),
      other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("foreign"),
        name: "Foreign",
        password: "foreign-password123",
      });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();
    const before = await state(ctx),
      credential = before.accounts.find(
        (row) =>
          row.userId === signup.data!.user.id &&
          row.providerId === "credential",
      )!,
      foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    const duplicated = await ctx.rawRequest({
      path: "/__test/social-provider/duplicate-account",
      method: "POST",
      json: {
        accountId: credential.id,
        userId: signup.data!.user.id,
        createdAt: "2000-01-01T00:00:00.000Z",
      },
    });
    expect(duplicated.status).toBe(200);
    const duplicateId = (duplicated.body as Row).accountId,
      cleared = await ctx.rawRequest({
        path: "/__test/social-provider/clear-credential-password",
        method: "POST",
        json: { accountId: credential.id },
      });
    expect(cleared.status).toBe(200);
    const prepared = await state(ctx);
    expect(
      prepared.accounts.find((row) => row.id === credential.id)?.password,
    ).toBeNull();
    expect(
      prepared.accounts.find((row) => row.id === duplicateId)?.password,
    ).toBe(credential.password);
    const listed = await owner.client.listAccounts();
    expect(listed.error).toBeNull();
    expect(listed.data!.map((row) => row.id)).toEqual([
      String(credential.id),
      String(duplicateId),
    ]);
    const denied = await ctx
      .actor("credential-login", fixture)
      .client.signIn.email({
        email: ctx.uniqueEmail("owner"),
        password: "password123",
      });
    expect(denied.error).toMatchObject({
      status: 401,
      code: "INVALID_EMAIL_OR_PASSWORD",
    });
    const afterDenied = await state(ctx);
    expect(rows(afterDenied)).toEqual(rows(prepared));
    expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(
      foreignBefore,
    );
    const deleteDenied = await owner.client.deleteUser({
      password: "password123",
    });
    expect(deleteDenied.error).toMatchObject({
      status: 400,
      code: "CREDENTIAL_ACCOUNT_NOT_FOUND",
    });
    expect(rows(await state(ctx))).toEqual(rows(prepared));
    const removed = await owner.client.unlinkAccount({
      accountId: String(credential.id),
    });
    expect(removed.data).toEqual({ status: true });
    const restored = await ctx
      .actor("restored-login", fixture)
      .client.signIn.email({
        email: ctx.uniqueEmail("owner"),
        password: "password123",
      });
    expect(restored.error).toBeNull();
    expect(restored.data?.user.id).toBe(signup.data!.user.id);
    const after = await state(ctx);
    expect(after.accounts).toEqual(
      prepared.accounts.filter((row) => row.id !== credential.id),
    );
    expect(after.users).toEqual(before.users);
    expect(after.sessions).toHaveLength(before.sessions.length + 1);
    return {
      signup: ctx.snapshot(signup),
      other: ctx.snapshot(other),
      before: observed(before),
      duplicated,
      cleared,
      prepared: observed(prepared),
      listed: ctx.snapshot(listed),
      denied: ctx.snapshot(denied),
      afterDenied: observed(afterDenied),
      deleteDenied: ctx.snapshot(deleteDenied),
      removed: ctx.snapshot(removed),
      restored: ctx.snapshot(restored),
      after: observed(after),
      foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    };
  },
  ["POST /sign-in/email", "POST /unlink-account", "POST /delete-user"],
);

compatScenario(
  "duplicate signed Google identity rejects direct sign-in and linking before selecting any owner",
  async (ctx) => {
    const { credential, state: googleState } =
      await import("../one-tap/helpers");
    const { decodeJwt, decodeProtectedHeader } = await import("jose");
    const owner = ctx.actor("owner", "google-id-default"),
      foreign = ctx.actor("foreign", "google-id-default");
    const signup = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("foreign"),
      password: "foreign-password123",
      name: "Foreign",
    });
    expect(signup.error).toBeNull();
    const token = await credential({
      aud: "google-default-client",
      sub: ctx.uniqueToken("google-identity"),
      email: ctx.uniqueEmail("owner"),
      name: "Signed Owner",
      email_verified: true,
    });
    const signed = await owner.client.signIn.social({
      provider: "google",
      idToken: { token },
    });
    expect(signed.error).toBeNull();
    const ownerId = signed.data!.user!.id,
      before = await state(ctx),
      account = before.accounts.find(
        (row) => row.userId === ownerId && row.providerId === "google",
      )!;
    const duplicate = await ctx.rawRequest({
      path: "/__test/social-provider/duplicate-account",
      method: "POST",
      json: { accountId: account.id, userId: signup.data!.user.id },
    });
    expect(duplicate.status).toBe(200);
    const prepared = await state(ctx),
      keyFetchesBefore = await googleState(ctx);
    const guest = ctx.actor("guest", "google-id-default"),
      denied = await guest.client.signIn.social(
        { provider: "google", idToken: { token } },
        { redirect: "manual" },
      );
    expect(denied.error?.status).toBe(302);
    const deniedLink = await foreign.client.linkSocial({
      provider: "google",
      idToken: { token },
    });
    expect(deniedLink.error?.status).toBe(500);
    const after = await state(ctx);
    expect(rows(after)).toEqual(rows(prepared));
    const original = await owner.client.getSession();
    expect(original.data?.user.id).toBe(ownerId);
    const foreignSession = await foreign.client.getSession();
    expect(foreignSession.data?.user.id).toBe(signup.data!.user.id);
    const guestSession = await guest.client.getSession();
    expect(guestSession.data).toBeNull();
    const keyFetchesAfter = await googleState(ctx);
    expect(keyFetchesAfter.jwksFetches).toBe(keyFetchesBefore.jwksFetches + 2);
    const [header, payload, signature] = token.split(".");
    return {
      signup: ctx.snapshot(signup),
      token: {
        token,
        header: decodeProtectedHeader(token),
        payload: decodeJwt(token),
        encodedHeader: header,
        encodedPayload: payload,
        signature: { token: signature },
      },
      signed: ctx.snapshot(signed),
      before: observed(before),
      duplicate,
      prepared: observed(prepared),
      denied: ctx.snapshot(denied),
      deniedLink: ctx.snapshot(deniedLink),
      after: observed(after),
      original: ctx.snapshot(original),
      foreignSession: ctx.snapshot(foreignSession),
      guestSession: ctx.snapshot(guestSession),
      jwksFetches: keyFetchesAfter.jwksFetches - keyFetchesBefore.jwksFetches,
    };
  },
  ["POST /sign-in/social", "POST /link-social"],
);
