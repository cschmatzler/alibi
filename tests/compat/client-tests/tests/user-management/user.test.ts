import { compatScenario } from "../../support/scenario";
import { expect } from "bun:test";
import { z } from "zod";

function proofLifetime(token: string): number {
  const claims = z
    .object({ iat: z.number().int(), exp: z.number().int() })
    .parse(
      JSON.parse(
        Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
      ),
    );
  return claims.exp - claims.iat;
}

compatScenario(
  "update user changes session-visible profile fields",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-update");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Original Name",
    });
    const update = await primary.client.updateUser({
      name: "Updated Name",
      image: null,
    });
    const session = await primary.client.getSession();

    return {
      signup: ctx.snapshot(signup),
      update: ctx.snapshot(update),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario("update user rejects direct email mutation", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-update-email");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Illegal Update User",
  });
  const update = await ctx.rawRequest({
    path: "/api/auth/update-user",
    method: "POST",
    json: {
      email: ctx.uniqueEmail("user-management-illegal-email"),
    },
  });

  return {
    signup: ctx.snapshot(signup),
    update: ctx.snapshot(update),
  };
});

compatScenario("update user rejects no-op body", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-update-noop");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Noop Update User",
  });
  const update = await ctx.rawRequest({
    path: "/api/auth/update-user",
    method: "POST",
    json: {},
  });

  return {
    signup: ctx.snapshot(signup),
    update: ctx.snapshot(update),
  };
});

compatScenario("update user rejects non-object body", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-update-array");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Array Update User",
  });
  const update = await ctx.rawRequest({
    path: "/api/auth/update-user",
    method: "POST",
    json: [],
  });

  return {
    signup: ctx.snapshot(signup),
    update: ctx.snapshot(update),
  };
});

compatScenario(
  "change email for an unverified user completes after verify email",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-change-unverified");
    const newEmail = ctx.uniqueEmail("user-management-change-unverified-new");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Unverified Change User",
    });
    const change = await primary.client.changeEmail({
      newEmail,
    });
    const record = (await ctx.readVerificationEmail({ email: newEmail })) as {
      token: string;
    };
    expect(proofLifetime(record.token)).toBe(3600);
    const verify = await primary.client.verifyEmail({
      query: {
        token: record.token,
      },
    });
    const session = await primary.client.getSession();

    return {
      signup: ctx.snapshot(signup),
      change: ctx.snapshot(change),
      verify: ctx.snapshot(verify),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario(
  "change email for a verified user requires old-email confirmation first",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-change-verified");
    const newEmail = ctx.uniqueEmail("user-management-change-verified-new");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Verified Change User",
    });
    const sendVerification = await primary.client.sendVerificationEmail({
      email,
    });
    const verification = (await ctx.readVerificationEmail({ email })) as {
      token: string;
    };
    const initialVerify = await primary.client.verifyEmail({
      query: {
        token: verification.token,
      },
    });
    const change = await primary.client.changeEmail({
      newEmail,
    });
    const confirmation = (await ctx.readChangeEmailConfirmation({ email })) as {
      token: string;
    };
    expect(proofLifetime(confirmation.token)).toBe(3600);
    const confirm = await primary.client.verifyEmail({
      query: {
        token: confirmation.token,
      },
    });
    const newVerification = (await ctx.readVerificationEmail({
      email: newEmail,
    })) as { token: string };
    expect(proofLifetime(newVerification.token)).toBe(3600);
    const finish = await primary.client.verifyEmail({
      query: {
        token: newVerification.token,
      },
    });
    const session = await primary.client.getSession();

    return {
      signup: ctx.snapshot(signup),
      sendVerification: ctx.snapshot(sendVerification),
      initialVerify: ctx.snapshot(initialVerify),
      change: ctx.snapshot(change),
      confirm: ctx.snapshot(confirm),
      finish: ctx.snapshot(finish),
      session: ctx.snapshot(session),
    };
  },
);

compatScenario("change email rejects setting the same email", async (ctx) => {
  const primary = ctx.actor();
  const email = ctx.uniqueEmail("user-management-change-same");

  const signup = await primary.client.signUp.email({
    email,
    password: "password123",
    name: "Same Email User",
  });
  const change = await primary.client.changeEmail({
    newEmail: email,
  });

  return {
    signup: ctx.snapshot(signup),
    change: ctx.snapshot(change),
  };
});

compatScenario(
  "delete user with a fresh session deletes the current account",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-delete-now");
    let originalCookie: string | undefined;

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Immediate Delete User",
      fetchOptions: {
        onSuccess({ response }) {
          originalCookie = response.headers
            .getSetCookie()
            .find((cookie) => cookie.startsWith("better-auth.session_token="))
            ?.split(";")[0];
        },
      },
    });
    expect(signup.error).toBeNull();
    if (!originalCookie || !signup.data)
      throw new Error(
        "Deletion proof requires the original signed session and user",
      );
    const remove = await primary.client.deleteUser();
    expect(remove.error).toBeNull();
    const session = await primary.client.getSession();
    const replay = await ctx.rawRequest({
      actor: "deleted-cookie-replay",
      path: "/api/auth/get-session",
      headers: { cookie: originalCookie },
    });
    expect(replay.body).toBeNull();
    const persisted = await ctx.readUserState({ userId: signup.data.user.id });
    expect(persisted).toMatchObject({ user: null, accounts: [], sessions: [] });
    const signin = await ctx
      .actor("deleted-password-replay")
      .client.signIn.email({ email, password: "password123" });
    expect(signin.error?.status).toBe(401);

    return {
      signup: ctx.snapshot(signup),
      remove: ctx.snapshot(remove),
      session: ctx.snapshot(session),
      replay,
      persisted,
      signin: ctx.snapshot(signin),
    };
  },
  ["POST /delete-user"],
);

compatScenario(
  "delete user callback deletes the current account with a seeded token",
  async (ctx) => {
    const primary = ctx.actor();
    const email = ctx.uniqueEmail("user-management-delete-callback");
    const token = ctx.uniqueToken("user-management-delete-token");

    const signup = await primary.client.signUp.email({
      email,
      password: "password123",
      name: "Callback Delete User",
    });
    await ctx.seedDeleteUserToken({
      email,
      token,
      expiresAt: "2099-01-01T00:00:00Z",
    });
    const callback = await ctx.rawRequest({
      path: `/api/auth/delete-user/callback?token=${encodeURIComponent(token)}`,
    });
    const session = await primary.client.getSession();

    return {
      signup: ctx.snapshot(signup),
      callback: ctx.snapshot(callback),
      session: ctx.snapshot(session),
    };
  },
);
