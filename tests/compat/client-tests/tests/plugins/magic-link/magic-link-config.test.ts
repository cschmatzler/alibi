import { expect } from "bun:test";

import { passwordlessNumericScenarios } from "../../../support/passwordless-numeric";
import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { readUserState, requireUser, verificationCount } from "../../../support/verification";
import { readMagicLink } from "./helpers";

compatScenario(
  "hashed magic-link configuration authenticates without storing the delivered token",
  async (ctx) => {
    const client = ctx.actor("primary", "magic-link-hashed").client;
    const email = ctx.uniqueEmail("hashed-magic");
    const issue = await client.signIn.magicLink({ email });
    expect(issue.error).toBeNull();

    const link = await readMagicLink(ctx, email);
    const hash = new Bun.CryptoHasher("sha256").update(link.token).digest("base64url");
    expect(await verificationCount(ctx, link.token)).toBe(0);
    expect(await verificationCount(ctx, hash)).toBe(1);

    const verify = await client.magicLink.verify({ query: { token: link.token } });
    expect(verify.error).toBeNull();
    expect(verify.data?.user.email).toBe(email);
    expect(await verificationCount(ctx, hash)).toBe(0);

    const user = requireUser(verify.data?.user);
    const state = await readUserState(ctx, user.id);
    expect(state.user?.emailVerified).toBe(true);
    expect(state.sessions).toHaveLength(1);

    return { issue, verify, state };
  },
  ["POST /sign-in/magic-link", "GET /magic-link/verify"],
);

compatScenario(
  "disabled magic-link signup consumes unknown-user links and authenticates existing users",
  async (ctx) => {
    const profile = "magic-link-disabled";
    const actor = ctx.actor("primary", profile);
    const client = actor.client;
    const absent = ctx.uniqueEmail("disabled-magic-absent");
    const issue = await client.signIn.magicLink({ email: absent });
    expect(issue.error).toBeNull();

    const link = await readMagicLink(ctx, absent);
    const response = await actor.fetch(
      new URL(
        `${authProfilePath(profile)}/magic-link/verify?token=${encodeURIComponent(link.token)}`,
        ctx.baseURL,
      ),
      { redirect: "manual" },
    );
    expect(response.status).toBe(302);

    const location = response.headers.get("location");
    expect(new URL(location ?? "", ctx.baseURL).searchParams.get("error")).toBe(
      "new_user_signup_disabled",
    );
    expect(await verificationCount(ctx, link.token)).toBe(0);

    const empty = await client.getSession();
    expect(empty.data).toBeNull();

    const email = ctx.uniqueEmail("disabled-magic-existing");
    const signup = await client.signUp.email({ email, password: "password123", name: "Existing" });
    const user = requireUser(signup.data?.user);
    await client.signIn.magicLink({ email });
    const existingLink = await readMagicLink(ctx, email);
    const existing = await client.magicLink.verify({ query: { token: existingLink.token } });
    expect(existing.error).toBeNull();
    expect(existing.data?.user.id).toBe(user.id);

    const state = await readUserState(ctx, user.id);
    expect(state.user?.emailVerified).toBe(true);
    expect(state.accounts).toHaveLength(0);
    expect(state.sessions).toHaveLength(1);

    return { issue, redirect: { status: response.status, location }, empty, existing, state };
  },
  ["POST /sign-in/magic-link", "GET /magic-link/verify"],
);

passwordlessNumericScenarios("magic-link");
