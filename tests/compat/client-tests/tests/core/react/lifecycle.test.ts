import { build } from "esbuild";
import { chromium, type Page } from "playwright";
import { expect } from "vitest";

import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { generateCurrentTotp, redactTwoFactorPayload } from "../../../support/totp";
import type { FetchInput } from "./browser-client";

const bundle = await build({
  entryPoints: [new URL("./browser-client.ts", import.meta.url).pathname],
  platform: "browser",
  bundle: true,
  write: false,
  format: "iife",
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
});
const script = bundle.outputFiles[0]!.text;
type ProbeOptions = { organizations?: boolean; jsonContentType?: boolean };
async function openProbe(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  options: ProbeOptions = {},
) {
  const browser = await chromium.launch({
    executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
  });
  const methods: string[] = [];
  try {
    const page = await browser.newPage();
    await page.exposeFunction("reactFetch", async (input: FetchInput) => {
      if (new URL(input.url).pathname.endsWith("/get-session")) methods.push(input.method);
      const response = await actor.fetch(input.url, {
        method: input.method,
        headers: input.headers,
        ...(input.body === undefined ? {} : { body: input.body }),
      });
      return {
        status: response.status,
        headers: [...response.headers],
        body: await response.text(),
      };
    });
    const query = new URLSearchParams({ organizations: String(options.organizations ?? true) });
    if (options.jsonContentType) query.set("jsonContentType", "true");
    await page.goto(`${ctx.baseURL}/__health?${query}`);
    await page.addScriptTag({ content: script });
    return { browser, page, methods };
  } catch (error) {
    await browser.close();
    throw error;
  }
}

async function settledSession(
  page: Page,
  expected: {
    userId: string | null;
    token?: string;
    role?: string;
    twoFactorEnabled?: boolean;
    readsAfter?: number;
  },
) {
  await page
    .waitForFunction(({ userId, token, role, twoFactorEnabled, readsAfter }) => {
      const node = document.querySelector("#session");
      if (!node) return false;
      const state = JSON.parse(node.textContent!);
      return (
        !state.isPending &&
        !state.isRefetching &&
        state.error === null &&
        (state.data?.user.id ?? null) === userId &&
        (token === undefined || state.data?.session.token === token) &&
        (role === undefined || state.data?.user.role === role) &&
        (twoFactorEnabled === undefined ||
          state.data?.user.twoFactorEnabled === twoFactorEnabled) &&
        (readsAfter === undefined || window.reactSessionReads > readsAfter)
      );
    }, expected)
    .catch(async (error: unknown) => {
      throw new Error(
        `Expected mounted session ${JSON.stringify(expected)}; observed ${await page.locator("#session").textContent()}`,
        { cause: error },
      );
    });
  return JSON.parse((await page.locator("#session").textContent())!);
}

compatScenario(
  "Official React hooks observe auth and organization lifecycle mutations",
  async (ctx) => {
    const actor = ctx.actor("react");
    const { browser, page } = await openProbe(ctx, actor);
    try {
      const session = async () => JSON.parse((await page.locator("#session").textContent())!);
      const organizations = async () =>
        JSON.parse((await page.locator("#organizations").textContent())!);
      await page.waitForFunction(() => {
        const node = document.querySelector("#session");
        if (!node) return false;
        const state = JSON.parse(node.textContent!);
        return !state.isPending && !state.isRefetching;
      });
      expect(await session()).toEqual({
        data: null,
        error: null,
        isPending: false,
        isRefetching: false,
      });
      const email = ctx.uniqueEmail("react");
      const username = `react${ctx
        .uniqueToken("owner")
        .replace(/[^a-z0-9]/gi, "")
        .slice(-20)}`;
      const created = await page.evaluate(
        async ({ email, username }) =>
          window.reactClient.signUp.email({
            email,
            username,
            name: "React Owner",
            password: "password123",
          }),
        { email, username },
      );
      expect(created.error).toBeNull();
      expect(created.data?.user.email).toBe(email);
      const userId = created.data!.user.id;
      await page.waitForFunction((id) => {
        const node = document.querySelector("#session");
        return node && JSON.parse(node.textContent!).data?.user.id === id;
      }, userId);
      const renamed = await page.evaluate(() =>
        window.reactClient.updateUser({ name: "Renamed Owner" }),
      );
      expect(renamed.error).toBeNull();
      await page.waitForFunction(
        () =>
          JSON.parse(document.querySelector("#session")!.textContent!).data?.user.name ===
          "Renamed Owner",
      );
      const afterUpdate = await session();
      expect(afterUpdate.error).toBeNull();
      const organization = await page.evaluate(
        async (slug) =>
          window.reactClient.organization.create({ name: "React Organization", slug }),
        ctx.uniqueToken("react-org"),
      );
      expect(organization.error).toBeNull();
      const organizationId = organization.data!.id;
      await page.waitForFunction((id) => {
        const node = document.querySelector("#organizations");
        if (!node) return false;
        const state = JSON.parse(node.textContent!);
        return (
          state.active.data?.id === id &&
          state.list.data?.some((org: { id: string }) => org.id === id) &&
          state.member.data?.organizationId === id &&
          state.role.data?.role === "owner" &&
          Object.values(state).every((entry: any) => !entry.isPending && !entry.isRefetching)
        );
      }, organizationId);
      const afterCreate = await organizations();
      const renamedOrganization = await page.evaluate(
        (organizationId) =>
          window.reactClient.organization.update({
            organizationId,
            data: { name: "Renamed Organization" },
          }),
        organizationId,
      );
      expect(renamedOrganization.error).toBeNull();
      await page.waitForFunction(() => {
        const state = JSON.parse(document.querySelector("#organizations")!.textContent!);
        return (
          state.active.data?.name === "Renamed Organization" &&
          state.list.data?.[0]?.name === "Renamed Organization" &&
          Object.values(state).every((entry: any) => !entry.isRefetching)
        );
      });
      const afterOrganizationUpdate = await organizations();
      const deleted = await page.evaluate(
        (organizationId) => window.reactClient.organization.delete({ organizationId }),
        organizationId,
      );
      expect(deleted.error).toBeNull();
      await page.waitForFunction(() => {
        const state = JSON.parse(document.querySelector("#organizations")!.textContent!);
        return (
          state.list.data?.length === 0 &&
          state.active.data === null &&
          Object.values(state).every((entry: any) => !entry.isRefetching)
        );
      });
      const afterDelete = await organizations();
      const signedOut = await page.evaluate(() => window.reactClient.signOut());
      expect(signedOut.error).toBeNull();
      await page.waitForFunction(
        () => JSON.parse(document.querySelector("#session")!.textContent!).data === null,
      );
      const wrongPassword = await page.evaluate(
        (username) =>
          window.reactClient.signIn.username({ username, password: "incorrect-password" }),
        username,
      );
      expect(wrongPassword.error?.status).toBe(401);
      expect((await session()).data).toBeNull();
      const signedIn = await page.evaluate(
        (username) => window.reactClient.signIn.username({ username, password: "password123" }),
        username,
      );
      expect(signedIn.error).toBeNull();
      await page.waitForFunction(
        (id) => JSON.parse(document.querySelector("#session")!.textContent!).data?.user.id === id,
        userId,
      );
      const afterSignIn = await session();
      expect(afterSignIn.data.user.name).toBe("Renamed Owner");
      const revoked = await page.evaluate(
        (token) => window.reactClient.revokeSession({ token }),
        afterSignIn.data.session.token,
      );
      expect(revoked.error).toBeNull();
      await page.waitForFunction(
        () => JSON.parse(document.querySelector("#session")!.textContent!).data === null,
      );
      return ctx.snapshot({
        created,
        afterUpdate,
        organization,
        afterCreate,
        renamedOrganization,
        afterOrganizationUpdate,
        deleted,
        afterDelete,
        signedOut,
        wrongPassword,
        signedIn,
        afterSignIn,
        revoked,
        final: await session(),
      });
    } finally {
      await browser.close();
    }
  },
  [],
  60_000,
);

compatScenario(
  "React deferred refresh exposes upstream media errors and recovers through explicit refresh",
  async (ctx) => {
    const observations = [];
    for (const [profile, jsonContentType] of [
      ["session-deferred", false],
      ["session-deferred", true],
      ["session-deferred-no-refresh", false],
    ] as const) {
      const actor = ctx.actor(`${profile}-${jsonContentType}`, profile);
      const issued = await actor.client.signUp.email({
        email: ctx.uniqueEmail(`${profile}-${jsonContentType}`),
        name: "React Refresh Owner",
        password: "password123",
      });
      expect(issued.error).toBeNull();
      const expiry = new Date(Date.now() + 3_600_000).toISOString();
      const aged = await actor.fetch(`${ctx.baseURL}/__test/expire-session`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: issued.data!.token, expiresAt: expiry }),
      });
      expect(aged.status).toBe(200);
      expect(await aged.json()).toEqual({ updated: 1 });
      const { browser, page, methods } = await openProbe(ctx, actor, {
        organizations: false,
        jsonContentType,
      });
      try {
        await page.waitForFunction(() => {
          const node = document.querySelector("#session");
          if (!node) return false;
          const state = JSON.parse(node.textContent!);
          return !state.isPending && !state.isRefetching;
        });
        const session = JSON.parse((await page.locator("#session").textContent())!);
        const persisted = (await ctx.readUserState({ userId: issued.data!.user.id })) as any;
        expect(persisted.sessions).toHaveLength(1);
        let recovered;
        if (profile === "session-deferred") {
          expect(methods).toEqual(["GET", "POST"]);
          expect(session.data).toBeNull();
          expect(session.error).toEqual(
            jsonContentType
              ? {
                  code: "BAD_REQUEST",
                  message: "Invalid JSON in request body",
                  status: 400,
                  statusText: "",
                }
              : {
                  code: "UNSUPPORTED_MEDIA_TYPE",
                  message: "Content-Type is required. Allowed types: application/json",
                  status: 415,
                  statusText: "",
                },
          );
          expect(persisted.sessions[0].expiresAt).toBe(expiry);
          const refresh = await page.evaluate(() =>
            window.reactClient.getSession({ fetchOptions: { method: "POST" } }),
          );
          expect(refresh.error).toBeNull();
          await page.locator("#refetch").click();
          await page.waitForFunction(() => {
            const state = JSON.parse(document.querySelector("#session")!.textContent!);
            return state.data && !state.isRefetching;
          });
          const rendered = JSON.parse((await page.locator("#session").textContent())!);
          expect(rendered.error).toBeNull();
          expect(rendered.data.session.userId).toBe(issued.data!.user.id);
          expect(Date.parse(rendered.data.session.expiresAt)).toBeGreaterThan(
            Date.parse(expiry) + 6 * 86_400_000,
          );
          expect(methods).toEqual(["GET", "POST", "POST", "GET"]);
          const renewed = (await ctx.readUserState({ userId: issued.data!.user.id })) as any;
          expect(renewed.sessions[0].expiresAt).toBe(rendered.data.session.expiresAt);
          recovered = { refresh, rendered, renewed };
        } else {
          expect(session.error).toBeNull();
          expect(session.data.session.userId).toBe(issued.data!.user.id);
          expect(persisted.sessions[0].expiresAt).toBe(session.data.session.expiresAt);
          expect(methods).toEqual(["GET"]);
          expect(session.data.session.expiresAt).toBe(expiry);
        }
        observations.push({
          profile,
          jsonContentType,
          issued,
          session,
          methods,
          persisted,
          recovered,
        });
      } finally {
        await browser.close();
      }
    }
    return ctx.snapshot(observations);
  },
);

compatScenario(
  "React multi-session actions switch mounted identity and explicitly recover revoked fallback",
  async (ctx) => {
    const actor = ctx.actor("react-multi", "multi-session");
    const { browser, page } = await openProbe(ctx, actor, { organizations: false });
    try {
      await settledSession(page, { userId: null });
      const alice = await page.evaluate(
        (email) =>
          window.reactClient.signUp.email({ email, name: "React Alice", password: "password123" }),
        ctx.uniqueEmail("react-alice"),
      );
      expect(alice.error).toBeNull();
      await settledSession(page, { userId: alice.data!.user.id, token: alice.data!.token! });
      const bob = await page.evaluate(
        (email) =>
          window.reactClient.signUp.email({ email, name: "React Bob", password: "password123" }),
        ctx.uniqueEmail("react-bob"),
      );
      expect(bob.error).toBeNull();
      const before = await settledSession(page, {
        userId: bob.data!.user.id,
        token: bob.data!.token!,
      });
      const listed = await page.evaluate(() =>
        window.reactClient.multiSession.listDeviceSessions(),
      );
      expect(listed.error).toBeNull();
      expect(new Set(listed.data!.map((row) => row.user.id))).toEqual(
        new Set([alice.data!.user.id, bob.data!.user.id]),
      );
      const rejected = await page.evaluate(() =>
        window.reactClient.multiSession.setActive({ sessionToken: "unproved-session-token" }),
      );
      expect(rejected.error?.code).toBe("INVALID_SESSION_TOKEN");
      expect(await settledSession(page, { userId: bob.data!.user.id })).toEqual(before);
      const selected = await page.evaluate(
        (sessionToken) => window.reactClient.multiSession.setActive({ sessionToken }),
        alice.data!.token!,
      );
      expect(selected.error).toBeNull();
      const switched = await settledSession(page, {
        userId: alice.data!.user.id,
        token: alice.data!.token!,
      });
      const revoked = await page.evaluate(
        (sessionToken) => window.reactClient.multiSession.revoke({ sessionToken }),
        alice.data!.token!,
      );
      expect(revoked.error).toBeNull();
      const stale = JSON.parse((await page.locator("#session").textContent())!);
      expect(stale).toEqual(switched);
      await page.locator("#refetch").click();
      const fallback = await settledSession(page, {
        userId: bob.data!.user.id,
        token: bob.data!.token!,
      });
      const replay = await page.evaluate(
        (sessionToken) => window.reactClient.multiSession.setActive({ sessionToken }),
        alice.data!.token!,
      );
      expect(replay.error?.code).toBe("INVALID_SESSION_TOKEN");
      expect(await settledSession(page, { userId: bob.data!.user.id })).toEqual(fallback);
      const aliceState = await ctx.readUserState({ userId: alice.data!.user.id });
      expect(aliceState).toMatchObject({ sessions: [] });
      return ctx.snapshot({
        alice,
        bob,
        listed,
        before,
        rejected,
        selected,
        switched,
        revoked,
        stale,
        fallback,
        replay,
        aliceState,
      });
    } finally {
      await browser.close();
    }
  },
  [],
  60_000,
);

compatScenario(
  "React admin impersonation publishes target identity and restores the original mounted session",
  async (ctx) => {
    const actor = ctx.actor("react-admin");
    const target = await ctx.actor("react-target").client.signUp.email({
      email: ctx.uniqueEmail("react-target"),
      name: "React Target",
      password: "password123",
    });
    expect(target.error).toBeNull();
    const { browser, page } = await openProbe(ctx, actor, { organizations: false });
    try {
      await settledSession(page, { userId: null });
      const denied = await page.evaluate(
        (userId) => window.reactClient.admin.impersonateUser({ userId }),
        target.data!.user.id,
      );
      expect(denied.error?.status).toBe(401);
      await settledSession(page, { userId: null });
      const email = ctx.uniqueEmail("react-admin");
      const owner = await page.evaluate(
        (email) =>
          window.reactClient.signUp.email({ email, name: "React Admin", password: "password123" }),
        email,
      );
      expect(owner.error).toBeNull();
      await settledSession(page, { userId: owner.data!.user.id });
      await ctx.promoteAdmin({ email });
      await page.locator("#refetch").click();
      const original = await settledSession(page, {
        userId: owner.data!.user.id,
        token: owner.data!.token!,
        role: "admin",
      });
      const targetBefore = await ctx.readUserState({ userId: target.data!.user.id });
      const impersonated = await page.evaluate(
        (userId) => window.reactClient.admin.impersonateUser({ userId }),
        target.data!.user.id,
      );
      expect(impersonated.error).toBeNull();
      const during = await settledSession(page, {
        userId: target.data!.user.id,
        token: impersonated.data!.session.token,
      });
      expect(during.data.session.impersonatedBy).toBe(owner.data!.user.id);
      const stopped = await page.evaluate(() => window.reactClient.admin.stopImpersonating());
      expect(stopped.error).toBeNull();
      const restored = await settledSession(page, {
        userId: owner.data!.user.id,
        token: owner.data!.token!,
        role: "admin",
      });
      expect(restored).toEqual(original);
      expect(await ctx.readUserState({ userId: target.data!.user.id })).toEqual(targetBefore);
      return ctx.snapshot({
        target,
        denied,
        owner,
        original,
        targetBefore,
        impersonated,
        during,
        stopped,
        restored,
      });
    } finally {
      await browser.close();
    }
  },
  [],
  60_000,
);

compatScenario(
  "React two-factor actions invalidate mounted security state and deliver the real redirect callback",
  async (ctx) => {
    const actor = ctx.actor("react-two-factor");
    const { browser, page } = await openProbe(ctx, actor, { organizations: false });
    try {
      await settledSession(page, { userId: null });
      const email = ctx.uniqueEmail("react-two-factor");
      const owner = await page.evaluate(
        (email) =>
          window.reactClient.signUp.email({
            email,
            name: "React Two Factor",
            password: "password123",
          }),
        email,
      );
      expect(owner.error).toBeNull();
      const initial = await settledSession(page, {
        userId: owner.data!.user.id,
        twoFactorEnabled: false,
      });
      const beforeEnableReads = await page.evaluate(() => window.reactSessionReads);
      const enabled = await page.evaluate(() =>
        window.reactClient.twoFactor.enable({ password: "password123" }),
      );
      expect(enabled.error).toBeNull();
      await settledSession(page, {
        userId: owner.data!.user.id,
        twoFactorEnabled: false,
        readsAfter: beforeEnableReads,
      });
      if (!enabled.data || !("totpURI" in enabled.data)) {
        throw new Error("Expected real TOTP enrollment");
      }
      const verified = await page.evaluate(
        (code) => window.reactClient.twoFactor.verifyTotp({ code }),
        await generateCurrentTotp(enabled.data.totpURI),
      );
      expect(verified.error).toBeNull();
      const enrolled = await settledSession(page, {
        userId: owner.data!.user.id,
        twoFactorEnabled: true,
      });
      const signedOut = await page.evaluate(() => window.reactClient.signOut());
      expect(signedOut.error).toBeNull();
      await settledSession(page, { userId: null });
      const beforePending = (await ctx.readUserState({ userId: owner.data!.user.id })) as {
        sessions: unknown[];
      };
      const beforeSignInReads = await page.evaluate(() => window.reactSessionReads);
      const pending = await page.evaluate(
        (email) => window.reactClient.signIn.email({ email, password: "password123" }),
        email,
      );
      expect(pending.error).toBeNull();
      expect(pending.data).toMatchObject({ twoFactorRedirect: true });
      const redirects = await page.evaluate(() => window.reactRedirects);
      expect(redirects).toHaveLength(1);
      expect(redirects[0]!.twoFactorMethods).toContain("totp");
      const pendingState = await settledSession(page, {
        userId: null,
        readsAfter: beforeSignInReads,
      });
      const afterPending = (await ctx.readUserState({ userId: owner.data!.user.id })) as {
        sessions: unknown[];
      };
      expect(afterPending.sessions).toEqual(beforePending.sessions);
      const authenticated = await page.evaluate(
        (code) => window.reactClient.twoFactor.verifyTotp({ code }),
        await generateCurrentTotp(enabled.data.totpURI),
      );
      expect(authenticated.error).toBeNull();
      const afterProof = await settledSession(page, {
        userId: owner.data!.user.id,
        twoFactorEnabled: true,
      });
      expect(await page.evaluate(() => window.reactRedirects)).toEqual(redirects);
      const disabled = await page.evaluate(() =>
        window.reactClient.twoFactor.disable({ password: "password123" }),
      );
      expect(disabled.error).toBeNull();
      const afterDisable = await settledSession(page, {
        userId: owner.data!.user.id,
        twoFactorEnabled: false,
      });
      return ctx.snapshot({
        owner,
        initial,
        enabled: redactTwoFactorPayload(enabled),
        verified,
        enrolled,
        signedOut,
        beforePending,
        pending,
        redirects,
        pendingState,
        afterPending,
        authenticated,
        afterProof,
        disabled,
        afterDisable,
      });
    } finally {
      await browser.close();
    }
  },
  [],
  60_000,
);
