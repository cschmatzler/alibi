import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario, type ScenarioContext } from "../../support/scenario";

const sessionName = "better-auth.session_token";
const preferenceName = "better-auth.dont_remember";
const persistedSchema = z.object({
  sessions: z.array(
    z.object({
      id: z.string(),
      token: z.string(),
      userId: z.string(),
      expiresAt: z.string(),
      activeOrganizationId: z.string().nullable(),
    }),
  ),
});
async function persisted(ctx: ScenarioContext, userId: string) {
  const response = await ctx.rawRequest({
    path: `/__test/user-state?userId=${encodeURIComponent(userId)}`,
  });
  expect(response.status).toBe(200);
  return persistedSchema.parse(response.body);
}

compatScenario(
  "organization selection and clearing honor only the first verified dont-remember preference",
  async (ctx) => {
    const actor = ctx.actor("selection-cookie-owner", "org-creation-empty-role");
    const email = ctx.uniqueEmail("selection-cookie");
    expect(
      (
        await actor.client.signUp.email({
          name: "Selection Cookie Owner",
          email,
          password: "password123",
        })
      ).error,
    ).toBeNull();
    expect((await actor.client.signOut()).error).toBeNull();
    let issued: string[] = [];
    const signedIn = await actor.client.signIn.email(
      { email, password: "password123", rememberMe: false },
      {
        onSuccess(result) {
          issued = result.response.headers.getSetCookie();
        },
      },
    );
    expect(signedIn.error).toBeNull();
    const { token, user } = z
      .object({ token: z.string(), user: z.object({ id: z.string() }) })
      .parse(signedIn.data);
    const sessionCookie = z.string().parse(
      z
        .string()
        .parse(issued.find((cookie) => cookie.startsWith(`${sessionName}=`)))
        .split(";")[0],
    );
    const preference = z.string().parse(
      z
        .string()
        .parse(issued.find((cookie) => cookie.startsWith(`${preferenceName}=`)))
        .split(";")[0],
    );
    expect(preference).toStartWith(`${preferenceName}=true.`);
    const created = await actor.client.$fetch("/organization/create", {
      method: "POST",
      body: {
        name: "Selection Cookie Organization",
        slug: ctx.uniqueToken("selection-cookie"),
        metadata: { guard: "retained" },
      },
    });
    expect(created.error).toBeNull();
    const id = z.object({ id: z.string() }).parse(created.data).id;
    const before = await persisted(ctx, user.id);
    expect(before.sessions).toHaveLength(1);
    expect(before.sessions[0]?.token).toBe(token);
    expect(before.sessions[0]?.activeOrganizationId).toBe(id);
    const issuedExpiry = Date.parse(z.string().parse(before.sessions[0]?.expiresAt));
    expect(issuedExpiry - Date.now()).toBeGreaterThan(23 * 3_600_000);
    expect(issuedExpiry - Date.now()).toBeLessThanOrEqual(86_400_000);
    async function set(body: unknown, header: string, browserSession: boolean | null) {
      const response = await actor.fetch("/api/auth/organization/set-active", {
        method: "POST",
        headers: { "content-type": "application/json", cookie: header },
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      const value: unknown = await response.json();
      const cookies = response.headers.getSetCookie();
      if (browserSession === null) {
        expect(cookies).toEqual([]);
      } else if (browserSession) {
        expect(cookies.map((cookie) => cookie.split("=")[0])).toEqual([
          sessionName,
          preferenceName,
        ]);
        expect(cookies[1]?.split(";")[0]).toBe(preference);
        for (const cookie of cookies) {
          expect(cookie).not.toMatch(/(?:^|;\s*)(?:Max-Age|Expires)=/i);
        }
      } else {
        expect(cookies.length).toBeGreaterThan(0);
        for (const cookie of cookies) {
          expect(cookie).toStartWith(`${sessionName}=`);
          expect(cookie).toMatch(/(?:^|;\s*)Max-Age=604800(?:;|$)/i);
        }
      }
      return { value, state: await persisted(ctx, user.id) };
    }
    const validHeader = `${sessionCookie}; ${preference}`;
    const selected = await set({ organizationId: id }, validHeader, true);
    expect(z.object({ id: z.string() }).parse(selected.value).id).toBe(id);
    expect(selected.state).toEqual(before);
    const cleared = await set({ organizationId: null }, validHeader, true);
    expect(cleared.value).toBeNull();
    expect(cleared.state.sessions).toEqual(
      before.sessions.map((row) => ({ ...row, activeOrganizationId: null })),
    );
    const unselected = await set({ organizationId: null }, validHeader, null);
    expect(unselected.value).toBeNull();
    expect(unselected.state).toEqual(cleared.state);
    // A modified signed payload and a later valid duplicate cannot authorize
    // the first matching preference cookie.
    const tampered = preference.replace("=true.", "=false.");
    const invalidHeader = `${sessionCookie}; ${tampered}; ${preference}`;
    const invalidSelected = await set({ organizationId: id }, invalidHeader, false);
    expect(z.object({ id: z.string() }).parse(invalidSelected.value).id).toBe(id);
    const refreshedExpiry = Date.parse(
      z.string().parse(invalidSelected.state.sessions[0]?.expiresAt),
    );
    expect(refreshedExpiry - issuedExpiry).toBeGreaterThan(5 * 86_400_000);
    expect(refreshedExpiry - Date.now()).toBeGreaterThan(6 * 86_400_000);
    expect(invalidSelected.state.sessions[0]?.activeOrganizationId).toBe(id);
    expect(invalidSelected.state.sessions[0]?.token).toBe(token);
    const invalidCleared = await set({ organizationId: null }, invalidHeader, false);
    expect(invalidCleared.value).toBeNull();
    expect(invalidCleared.state.sessions).toEqual(
      invalidSelected.state.sessions.map((row) => ({ ...row, activeOrganizationId: null })),
    );
    // A later malformed duplicate cannot override the valid first signature.
    const restored = await set({ organizationId: id }, `${validHeader}; ${tampered}`, true);
    expect(z.object({ id: z.string() }).parse(restored.value).id).toBe(id);
    expect(restored.state).toEqual(invalidSelected.state);
    return {
      signedIn,
      created,
      before,
      selected,
      cleared,
      unselected,
      invalidSelected,
      invalidCleared,
      restored,
    };
  },
  ["POST /organization/set-active"],
);
