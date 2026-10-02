import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";

// Valid inputs, so each route reaches its session requirement instead of
// rejecting the body first.
const sessionGated = [
  { method: "GET", path: "/account-info?accountId=missing-account" },
  { method: "POST", path: "/revoke-session", json: { token: "missing-token" } },
  { method: "POST", path: "/revoke-sessions", json: {} },
  { method: "POST", path: "/revoke-other-sessions", json: {} },
  { method: "GET", path: "/organization/list" },
  { method: "GET", path: "/organization/list-invitations" },
  { method: "GET", path: "/organization/get-active-member" },
  { method: "GET", path: "/organization/get-active-member-role" },
  { method: "POST", path: "/organization/check-slug", json: { slug: "missing-slug" } },
  { method: "POST", path: "/organization/leave", json: { organizationId: "missing-org" } },
  {
    method: "POST",
    path: "/organization/cancel-invitation",
    json: { invitationId: "missing-invitation" },
  },
  {
    method: "POST",
    path: "/organization/reject-invitation",
    json: { invitationId: "missing-invitation" },
  },
  { method: "POST", path: "/two-factor/get-totp-uri", json: { password: "password123" } },
  { method: "POST", path: "/two-factor/generate-backup-codes", json: { password: "password123" } },
] as const;

compatScenario("session-gated routes reject requests without a session", async (ctx) => {
  const responses = [];

  for (const route of sessionGated) {
    const response = await ctx.rawRequest({
      actor: "anonymous-caller",
      method: route.method,
      path: `/api/auth${route.path}`,
      ...("json" in route ? { json: route.json } : {}),
    });
    expect({ route: route.path, status: response.status }).toEqual({
      route: route.path,
      status: 401,
    });
    responses.push({ route: route.path, response });
  }

  return responses;
});

compatScenario(
  "POST get-session is rejected unless deferred session refresh is enabled",
  async (ctx) => {
    const response = await ctx.rawRequest({
      actor: "anonymous-caller",
      method: "POST",
      path: "/api/auth/get-session",
      json: {},
    });
    expect(response.status).toBe(405);

    return response;
  },
);
