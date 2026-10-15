import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compareValues } from "../../../support/compare";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "Consent updates persist client-approved scopes without changing grant identity",
  async (ctx) => {
    const actor = ctx.actor();
    const control = (input: unknown) =>
      actor.fetch(`${ctx.baseURL}/__test/server-api/oauth-provider-clients`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
    const signup = await control({
      action: "signup",
      body: { email: ctx.uniqueEmail("consent-owner"), name: "Owner", password: "password123" },
    });
    expect(signup.status).toBe(200);
    const owner = (await signup.json()) as any;
    const cookie = signup.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const created = await control({
      headers: { cookie },
      body: {
        client_name: "Consent client",
        redirect_uris: ["https://app.fixture.test/callback"],
        scope: "email profile",
        token_endpoint_auth_method: "none",
      },
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as any).client_id;
    const query = {
      client_id: id,
      response_type: "code",
      redirect_uri: "https://app.fixture.test/callback",
      scope: "email profile",
      state: "consent-state",
      code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      code_challenge_method: "S256",
    };
    const producer = await control({
      action: "authorize",
      query,
      headers: { accept: "application/json" },
    });
    expect(producer.status).toBe(200);
    const signed = new URL(((await producer.json()) as any).url, ctx.baseURL).search.slice(1);
    const accepted = await control({
      action: "consent",
      headers: { cookie },
      body: { accept: true, scope: "email", oauth_query: signed },
    });
    expect(accepted.status).toBe(200);
    const other = await control({
      action: "signup",
      body: {
        email: ctx.uniqueEmail("consent-list-other"),
        name: "Other",
        password: "password123",
      },
    });
    expect(other.status).toBe(200);
    const otherUser = (await other.json()) as any;
    const otherCookie = other.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; ");
    const listed = await control({ action: "consents", headers: { cookie } });
    expect(listed.status).toBe(200);
    const expected = ((await listed.json()) as any[])[0];
    const start = Date.now();
    const changed = await control({
      action: "consent-update",
      headers: { cookie },
      body: { id: expected.id, update: { scopes: ["profile"] } },
    });
    expect(changed.status).toBe(200);
    const updated = (await changed.json()) as any;
    expect(updated.id).toBe(expected.id);
    expect(updated.clientId).toBe(id);
    expect(updated.userId).toBe(owner.user.id);
    expect(updated.createdAt).toBe(expected.createdAt);
    expect(updated.scopes).toEqual(["profile"]);
    expect(new Date(updated.updatedAt).getTime()).toBeGreaterThanOrEqual(
      Math.floor(start / 1000) * 1000,
    );
    expect(new Date(updated.updatedAt).getTime()).toBeLessThanOrEqual(Date.now());
    for (const field of ["resources", "referenceId", "requestedUserInfoClaims"]) {
      expect(updated[field]).toEqual(expected[field]);
    }
    const failures = [];
    let scopeError: any;
    for (const [body, headers, status, error] of [
      [{ id: expected.id, update: { scopes: ["openid"] } }, { cookie }, 400, "invalid_request"],
      [{ id: expected.id, update: { scopes: ["email"] } }, { cookie: otherCookie }, 401, null],
      [{ id: expected.id, update: { scopes: ["email"] } }, {}, 401, null],
      [{ id: "unknown-consent", update: { scopes: ["email"] } }, { cookie }, 404, "not_found"],
      [{ id: "", update: { scopes: ["email"] } }, { cookie }, 404, "not_found"],
      [{ id: expected.id, update: { scopes: [true] } }, { cookie }, 400, null],
    ] as const) {
      const r = await control({ action: "consent-update", headers, body });
      expect(r.status).toBe(status);
      const text = await r.text();
      const value = text ? JSON.parse(text) : null;
      if (error) {
        expect(value.error).toBe(error);
        if (error === "invalid_request") {
          expect(value.error_description).toBe(`unable to provide scopes to ${owner.user.id}`);
          scopeError = value;
        }
      } else if (status === 400) {
        expect(value.code).toBe("VALIDATION_ERROR");
      }
      // Compare the message after validating its identity against the actual signup owner.
      const observation =
        error === "invalid_request"
          ? {
              ...value,
              error_description: value.error_description.replace(owner.user.id, "<owner>"),
            }
          : value;
      failures.push({ status: r.status, body: observation });
    }
    const receipt = {
      observation: { owner: { userId: owner.user.id }, other: { userId: otherUser.user.id } },
      traces: [
        { path: "/__test/server-api/oauth-provider-clients", responseErrorBody: scopeError },
      ],
    };
    const wrongTarget = {
      ...receipt,
      traces: [
        {
          path: receipt.traces[0]!.path,
          responseErrorBody: {
            ...scopeError,
            error_description: `unable to provide scopes to ${otherUser.user.id}`,
          },
        },
      ],
    };
    expect(
      compareValues(receipt, wrongTarget, {
        leftBaseURL: ctx.baseURL,
        rightBaseURL: ctx.baseURL,
        leftStartedAt: start,
        rightStartedAt: start,
      }).length,
    ).toBeGreaterThan(0);
    const loaded = await control({
      action: "consent-get",
      query: { id: expected.id },
      headers: { cookie },
    });
    expect(await loaded.json()).toEqual(updated);
    const clear = await control({
      action: "consent-update",
      headers: { cookie },
      body: { id: expected.id, update: { scopes: [] } },
    });
    expect(clear.status).toBe(200);
    const cleared = (await clear.json()) as any;
    expect(cleared.id).toBe(expected.id);
    expect(cleared.createdAt).toBe(expected.createdAt);
    expect(cleared.scopes).toEqual([]);
    const reread = await control({
      action: "consent-get",
      query: { id: expected.id },
      headers: { cookie },
    });
    expect(await reread.json()).toEqual(cleared);
    const project = ({ createdAt, updatedAt, ...row }: any) => row;
    return ctx.snapshot({ updated: project(updated), cleared: project(cleared), failures });
  },
);
