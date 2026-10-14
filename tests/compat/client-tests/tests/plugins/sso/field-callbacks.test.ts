import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import { compatScenario } from "../../../support/scenario";
compatScenario("Provider field callbacks run at storage and read boundaries", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ mode: "field-callbacks", ...input }),
    });
  const owner = await control({
    action: "signup",
    body: { email: ctx.uniqueEmail("callback-fields"), name: "Owner", password: "password123" },
  });
  expect(owner.status).toBe(200);
  const cookie = owner.headers
    .getSetCookie()
    .filter((raw) => Boolean(Cookie.parse(raw)?.value))
    .map((raw) => raw.split(";")[0])
    .join("; ");
  const headers = { cookie };
  const input = {
    providerId: "callback-fields",
    issuer: "https://idp.example.com",
    domain: "company.test",
    label: "Start",
    oidcConfig: {
      clientId: "client",
      clientSecret: "secret",
      skipDiscovery: true,
      pkce: true,
      authorizationEndpoint: "https://idp.example.com/authorize",
      tokenEndpoint: "https://idp.example.com/token",
      jwksEndpoint: "https://idp.example.com/jwks",
    },
  };
  const created = await control({ headers, body: input });
  expect(created.status).toBe(200);
  const registered = (await created.json()) as any;
  expect(registered.label).toBe("output:input:input:Start");
  expect(registered.stamp).toBe("generated");
  expect(registered.tier).toBe(2);
  const updated = await control({
    action: "update",
    headers,
    body: { providerId: input.providerId, label: "Changed" },
  });
  expect(updated.status).toBe(200);
  const changed = (await updated.json()) as any;
  expect(changed.label).toBe("output:input:input:Changed");
  expect(changed.tier).toBe(7);
  const unrelated = await control({
    action: "update",
    headers,
    body: { providerId: input.providerId, domain: "changed.company.test" },
  });
  expect(unrelated.status).toBe(200);
  const final = (await unrelated.json()) as any;
  expect(final.label).toBe("output:input:input:Changed");
  expect(final.stamp).toBe("generated");
  expect(((await (await control({ action: "restart" })).json()) as any).restarted).toBe(true);
  const read = await control({ action: "get", headers, query: { providerId: input.providerId } });
  expect(read.status).toBe(200);
  expect(await read.json()).toEqual(final);
  const listed = await control({ action: "list", headers });
  expect(listed.status).toBe(200);
  expect(((await listed.json()) as any).providers).toEqual([final]);
  const row = (await (
    await control({ action: "row", providerId: input.providerId })
  ).json()) as any;
  expect(row.label).toBe("output:input:input:Changed");
  return {
    registered: { ...registered, redirectURI: new URL(registered.redirectURI).pathname },
    changed,
    final,
  };
});
