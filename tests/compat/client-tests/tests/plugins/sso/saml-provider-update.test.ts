import { readFile as readFixtureFile } from "node:fs/promises";

import { Cookie } from "tough-cookie";
import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario("SAML updates merge nested credentials and protect linked identity", async (ctx) => {
  const actor = ctx.actor();
  const control = (input: Record<string, unknown>) =>
    actor.fetch(`${ctx.baseURL}/__test/server-api/sso`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
      redirect: "manual",
    });
  const owner = await control({
    action: "signup",
    body: {
      email: ctx.uniqueEmail("saml-update-owner"),
      name: "Native owner",
      password: "password123",
    },
  });
  expect(owner.status).toBe(200);
  const headers = {
    cookie: owner.headers
      .getSetCookie()
      .filter((raw) => Boolean(Cookie.parse(raw)?.value))
      .map((raw) => raw.split(";")[0])
      .join("; "),
  };
  const cert = await readFixtureFile(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
    "utf8",
  );
  const registered = await control({
    headers,
    body: {
      providerId: "saml-update-provider",
      issuer: "https://sp.example.test/entity",
      domain: "company.test",
      samlConfig: {
        entryPoint: "https://idp.example.test/sso",
        cert,
        privateKey: "original-sp-key",
        idpMetadata: {
          entityID: "https://idp.example.test/entity",
          privateKey: "original-idp-key",
          singleSignOnService: [
            {
              Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
              Location: "https://idp.example.test/post-sso",
            },
            {
              Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
              Location: "https://idp.example.test/sso",
            },
          ],
          singleLogoutService: [
            {
              Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
              Location: "https://idp.example.test/logout",
            },
          ],
        },
        spMetadata: {
          entityID: "https://sp.example.test/entity",
          encPrivateKey: "original-decryption-key",
        },
        idpInitiatedCallbackUrl: `${ctx.baseURL}/idp-complete`,
        wantAssertionsSigned: true,
      },
    },
  });
  expect(registered.status).toBe(200);
  const updated = await control({
    action: "update",
    headers,
    body: {
      providerId: "saml-update-provider",
      domain: "updated.test",
      samlConfig: {
        idpMetadata: { privateKeyPass: "new-passphrase" },
        spMetadata: { privateKey: "nested-sp-key" },
        authnRequestsSigned: false,
      },
    },
  });
  expect(updated.status, await updated.clone().text()).toBe(200);
  const output = (await updated.json()) as any;
  expect(output.domain).toBe("updated.test");
  expect(output.samlConfig.authnRequestsSigned).toBe(false);
  const email = ctx.uniqueEmail("saml-updated-user");
  const started = await control({
    action: "sign-in",
    body: { providerId: "saml-update-provider", callbackURL: `${ctx.baseURL}/complete` },
  });
  expect(started.status).toBe(200);
  const grant = await (
    await control({
      action: "saml-grant",
      authorization: ((await started.json()) as any).url,
      email,
    })
  ).json();
  const completed = await control({
    action: "acs",
    params: { providerId: "saml-update-provider" },
    body: grant,
    headers: {},
  });
  expect(completed.status).toBe(302);
  expect(
    await (
      await control({
        action: "saml-account-row",
        providerId: "saml-update-provider",
        accountId: email,
      })
    ).json(),
  ).not.toBe(null);
  const rotated = await control({
    action: "update",
    headers,
    body: {
      providerId: "saml-update-provider",
      samlConfig: { privateKey: "rotated-sp-key", idpInitiatedCallbackUrl: null },
    },
  });
  expect(rotated.status, await rotated.clone().text()).toBe(200);
  const projected = (await rotated.json()) as any;
  expect(projected.samlConfig.idpInitiatedCallbackUrl).toBeUndefined();
  const row = (await (
    await control({ action: "row", providerId: "saml-update-provider" })
  ).json()) as any;
  const stored = JSON.parse(row.samlConfig);
  expect(stored.privateKey).toBe("rotated-sp-key");
  expect(stored.idpMetadata.privateKey).toBe("original-idp-key");
  expect(stored.idpMetadata.privateKeyPass).toBe("new-passphrase");
  expect(stored.idpMetadata.singleLogoutService[0].Location).toBe(
    "https://idp.example.test/logout",
  );
  expect(stored.spMetadata.encPrivateKey).toBe("original-decryption-key");
  expect(stored.spMetadata.privateKey).toBe("nested-sp-key");
  for (const change of [
    {
      idpMetadata: {
        singleSignOnService: [
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location: "https://other-idp.example.test/sso",
          },
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location: "https://idp.example.test/post-sso",
          },
        ],
      },
    },
    {
      idpMetadata: {
        singleSignOnService: [
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location: "https://idp.example.test/sso",
          },
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location: "https://other-idp.example.test/post-sso",
          },
        ],
      },
    },
    { audience: "urn:other:audience" },
    { idpMetadata: { entityID: "https://other-idp.example.test/entity" } },
    { cert: "different-trust-anchor" },
    { spMetadata: { entityID: "https://other-sp.example.test/entity" } },
    { wantAssertionsSigned: false },
  ]) {
    const rejected = await control({
      action: "update",
      headers,
      body: { providerId: "saml-update-provider", samlConfig: change },
    });
    expect(rejected.status).toBe(409);
    expect(await rejected.json()).toEqual({
      message: "Cannot change SSO provider identity fields while linked accounts exist",
    });
    expect(
      await (await control({ action: "row", providerId: "saml-update-provider" })).json(),
    ).toEqual(row);
  }
  const unused = await control({
    action: "update",
    headers,
    body: {
      providerId: "saml-update-provider",
      samlConfig: { entryPoint: "https://unused.example.test/changed" },
    },
  });
  expect(unused.status).toBe(200);
  const restarted = await control({
    action: "sign-in",
    body: { providerId: "saml-update-provider", callbackURL: `${ctx.baseURL}/complete` },
  });
  expect(restarted.status).toBe(200);
  const active = new URL(((await restarted.json()) as any).url);
  expect(active.origin).toBe("https://idp.example.test");
  expect(active.pathname).toBe("/sso");
  projected.spMetadataUrl =
    new URL(projected.spMetadataUrl).pathname + new URL(projected.spMetadataUrl).search;
  return { projected, preserved: true };
});
