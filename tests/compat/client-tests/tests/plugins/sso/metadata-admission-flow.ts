import { expect } from "bun:test";

import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "../../../support/scenario";
type InvalidCase = { field: string; patch: Record<string, unknown>; issue: string };
const scalar = (
  field: string,
  value: unknown,
  expected: string,
  received: string,
): InvalidCase => ({
  field,
  patch: { [field]: value },
  issue: `${field}] Invalid input: expected ${expected}, received ${received}`,
});
export async function samlMetadataAdmissionFlow(ctx: ScenarioContext, idp: boolean) {
  const prefix = idp ? "idp" : "sp";
  const target = idp ? "idpMetadata" : "spMetadata";
  const providerId = `${prefix}-schema-provider`;
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
      email: ctx.uniqueEmail(`${prefix}-schema-owner`),
      name: "Owner",
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
  const cert = await Bun.file(
    new URL("../../../../fixtures/salesforce-transport/leaf.pem", import.meta.url),
  ).text();
  const base: any = {
    providerId,
    issuer: "https://sp.example.test/entity",
    domain: "company.test",
    samlConfig: {
      entryPoint: "https://idp.example.test/sso",
      cert,
      idpMetadata: { entityID: "https://idp.example.test/entity" },
      wantAssertionsSigned: true,
    },
  };
  expect((await control({ headers, body: base })).status).toBe(200);
  const original = await (await control({ action: "row", providerId })).json();
  const cases: InvalidCase[] = idp
    ? [
        scalar("privateKey", true, "string", "boolean"),
        scalar("privateKeyPass", 2, "string", "number"),
        scalar("isAssertionEncrypted", "true", "boolean", "string"),
        scalar("encPrivateKey", [], "string", "array"),
        scalar("encPrivateKeyPass", {}, "string", "object"),
        scalar("entityID", false, "string", "boolean"),
        scalar("metadata", 41, "string", "number"),
        scalar("singleSignOnService", {}, "array", "object"),
        scalar("singleLogoutService", false, "array", "boolean"),
        {
          field: "service-binding",
          patch: {
            singleSignOnService: [{ Binding: 42, Location: "https://idp.example.test/sso" }],
          },
          issue: "singleSignOnService.0.Binding] Invalid input: expected string, received number",
        },
        {
          field: "service-url",
          patch: { singleLogoutService: [{ Binding: "urn:logout", Location: "not-a-url" }] },
          issue: "singleLogoutService.0.Location] Invalid URL",
        },
        {
          field: "service-record",
          patch: { singleSignOnService: [null] },
          issue: "singleSignOnService.0] Invalid input: expected object, received null",
        },
        {
          field: "service-location",
          patch: { singleLogoutService: [{ Binding: "urn:logout" }] },
          issue:
            "singleLogoutService.0.Location] Invalid input: expected string, received undefined",
        },
      ]
    : [
        scalar("metadata", 41, "string", "number"),
        scalar("entityID", false, "string", "boolean"),
        scalar("binding", null, "string", "null"),
        scalar("privateKey", true, "string", "boolean"),
        scalar("privateKeyPass", 2, "string", "number"),
        scalar("isAssertionEncrypted", "true", "boolean", "string"),
        scalar("encPrivateKey", [], "string", "array"),
        scalar("encPrivateKeyPass", {}, "string", "object"),
      ];
  const observed = [];
  for (const update of [false, true]) {
    for (const [index, test] of cases.entries()) {
      const attemptedId = update ? providerId : `invalid-${prefix}-${index}`;
      const metadata = { ...base.samlConfig[target], ...test.patch };
      const response = await control({
        headers,
        ...(update ? { action: "update" } : {}),
        body: update
          ? { providerId: attemptedId, samlConfig: { [target]: metadata } }
          : {
              ...base,
              providerId: attemptedId,
              samlConfig: { ...base.samlConfig, [target]: metadata },
            },
      });
      expect(response.status).toBe(400);
      const error = await response.json();
      const message =
        idp && !update && !test.issue.endsWith("Invalid URL")
          ? "[body.samlConfig.idpMetadata] idpMetadata.entityID is required when IdP metadata XML is not provided"
          : `[body.samlConfig.${target}.${test.issue}`;
      expect(error).toEqual({ code: "VALIDATION_ERROR", message });
      const row = await (await control({ action: "row", providerId: attemptedId })).json();
      if (update) {
        expect(row).toEqual(original);
      } else {
        expect(row).toBe(null);
      }
      observed.push({ update, field: test.field, error });
    }
  }
  const metadata: Record<string, unknown> = {
    privateKeyPass: "accepted-pass",
    isAssertionEncrypted: false,
    ignored: "must-not-persist",
  };
  const expected = idp
    ? {
        entityID: "https://idp.example.test/entity",
        privateKeyPass: "accepted-pass",
        isAssertionEncrypted: false,
        singleSignOnService: [
          {
            Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            Location: "https://idp.example.test/sso",
          },
        ],
      }
    : { privateKeyPass: "accepted-pass", isAssertionEncrypted: false };
  if (idp) {
    metadata.entityID = "https://idp.example.test/entity";
    metadata.singleSignOnService = [
      {
        Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        Location: "https://idp.example.test/sso",
        ignored: "must-not-persist",
      },
    ];
  }
  const cleanId = `clean-${prefix}-provider`;
  expect(
    (
      await control({
        headers,
        body: {
          ...base,
          providerId: cleanId,
          samlConfig: { ...base.samlConfig, [target]: metadata },
        },
      })
    ).status,
  ).toBe(200);
  const clean = (await (await control({ action: "row", providerId: cleanId })).json()) as any;
  expect(JSON.parse(clean.samlConfig)[target]).toEqual(expected);
  expect(
    (
      await control({
        action: "update",
        headers,
        body: { providerId, samlConfig: { [target]: metadata } },
      })
    ).status,
  ).toBe(200);
  const updated = (await (await control({ action: "row", providerId })).json()) as any;
  expect(JSON.parse(updated.samlConfig)[target]).toEqual(expected);
  return observed;
}
