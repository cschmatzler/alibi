import { expect } from "bun:test";

import { z } from "zod";

import type { FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

const documentSchema = z
  .object({
    openapi: z.literal("3.1.1"),
    info: z.object({
      title: z.literal("Better Auth"),
      description: z.literal("API Reference for your Better Auth Instance"),
      version: z.literal("1.1.0"),
    }),
    components: z.object({
      schemas: z.record(z.string(), z.unknown()),
      securitySchemes: z.record(z.string(), z.unknown()),
    }),
    security: z.array(z.unknown()),
    servers: z.array(z.object({ url: z.string() })),
    tags: z.array(z.unknown()),
    paths: z.record(z.string(), z.record(z.string(), z.unknown())),
  })
  .passthrough();

for (const profile of [
  "openapi-minimal",
  "openapi-last-login",
  "openapi-last-login-database",
  "openapi-default",
  "openapi-configured",
  "openapi-jwt",
  "openapi-username",
  "openapi-custom-schema",
  "openapi-plugins",
  "openapi-plugins-teams",
  "openapi-plugins-configured",
] as const) {
  compatScenario(
    `OpenAPI ${profile} generates the complete configured document and reference frame`,
    async (ctx) => {
      const actor = ctx.actor("docs", profile);
      const sdk = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
      expect(sdk.error).toBeNull();

      const schema = documentSchema.parse(sdk.data);

      if (!profile.startsWith("openapi-plugins") && profile !== "openapi-custom-schema") {
        expect(Object.keys(schema.paths).sort()).toEqual(
          [
            ...(profile === "openapi-username"
              ? ["/sign-in/username", "/is-username-available"]
              : []),
            ...(profile === "openapi-configured" ? [] : ["/error"]),
            "/sign-in/social",
            "/sign-up/email",
            "/sign-in/email",
            "/link-social",
            "/account-info",
            "/callback/{id}",
            "/change-email",
            "/change-password",
            "/delete-user",
            "/delete-user/callback",
            "/get-access-token",
            "/get-session",
            "/list-accounts",
            "/list-sessions",
            "/ok",
            "/refresh-token",
            "/request-password-reset",
            "/reset-password",
            "/reset-password/{token}",
            "/revoke-other-sessions",
            "/revoke-session",
            "/revoke-sessions",
            "/send-verification-email",
            "/sign-out",
            "/unlink-account",
            "/update-user",
            "/update-session",
            "/verify-email",
            "/verify-password",
          ].sort(),
        );
      }

      expect(schema.servers).toEqual([
        { url: `${ctx.baseURL}/__test/profiles/${profile}/api/auth` },
      ]);
      expect(schema.paths["/get-session"]).toHaveProperty("get.operationId", "getSession");
      expect(schema.paths["/get-session"]).toHaveProperty("post.operationId", "getSessionPost");
      expect(schema.paths["/update-session"]).toHaveProperty("post.operationId", "updateSession");
      expect(schema.paths).not.toHaveProperty("/reference");
      expect(schema.paths).not.toHaveProperty("/open-api/generate-schema");

      if (!profile.startsWith("openapi-plugins")) {
        expect(Object.keys(schema.components.schemas).sort()).toEqual(
          profile === "openapi-jwt"
            ? ["Account", "Jwks", "Session", "User", "Verification"]
            : profile === "openapi-custom-schema"
              ? ["Account", "Document", "Session", "User", "Verification"]
              : ["Account", "Session", "User", "Verification"],
        );
      }

      expect(schema.components.schemas.User).toHaveProperty("properties.emailVerified", {
        type: "boolean",
        default: false,
        readOnly: true,
      });

      if (profile.startsWith("openapi-plugins")) {
        expect(schema.paths).toHaveProperty("/admin/remove-user");
        expect(schema.paths).toHaveProperty("/organization/create");
        expect(schema.paths).toHaveProperty("/passkey/verify-registration");
        expect(schema.paths).toHaveProperty("/two-factor/enable");
        expect(schema.paths).toHaveProperty("/multi-session/list-device-sessions");
        expect(schema.paths).toHaveProperty("/phone-number/verify");
        expect(schema.paths).toHaveProperty("/siwe/nonce");
        expect(schema.components.schemas).toHaveProperty("WalletAddress");
        expect(schema.components.schemas.User).toHaveProperty("properties.phoneNumberVerified", {
          type: "boolean",
          readOnly: true,
        });
        expect(schema.components.schemas).toHaveProperty("Apikey");
        expect(schema.components.schemas.Apikey).toHaveProperty(
          "properties.rateLimitMax.default",
          profile === "openapi-plugins-configured" ? 43 : 10,
        );
        expect(schema.components.schemas.Apikey).toHaveProperty(
          "properties.rateLimitTimeWindow.default",
          profile === "openapi-plugins-configured" ? 7654321 : 86400000,
        );
        expect(schema.components.schemas).toHaveProperty("Passkey");
        expect(schema.components.schemas.User).toHaveProperty("properties.banned", {
          type: "boolean",
          default: false,
          readOnly: true,
        });

        if (profile === "openapi-plugins-teams") {
          expect(schema.paths).toHaveProperty("/organization/create-team");
          expect(schema.components.schemas).toHaveProperty("Team");
          expect(schema.components.schemas).toHaveProperty("OrganizationRole");
          expect(schema.components.schemas.Session).toHaveProperty("properties.activeTeamId");
        } else {
          expect(schema.components.schemas).not.toHaveProperty("Team");
          expect(schema.components.schemas).not.toHaveProperty("OrganizationRole");
          expect(schema.components.schemas.Session).not.toHaveProperty("properties.activeTeamId");
        }
      } else {
        expect(schema.components.schemas.User).not.toHaveProperty("properties.banned");
      }

      if (profile.startsWith("openapi-last-login")) {
        const user = z
          .object({ properties: z.record(z.string(), z.unknown()) })
          .parse(schema.components.schemas.User);
        expect(user.properties.lastLoginMethod).toEqual(
          profile === "openapi-last-login-database"
            ? { type: "string", readOnly: true }
            : undefined,
        );
      }

      if (profile === "openapi-custom-schema") {
        expect(schema.components.schemas.User).toHaveProperty("properties.access", {
          type: ["reader", "editor"],
          default: "reader",
        });
        expect(schema.paths["/sign-up/email"]).toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.access",
          { type: "string", enum: ["reader", "editor"] },
        );
        expect(schema.paths["/update-user"]).toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.aliases",
          { type: "array", items: { type: "string" } },
        );
        expect(schema.paths["/sign-up/email"]).toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.anniversary",
          { type: "string", format: "date-time" },
        );
        expect(schema.components.schemas.User).toHaveProperty("properties.metadata", {
          type: "json",
          default: null,
          readOnly: true,
        });

        const model = z
          .object({ required: z.array(z.string()) })
          .passthrough()
          .parse(schema.components.schemas.User);
        expect(model.required).not.toContain("metadata");
        expect(schema.paths["/sign-up/email"]).not.toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.metadata",
        );
        expect(schema.paths["/update-user"]).not.toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.metadata",
        );
      }

      if (profile === "openapi-username") {
        expect(schema.components.schemas.User).toHaveProperty("properties.username", {
          type: "string",
        });
        expect(schema.paths["/sign-up/email"]).toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.username",
          { type: "string" },
        );
        expect(schema.paths["/update-user"]).toHaveProperty(
          "post.requestBody.content.application/json.schema.properties.displayUsername",
          { type: "string" },
        );
      }

      expect(schema.components.schemas.Session).not.toHaveProperty("properties.active");

      const raw = await actor.fetch(`${ctx.baseURL}/api/auth/open-api/generate-schema`);
      expect(raw.status).toBe(200);
      expect(raw.headers.get("content-type")?.split(";")[0]).toBe("application/json");
      expect(await raw.json()).toEqual(schema);

      const path = profile === "openapi-configured" ? "/docs" : "/reference";
      const html = await actor.fetch(`${ctx.baseURL}/api/auth${path}`);
      expect(html.status).toBe(200);
      expect(html.headers.get("content-type")?.split(";")[0]).toBe("text/html");

      const page = await html.text();
      const embedded =
        /<script\s+id="api-reference"\s+type="application\/json">\s*([^]*?)\s*<\/script>/.exec(
          page,
        );

      if (!embedded?.[1]) {
        throw new Error("reference must include a complete schema JSON script");
      }

      expect(JSON.parse(embedded[1])).toEqual(schema);
      expect(page.match(/nonce="fixture-reference-nonce"/g)?.length ?? 0).toBe(
        profile === "openapi-configured" ? 2 : 0,
      );
      expect(page).toContain(`theme: "${profile === "openapi-configured" ? "moon" : "default"}"`);

      // Compare the entire HTML frame verbatim, with the complete embedded document
      // compared structurally above and in the returned observation.
      const frame = page.replace(embedded[1], "<document>");
      const wrongPath = await actor.fetch(
        `${ctx.baseURL}/api/auth${profile === "openapi-configured" ? "/reference" : "/docs"}`,
      );
      expect(wrongPath.status).toBe(404);

      const custom = [];

      if (profile === "openapi-custom-schema") {
        expect(schema.paths["/documents/{id}"]).toHaveProperty("post.operationId", "documentPost");
        expect(schema.paths).toHaveProperty("/documentation-hidden");
        expect(schema.paths).not.toHaveProperty("/documentation-server-only");
        expect(schema.paths).not.toHaveProperty("/documentation-disabled");
        expect(schema.components.schemas.Document).toHaveProperty("required", ["id", "label"]);
        expect(schema.components.schemas.Document).toHaveProperty("properties.secret", {
          type: "string",
          readOnly: true,
        });
        expect(schema.components.schemas.Document).toHaveProperty("properties.dynamic", {
          type: "number",
        });

        for (const [path, method, body] of [
          ["/__test/server-document", "GET", undefined],
          ["/documents/fixture-id", "GET", undefined],
          ["/documents/fixture-id", "POST", ["approved"]],
          ["/documents/fixture-id", "POST", null],
          ["/documentation-hidden", "GET", undefined],
          ["/documentation-server-only", "GET", undefined],
          ["/documentation-disabled", "GET", undefined],
        ] as const) {
          const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, {
            method,
            ...(body !== undefined
              ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }
              : {}),
          });
          custom.push({ path, status: response.status, body: await response.text() });
        }

        expect(custom.map((result) => result.status)).toEqual([200, 200, 200, 200, 200, 404, 404]);
      }

      const minimal = [];

      if (profile === "openapi-minimal") {
        for (const [path, method, body] of [
          ["/get-session", "GET", undefined],
          [
            "/sign-up/email",
            "POST",
            {
              name: "Disabled User",
              email: "disabled-openapi@example.test",
              password: "disabled-openapi-password",
            },
          ],
          [
            "/sign-in/email",
            "POST",
            { email: "disabled-openapi@example.test", password: "disabled-openapi-password" },
          ],
          ["/list-sessions", "GET", undefined],
          ["/change-email", "POST", { newEmail: "changed-openapi@example.test" }],
          ["/delete-user", "POST", {}],
        ] as const) {
          const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, {
            method,
            headers: body ? { "content-type": "application/json" } : {},
            ...(body ? { body: JSON.stringify(body) } : {}),
          });
          minimal.push({ path, status: response.status, body: await response.json() });
        }

        expect(minimal[0]).toEqual({ path: "/get-session", status: 200, body: null });
        expect(minimal[1]?.status).toBe(400);
        expect(minimal[2]?.status).toBe(400);
        expect(minimal[3]?.status).toBe(401);

        const signup = await actor.fetch(
          `${ctx.baseURL}/__test/profiles/openapi-default/api/auth/sign-up/email`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              name: "Configured User",
              email: ctx.uniqueEmail("openapi-minimal"),
              password: "configured-openapi-password",
            }),
          },
        );
        expect(signup.status).toBe(200);

        const created = z
          .object({ user: z.object({ id: z.string(), email: z.string() }) })
          .passthrough()
          .parse(await signup.json());

        for (const [path, method, body, status] of [
          ["/change-email", "POST", { newEmail: "changed-openapi@example.test" }, 400],
          ["/delete-user", "POST", {}, 404],
          ["/delete-user/callback?token=unused", "GET", undefined, 404],
        ] as const) {
          const response = await actor.fetch(`${ctx.baseURL}/api/auth${path}`, {
            method,
            ...(body
              ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }
              : {}),
          });
          expect(response.status).toBe(status);

          const text = await response.text();
          minimal.push({ path, status: response.status, body: text ? JSON.parse(text) : "" });
        }

        const session = await actor.fetch(`${ctx.baseURL}/api/auth/get-session`);
        const retained = z
          .object({ user: z.object({ id: z.string(), email: z.string() }) })
          .passthrough()
          .parse(await session.json());
        expect(retained.user).toEqual(created.user);

        minimal.push({ path: "retained-session", status: session.status, body: retained });
      }

      return ctx.snapshot({ schema, frame, wrongPath: wrongPath.status, minimal, custom });
    },
    [],
    30_000,
    {
      oracle: {
        unroutedRequests: "asserts the unconfigured reference path and disabled routes 404",
      },
    },
  );
}

compatScenario(
  "OpenAPI disabling the reference preserves the public schema endpoint",
  async (ctx) => {
    const profile: FixtureProfile = "openapi-disabled";
    const actor = ctx.actor("docs", profile);
    const schema = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
    expect(schema.error).toBeNull();

    const document = documentSchema.parse(schema.data);
    const page = await actor.fetch(`${ctx.baseURL}/api/auth/reference`);
    expect(page.status).toBe(404);
    expect(await page.text()).toBe("");

    return ctx.snapshot({ document, status: page.status });
  },
  [],
  30_000,
  { oracle: { unroutedRequests: "asserts the disabled reference page 404s" } },
);

for (const profile of ["session-fields", "session-fields-plugins"] as const) {
  compatScenario(
    `OpenAPI ${profile} documents real custom session columns with source-specific config precedence`,
    async (ctx) => {
      const actor = ctx.actor("docs", profile);
      const response = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
      expect(response.error).toBeNull();

      const schema = documentSchema.parse(response.data);
      const model = z
        .object({ properties: z.record(z.string(), z.unknown()), required: z.array(z.string()) })
        .parse(schema.components.schemas.Session);
      expect(model.properties.label).toEqual({ type: "string", default: "initial" });
      expect(model.properties.hidden).toEqual({ type: "string", default: "server-secret" });
      expect(model.properties.serverOnly).toEqual({
        type: "string",
        default: "locked",
        readOnly: true,
      });
      expect(model.properties.callback).toEqual({ type: "string" });
      expect(model.properties.payload).toEqual({ type: "json", default: { initial: true } });
      expect(model.required).not.toContain("hidden");
      expect(model.properties.activeOrganizationId).toEqual({
        type: "string",
        default:
          profile === "session-fields-plugins"
            ? "configured-default-org"
            : "declared-without-plugin",
      });
      // The configured required/returned flags override plugin table metadata here,
      // while the plugin's distinct output policy returns this field in session SDK tests.
      expect(model.required).not.toContain("activeOrganizationId");
      expect(schema.paths["/update-session"]).toHaveProperty("post.operationId", "updateSession");
      expect(schema.paths).not.toHaveProperty("/open-api/generate-schema");

      const raw = await actor.fetch(`${ctx.baseURL}/api/auth/open-api/generate-schema`);
      expect(raw.status).toBe(200);
      expect(await raw.json()).toEqual(schema);

      return ctx.snapshot({ schema });
    },
  );
}

for (const mode of ["explicit", "empty"] as const) {
  compatScenario(
    `OpenAPI explicit parameter metadata ${mode} replaces inference and deduplicates paths`,
    async (ctx) => {
      const actor = ctx.actor("parameter-docs", "openapi-parameters");
      const live = await actor.client.$fetch(`/parameters-${mode}/document-42`, {
        method: "GET",
        query: { inferred: "real-input", documented: "visible" },
      });
      expect(live.error).toBeNull();
      expect(live.data).toEqual({
        id: "document-42",
        inferred: "real-input",
        documented: "visible",
      });
      const generated = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
      expect(generated.error).toBeNull();
      const schema = documentSchema.parse(generated.data);
      const operation: any = schema.paths[`/parameters-${mode}/{id}`]!.get;
      expect(operation.operationId).toBe(`parameters${mode}`);
      expect(operation.parameters).toEqual(
        mode === "empty"
          ? [{ name: "id", in: "path", required: true, schema: { type: "string" } }]
          : [
              {
                name: "documented",
                in: "query",
                required: true,
                description: "Explicit query",
                schema: { type: "string", enum: ["visible"] },
              },
              {
                name: "id",
                in: "path",
                required: true,
                description: "Application identifier",
                schema: { type: "string", pattern: "^document-[0-9]+$" },
              },
            ],
      );
      expect(
        operation.parameters.filter((p: any) => p.in === "path" && p.name === "id"),
      ).toHaveLength(1);
      expect(operation.parameters.some((p: any) => p.name === "inferred")).toBe(false);
      return { live: ctx.snapshot(live), generated: ctx.snapshot(generated) };
    },
    ["GET /open-api/generate-schema"],
  );
}

compatScenario(
  "OpenAPI repeated operation IDs skip occupied method suffixes and remain stable",
  async (ctx) => {
    const actor = ctx.actor("collision-docs", "openapi-collisions");
    const expected = {
      reserved: "collisionGet",
      first: "collision",
      second: "collisionGet2",
      third: "collisionGet3",
    };
    const live = [];
    for (const route of Object.keys(expected)) {
      const result = await actor.client.$fetch(`/collisions/${route}`, { method: "GET" });
      expect(result.error).toBeNull();
      expect(result.data).toEqual({ route });
      live.push(ctx.snapshot(result));
    }
    const generated = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
    expect(generated.error).toBeNull();
    const schema = documentSchema.parse(generated.data);
    for (const [route, operationId] of Object.entries(expected)) {
      expect(schema.paths[`/collisions/${route}`]).toHaveProperty("get.operationId", operationId);
    }
    const identifiers = Object.keys(expected).map(
      (route) => (schema.paths[`/collisions/${route}`]!.get as any).operationId,
    );
    expect(new Set(identifiers).size).toBe(identifiers.length);
    const repeated = await actor.client.$fetch("/open-api/generate-schema", { method: "GET" });
    expect(repeated).toEqual(generated);
    return { live, generated: ctx.snapshot(generated), repeated: ctx.snapshot(repeated) };
  },
  ["GET /open-api/generate-schema"],
);
