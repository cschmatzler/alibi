import { expect } from "bun:test";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

async function events(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/dispatch-events" });
  expect(response.status).toBe(200);
  return response.body as { path: string; method: string }[];
}

// Every operation keeps its own real credential/session setup and issuance window.
// Earlier independent password operations must not accumulate into later raw dates.
const admissionCases = [
  {
    kind: "origin",
    name: "foreign-cookie-origin",
    headers: { origin: "https://foreign.fixture.test" },
    callbackURL: "/owned",
  },
  {
    kind: "origin",
    name: "foreign-callback",
    headers: {},
    callbackURL: "https://foreign.fixture.test/owned",
  },
  {
    kind: "origin",
    name: "null-same-origin",
    headers: { origin: "null", "sec-fetch-site": "same-origin" },
    callbackURL: "/owned",
  },
  {
    kind: "origin",
    name: "null-cross-site",
    headers: { origin: "null", "sec-fetch-site": "cross-site" },
    callbackURL: "/owned",
  },
  {
    kind: "origin",
    name: "null-forged-host",
    headers: {
      origin: "null",
      "sec-fetch-site": "same-origin",
      host: "foreign.fixture.test",
    },
    callbackURL: "/owned",
  },

  { kind: "navigation", name: "cross-site-navigation" },
  { kind: "legacy", name: "legacy-no-origin", explicitOrigin: false },
  { kind: "legacy", name: "legacy-explicit-origin", explicitOrigin: true },
  { kind: "prefix", name: "prefix-child", route: "/sign-in/child" },
  { kind: "prefix", name: "prefix-peer", route: "/sign-in-peer" },
] as const;

for (const mode of [
  "default",
  "csrf-off",
  "origin-off",
  "origin-off-explicit-csrf",
  "origin-path",
] as const) {
  for (const input of admissionCases) {
    compatScenario(
      `dispatch ${mode} origin and CSRF configuration preserves writes only after admission: ${input.name}`,
      async (ctx) => {
        const profile = `dispatch-${mode}` as FixtureProfile;
        const owner = ctx.actor("owner", profile);
        const foreign = ctx.actor("foreign", profile);
        const signup = await owner.client.signUp.email({
          email: ctx.uniqueEmail("dispatch-owner"),
          password: "password123",
          name: "Owner",
        });
        const other = await foreign.client.signUp.email({
          email: ctx.uniqueEmail("dispatch-foreign"),
          password: "password123",
          name: "Foreign",
        });
        expect(signup.error).toBeNull();
        expect(other.error).toBeNull();

        const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
        await events(ctx);
        if (input.kind === "origin") {
          const before = await ctx.readUserState({ userId: signup.data!.user.id });
          const result = await owner.client.signIn.email(
            {
              email: signup.data!.user.email,
              password: "password123",
              callbackURL: input.callbackURL,
            },
            { headers: input.headers },
          );
          const allowed =
            input.name === "null-same-origin" ||
            (input.name === "foreign-callback"
              ? ["origin-off", "origin-off-explicit-csrf", "origin-path"].includes(mode)
              : mode !== "default");
          const after = await ctx.readUserState({ userId: signup.data!.user.id });
          const callbacks = await events(ctx);

          if (allowed) {
            expect(result.error).toBeNull();
            expect(result.data?.user.id).toBe(signup.data!.user.id);
            expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]);
          } else {
            expect(result.error?.code).toBe(
              input.name === "null-cross-site"
                ? "MISSING_OR_NULL_ORIGIN"
                : input.name === "foreign-callback"
                  ? "INVALID_CALLBACK_URL"
                  : "INVALID_ORIGIN",
            );
            expect(after).toEqual(before);
            expect(callbacks).toEqual([]);
          }

          expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

          return {
            input,
            before,
            result: ctx.snapshot(result),
            after,
            callbacks,
            signup: ctx.snapshot(signup),
            other: ctx.snapshot(other),
            foreignBefore,
            foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
          };
        }

        if (input.kind === "navigation") {
          const guest = ctx.actor("cross-site", profile);
          const before = await ctx.readUserState({ userId: signup.data!.user.id });
          const navigation = await guest.client.signIn.email(
            { email: signup.data!.user.email, password: "password123" },
            {
              headers: {
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "navigate",
                origin: "https://foreign.fixture.test",
              },
            },
          );
          const callbacks = await events(ctx);
          const after = await ctx.readUserState({ userId: signup.data!.user.id });

          if (mode === "csrf-off" || mode === "origin-off") {
            expect(navigation.error).toBeNull();
          } else {
            expect(navigation.error?.code).toBe("CROSS_SITE_NAVIGATION_LOGIN_BLOCKED");
            expect(after).toEqual(before);
            expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]);
          }

          expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

          return {
            input,
            navigation: ctx.snapshot(navigation),
            callbacks,
            before,
            after,
            signup: ctx.snapshot(signup),
            other: ctx.snapshot(other),
            foreignBefore,
            foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
          };
        }

        if (input.kind === "legacy") {
          const { explicitOrigin } = input;
          const legacyBefore = await ctx.readUserState({ userId: signup.data!.user.id });
          const result = await ctx
            .actor(`legacy-${explicitOrigin}`, profile)
            .client.signIn.email(
              { email: signup.data!.user.email, password: "password123" },
              { headers: explicitOrigin ? { origin: "https://foreign.fixture.test" } : {} },
            );
          const legacyAfter = await ctx.readUserState({ userId: signup.data!.user.id });
          const receipts = await events(ctx);

          if (explicitOrigin && mode === "default") {
            expect(result.error?.code).toBe("INVALID_ORIGIN");
            expect(legacyAfter).toEqual(legacyBefore);
          } else {
            expect(result.error).toBeNull();
            expect(result.data?.user.id).toBe(signup.data!.user.id);
          }

          expect(receipts).toEqual([{ path: "/sign-in/email", method: "POST" }]);
          expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

          return {
            input,
            explicitOrigin,
            result: ctx.snapshot(result),
            before: legacyBefore,
            after: legacyAfter,
            receipts,
            signup: ctx.snapshot(signup),
            other: ctx.snapshot(other),
            foreignBefore,
            foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
          };
        }

        const { route } = input;
        const physicalBefore = await ctx.readUserState({ userId: signup.data!.user.id });
        const response = await owner.fetch(authProfilePath(profile) + route, {
          method: "POST",
          headers: { origin: "https://foreign.fixture.test", "content-type": "application/json" },
          body: JSON.stringify({ value: "observable application input" }),
        });
        const result = { status: response.status, body: await response.json() };
        const receipts = await events(ctx);
        const allowed =
          mode !== "default" && (mode !== "origin-path" || route === "/sign-in/child");
        expect(result.status).toBe(allowed ? 200 : 403);

        if (allowed) {
          expect(result.body).toEqual({ payload: { value: "observable application input" } });
          expect(receipts).toEqual([{ path: route, method: "POST" }]);
        } else {
          expect(result.body).toMatchObject({ code: "INVALID_ORIGIN" });
          expect(receipts).toEqual([]);
        }

        const physicalAfter = await ctx.readUserState({ userId: signup.data!.user.id });
        expect(physicalAfter).toEqual(physicalBefore);
        expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

        return {
          input,
          route,
          result,
          receipts,
          before: physicalBefore,
          after: physicalAfter,
          signup: ctx.snapshot(signup),
          other: ctx.snapshot(other),
          foreignBefore,
          foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
        };
      },
      ["POST /sign-up/email", "POST /sign-in/email"],
    );
  }
}

for (const mode of [
  "default",
  "trailing",
  "disabled-email",
  "disabled-template",
  "disabled-literal",
] as const) {
  compatScenario(
    `dispatch ${mode} literal paths and unknown methods preserve router rejection before application hooks`,
    async (ctx) => {
      const path = authProfilePath(`dispatch-${mode}` as FixtureProfile);
      await events(ctx);
      const results = [];

      for (const [route, method, expected] of [
        ["/ok/", "GET", mode === "trailing" ? 200 : 404],
        ["/ok", "POST", 404],
        ["/ok", "HEAD", 404],
        ["/ok", "PATCH", 404],
        ["/unregistered", "POST", 404],
        ["/owned/item", "GET", mode === "disabled-literal" ? 404 : 200],
        ["/owned/item/", "GET", mode === "trailing" ? 200 : 404],
      ] as const) {
        const result = await ctx.rawRequest({ path: path + route, method });
        expect(result.status).toBe(expected);

        const callbacks = await events(ctx);
        expect(callbacks).toEqual(expected === 200 ? [{ path: route, method }] : []);

        results.push({ route, method, result, callbacks });
      }

      if (mode === "disabled-email") {
        const result = await ctx.rawRequest({
          path: path + "/sign-in/email/",
          method: "POST",
          body: "{",
          headers: { "content-type": "application/json", origin: "https://foreign.fixture.test" },
        });
        expect(result).toEqual({ status: 404, location: null, body: "Not Found" });
        expect(await events(ctx)).toEqual([]);

        results.push({ route: "/sign-in/email/", method: "POST", result, callbacks: [] });
      }

      return results;
    },
    ["GET /ok", "POST /sign-in/email"],
    30_000,
    {
      oracle: {
        unroutedRequests:
          "asserts trailing slashes, unknown paths and unknown methods are not routed",
      },
    },
  );
}

compatScenario(
  "dispatch media and JSON syntax validation precede origin rejection and preserve physical principals",
  async (ctx) => {
    const profile: FixtureProfile = "dispatch-default";
    const path = authProfilePath(profile);
    const owner = ctx.actor("owner", profile);
    const foreign = ctx.actor("foreign", profile);
    const signup = await owner.client.signUp.email({
      email: ctx.uniqueEmail("media-owner"),
      name: "Owner",
      password: "password123",
    });
    const other = await foreign.client.signUp.email({
      email: ctx.uniqueEmail("media-foreign"),
      name: "Foreign",
      password: "password123",
    });
    expect(signup.error).toBeNull();
    expect(other.error).toBeNull();

    await events(ctx);
    const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
    const results = [];

    for (const [name, contentType, body, status, code] of [
      [
        "malformed-allowed",
        "application/foo*+jsonapplication/json",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        400,
        "VALIDATION_ERROR",
      ],
      [
        "non-json-allowed",
        "text/plainapplication/json",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        400,
        "VALIDATION_ERROR",
      ],
      ["multipart-missing-boundary", "multipart/form-dataapplication/json", "invalid", 500, null],
      [
        "multipart",
        "multipart/form-dataapplication/json; boundary=dispatch-boundary",
        `--dispatch-boundary\r\nContent-Disposition: form-data; name="email"\r\n\r\n${signup.data!.user.email}\r\n--dispatch-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\npassword123\r\n--dispatch-boundary--\r\n`,
        200,
        null,
      ],
      [
        "multipart-file-allowed",
        "multipart/form-dataapplication/json; boundary=dispatch-boundary",
        `--dispatch-boundary\r\nContent-Disposition: form-data; name="email"; filename="email.txt"\r\nContent-Type: text/plain\r\n\r\n${signup.data!.user.email}\r\n--dispatch-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\npassword123\r\n--dispatch-boundary--\r\n`,
        400,
        "VALIDATION_ERROR",
      ],
      [
        "text",
        "text/plain",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        415,
        "UNSUPPORTED_MEDIA_TYPE",
      ],
      [
        "missing",
        "",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        415,
        "UNSUPPORTED_MEDIA_TYPE",
      ],
      ["malformed", "application/json", "{", 400, "BAD_REQUEST"],
      [
        "form",
        "application/x-www-form-urlencoded",
        new URLSearchParams({ email: signup.data!.user.email, password: "password123" }).toString(),
        200,
        null,
      ],
      [
        "json-parameter",
        "Application/JSON; charset=UTF-8",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        200,
        null,
      ],
      [
        "stream",
        "application/json",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        200,
        null,
      ],
      ["stream-malformed", "application/json", "{", 400, "BAD_REQUEST"],
      [
        "valid-json-foreign-origin",
        "application/json",
        JSON.stringify({ email: signup.data!.user.email, password: "password123" }),
        403,
        "INVALID_ORIGIN",
      ],
    ] as const) {
      const before = await ctx.readUserState({ userId: signup.data!.user.id });
      const requestBody = name.startsWith("stream")
        ? new ReadableStream<Uint8Array>({
            start(controller) {
              const encoded = new TextEncoder().encode(body);
              controller.enqueue(encoded.slice(0, 1));
              controller.enqueue(encoded.slice(1));
              controller.close();
            },
          })
        : body;
      const result = await ctx.rawRequest({
        actor: `media-${name}`,
        path: path + "/sign-in/email",
        method: "POST",
        body: requestBody,
        headers: {
          "content-type": contentType,
          ...(status !== 200 ? { origin: "https://foreign.fixture.test" } : {}),
        },
      });
      expect(result.status).toBe(status);

      const after = await ctx.readUserState({ userId: signup.data!.user.id });
      const callbacks = await events(ctx);

      if (status !== 200) {
        if (code) {
          expect(result.body).toMatchObject({ code });
        } else {
          expect(result.body).toBeNull();
        }
        expect(after).toEqual(before);
        expect(callbacks).toEqual(
          name.endsWith("allowed") || name === "valid-json-foreign-origin"
            ? [{ path: "/sign-in/email", method: "POST" }]
            : [],
        );
      } else {
        expect(callbacks).toEqual([{ path: "/sign-in/email", method: "POST" }]);
        expect(result.body).toMatchObject({ user: { id: signup.data!.user.id } });
      }

      expect(await ctx.readUserState({ userId: other.data!.user.id })).toEqual(foreignBefore);

      results.push({ name, contentType, body, before, result, after, callbacks });
    }

    return {
      signup: ctx.snapshot(signup),
      other: ctx.snapshot(other),
      results,
      foreignBefore,
      foreignAfter: await ctx.readUserState({ userId: other.data!.user.id }),
    };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);
