import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";
import { readUserState } from "../../../support/verification";

type HttpResponse = {
  kind: "http-response";
  status: number;
  headers: Record<string, string>;
  cookies: string[];
  body: string | null;
};
type Reply = {
  events: {
    stage: string;
    path: string;
    request: boolean;
    query: unknown;
    sessionUserId?: string | null;
    returned?: HttpResponse;
  }[];
  result: {
    kind: string;
    api?: boolean;
    message?: string;
    hasHeaders?: boolean;
    headers?: Record<string, string>;
    cookies?: string[];
    response?: HttpResponse | { kind: "json"; value: unknown };
  };
};
const applicationCookies = [
  "application_a=first; Path=/; HttpOnly",
  "application_b=second; Path=/; HttpOnly",
];
compatScenario(
  "server error returns real response values from the physical URL and preserves hook ownership",
  async (ctx) => {
    const actor = ctx.actor("error-foreign");
    let signedCookies = "";
    const foreign = await actor.client.signUp.email({
      email: ctx.uniqueEmail("error-foreign"),
      password: "Password123!",
      name: "Error foreign",
      fetchOptions: {
        onSuccess({ response }) {
          signedCookies = response.headers
            .getSetCookie()
            .map((c) => c.split(";")[0])
            .join("; ");
        },
      },
    });
    expect(foreign.error).toBeNull();
    const before = await readUserState(ctx, foreign.data!.user.id);
    async function invoke(query: string, input: Record<string, unknown>) {
      const response = await ctx.rawRequest({
        path: "/__test/server-error/call" + (query ? `?${query}` : ""),
        method: "POST",
        json: {
          query: { error: "FORGED_LOGICAL", error_description: "forged description" },
          body: { url: "https://forged.example.test/?error=FORGED_BODY" },
          headers: { cookie: signedCookies, origin: "https://untrusted.example.test" },
          ...input,
        },
      });
      expect(response.status).toBe(200);
      return response.body as Reply;
    }
    const missing = await invoke("error=PHYSICAL_CONTROL", {});
    expect(missing.result).toEqual({
      kind: "failure",
      api: false,
      message: "Invalid URL",
      hasHeaders: false,
    });
    expect(missing.events.map((e) => e.stage)).toEqual(["before"]);
    const observations = [missing];
    const description = '<b>space + & café</b> &lt; &#65; "quoted"';
    for (const profile of ["default", "html", "configured"]) {
      for (const [query, code, detail] of [
        ["", "UNKNOWN", undefined],
        ["error=FIRST_CODE&error=SECOND_CODE&error_description=", "FIRST_CODE", undefined],
        [
          new URLSearchParams({
            error: "<script>alert(1)</script>",
            error_description: description,
          }).toString(),
          "UNKNOWN",
          description,
        ],
      ] as const) {
        for (const asResponse of [false, true]) {
          const observed = await invoke(query, { profile, physicalRequest: true, asResponse });
          expect(observed.result.kind).toBe(asResponse ? "forwarded" : "metadata");
          expect(observed.events.map((e) => e.stage)).toEqual(["before", "after"]);
          const after = observed.events[1]!;
          expect(after.path).toBe("/error");
          expect(after.request).toBe(true);
          expect(after.sessionUserId).toBeNull();
          expect(after.returned!.kind).toBe("http-response");
          expect(after.query).toEqual({
            error: "FORGED_LOGICAL",
            error_description: "forged description",
          });
          const returned = observed.result.response as HttpResponse;
          expect(returned.kind).toBe("http-response");
          expect(observed.result).not.toHaveProperty("status");
          expect(returned.headers["x-before"]).toBeUndefined();
          if (asResponse) {
            expect(returned.headers["x-after"]).toBe("actual");
            expect(returned.headers.authorization).toBeUndefined();
            expect(returned.cookies).toEqual(applicationCookies);
          } else {
            expect(observed.result.headers).toEqual({
              "x-after": "actual",
              authorization: "request-only-header",
            });
            expect(observed.result.cookies).toEqual(applicationCookies);
            expect(returned.headers["x-after"]).toBeUndefined();
            expect(returned.cookies).toEqual([]);
          }
          if (profile === "html") {
            expect(returned.status).toBe(200);
            expect(returned.headers["content-type"]).toBe("text/html");
            expect(returned.body).toContain("<!DOCTYPE html>");
            expect(returned.body).toContain(code);
            expect(returned.body).not.toContain("FORGED_LOGICAL");
            expect(returned.body).not.toContain("SECOND_CODE");
            if (detail) {
              expect(returned.body).toContain(
                "&lt;b&gt;space + &amp; café&lt;/b&gt; &lt; &#65; &quot;quoted&quot;",
              );
              expect(returned.body).not.toContain("<b>space");
            }
          } else {
            const params = new URLSearchParams({ error: code });
            if (detail) {
              params.set("error_description", detail);
            }
            expect(returned.status).toBe(302);
            expect(returned.body).toBeNull();
            expect(returned.headers.location).toBe(
              profile === "configured"
                ? `/problem?keep=a%2Bb&${params}#error-panel`
                : `/?${params}`,
            );
            expect(returned.headers["content-type"]).toBeUndefined();
          }
          observations.push(observed);
        }
      }
    }
    for (const mode of ["patch-query", "mutate-response", "replace-json", "before-return"]) {
      for (const asResponse of [false, true]) {
        const observed = await invoke("error=ACTUAL_CODE", {
          mode,
          asResponse,
          physicalRequest: mode !== "before-return",
        });
        const returned = observed.result.response!;
        if (mode === "before-return") {
          expect(observed.events.map((e) => e.stage)).toEqual(["before"]);
          expect(returned).toMatchObject({
            kind: "http-response",
            status: 209,
            body: "application early",
          });
          expect((returned as HttpResponse).headers["x-before"]).toBe(
            asResponse ? "discarded" : undefined,
          );
        } else {
          expect(observed.events[1]!.returned!.status).toBe(302);
          if (mode === "patch-query") {
            expect(observed.events[1]!.query).toMatchObject({ error: "PATCHED_LOGICAL" });
            expect((returned as HttpResponse).headers.location).toBe("/?error=ACTUAL_CODE");
          } else if (mode === "mutate-response") {
            expect((returned as HttpResponse).headers["x-response-mutated"]).toBe("actual");
            expect((returned as HttpResponse).cookies).toEqual([
              "raw_a=one; Path=/",
              "raw_b=two; Path=/",
              ...(asResponse ? applicationCookies : []),
            ]);
          } else if (asResponse) {
            expect(returned).toMatchObject({
              kind: "http-response",
              status: 200,
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ replacement: true }),
            });
          } else {
            expect(returned).toEqual({ kind: "json", value: { replacement: true } });
          }
        }
        observations.push(observed);
      }
    }
    const transport = [];
    for (const mode of ["normal", "patch-query", "mutate-response", "replace-json"]) {
      const query = new URLSearchParams({ error: "ACTUAL_CODE", application_mode: mode });
      const response = await ctx
        .actor("error-http")
        .fetch(ctx.baseURL + "/__test/profiles/server-error-default/api/auth/error?" + query, {
          redirect: "manual",
        });
      const text = await response.text();
      const events = (await ctx.rawRequest({ path: "/__test/server-error/events" }))
        .body as Reply["events"];
      expect(events.map((event) => event.stage)).toEqual(["before", "after"]);
      expect(events[1]!.returned!.kind).toBe("http-response");
      expect(events[1]!.returned!.status).toBe(302);
      expect(events[1]!.sessionUserId).toBeNull();
      expect(response.headers.get("x-before")).toBeNull();
      expect(response.headers.get("x-after")).toBe("actual");
      expect(response.headers.get("authorization")).toBeNull();
      expect(response.status).toBe(mode === "replace-json" ? 200 : 302);
      expect(text).toBe(mode === "replace-json" ? JSON.stringify({ replacement: true }) : "");
      expect(response.headers.get("location")).toBe(
        mode === "replace-json" ? null : "/?error=ACTUAL_CODE",
      );
      expect(response.headers.getSetCookie()).toEqual(
        mode === "mutate-response"
          ? ["raw_a=one; Path=/", "raw_b=two; Path=/", ...applicationCookies]
          : applicationCookies,
      );
      transport.push({
        mode,
        status: response.status,
        location: response.headers.get("location"),
        body: text,
        events,
        cookies: response.headers.getSetCookie(),
      });
    }
    expect(await readUserState(ctx, foreign.data!.user.id)).toEqual(before);
    return ctx.snapshot({
      foreign,
      before,
      observations,
      transport,
      after: await readUserState(ctx, foreign.data!.user.id),
    });
  },
  [],
  30_000,
);
