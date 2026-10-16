import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Form decoding rejects admitted malformed MIME subtypes without authenticating",
  async (ctx) => {
    const actor = ctx.actor("multipart", "dispatch-default");
    const email = ctx.uniqueEmail("multipart-mime");
    const issued = await actor.client.signUp.email({
      email,
      name: "Multipart Owner",
      password: "password123",
    });
    expect(issued.error).toBeNull();
    const before = await ctx.readUserState({ userId: issued.data!.user.id });
    const raw = `--fixture-boundary\r\nContent-Disposition: form-data; name="email"\r\n\r\n${email}\r\n--fixture-boundary\r\nContent-Disposition: form-data; name="password"\r\n\r\npassword123\r\n--fixture-boundary--\r\n`;
    const form = new URLSearchParams({ email, password: "password123" }).toString();
    const results = [];
    for (const [contentType, body] of [
      ["multipart/form-dataapplication/json; boundary=fixture-boundary", raw],
      ["multipart/form-dataapplication/json; boundary=fixture-boundary; charset=utf-8", raw],
      ["application/x-www-form-urlencodedapplication/json", form],
      ["text/application/x-www-form-urlencoded", form],
    ] as const) {
      await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      const response = await actor.fetch("/api/auth/sign-in/email", {
        method: "POST",
        headers: { "content-type": contentType },
        body,
      });
      expect(response.status).toBe(500);
      expect(await response.text()).toBe("");
      expect(response.headers.getSetCookie()).toEqual([]);
      const hooks = await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      expect(await hooks.json()).toEqual([]);
      expect(await ctx.readUserState({ userId: issued.data!.user.id })).toEqual(before);
      results.push({ contentType, status: response.status });
    }
    const response = await actor.fetch("/api/auth/sign-in/email", {
      method: "POST",
      headers: { "content-type": "Application/X-WWW-Form-Urlencoded; charset=utf-8" },
      body: form,
    });
    expect(response.status).toBe(200);
    const valid = await response.json();
    expect(valid.user.id).toBe(issued.data!.user.id);
    const fileBody =
      '--fixture-boundary\r\nContent-Disposition: form-data; name="literal"\r\n\r\nform-text\r\n--fixture-boundary\r\nContent-Disposition: form-data; name="file"; filename="probe.txt"\r\nContent-Type: text/plain\r\n\r\nsecret-contents\r\n--fixture-boundary--\r\n';
    const mixed = await actor.fetch("/api/auth/form-probe", {
      method: "POST",
      headers: {
        "content-type":
          'multipart/form-data; boundary=fixture-boundary; mode="application/x-www-form-urlencoded"',
      },
      body: fileBody,
    });
    expect(mixed.status).toBe(200);
    const coerced = await mixed.json();
    expect(coerced).toEqual({ payload: { literal: "form-text", file: "[object File]" } });
    const callbackURL = "https://foreign.fixture.test/untrusted";
    const callbackForm = raw.replace(
      "--fixture-boundary--",
      `--fixture-boundary\r\nContent-Disposition: form-data; name="callbackURL"\r\n\r\n${callbackURL}\r\n--fixture-boundary--`,
    );
    const beforeCallbacks = await ctx.readUserState({ userId: issued.data!.user.id });
    const deniedCallbacks = [];
    for (const [path, contentType, body] of [
      [
        "/api/auth/sign-in/email",
        'application/json; mode="application/x-www-form-urlencoded"',
        JSON.stringify({ email, password: "password123", callbackURL }),
      ],
      [
        "/api/auth/form-probe",
        'multipart/form-data; boundary=fixture-boundary; mode="application/x-www-form-urlencoded"',
        callbackForm,
      ],
    ] as const) {
      await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      const response = await actor.fetch(path, {
        method: "POST",
        headers: { "content-type": contentType },
        body,
      });
      expect(response.status).toBe(403);
      const error = await response.json();
      expect(error).toEqual({ code: "INVALID_CALLBACK_URL", message: "Invalid callbackURL" });
      expect(response.headers.getSetCookie()).toEqual([]);
      const hooks = await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      expect(await hooks.json()).toEqual([]);
      expect(await ctx.readUserState({ userId: issued.data!.user.id })).toEqual(beforeCallbacks);
      deniedCallbacks.push({ contentType, status: response.status, error });
    }
    return ctx.snapshot({
      issued,
      before,
      results,
      valid,
      coerced,
      beforeCallbacks,
      deniedCallbacks,
    });
  },
);
