import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "Multipart decoding rejects admitted malformed MIME subtypes without authenticating",
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
    const results = [];
    for (const contentType of [
      "multipart/form-dataapplication/json; boundary=fixture-boundary",
      "multipart/form-dataapplication/json; boundary=fixture-boundary; charset=utf-8",
    ]) {
      await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      const response = await actor.fetch("/api/auth/sign-in/email", {
        method: "POST",
        headers: { "content-type": contentType },
        body: raw,
      });
      expect(response.status).toBe(500);
      expect(await response.text()).toBe("");
      expect(response.headers.getSetCookie()).toEqual([]);
      const hooks = await actor.fetch(`${ctx.baseURL}/__test/dispatch-events`);
      expect(await hooks.json()).toEqual([]);
      expect(await ctx.readUserState({ userId: issued.data!.user.id })).toEqual(before);
      results.push({ contentType, status: response.status });
    }
    const valid = await actor.client.signIn.email({ email, password: "password123" });
    expect(valid.error).toBeNull();
    expect(valid.data!.user.id).toBe(issued.data!.user.id);
    return ctx.snapshot({ issued, before, results, valid });
  },
);
