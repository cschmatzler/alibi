import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario("error page sanitizes script injection in error code", async (ctx) => {
  const redirect = await ctx.rawRequest({
    path: `/api/auth/error?error=${encodeURIComponent("<script>alert(1)</script>")}`,
    redirect: "manual",
  });
  expect(redirect).toEqual({ status: 302, location: "/?error=UNKNOWN", body: null });

  const response = await ctx.rawRequest({
    path: `${authProfilePath("error-page")}/error?error=${encodeURIComponent("<script>alert(1)</script>")}`,
  });
  expect(response.status).toBe(200);
  expect(response.body).toContain("UNKNOWN");
  expect(response.body).not.toContain("<script>alert(1)</script>");

  return {
    redirect,
    response: ctx.snapshot(response),
  };
});

compatScenario("error page renders valid error code", async (ctx) => {
  const observations = [];
  for (const [description, expectedLocation] of [
    [undefined, "/?error=SOME_ERROR"],
    ["", "/?error=SOME_ERROR"],
    [
      "<b>space + & café</b>\r\nLocation: https://foreign.test/",
      "/?error=SOME_ERROR&error_description=%3Cb%3Espace+%2B+%26+caf%C3%A9%3C%2Fb%3E%0D%0ALocation%3A+https%3A%2F%2Fforeign.test%2F",
    ],
  ] as const) {
    const query = new URLSearchParams({ error: "SOME_ERROR" });

    if (description !== undefined) {
      query.set("error_description", description);
    }

    const redirect = await ctx.rawRequest({ path: `/api/auth/error?${query}`, redirect: "manual" });
    expect(redirect).toEqual({ status: 302, location: expectedLocation, body: null });

    const response = await ctx.rawRequest({
      path: `${authProfilePath("error-page")}/error?${query}`,
    });
    expect(response.status).toBe(200);
    expect(response.body).toContain("SOME_ERROR");

    if (description) {
      expect(response.body).toContain("&lt;b&gt;space + &amp; café&lt;/b&gt;");
      expect(response.body).not.toContain("<b>space");
    } else {
      expect(response.body).toContain("We encountered an unexpected error.");
    }

    observations.push({ redirect, response: ctx.snapshot(response) });
  }
  return { observations };
});
