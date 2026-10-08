import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
compatScenario(
  "error HTML preserves legal numeric entities while escaping unknown ampersands",
  async (ctx) => {
    const description = "before &#65; middle &#x41; after &amp; &bogus;";
    const query = new URLSearchParams({ error: "BAD_CODE", error_description: description });
    const html = await ctx.rawRequest({ path: authProfilePath("error-page") + "/error?" + query });
    expect(html.status).toBe(200);
    expect(html.body).toContain("before &#65; middle &#x41; after &amp; &amp;bogus;");
    expect(html.body).not.toContain("&amp;#65;");
    expect(html.body).not.toContain("&amp;#x41;");
    const redirect = await ctx.rawRequest({ path: "/api/auth/error?" + query, redirect: "manual" });
    expect(redirect).toEqual({
      status: 302,
      location:
        "/?error=BAD_CODE&error_description=before+%26%2365%3B+middle+%26%23x41%3B+after+%26amp%3B+%26bogus%3B",
      body: null,
    });
    const parsed = new URL(redirect.location!, ctx.baseURL);
    expect(parsed.searchParams.get("error_description")).toBe(description);
    return { html: ctx.snapshot(html), redirect };
  },
  ["GET /error"],
);
