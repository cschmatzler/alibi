import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { Cookie } from "tough-cookie";

import type { ScenarioContext } from "./scenario";
/** Separate cookie-less HTTP requests let responses be compared as a multiset:
 * which browser wins an overlapping redemption is deliberately unspecified. */
export async function raceOneTimeProof(ctx: ScenarioContext, path: string, json?: unknown) {
  const responses = await Promise.all(
    [0, 1].map(async () => {
      const response = await fetch(ctx.baseURL + path, {
        method: json === undefined ? "GET" : "POST",
        headers: { origin: ctx.baseURL, "content-type": "application/json" },
        ...(json === undefined ? {} : { body: JSON.stringify(json) }),
        redirect: "manual",
      });
      const text = await response.text();
      let body: any = null;
      if (text) {
        try {
          body = JSON.parse(text);
        } catch {
          body = text;
        }
      }
      const parsed = response.headers.getSetCookie().map((raw) => Cookie.parse(raw)!);
      for (const cookie of parsed) expect(cookie).toBeDefined();
      const principal = parsed.find((c) => c.key === "better-auth.session_token" && c.maxAge !== 0);
      if (principal) {
        expect(body.token).toBeString();
        const signature = createHmac("sha256", "compat-test-only-key-not-real-minimum-32chars")
          .update(body.token)
          .digest("base64");
        expect(decodeURIComponent(principal.value)).toBe(`${body.token}.${signature}`);
      }
      const session = await fetch(
        ctx.baseURL + path.split("/api/auth/")[0] + "/api/auth/get-session",
        { headers: { cookie: parsed.map((c) => `${c.key}=${c.value}`).join("; ") } },
      );
      expect(session.status).toBe(200);
      const sessionBody = await session.json();
      return {
        status: response.status,
        headers: Object.fromEntries(
          [...response.headers.entries()].filter(
            ([key]) =>
              !["set-cookie", "date", "connection", "keep-alive", "content-length"].includes(key),
          ),
        ),
        body,
        cookies: parsed.map((c) => ({
          name: c.key,
          token: decodeURIComponent(c.value),
          path: c.path,
          domain: c.domain ?? null,
          maxAge: c.maxAge ?? null,
          expires: c.expires instanceof Date ? c.expires.toISOString() : null,
          secure: c.secure,
          httpOnly: c.httpOnly,
          sameSite: c.sameSite,
        })),
        session: sessionBody as any,
      };
    }),
  );
  return responses.sort((a, b) => a.status - b.status);
}
