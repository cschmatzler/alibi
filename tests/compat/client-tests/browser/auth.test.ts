import { expect, test } from "bun:test";

import { chromium } from "playwright";
import { z } from "zod";

import { RUST_BASE_URL, requireHealthy, TS_BASE_URL } from "../support/config";
import { resetServerState } from "../support/controls";

for (const [label, baseURL] of [
  ["TypeScript", TS_BASE_URL],
  ["Rust", RUST_BASE_URL],
] as const) {
  for (const mode of ["default", "secure-prefix", "secure-custom"] as const) {
    const path =
      mode === "default" ? "/api/auth" : `/__test/profiles/physical-cookie-${mode}/api/auth`;
    const cookieName =
      mode === "default"
        ? "better-auth.session_token"
        : mode === "secure-custom"
          ? "__Secure-configured_session"
          : "__Secure-better-auth.session_token";
    test.serial(
      `${label} ${mode}: Chromium enforces session cookies, reload persistence and logout`,
      async () => {
        await requireHealthy(baseURL, label);
        await resetServerState(baseURL);
        const browser = await chromium.launch({
          executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
        });

        try {
          const context = await browser.newContext();
          const page = await context.newPage();
          await page.goto(`${baseURL}/__health`);
          const email = `browser-${crypto.randomUUID()}@test.com`;
          const signup = await page.evaluate(
            async ({ email, path }) => {
              const response = await fetch(path + "/sign-up/email", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ email, password: "password123", name: "Browser Test" }),
              });
              return { status: response.status, body: await response.json() };
            },
            { email, path },
          );
          expect(signup.status).toBe(200);

          const user = z
            .object({ user: z.object({ id: z.string().min(1) }) })
            .parse(signup.body).user;
          const cookies = await context.cookies();
          const sessionCookie = cookies.find((cookie) => cookie.name === cookieName);
          expect(sessionCookie).toBeDefined();
          expect(sessionCookie?.httpOnly).toBe(true);
          expect(sessionCookie?.sameSite).toBe("Lax");
          expect(sessionCookie?.path).toBe(mode === "secure-custom" ? path : "/");
          expect(sessionCookie?.secure).toBe(mode !== "default");
          expect(sessionCookie?.expires).toBeGreaterThan(Date.now() / 1000);
          expect(await page.evaluate(() => document.cookie)).not.toContain("session_token");

          await page.reload();
          const session = z
            .object({ user: z.object({ id: z.string() }) })
            .parse(
              await page.evaluate(
                async (path) => (await fetch(path + "/get-session")).json(),
                path,
              ),
            );
          expect(session.user.id).toBe(user.id);

          const logout = await page.evaluate(
            async (path) =>
              (
                await fetch(path + "/sign-out", {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: "{}",
                })
              ).status,
            path,
          );
          expect(logout).toBe(200);
          expect((await context.cookies()).some((cookie) => cookie.name === cookieName)).toBe(
            false,
          );

          await page.reload();
          expect(
            await page.evaluate(async (path) => (await fetch(path + "/get-session")).json(), path),
          ).toBeNull();

          await context.close();
        } finally {
          await browser.close();
        }
      },
      30_000,
    );
  }
}
