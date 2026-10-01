import { betterAuth, type BetterAuthOptions } from "better-auth";
import { bearer, multiSession } from "better-auth/plugins";
import { apiKey } from "@better-auth/api-key";
import { createAuthMiddleware } from "better-auth/api";

/** Genuine configured tokens let both runtimes compare complete signed headers. */
export function createBearerFixture(base: BetterAuthOptions) {
  let counter = 0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of ["bearer-default", "bearer-signed", "bearer-composition"]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(path, betterAuth({
      ...base, basePath: path,
      databaseHooks: { session: { create: { async before(session) {
        return { data: { ...session, token: `bearer${String(++counter).padStart(26, "0")}` } };
      } } } },
      plugins: [
        ...(name === "bearer-signed" ? [{ id: "application-exposure", hooks: { after: [{
          matcher: () => true,
          handler: createAuthMiddleware(async ctx => { ctx.setHeader("access-control-expose-headers", "X-First, X-First, X-Second"); }),
        }] } }] : []),
        bearer({ requireSignature: name === "bearer-signed" }),
        ...(name === "bearer-composition" ? [multiSession(), apiKey({ enableSessionForAPIKeys: true })] : [])],
    }));
  }
  return { profiles, reset() { counter = 0; } };
}
