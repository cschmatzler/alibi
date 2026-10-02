import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { jwtClient } from "better-auth/client/plugins";
import { decodeProtectedHeader, importJWK, type JWK, type JWTPayload, jwtVerify } from "jose";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import type { ScenarioContext } from "../../support/scenario";

export function jwtActor(
  ctx: ScenarioContext,
  name = "primary",
  profile: FixtureProfile = "jwt-default",
  jwksPath = "/jwks",
) {
  return createAuthClient({
    baseURL: ctx.baseURL,
    plugins: [jwtClient({ jwks: { jwksPath } })],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

export async function verifyWithOfficialJose(
  token: string,
  keys: JWK[],
  issuer: string,
  audience: string | string[],
): Promise<{ header: ReturnType<typeof decodeProtectedHeader>; payload: JWTPayload }> {
  const header = decodeProtectedHeader(token);
  const key = keys.find((key) => key.kid === header.kid);
  expect(key).toBeDefined();
  if (!key || !header.alg) throw new Error("JWT must identify its public signing key");
  expect(key.alg).toBe(header.alg);
  expect(key.d).toBeUndefined();
  const verified = await jwtVerify(token, await importJWK(key, header.alg), {
    issuer,
    audience,
    algorithms: [header.alg],
  });
  expect(z.record(z.string(), z.unknown()).parse(verified.protectedHeader)).toEqual(
    z.record(z.string(), z.unknown()).parse(header),
  );
  return { header, payload: verified.payload };
}
