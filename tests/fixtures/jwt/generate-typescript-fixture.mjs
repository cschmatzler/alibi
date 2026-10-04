// Run with the repository's pinned Bun after installing the frozen reference lockfile.
// This uses only Better Auth 1.7.7's published implementation and actual SQLite.
const runtime = new URL("../../compat/reference-server/node_modules/better-auth/dist/", import.meta.url);
const { betterAuth } = await import(new URL("index.mjs", runtime).href);
const { createAuthEndpoint } = await import(new URL("api/index.mjs", runtime).href);
const { getMigrations } = await import(new URL("db/get-migration.mjs", runtime).href);
const { jwt, createJwk, signJWT, verifyJWT } = await import(new URL("plugins/jwt/index.mjs", runtime).href);
import { Database } from "bun:sqlite";
const origin = "http://jwt-interoperability.fixture.test";
const secret = "jwt-interoperability-fixture-secret-at-least-32chars";
const payload = { sub: "cipher-import-owner", iat: 100, exp: 4102444800, iss: origin, aud: origin };
const probe = { id: "private-cipher-probe", endpoints: { cipherProbe: createAuthEndpoint.serverOnly({method:"POST"}, async ctx => {
 const key = await createJwk(ctx);
 const token = await signJWT(ctx, { payload, signingKeyId: key.id });
 const verified = await verifyJWT(token);
 if (JSON.stringify(verified) !== JSON.stringify(payload)) throw Error("upstream-produced signature must verify");
 return { referenceVersion: "better-auth@1.7.7", origin, secret, payload, key, token };
})}};
const options = { database:new Database(":memory:"), baseURL:origin, secret, plugins:[jwt(),probe], logger:{disabled:true} };
const auth = betterAuth(options);
await(await getMigrations(options)).runMigrations();
console.log(JSON.stringify(await auth.api.cipherProbe(),null,2));
