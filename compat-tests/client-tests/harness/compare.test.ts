import { createHash } from "node:crypto";
import { expect, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { compareValues } from "../support/compare";
import { jsonShape, normalizeClientValue } from "../support/normalize";
import { RAW_DIFF_ALLOWLIST } from "../support/allowlist";

const context = { leftBaseURL: "http://localhost:3100", rightBaseURL: "http://localhost:3200", leftStartedAt: 0, rightStartedAt: 0 };

test("identity bijection preserves cross-object relationships and token rotation", () => {
  const a = { user: { id: "alice" }, session: { userId: "alice", token: "a" }, renewed: { token: "b" } };
  const b = { user: { id: "bob" }, session: { userId: "bob", token: "c" }, renewed: { token: "d" } };
  expect(compareValues(a, b, context)).toEqual([]);
  expect(compareValues(a, { ...b, session: { ...b.session, userId: "wrong" } }, context).length).toBeGreaterThan(0);
  expect(compareValues(a, { ...b, renewed: { token: "c" } }, context).length).toBeGreaterThan(0);
});

test("multi-team invitations preserve every ordered team identity", () => {
  const left = { teams: [{ id: "left-first" }, { id: "left-second" }], invitation: { teamId: "left-first,left-second" } };
  const right = { teams: [{ id: "right-first" }, { id: "right-second" }], invitation: { teamId: "right-first,right-second" } };
  expect(compareValues(left, right, context)).toEqual([]);
  for (const teamId of ["right-second,right-first", "right-first,unrelated", "right-first", "right-first,right-second,extra"]) {
    expect(compareValues(left, { ...right, invitation: { teamId } }, context).length).toBeGreaterThan(0);
  }
});

test("dynamic role selectors retain their persisted role identity and literal role names", () => {
  const left = { persisted: { id: "left-role", role: "auditor" }, url: "/organization/get-role?roleId=left-role" };
  const right = { persisted: { id: "right-role", role: "auditor" }, url: "/organization/get-role?roleId=right-role" };
  expect(compareValues(left, right, context)).toEqual([]);
  expect(compareValues(left, { ...right, url: "/organization/get-role?roleId=unrelated" }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...right, persisted: { ...right.persisted, role: "owner" } }, context).length).toBeGreaterThan(0);
});

test("issued API-key entropy retains stored start, configured prefix, row scope and rotation", () => {
  const issued = (id: string, key: string, referenceId: string) => ({ id, key, prefix: "test-", start: key.slice(0, 8), configId: "organization", referenceId, enabled: true, remaining: null });
  const left = issued("left-id", "test-LeftFirstRandom", "left-org"), right = issued("right-id", "test-RightFirstRandm", "right-org");
  const read = ({ key: _key, ...row }: ReturnType<typeof issued>) => row;
  const a = { issued: left, read: read(left), next: issued("left-next", "test-LeftOtherRandom", "left-org") };
  const b = { issued: right, read: read(right), next: issued("right-next", "test-RightOtherRandm", "right-org") };
  expect(compareValues(a, b, context)).toEqual([]);
  for (const changed of [
    { ...b, read: { ...b.read, start: "test-Bad" } },
    { ...b, read: { ...b.read, start: b.read.start.slice(0, -1) } },
    { ...b, issued: { ...right, prefix: "other-" } },
    { ...b, read: { ...b.read, configId: "default" } },
    { ...b, read: { ...b.read, referenceId: "unrelated-org" } },
    { ...b, read: { ...b.read, id: "unrelated-row" } },
    { ...b, issued: { ...right, key: `${right.key}extra` } },
    { ...b, next: { ...b.next, key: right.key, start: right.start } },
    { ...b, read: { ...b.read, enabled: false } },
    { ...b, read: { ...b.read, remaining: 1 } },
  ]) expect(compareValues(a, changed, context).length).toBeGreaterThan(0);
  const shape = { traces: [{ responseBodyShape: jsonShape(left) }] };
  expect(compareValues(shape, { traces: [{ responseBodyShape: jsonShape(right) }] }, context)).toEqual([]);
  expect(compareValues(shape, { traces: [{ responseBodyShape: jsonShape({ ...right, start: null }) }] }, context).length).toBeGreaterThan(0);
  expect(compareValues({ payload: { responseBodyShape: left } }, { payload: { responseBodyShape: right } }, context)).toEqual([]);
  expect(compareValues({ payload: { responseBodyShape: left } }, { payload: { responseBodyShape: { ...right, start: "test-Bad" } } }, context).length).toBeGreaterThan(0);
  expect(compareValues({ key: "literal" }, { key: "changed" }, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued: left, metadata: left }, { issued: right, metadata: left }, context)).toEqual([]);
  expect(compareValues({ issued: left, metadata: left }, { issued: right, metadata: right }, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued: left, metadata: { nested: [left] } }, { issued: right, metadata: { nested: [right] } }, context).length).toBeGreaterThan(0);
});

for (const [name, left, right] of [
  ["provider", { providerId: "github" }, { providerId: "google" }],
  ["config", { configId: "one" }, { configId: "two" }],
  ["empty token", { token: "abc" }, { token: "" }],
  ["invalid timestamp", { expiresAt: "2026-10-01T00:00:00Z" }, { expiresAt: "invalid" }],
  ["wrong lifetime", { expiresAt: "2026-10-01T00:00:00Z" }, { expiresAt: "2026-10-02T00:00:00Z" }],
  ["missing expiry", { refreshTokenExpiresAt: null }, {}],
  ["error cause", { cause: "one" }, { cause: "two" }],
  ["wrong callback host", { callbackURL: "https://a.example/ok" }, { callbackURL: "https://b.example/ok" }],
  ["wrong callback protocol", { callbackURL: "http://localhost:3100/ok" }, { callbackURL: "https://localhost:3200/ok" }],
  ["wrong callback path", { callbackURL: "/ok" }, { callbackURL: "/wrong" }],
  ["array length", [1], [1, 2]],
  ["later array item", [1, { ok: true }], [1, { ok: false }]],
  ["null vs object", { user: null }, { user: {} }],
] as const) {
  test(`comparison rejects ${name}`, () => expect(compareValues(left, right, context).length).toBeGreaterThan(0));
}

test("only configured server origins and opaque URL parameters are normalized", () => {
  expect(compareValues({ url: "http://localhost:3100/callback?state=abc&provider=github" }, { url: "http://localhost:3200/callback?state=xyz&provider=github" }, context)).toEqual([]);
  expect(compareValues({ url: "http://localhost:3100/callback?state=abc" }, { url: "http://elsewhere:3200/callback?state=xyz" }, context).length).toBeGreaterThan(0);
});

test("snapshots retain fields and array shapes include every item", () => {
  expect(normalizeClientValue({ token: "secret", cause: 1, refreshTokenExpiresAt: null })).toEqual({ token: "secret", cause: 1, refreshTokenExpiresAt: null });
  expect(jsonShape([{ ok: true }, { wrong: 1 }])).toEqual([{ ok: "boolean" }, { wrong: "number" }]);
});

test("API key response shapes stay literal while actual key relationships remain checked", () => {
  const issued = { key: "prefix-one", prefix: "prefix-", start: "prefix", configId: "default", enabled: true, remaining: null };
  const other = { ...issued, key: "prefix-two" };
  const leftShape = { traces: [{ responseBodyShape: jsonShape({ ...issued, prefix: null, start: null }) }] };
  const rightShape = { traces: [{ responseBodyShape: jsonShape({ ...other, prefix: null, start: null }) }] };
  expect(compareValues(leftShape, rightShape, context)).toEqual([]);
  expect(compareValues(leftShape, { traces: [{ responseBodyShape: jsonShape({ ...other, prefix: null, start: null, remaining: 1 }) }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(leftShape, { traces: [{ responseBodyShape: jsonShape({ ...other, prefix: null, start: null, configId: undefined }) }] }, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued, persisted: issued }, { issued: other, persisted: other }, context)).toEqual([]);
  expect(compareValues({ payload: { responseBodyShape: issued } }, { payload: { responseBodyShape: other } }, context)).toEqual([]);
  expect(compareValues({ payload: { responseBodyShape: issued } }, { payload: { responseBodyShape: { ...other, prefix: "unrelated" } } }, context).length).toBeGreaterThan(0);
  for (const wrong of [
    { ...other, key: "wrong--two" },
    { ...other, start: "unrelated" },
    { ...other, key: "prefix-too-long" },
  ]) expect(compareValues(issued, wrong, context).length).toBeGreaterThan(0);
  expect(compareValues({ issued, persisted: issued }, { issued: other, persisted: { ...other, key: "prefix-new" } }, context).length).toBeGreaterThan(0);
});

test("no exception can swallow an entire cookie or its security attributes", () => {
  for (const allowance of RAW_DIFF_ALLOWLIST) {
    for (const field of ["", ".httpOnly", ".secure", ".path", ".domain", ".sameSite"]) {
      expect(allowance.path.test(`0.responseCookies.better-auth.session_token${field}`)).toBe(false);
    }
    expect(allowance.path.source.endsWith("$")).toBe(true);
  }
});

test("reset-password URL entropy retains token relationships", () => {
  const left = { first: { url: "/reset-password/one" }, second: { url: "/reset-password/one" } };
  expect(compareValues(left, { first: { url: "/reset-password/two" }, second: { url: "/reset-password/two" } }, context)).toEqual([]);
  expect(compareValues(left, { first: { url: "/reset-password/two" }, second: { url: "/reset-password/three" } }, context).length).toBeGreaterThan(0);
});

test("one-time-token storage preserves exact derivation session ownership and response header relationships", () => {
  const timestamp = "2026-09-30T00:00:00.000Z";
  const stored = (token: string, hashed: boolean) => `one-time-token:${hashed ? createHash("sha256").update(token).digest("base64url") : token}`;
  for (const hashed of [false, true]) {
    const run = (side: string) => ({
      issued: { token: `${side}-ott` },
      owner: { id: `${side}-owner`, token: `${side}-session`, expiresAt: timestamp },
      other: { id: `${side}-other`, token: `${side}-other-session`, expiresAt: timestamp },
      persisted: { id: `${side}-proof`, identifier: stored(`${side}-ott`, hashed), value: `${side}-session`, expiresAt: timestamp, createdAt: timestamp, updatedAt: timestamp },
      traces: [{ responseHeaders: { "set-ott": `${side}-ott` } }],
      url: `/__test/verification-state?identifier=${encodeURIComponent(stored(`${side}-ott`, hashed))}`,
    });
    const left = run("left"), right = run("right");
    expect(compareValues(left, right, context)).toEqual([]);
    for (const incorrect of [
      { ...right, persisted: { ...right.persisted, identifier: stored("unrelated", hashed) } },
      { ...right, persisted: { ...right.persisted, identifier: stored("right-ott", !hashed) } },
      { ...right, persisted: { ...right.persisted, identifier: "wrong-prefix:right-ott" } },
      { ...right, persisted: { ...right.persisted, value: "right-other-session" } },
      { ...right, persisted: { ...right.persisted, value: "unobserved-session" } },
      { ...right, persisted: { ...right.persisted, value: null } },
      { ...right, traces: [{ responseHeaders: { "set-ott": "rotated-ott" } }] },
      { ...right, url: `/__test/verification-state?identifier=${encodeURIComponent(stored("unrelated", hashed))}` },
      { ...right, persisted: { ...right.persisted, expiresAt: "2026-09-30T00:03:00.000Z" } },
    ]) expect(compareValues(left, incorrect, context).length).toBeGreaterThan(0);
  }
  expect(compareValues({ identifier: "literal", value: "literal" }, { identifier: "literal", value: "changed" }, context).length).toBeGreaterThan(0);
});

test("JWTs and JWKS retain full claims key relationships rotation and key sizes",()=>{
  const start=Date.parse("2026-09-30T00:00:00.000Z");
  const clocks={...context,leftStartedAt:start,rightStartedAt:start+10000};
  const encode=(header:unknown,payload:unknown,signature="signature")=>[Buffer.from(JSON.stringify(header)).toString("base64url"),Buffer.from(JSON.stringify(payload)).toString("base64url"),Buffer.from(signature).toString("base64url")].join(".");
  const leftPayload={sub:"alice",iat:start/1000,exp:start/1000+900,iss:context.leftBaseURL,aud:context.leftBaseURL,name:"Alice"};
  const rightPayload={...leftPayload,sub:"bob",iat:start/1000+10,exp:start/1000+910,iss:context.rightBaseURL,aud:context.rightBaseURL};
  const leftHeader={alg:"EdDSA",kid:"left-key"},rightHeader={alg:"EdDSA",kid:"right-key"};
  const leftKey={kty:"OKP",alg:"EdDSA",crv:"Ed25519",kid:"left-key",x:Buffer.alloc(32,1).toString("base64url")};
  const rightKey={...leftKey,kid:"right-key",x:Buffer.alloc(32,2).toString("base64url")};
  const left={user:{id:"alice"},jwks:{keys:[leftKey]},token:encode(leftHeader,leftPayload),checked:leftPayload};
  const right={user:{id:"bob"},jwks:{keys:[rightKey]},token:encode(rightHeader,rightPayload),checked:rightPayload};
  expect(compareValues(left,right,clocks)).toEqual([]);
  for(const incorrect of [
    {...right,token:encode({...rightHeader,kid:"unrelated"},rightPayload)},
    {...right,token:encode(rightHeader,{...rightPayload,sub:"wrong-user"})},
    {...right,token:encode(rightHeader,{...rightPayload,exp:rightPayload.exp+1})},
    {...right,token:encode(rightHeader,{...rightPayload,iss:"untrusted"})},
    {...right,token:encode(rightHeader,{...rightPayload,name:"Bob"})},
    {...right,token:encode({...rightHeader,typ:"JWT"},rightPayload)},
    {...right,token:encode(rightHeader,rightPayload,"short")},
    {...right,jwks:{keys:[{...rightKey,x:Buffer.alloc(31,2).toString("base64url")}]}},
    {...right,jwks:{keys:[]}},
  ]) expect(compareValues(left,incorrect,clocks).length).toBeGreaterThan(0);
  expect(compareValues({...left,again:left.token},{...right,again:encode(rightHeader,rightPayload,"different")},clocks).length).toBeGreaterThan(0);
  const literalLeft=encode(leftHeader,{sub:"service-one",exp:4102444800,iss:"custom",aud:["one","two"]});
  const literalRight=encode(rightHeader,{sub:"service-two",exp:4102444800,iss:"custom",aud:["one","two"]});
  expect(compareValues({token:literalLeft},{token:literalRight},clocks).length).toBeGreaterThan(0);
  const fixed={sub:"service",iat:100,exp:4102444800,iss:"custom",aud:"custom"};
  expect(compareValues({token:encode(leftHeader,fixed)},{token:encode(rightHeader,{...fixed,iat:110,exp:4102444810})},clocks).length).toBeGreaterThan(0);
  expect(compareValues({kid:"literal"},{kid:"changed"},clocks).length).toBeGreaterThan(0);
});

test("accepted compact JWT encodings retain decoded claims key sizes and token relationships", () => {
  const encode = (header: unknown, payload: unknown, signature: Buffer) => [Buffer.from(JSON.stringify(header)).toString("base64url"), Buffer.from(JSON.stringify(payload)).toString("base64url"), signature.toString("base64url")].join(".");
  const claims = { sub: "service", iat: 100, exp: 4102444800, iss: "literal", aud: "literal", permission: "read" };
  const leftHeader = { alg: "EdDSA", kid: "left-key" }, rightHeader = { alg: "EdDSA", kid: "right-key" };
  const pad = (value: string) => value + "=".repeat((4 - value.length % 4) % 4);
  const encodeVariants = (token: string): string[] => {
    const parts = token.split(".");
    if (!parts[0] || !parts[1] || !parts[2]) throw new Error("three JWT segments are required");
    const [header, payload, signature] = parts;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(signature.at(-1) ?? "");
    return [
      `${header}.${payload}.${pad(signature)}`,
      `${pad(header)}.${payload}.${signature}`,
      `${header}.${pad(payload)}.${signature}`,
      `${header}.${payload}.${signature.slice(0, -1)}${alphabet[lastIndex + 1]}`,
      `${header}.${payload}.${signature.slice(0, 20)} \t\n\r\f${signature.slice(20)}== `,
      `${header}.${payload.slice(0, 3)} \t\n\r\f${payload.slice(3)}.${signature}`,
    ];
  };
  const leftToken = encode(leftHeader, claims, Buffer.alloc(64, 1)), rightToken = encode(rightHeader, claims, Buffer.alloc(64, 2));
  const left = { key: { kid: "left-key", alg: "EdDSA", kty: "OKP", x: Buffer.alloc(32, 1).toString("base64url") }, token: leftToken };
  const right = { key: { ...left.key, kid: "right-key", x: Buffer.alloc(32, 2).toString("base64url") }, token: rightToken };
  for (let index = 0; index < encodeVariants(leftToken).length; index++) {
    const a = { ...left, token: encodeVariants(leftToken)[index] }, b = { ...right, token: encodeVariants(rightToken)[index] };
    expect(compareValues(a, b, context)).toEqual([]);
    for (const wrongToken of [
      encode({ ...rightHeader, kid: "unrelated" }, claims, Buffer.alloc(64, 2)),
      encode({ ...rightHeader, typ: "JWT" }, claims, Buffer.alloc(64, 2)),
      encode(rightHeader, { ...claims, permission: "write" }, Buffer.alloc(64, 2)),
      encode(rightHeader, { ...claims, exp: claims.exp + 1 }, Buffer.alloc(64, 2)),
    ]) {
      const wrong = encodeVariants(wrongToken)[index];
      expect(compareValues(a, { ...b, token: wrong }, context).length).toBeGreaterThan(0);
    }
    const changedSignature = encodeVariants(encode(rightHeader, claims, Buffer.alloc(64, 3)))[index];
    expect(compareValues({ ...a, again: a.token }, { ...b, again: changedSignature }, context).length).toBeGreaterThan(0);
    const shorter = encode(rightHeader, claims, Buffer.alloc(32, 2));
    expect(compareValues(a, { ...b, token: shorter + "=" }, context).length).toBeGreaterThan(0);
  }
});

test("nested OKP and EC shaped application claims stay literal alongside real public JWKS", () => {
  const leftPair = generateKeyPairSync("ed25519"), rightPair = generateKeyPairSync("ed25519");
  const leftKey = { ...leftPair.publicKey.export({ format: "jwk" }), alg: "EdDSA", kid: "left-key" };
  const rightKey = { ...rightPair.publicKey.export({ format: "jwk" }), alg: "EdDSA", kid: "right-key" };
  const encode = (pair: typeof leftPair, kid: string, metadata: unknown) => {
    const input = [Buffer.from(JSON.stringify({ alg: "EdDSA", kid })).toString("base64url"), Buffer.from(JSON.stringify({ sub: "service", iat: 100, exp: 4102444800, iss: "fixed", aud: "fixed", metadata })).toString("base64url")].join(".");
    return `${input}.${sign(null, Buffer.from(input), pair.privateKey).toString("base64url")}`;
  };
  for (const metadata of [
    { kty: "OKP", crv: "Ed25519", x: Buffer.alloc(32, 9).toString("base64url") },
    { kty: "EC", crv: "P-256", x: Buffer.alloc(32, 9).toString("base64url"), y: Buffer.alloc(32, 10).toString("base64url") },
    { alg: "EdDSA", kid: "application-key-label" },
  ]) {
    const left = { jwks: { keys: [leftKey] }, token: encode(leftPair, leftKey.kid, { nested: [metadata] }) };
    const right = { jwks: { keys: [rightKey] }, token: encode(rightPair, rightKey.kid, { nested: [metadata] }) };
    expect(compareValues(left, right, context)).toEqual([]);
    const wrong = "x" in metadata ? { ...metadata, x: Buffer.alloc(32, 11).toString("base64url") } : { ...metadata, kid: "wrong-application-label" };
    expect(compareValues(left, { ...right, token: encode(rightPair, rightKey.kid, { nested: [wrong] }) }, context).length).toBeGreaterThan(0);
    expect(compareValues(left, { ...right, token: encode(rightPair, "unrelated-key", { nested: [metadata] }) }, context).length).toBeGreaterThan(0);
  }
});

test("scoped trace timestamp shapes remain literal while payloads cookies and arrays stay strict", () => {
  const trace = {
    actor: "owner", method: "GET", path: "/api/auth/get-session", responseStatus: 200,
    requestBodyShape: null, responseHeaders: { "content-type": "application/json" },
    responseCookies: { "session;/;/": { httpOnly: true, secure: false, maxAge: 604800, expiresAt: null } },
    responseBodyShape: { user: { id: "string", createdAt: "string", updatedAt: "string", banExpires: "null" }, items: [{ id: "string" }, { id: "string" }] },
  };
  const left = { observation: { createdAt: "1970-01-01T00:00:00.000Z" }, traces: [trace] };
  expect(compareValues(left, structuredClone(left), context)).toEqual([]);
  expect(compareValues(left, { ...left, observation: { createdAt: "string" } }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...left, traces: [{ ...trace, responseBodyShape: { ...trace.responseBodyShape, user: { ...trace.responseBodyShape.user, createdAt: "number" } } }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...left, traces: [{ ...trace, responseBodyShape: { ...trace.responseBodyShape, user: { ...trace.responseBodyShape.user, extra: "string" } } }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...left, traces: [{ ...trace, responseBodyShape: { ...trace.responseBodyShape, items: [{ id: "string" }] } }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...left, traces: [{ ...trace, responseStatus: 201 }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...left, traces: [{ ...trace, responseCookies: { "session;/;/": { ...trace.responseCookies["session;/;/"], httpOnly: false } } }] }, context).length).toBeGreaterThan(0);
});

test("one comparison graph links observed issuance and transport owner token references", () => {
  const left = { observation: { id: "left-owner", token: "left-token" }, traces: [{ responseHeaders: { location: "/reset-password/left-token?userId=left-owner" } }] };
  const right = { observation: { id: "right-owner", token: "right-token" }, traces: [{ responseHeaders: { location: "/reset-password/right-token?userId=right-owner" } }] };
  expect(compareValues(left, right, context)).toEqual([]);
  expect(compareValues(left, { ...right, traces: [{ responseHeaders: { location: "/reset-password/other-token?userId=right-owner" } }] }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...right, traces: [{ responseHeaders: { location: "/reset-password/right-token?userId=other-owner" } }] }, context).length).toBeGreaterThan(0);
});

test("persisted device-code aliases preserve issued-code relationships and rotation", () => {
  for (const field of ["deviceCode", "userCode"]) {
    const leftClaim = { exp: 4102444800, iss: "https://issuer.fixture", aud: "https://audience.fixture", custom: { [field]: "literal-left" } };
    const rightClaim = { ...leftClaim, custom: { [field]: "literal-right" } };
    expect(compareValues({ payload: leftClaim }, { payload: rightClaim }, context).some(difference => difference.path === `payload.custom.${field}`)).toBe(true);
  }

  const left = { issued: { device_code: "device-a", user_code: "user-a" }, persisted: { deviceCode: "device-a", userCode: "user-a" }, rotated: { device_code: "device-b" } };
  const right = { issued: { device_code: "device-c", user_code: "user-c" }, persisted: { deviceCode: "device-c", userCode: "user-c" }, rotated: { device_code: "device-d" } };
  expect(compareValues(left, right, context)).toEqual([]);
  expect(compareValues(left, { ...right, persisted: { ...right.persisted, deviceCode: "wrong" } }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...right, persisted: { ...right.persisted, userCode: "wrong" } }, context).length).toBeGreaterThan(0);
  expect(compareValues(left, { ...right, rotated: { device_code: "device-c" } }, context).length).toBeGreaterThan(0);
});

test("computed device session TTL permits only the proved floor boundary",()=>{
  const start=Date.parse("2026-09-30T00:00:00.000Z");
  const clocks={...context,leftStartedAt:start,rightStartedAt:start+10000,leftFinishedAt:start+1300,rightFinishedAt:start+11300};
  const left={persisted:{id:"left-id",userId:"left-owner",token:"left",expiresAt:new Date(start+604800000).toISOString()},issued:{access_token:"left",token_type:"Bearer",expires_in:604800}};
  const right={persisted:{id:"right-id",userId:"right-owner",token:"right",expiresAt:new Date(start+10000+604800000).toISOString()},issued:{access_token:"right",token_type:"Bearer",expires_in:604799}};
  expect(compareValues(left,right,clocks)).toEqual([]);
  for(const incorrect of [
    {...right,issued:{...right.issued,expires_in:604798}},
    {...right,issued:{...right.issued,access_token:"unrelated"}},
    {...right,persisted:{...right.persisted,expiresAt:new Date(start+10000+604700000).toISOString()}},
    {...right,issued:{...right.issued,expires_in:604801}},
  ]) expect(compareValues(left,incorrect,clocks).length).toBeGreaterThan(0);
  expect(compareValues({expires_in:10},{expires_in:9},clocks).length).toBeGreaterThan(0);
  expect(compareValues(left,right,context).length).toBeGreaterThan(0);
  for (const field of ["metadata", "additionalFields"]) {
    const differences = compareValues({ ...left, [field]: left.issued }, { ...right, [field]: right.issued }, clocks);
    expect(differences.some(difference => difference.path === `${field}.expires_in`)).toBe(true);
  }
  const shapeDiffs = compareValues({ ...left, traces: [{ responseBodyShape: left.issued }] }, { ...right, traces: [{ responseBodyShape: right.issued }] }, clocks);
  expect(shapeDiffs.some(difference => difference.path === "traces.0.responseBodyShape.expires_in")).toBe(true);
  const unproved = compareValues({ metadata: left.persisted, issued: left.issued }, { metadata: right.persisted, issued: right.issued }, clocks);
  expect(unproved.some(difference => difference.path === "issued.expires_in")).toBe(true);

});
