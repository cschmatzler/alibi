import { expect, test } from "bun:test";
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
