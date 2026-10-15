import { expect } from "bun:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
const weakKey = generateKeyPairSync("rsa", { modulusLength: 1024 });

import { SignJWT, importJWK } from "jose";

import { compatScenario } from "../../../support/scenario";
const signed = new Map<string, string>();
const hash = (value: string) => createHash("sha256").update(value).digest("base64url");
const url = "https://api.fixture.test/resource";
compatScenario(
  "DPoP verification binds genuine signatures, HTTP context, token hash and one-time receipts",
  async (ctx) => {
    const actor = ctx.actor();
    const control = async (body: object) => {
      const response = await actor.fetch(
        `${ctx.baseURL}/__test/server-api/oauth-provider-clients`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action: "dpop-proof", body }),
        },
      );
      expect(response.status).toBe(200);
      return (await response.json()) as any;
    };
    const keys = (
      await Bun.file(
        new URL("../../../../../fixtures/oauth/client-assertion-keys.json", import.meta.url),
      ).json()
    ).keys;
    const ed = keys.find((key: any) => key.family === "Ed25519");
    const publicKey = ed.publicJwk;
    const jkt = hash(JSON.stringify({ crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x }));
    const options = { method: "POST", url: `${url}?ignored=1`, nowSeconds: 2000000000 };
    const proof = async (
      label: string,
      payload: object = {},
      header: object = {},
      family = "Ed25519",
      alg = "EdDSA",
    ) => {
      const key = keys.find((key: any) => key.family === family);
      const claims = {
        htm: "post",
        htu: `${url}?different=2`,
        jti: label,
        iat: 2000000000,
        ...payload,
      };
      const protectedHeader = { typ: "dpop+jwt", alg, jwk: key.publicJwk, ...header };
      const id = JSON.stringify({ claims, protectedHeader });
      // Send identical externally signed bytes to the independent servers.
      if (!signed.has(id)) {
        signed.set(
          id,
          await new SignJWT(claims)
            .setProtectedHeader(protectedHeader)
            .sign(await importJWK({ ...key.privateJwk, alg }, alg)),
        );
      }
      return signed.get(id)!;
    };
    const results = [];
    for (const [family, alg] of [
      ["Ed25519", "EdDSA"],
      ["P-256", "ES256"],
      ["P-521", "ES512"],
      ["RSA", "RS256"],
      ["RSA", "PS256"],
      ["P-384", "ES384"],
      ["RSA", "RS384"],
      ["RSA", "RS512"],
      ["RSA", "PS384"],
      ["RSA", "PS512"],
      ["Ed25519", "Ed25519"],
    ] as const) {
      const token = await proof(`crypto-${alg}`, {}, {}, family, alg);
      const result = await control({
        operation: "verify",
        ...options,
        proofJwt: token,
        ...(["ES384", "RS384", "RS512", "PS384", "PS512", "Ed25519"].includes(alg)
          ? { signingAlgorithms: [alg] }
          : {}),
      });
      expect(result.error).toBeUndefined();
      expect(result.htm).toBe("post");
      expect(result.htu).toBe(url);
      expect(result.iat).toBe(2000000000);
      expect(Date.parse(result.expiresAt)).toBe(2000000300000);
      results.push({ alg, htu: result.htu });
    }
    const pq = (await Bun.file(
      new URL("../../../../../fixtures/oauth/dpop-pq-proofs.json", import.meta.url),
    ).json()) as { algorithm: string; proofJwt: string; jkt: string; privateSeed: string }[];
    for (const vector of pq) {
      const configured = {
        ...options,
        proofJwt: vector.proofJwt,
        signingAlgorithms: [vector.algorithm],
      };
      const verified = await control(configured);
      expect(verified.jkt).toBe(vector.jkt);
      expect(verified.jti).toBe("pq-" + vector.algorithm);
      expect(await control({ ...options, proofJwt: vector.proofJwt })).toEqual({
        error: "invalid_dpop_proof",
        message: "DPoP proof uses an unsupported JWS algorithm",
      });
      const parts = vector.proofJwt.split(".");
      const signature = Buffer.from(parts[2]!, "base64url");
      signature[0] = signature[0]! ^ 1;
      expect(
        await control({
          ...configured,
          proofJwt: parts.slice(0, 2).join(".") + "." + signature.toString("base64url"),
        }),
      ).toEqual({ error: "invalid_dpop_proof", message: "signature verification failed" });
      const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
      const arrayHeader = { ...header, jwk: { ...header.jwk, pub: [header.jwk.pub] } };
      const coercionId = "pq-coercion-" + vector.algorithm;
      if (!signed.has(coercionId)) {
        const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
        signed.set(
          coercionId,
          await new SignJWT(claims)
            .setProtectedHeader(arrayHeader)
            .sign(await importJWK({ ...header.jwk, priv: vector.privateSeed }, vector.algorithm)),
        );
      }
      // WebCrypto coerces the public-key bytes, but RFC thumbprints still require a string.
      expect(await control({ ...configured, proofJwt: signed.get(coercionId)! })).toEqual({
        ordinary_error: true,
      });
      for (const [extra, message] of [
        [{ alg: "other" }, "JWK alg and alg option value mismatch"],
        [{ pub: "AA" }, "Invalid keyData"],
        [{ pub: [header.jwk.pub] }, "signature verification failed"],
        [{ priv: Buffer.alloc(32, 7).toString("base64url") }, "Invalid keyData"],
        [{ priv: "extra" }, "Invalid keyData"],
        [{ priv: null }, `Unsupported key usage for a ${vector.algorithm} key`],
        [
          { priv: vector.privateSeed },
          `CryptoKey instances must be of type "public" for the ${vector.algorithm} algorithm`,
        ],
        [{ key_ops: ["sign"] }, `Unsupported key usage for a ${vector.algorithm} key`],
        [
          { key_ops: [] },
          "CryptoKey does not support this operation, its usages must include verify.",
        ],
      ] as const) {
        const malformed =
          Buffer.from(JSON.stringify({ ...header, jwk: { ...header.jwk, ...extra } })).toString(
            "base64url",
          ) + ".e30.sig";
        expect(await control({ ...configured, proofJwt: malformed })).toEqual({
          error: "invalid_dpop_proof",
          message,
        });
      }
    }
    const accepted = await control({
      operation: "verify",
      ...options,
      proofJwt: await proof("thumbprint"),
    });
    expect(accepted.jkt).toBe(jkt);
    expect(accepted.replayKey).toBe(hash(`${jkt}\nPOST\n${url}\nthumbprint`));
    const cases: [string, object, object, object, string][] = [
      ["typ", {}, { typ: "JWT" }, {}, 'DPoP proof typ must be "dpop+jwt"'],
      ["method", { htm: "GET" }, {}, {}, "DPoP proof htm does not match the request method"],
      [
        "url",
        { htu: "https://api.fixture.test/other" },
        {},
        {},
        "DPoP proof htu does not match the request URL",
      ],
      [
        "fragment",
        { htu: `${url}#fragment` },
        {},
        {},
        "DPoP proof htu must not contain a fragment",
      ],
      ["old", { iat: 1999999699 }, {}, {}, "DPoP proof iat is outside the accepted window"],
      ["future", { iat: 2000000006 }, {}, {}, "DPoP proof iat is outside the accepted window"],
      ["claims", { jti: "" }, {}, {}, "DPoP proof must include htm, htu, jti, and iat claims"],
      ["long", { jti: "a".repeat(513) }, {}, {}, "DPoP proof jti is too large"],
      [
        "private",
        {},
        { jwk: { ...publicKey, d: null } },
        {},
        "DPoP proof jwk must not contain private key material",
      ],
      [
        "symmetric",
        {},
        { jwk: { kty: "oct", k: "secret" } },
        {},
        "DPoP proof jwk must be asymmetric",
      ],
      ["ath-missing", {}, {}, { requireAth: true }, "DPoP proof must include an ath claim"],
      [
        "ath-wrong",
        { ath: hash("other") },
        {},
        { accessToken: "access" },
        "DPoP proof ath does not match the access token",
      ],
      ["key", {}, {}, { expectedJkt: "other" }, "DPoP proof key does not match the bound token"],
      [
        "allowlist",
        {},
        {},
        { signingAlgorithms: ["ES256"] },
        "DPoP proof uses an unsupported JWS algorithm",
      ],
    ];
    for (const [name, payload, header, extra, message] of cases) {
      const result = await control({
        operation: "verify",
        ...options,
        ...extra,
        proofJwt: await proof(name, payload, header),
      });
      expect(result).toEqual({ error: "invalid_dpop_proof", message });
      results.push({ name, error: result.error });
    }
    const original = await proof("tamper");
    const parts = original.split(".");
    parts[2] = (parts[2]![0] === "A" ? "B" : "A") + parts[2]!.slice(1);
    expect(await control({ operation: "verify", ...options, proofJwt: parts.join(".") })).toEqual({
      error: "invalid_dpop_proof",
      message: "signature verification failed",
    });
    const token = await proof("token-hash", { ath: hash("access") });
    expect(
      (
        await control({
          operation: "verify",
          ...options,
          proofJwt: token,
          accessToken: "access",
          requireAth: true,
          expectedJkt: jkt,
        })
      ).jkt,
    ).toBe(jkt);
    // UTF-16 length, not UTF-8 bytes, controls jti admission.
    expect(
      (
        await control({
          operation: "verify",
          ...options,
          proofJwt: await proof("unicode", { jti: "😀".repeat(256) }),
        })
      ).error,
    ).toBeUndefined();
    for (const replay of ["memory", "database", "wrapped"]) {
      const jwt = await proof(`replay-${replay}`);
      const first = await control({ operation: "verify", ...options, proofJwt: jwt, replay });
      expect(first.jkt).toBe(jkt);
      if (replay === "wrapped") {
        expect(first.reservation).toEqual({
          identifier: `dpop-proof:${first.replayKey}`,
          value: first.replayKey,
          expiresAt: first.expiresAt,
        });
      }

      const second = await control({ operation: "verify", ...options, proofJwt: jwt, replay });
      expect(second).toEqual({
        error: "invalid_dpop_proof",
        message: "DPoP proof jti has already been used",
      });
      if (replay !== "memory") {
        const stored = await control({ operation: "row", key: first.replayKey });
        expect(stored.value).toBe(first.replayKey);
        expect(Date.parse(stored.expiresAt)).toBe(2000000300000);
      }
    }
    // A future manual clock does not override JOSE's real-clock exp validation.
    expect(
      await control({
        operation: "verify",
        ...options,
        proofJwt: await proof("expired", { exp: 1 }),
      }),
    ).toEqual({ error: "invalid_dpop_proof", message: '"exp" claim timestamp check failed' });
    // Header alg type errors are ordinary reference exceptions, not protocol proof errors.
    const invalidHeader =
      Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: 1, jwk: publicKey })).toString(
        "base64url",
      ) + ".e30.sig";
    expect(await control({ operation: "verify", ...options, proofJwt: invalidHeader })).toEqual({
      ordinary_error: true,
    });
    for (const [header, extra, message] of [
      [
        { typ: "dpop+jwt", alg: "FOO", jwk: publicKey },
        { signingAlgorithms: ["FOO"] },
        'Invalid or unsupported JWK "alg" (Algorithm) Parameter value',
      ],
      [
        { typ: "dpop+jwt", alg: "EdDSA", jwk: publicKey, crit: null },
        {},
        '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
      ],
      [
        { typ: "dpop+jwt", alg: "EdDSA", jwk: publicKey, crit: ["foo"], foo: true },
        {},
        'Extension Header Parameter "foo" is not recognized',
      ],
    ] as const) {
      const malformed = Buffer.from(JSON.stringify(header)).toString("base64url") + ".e30.sig";
      expect(
        await control({ operation: "verify", ...options, ...extra, proofJwt: malformed }),
      ).toEqual({ error: "invalid_dpop_proof", message });
    }
    for (const [extra, message] of [
      [
        { key_ops: [] },
        "CryptoKey does not support this operation, its usages must include verify.",
      ],
      [{ key_ops: ["sign"] }, "Unsupported key usage for an Ed25519 key"],
      [
        { key_ops: ["verify", "verify"] },
        '"key_ops" (Key Operations) Parameter must be an array of unique strings',
      ],
      [
        { key_ops: ["verify", 1] },
        '"key_ops" (Key Operations) Parameter must be an array of unique strings',
      ],
      [{ ext: 0 }, '"ext" (Extractable) Parameter must be a boolean'],
      [{ priv: "extra" }, "Unsupported key usage for an Ed25519 key"],
    ] as const) {
      expect(
        await control({
          ...options,
          proofJwt: await proof(
            "metadata-" + JSON.stringify(extra),
            {},
            { jwk: { ...publicKey, ...extra } },
          ),
        }),
      ).toEqual({ error: "invalid_dpop_proof", message });
    }
    for (const [family, alg] of [
      ["Ed25519", "EdDSA"],
      ["P-384", "ES384"],
    ] as const) {
      const key = keys.find((k: any) => k.family === family)!.publicJwk;
      for (const extra of [
        { use: "enc", alg: "FOO" },
        { ext: false },
        { priv: "extra", key_ops: ["verify"] },
      ]) {
        const jwk = { ...key, ...extra };
        const verified = await control({
          ...options,
          signingAlgorithms: [alg],
          proofJwt: await proof(
            "metadata-accepted-" + family + JSON.stringify(extra),
            {},
            { jwk },
            family,
            alg,
          ),
        });
        expect(verified.jwk).toEqual(jwk);
        expect(verified.jkt).toBe(
          hash(JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y })),
        );
      }
    }
    const weakInput =
      Buffer.from(
        JSON.stringify({
          typ: "dpop+jwt",
          alg: "RS256",
          jwk: weakKey.publicKey.export({ format: "jwk" }),
        }),
      ).toString("base64url") +
      "." +
      Buffer.from(
        JSON.stringify({ htm: "POST", htu: url, jti: "weak-rsa", iat: 2000000000 }),
      ).toString("base64url");
    const weakProof =
      weakInput +
      "." +
      sign("RSA-SHA256", Buffer.from(weakInput), weakKey.privateKey).toString("base64url");
    expect(await control({ ...options, proofJwt: weakProof })).toEqual({
      error: "invalid_dpop_proof",
      message: "RS256 requires key modulusLength to be 2048 bits or larger",
    });
    const bindingNow = Math.floor(Date.now() / 1000);
    const bindingProof = await proof("binding", {
      htm: "GET",
      iat: bindingNow,
      ath: hash("access"),
    });
    const bind = (payload: object, scheme: string, proofJwt?: string) =>
      control({
        operation: "binding",
        payload,
        authorization: { scheme, token: "access" },
        method: "GET",
        url,
        proofJwt,
        replay: "memory",
      });
    expect(await bind({}, "Bearer", bindingProof)).toEqual({ accepted: true });
    expect(await bind({}, "DPoP")).toEqual({
      error: "invalid_token",
      message: "DPoP authorization requires a DPoP-bound access token",
    });
    expect(await bind({ cnf: { jkt } }, "Bearer")).toEqual({
      error: "invalid_token",
      message: "DPoP-bound access token requires the DPoP authorization scheme",
    });
    expect(await bind({ cnf: { jkt } }, "DPoP")).toEqual({
      error: "invalid_dpop_proof",
      message: "DPoP proof header is required",
    });
    expect(await bind({ cnf: { jkt } }, "DPoP", bindingProof)).toEqual({ accepted: true });
    expect(await bind({ cnf: { jkt } }, "DPoP", bindingProof)).toEqual({
      error: "invalid_dpop_proof",
      message: "DPoP proof jti has already been used",
    });
    for (const [authorization, scheme, token] of [
      [" bEaReR  access ", "Bearer", "access"],
      ["DPoP\taccess", "DPoP", "access"],
      ["Basic access", "Unknown", "Basic access"],
      ["Bearer", "Unknown", "Bearer"],
      ["   ", null, "   "],
    ] as const) {
      const utility = await control({
        operation: "utilities",
        authorization,
        token: authorization,
        confirmation: { jkt: "" },
        url: "https://API.FIXTURE.TEST:443/resource?ignored=1",
        accessToken: "access",
        jwk: publicKey,
      });
      expect(utility.authorization).toEqual(scheme ? { scheme, token } : null);
      expect(utility.stripped).toBe(token);
      expect(utility.confirmation).toBeNull();
      expect(utility.normalized).toBe(url);
      expect(utility.ath).toBe(hash("access"));
      expect(utility.jkt).toBe(jkt);
    }
    for (const [payload, expected] of [
      [{ cnf: { jkt: "bound" } }, { jkt: "bound" }],
      [{ cnf: { "x5t#S256": "certificate" } }, { jkt: null }],
      [{ cnf: [{ jkt: "bound" }] }, { jkt: null }],
      [null, { ordinary_error: true }],
    ] as const) {
      expect(await control({ operation: "payload-jkt", payload })).toEqual(expected);
    }
    return ctx.snapshot({ results, thumbprint: jkt });
  },
);
