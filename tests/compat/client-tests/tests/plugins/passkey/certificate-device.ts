import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";

const ca = new URL("../../../../fixtures/passkey-attestation/ca.pem", import.meta.url);
const caKey = new URL("../../../../fixtures/passkey-attestation/ca-key.pem", import.meta.url);
const root = readFileSync(ca, "utf8");
const rootDER = new X509Certificate(root).raw;
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest();
const u16 = (value: number) => {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16BE(value);
  return bytes;
};
const sized = (bytes: Uint8Array) => Buffer.concat([u16(bytes.length), bytes]);
const der = (tag: number, ...parts: Uint8Array[]) => {
  const data = Buffer.concat(parts);
  return Buffer.concat([
    Buffer.from([tag, ...(data.length < 128 ? [data.length] : [0x81, data.length])]),
    data,
  ]);
};
const seq = (...parts: Uint8Array[]) => der(0x30, ...parts);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex").match(/../g)!.join(":");
const ecKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const replacementKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const replacementJWK = replacementKeys.publicKey.export({ format: "jwk" });
export const replacementPublicKey = Buffer.from(
  encodeCBOR(
    new Map<number, CBORType>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(replacementJWK.x!, "base64url")],
      [-3, Buffer.from(replacementJWK.y!, "base64url")],
    ]),
  ),
);
const attestationKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = ecKeys.publicKey.export({ format: "jwk" });
const x = Buffer.from(jwk.x!, "base64url"),
  y = Buffer.from(jwk.y!, "base64url");
export const publicKey = Buffer.from(
  encodeCBOR(
    new Map<number, CBORType>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, x],
      [-3, y],
    ]),
  ),
);

function certificate(key: typeof ecKeys, subject: string, extra: string, wrongRoot: boolean) {
  const directory = mkdtempSync(join(tmpdir(), "close215-device-"));
  function openssl(args: string[]) {
    const result = spawnSync("openssl", args, { cwd: directory });
    if (result.status !== 0) throw new Error(result.stderr.toString());
  }
  try {
    writeFileSync(
      join(directory, "key.pem"),
      key.privateKey.export({ format: "pem", type: "pkcs8" }),
    );
    writeFileSync(
      join(directory, "extensions.cnf"),
      `[leaf]\nbasicConstraints=critical,CA:FALSE\n${extra}\n`,
    );
    let issuer = new URL(ca).pathname,
      issuerKey = new URL(caKey).pathname;
    if (wrongRoot) {
      openssl([
        "req",
        "-new",
        "-x509",
        "-key",
        "key.pem",
        "-out",
        "other.pem",
        "-days",
        "7300",
        "-subj",
        "/CN=Other test root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
      ]);
      issuer = join(directory, "other.pem");
      issuerKey = join(directory, "key.pem");
    }
    openssl(["req", "-new", "-key", "key.pem", "-out", "leaf.csr", "-subj", subject]);
    openssl([
      "x509",
      "-req",
      "-in",
      "leaf.csr",
      "-CA",
      issuer,
      "-CAkey",
      issuerKey,
      "-set_serial",
      extra.includes("crlDistributionPoints") ? "42" : "0x" + randomBytes(12).toString("hex"),
      "-out",
      "leaf.pem",
      "-days",
      "7300",
      "-extfile",
      "extensions.cnf",
      "-extensions",
      "leaf",
    ]);
    const leaf = new X509Certificate(readFileSync(join(directory, "leaf.pem")));
    if (!leaf.verify(new X509Certificate(readFileSync(issuer)).publicKey))
      throw new Error("leaf signature was not genuine");
    return leaf.raw;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export type AttestationFormat =
  | "packed"
  | "fido-u2f"
  | "android-key"
  | "apple"
  | "tpm"
  | "android-safetynet";
export type CeremonyMode =
  | "valid"
  | "crossOrigin"
  | "extension"
  | "wrong-rp"
  | "wrong-origin"
  | "signature"
  | "wrong-root"
  | "wrong-nonce"
  | "cts"
  | "future"
  | "revoked"
  | "noncanonical"
  | "duplicate"
  | "timestamp-omitted"
  | "timestamp-string"
  | "version-number";

/** Software certificates and attestation signatures; never a synthetic verified flag. */
export class CertificateDevice {
  constructor(readonly id: string) {}
  register(options: any, origin: string, format: AttestationFormat, mode: CeremonyMode = "valid") {
    const credential = Buffer.from(this.id);
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.create",
        challenge: options.challenge,
        origin: mode === "wrong-origin" ? "https://wrong.example" : origin,
        crossOrigin: mode === "crossOrigin",
      }),
    );
    const extension =
      mode === "extension"
        ? Buffer.from(
            encodeCBOR(
              new Map<string, CBORType>([
                ["credProtect", "ignored-source-value"],
                ["application", new Map([["flag", true]])],
              ]),
            ),
          )
        : Buffer.alloc(0);
    let credentialKey = publicKey;
    if (mode === "noncanonical")
      credentialKey = Buffer.concat([Buffer.from([0xb8, 5]), publicKey.subarray(1)]);
    if (mode === "duplicate")
      credentialKey = Buffer.concat([
        Buffer.from([0xa6]),
        publicKey.subarray(1),
        Buffer.from([3, 0x26]),
      ]);
    const authData = Buffer.concat([
      hash(mode === "wrong-rp" ? "wrong.example" : options.rp.id),
      Buffer.from([extension.length ? 0xc1 : 0x41]),
      Buffer.alloc(4),
      Buffer.alloc(16),
      sized(credential),
      credentialKey,
      extension,
    ]);
    const signed = Buffer.concat([authData, hash(client)]);
    let leaf: Buffer;
    const statement = new Map<string, CBORType>();
    let signature: Buffer;
    if (format === "apple" || format === "android-key") {
      const nonce =
        mode === "wrong-nonce"
          ? Buffer.alloc(32, 1)
          : format === "apple"
            ? hash(signed)
            : hash(client);
      const description =
        format === "apple"
          ? seq(der(0xa1, der(4, nonce)))
          : seq(
              der(2, Buffer.from([3])),
              der(10, Buffer.from([1])),
              der(2, Buffer.from([4])),
              der(10, Buffer.from([1])),
              der(4, nonce),
              der(4, Buffer.alloc(0)),
              seq(),
              seq(),
            );
      leaf = certificate(
        ecKeys,
        "/CN=Software authenticator",
        `${format === "apple" ? "1.2.840.113635.100.8.2" : "1.3.6.1.4.1.11129.2.1.17"}=DER:${hex(description)}`,
        mode === "wrong-root",
      );
      statement.set("x5c", format === "android-key" ? [leaf, rootDER] : [leaf]);
      signature = sign("sha256", signed, ecKeys.privateKey);
    } else if (format === "tpm") {
      leaf = certificate(
        attestationKeys,
        "/",
        "extendedKeyUsage=2.23.133.8.3\nsubjectAltName=critical,dirName:tpm\n[tpm]\n0.2.23.133.2.1=id:49424D00\n0.2.23.133.2.2=Fixture\n0.2.23.133.2.3=id:00010000",
        mode === "wrong-root",
      );
      const pubArea = Buffer.concat([
        u16(0x23),
        u16(0x0b),
        Buffer.alloc(4),
        u16(0),
        u16(0x10),
        u16(0x10),
        u16(3),
        u16(0x10),
        sized(x),
        sized(y),
      ]);
      const certInfo = Buffer.concat([
        Buffer.from([0xff, 0x54, 0x43, 0x47]),
        u16(0x8017),
        u16(0),
        sized(mode === "wrong-nonce" ? Buffer.alloc(32, 1) : hash(signed)),
        Buffer.alloc(17),
        Buffer.alloc(8),
        sized(Buffer.concat([u16(0x0b), hash(pubArea)])),
        u16(0),
      ]);
      statement.set("ver", "2.0");
      statement.set("pubArea", pubArea);
      statement.set("certInfo", certInfo);
      statement.set("x5c", [leaf]);
      signature = sign("sha256", certInfo, attestationKeys.privateKey);
    } else if (format === "android-safetynet") {
      leaf = certificate(attestationKeys, "/CN=attest.android.com", "", mode === "wrong-root");
      const header = Buffer.from(
        JSON.stringify({ alg: "ES256", x5c: [leaf.toString("base64")] }),
      ).toString("base64url");
      const payload = Buffer.from(
        JSON.stringify({
          nonce: (mode === "wrong-nonce" ? Buffer.alloc(32, 1) : hash(signed)).toString("base64"),
          ctsProfileMatch: mode !== "cts",
          timestampMs:
            mode === "timestamp-omitted"
              ? undefined
              : mode === "timestamp-string"
                ? String(Date.now() - 1000)
                : mode === "future"
                  ? Date.now() + 120000
                  : Date.now() - 1000,
        }),
      ).toString("base64url");
      signature = sign("sha256", Buffer.from(`${header}.${payload}`), attestationKeys.privateKey);
      if (mode === "signature") signature[signature.length - 1]! ^= 1;
      statement.set("ver", mode === "version-number" ? 1 : "1.0");
      statement.set(
        "response",
        Buffer.from(`${header}.${payload}.${signature.toString("base64url")}`),
      );
    } else {
      leaf = certificate(
        attestationKeys,
        format === "packed"
          ? "/C=US/O=Compatibility fixture/OU=Authenticator Attestation/CN=Public test authenticator"
          : "/CN=Public U2F test authenticator",
        mode === "revoked" ? `crlDistributionPoints=URI:${origin}/__test/passkey-crl` : "",
        mode === "wrong-root",
      );
      statement.set("x5c", [leaf]);
      signature = sign(
        "sha256",
        format === "packed"
          ? signed
          : Buffer.concat([
              Buffer.from([0]),
              authData.subarray(0, 32),
              hash(client),
              credential,
              Buffer.from([4]),
              x,
              y,
            ]),
        attestationKeys.privateKey,
      );
    }
    if (format !== "android-safetynet") {
      if (mode === "signature") {
        if (format === "apple") {
          const damaged = Buffer.from(leaf);
          damaged[damaged.length - 1]! ^= 1;
          statement.set("x5c", [damaged]);
        } else signature[signature.length - 1]! ^= 1;
      }
      if (format !== "apple") {
        statement.set("alg", -7);
        statement.set("sig", signature);
      }
    }
    const proof = {
      id: credential.toString("base64url"),
      rawId: credential.toString("base64url"),
      type: "public-key",
      response: {
        clientDataJSON: client.toString("base64url"),
        attestationObject: Buffer.from(
          encodeCBOR(
            new Map<string, CBORType>([
              ["fmt", format],
              ["attStmt", statement],
              ["authData", authData],
            ]),
          ),
        ).toString("base64url"),
        transports: ["internal"],
      },
      clientExtensionResults: {},
    };
    return proof;
  }
  authenticate(options: any, origin: string, counter = 1, bad = false, replacement = false) {
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: options.challenge,
        origin,
        crossOrigin: true,
      }),
    );
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    const data = Buffer.concat([hash(options.rpId), Buffer.from([1]), count]);
    const signature = sign(
      "sha256",
      Buffer.concat([data, hash(client)]),
      replacement ? replacementKeys.privateKey : ecKeys.privateKey,
    );
    if (bad) signature[signature.length - 1]! ^= 1;
    return {
      id: Buffer.from(this.id).toString("base64url"),
      rawId: Buffer.from(this.id).toString("base64url"),
      type: "public-key",
      response: {
        clientDataJSON: client.toString("base64url"),
        authenticatorData: data.toString("base64url"),
        signature: signature.toString("base64url"),
      },
      clientExtensionResults: {},
    };
  }
}
