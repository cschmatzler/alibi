import { createHash, generateKeyPairSync, sign } from "node:crypto";

import { type CBORType, encodeCBOR } from "@levischuck/tiny-cbor";
import { ed448 } from "@noble/curves/ed448.js";
import { z } from "zod";

// A synthetic key shared by both runs makes stored public-key bytes comparable.
const es256Key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = es256Key.publicKey.export({ format: "jwk" });
const coordinates = z.object({ x: z.string(), y: z.string() }).parse(jwk);
const defaultCredential = Buffer.from("compat-authenticator-credential-id");

const es256PublicKey = encodeCBOR(
  new Map<number, CBORType>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(coordinates.x, "base64url")],
    [-3, Buffer.from(coordinates.y, "base64url")],
  ]),
);

const ed25519Key = generateKeyPairSync("ed25519");

const ed25519Jwk = z
  .object({ x: z.string() })
  .parse(ed25519Key.publicKey.export({ format: "jwk" }));

const ed25519PublicKey = encodeCBOR(
  new Map<number, CBORType>([
    [1, 1],
    [3, -8],
    [-1, 6],
    [-2, Buffer.from(ed25519Jwk.x, "base64url")],
  ]),
);

const mismatchedEd25519PublicKey = encodeCBOR(
  new Map<number, CBORType>([
    [1, 1],
    [3, -7],
    [-1, 6],
    [-2, Buffer.from(ed25519Jwk.x, "base64url")],
  ]),
);

const unknownOkpPublicKey = encodeCBOR(
  new Map<number, CBORType>([
    [1, 1],
    [3, -8],
    [-1, 8],
    [-2, Buffer.from(ed25519Jwk.x, "base64url")],
  ]),
);

const ed448Key = ed448.keygen();

const ed448PublicKey = encodeCBOR(
  new Map<number, CBORType>([
    [1, 1],
    [3, -8],
    [-1, 7],
    [-2, ed448Key.publicKey],
  ]),
);

const registrationOptions = z.object({
  challenge: z.string().min(1),
  rp: z.object({ id: z.string() }),
  user: z.object({ id: z.string() }),
});

const authenticationOptions = z.object({ challenge: z.string().min(1), rpId: z.string() });
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest();

type BackupFlags = {
  backupEligible?: boolean;
  backedUp?: boolean;
  userVerified?: boolean;
  userPresent?: boolean;
  counter?: number;
  rpId?: string;
  attestation?: "none" | "packed";
  badSignature?: boolean;
  malformedSignature?: boolean;
  malformedKey?: boolean;
  statementAlgorithm?: -7 | -8;
  tokenBinding?: { status: string; id?: string };
};

const flags = (base: number, state: BackupFlags) =>
  ((state.userVerified === false ? base & ~0x04 : base) &
    (state.userPresent === false ? ~0x01 : 0xff)) |
  (state.backupEligible ? 0x08 : 0) |
  (state.backedUp ? 0x10 : 0);

/** Software ES256, Ed25519 or Ed448 WebAuthn device for deterministic credential round trips. */
export class Authenticator {
  private counter = 0;
  private userHandle = "";

  constructor(
    private readonly algorithm:
      | "ES256"
      | "Ed25519"
      | "Ed448"
      | "Ed25519Curve8"
      | "Ed25519Alg7" = "ES256",
    private readonly credential: Uint8Array = defaultCredential,
  ) {}

  private sign(input: Uint8Array) {
    if (this.algorithm === "Ed448") {
      return Buffer.from(ed448.sign(input, ed448Key.secretKey));
    }
    return this.algorithm === "Ed25519" ||
      this.algorithm === "Ed25519Curve8" ||
      this.algorithm === "Ed25519Alg7"
      ? sign(null, input, ed25519Key.privateKey)
      : sign("sha256", input, es256Key.privateKey);
  }

  /** Produce a none or genuinely signed packed self-attestation for the supplied challenge. */
  register(options: unknown, origin: string, backup: BackupFlags = {}) {
    const parsed = registrationOptions.parse(options);
    this.userHandle = parsed.user.id;
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: "webauthn.create",
        challenge: parsed.challenge,
        origin,
        crossOrigin: false,
        ...(backup.tokenBinding === undefined ? {} : { tokenBinding: backup.tokenBinding }),
      }),
    );
    const length = Buffer.alloc(2);
    length.writeUInt16BE(this.credential.length);
    const initialCounter = Buffer.alloc(4);
    initialCounter.writeUInt32BE(backup.counter ?? 0);
    const authData = Buffer.concat([
      hash(backup.rpId ?? parsed.rp.id),
      Buffer.from([flags(0x45, backup)]),
      initialCounter,
      Buffer.alloc(16),
      length,
      this.credential,
      backup.malformedKey
        ? Buffer.from([0xa0])
        : this.algorithm === "Ed25519Alg7"
          ? mismatchedEd25519PublicKey
          : this.algorithm === "Ed25519Curve8"
            ? unknownOkpPublicKey
            : this.algorithm === "Ed448"
              ? ed448PublicKey
              : this.algorithm === "Ed25519"
                ? ed25519PublicKey
                : es256PublicKey,
    ]);
    const signature = backup.malformedSignature
      ? Buffer.from([0x01])
      : this.sign(Buffer.concat([authData, hash(clientDataJSON)]));

    if (backup.badSignature) {
      signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    }

    const attestation = encodeCBOR(
      new Map<string, CBORType>([
        ["fmt", backup.attestation ?? "none"],
        [
          "attStmt",
          backup.attestation === "packed"
            ? new Map<string, CBORType>([
                [
                  "alg",
                  backup.statementAlgorithm ??
                    (this.algorithm === "ES256" || this.algorithm === "Ed25519Alg7" ? -7 : -8),
                ],
                ["sig", signature],
              ])
            : new Map(),
        ],
        ["authData", authData],
      ]),
    );
    return {
      id: Buffer.from(this.credential).toString("base64url"),
      rawId: Buffer.from(this.credential).toString("base64url"),
      type: "public-key",
      response: {
        clientDataJSON: clientDataJSON.toString("base64url"),
        attestationObject: Buffer.from(attestation).toString("base64url"),
        transports: ["internal"],
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }

  /** Sign an assertion for the challenge and increment the credential counter. */
  authenticate(options: unknown, origin: string, backup: BackupFlags = {}) {
    const parsed = authenticationOptions.parse(options);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: parsed.challenge,
        origin,
        crossOrigin: false,
        ...(backup.tokenBinding === undefined ? {} : { tokenBinding: backup.tokenBinding }),
      }),
    );
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(backup.counter ?? ++this.counter);
    const authenticatorData = Buffer.concat([
      hash(backup.rpId ?? parsed.rpId),
      Buffer.from([flags(0x05, backup)]),
      counter,
    ]);
    const signature = backup.malformedSignature
      ? Buffer.from([0x01])
      : this.sign(Buffer.concat([authenticatorData, hash(clientDataJSON)]));

    if (backup.badSignature) {
      signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    }

    return {
      id: Buffer.from(this.credential).toString("base64url"),
      rawId: Buffer.from(this.credential).toString("base64url"),
      type: "public-key",
      response: {
        clientDataJSON: clientDataJSON.toString("base64url"),
        authenticatorData: authenticatorData.toString("base64url"),
        signature: signature.toString("base64url"),
        userHandle: this.userHandle,
      },
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
    };
  }
}
