import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { z } from "zod";

// A synthetic key shared by both runs makes stored public-key bytes comparable.
const es256Key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = es256Key.publicKey.export({ format: "jwk" });
const coordinates = z.object({ x: z.string(), y: z.string() }).parse(jwk);
const credential = Buffer.from("compat-authenticator-credential-id");
const es256PublicKey = encodeCBOR(new Map<number, CBORType>([
  [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(coordinates.x, "base64url")], [-3, Buffer.from(coordinates.y, "base64url")],
]));
const ed25519Key = generateKeyPairSync("ed25519");
const ed25519Jwk = z.object({ x: z.string() }).parse(ed25519Key.publicKey.export({ format: "jwk" }));
const ed25519PublicKey = encodeCBOR(new Map<number, CBORType>([
  [1, 1], [3, -8], [-1, 6], [-2, Buffer.from(ed25519Jwk.x, "base64url")],
]));
const registrationOptions = z.object({ challenge: z.string().min(1), rp: z.object({ id: z.string() }), user: z.object({ id: z.string() }) });
const authenticationOptions = z.object({ challenge: z.string().min(1), rpId: z.string() });
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest();

type BackupFlags = { backupEligible?: boolean; backedUp?: boolean; userVerified?: boolean; userPresent?: boolean; counter?: number; rpId?: string; attestation?: "none" | "packed"; badSignature?: boolean; malformedSignature?: boolean; malformedKey?: boolean };
const flags = (base: number, state: BackupFlags) => (state.userVerified === false ? base & ~0x04 : base) & (state.userPresent === false ? ~0x01 : 0xff) | (state.backupEligible ? 0x08 : 0) | (state.backedUp ? 0x10 : 0);

/** Software ES256 or Ed25519 WebAuthn device for deterministic credential round trips. */
export class Authenticator {
  private counter = 0;
  private userHandle = "";

  constructor(private readonly algorithm: "ES256" | "Ed25519" = "ES256") {}

  private sign(input: Uint8Array) {
    return this.algorithm === "Ed25519" ? sign(null, input, ed25519Key.privateKey) : sign("sha256", input, es256Key.privateKey);
  }

  /** Produce a none or genuinely signed packed self-attestation for the supplied challenge. */
  register(options: unknown, origin: string, backup: BackupFlags = {}) {
    const parsed = registrationOptions.parse(options);
    this.userHandle = parsed.user.id;
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: parsed.challenge, origin, crossOrigin: false }));
    const length = Buffer.alloc(2); length.writeUInt16BE(credential.length);
    const authData = Buffer.concat([hash(backup.rpId ?? parsed.rp.id), Buffer.from([flags(0x45, backup)]), Buffer.alloc(4), Buffer.alloc(16), length, credential, backup.malformedKey ? Buffer.from([0xa0]) : this.algorithm === "Ed25519" ? ed25519PublicKey : es256PublicKey]);
    const signature = backup.malformedSignature ? Buffer.from([0x01]) : this.sign(Buffer.concat([authData, hash(clientDataJSON)]));
    if (backup.badSignature) signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    const attestation = encodeCBOR(new Map<string, CBORType>([["fmt", backup.attestation ?? "none"], ["attStmt", backup.attestation === "packed" ? new Map<string, CBORType>([["alg", this.algorithm === "Ed25519" ? -8 : -7], ["sig", signature]]) : new Map()], ["authData", authData]]));
    return {
      id: credential.toString("base64url"), rawId: credential.toString("base64url"), type: "public-key",
      response: { clientDataJSON: clientDataJSON.toString("base64url"), attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"] },
      clientExtensionResults: {}, authenticatorAttachment: "platform",
    };
  }

  /** Sign an assertion for the challenge and increment the credential counter. */
  authenticate(options: unknown, origin: string, backup: BackupFlags = {}) {
    const parsed = authenticationOptions.parse(options);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: parsed.challenge, origin, crossOrigin: false }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(backup.counter ?? ++this.counter);
    const authenticatorData = Buffer.concat([hash(backup.rpId ?? parsed.rpId), Buffer.from([flags(0x05, backup)]), counter]);
    const signature = backup.malformedSignature ? Buffer.from([0x01]) : this.sign(Buffer.concat([authenticatorData, hash(clientDataJSON)]));
    if (backup.badSignature) signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
    return {
      id: credential.toString("base64url"), rawId: credential.toString("base64url"), type: "public-key",
      response: { clientDataJSON: clientDataJSON.toString("base64url"), authenticatorData: authenticatorData.toString("base64url"), signature: signature.toString("base64url"), userHandle: this.userHandle },
      clientExtensionResults: {}, authenticatorAttachment: "platform",
    };
  }
}
