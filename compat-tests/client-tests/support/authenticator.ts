import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { encodeCBOR, type CBORType } from "@levischuck/tiny-cbor";
import { z } from "zod";

// A synthetic key shared by both runs makes stored public-key bytes comparable.
const key = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = key.publicKey.export({ format: "jwk" });
const coordinates = z.object({ x: z.string(), y: z.string() }).parse(jwk);
const credential = Buffer.from("compat-authenticator-credential-id");
const publicKey = encodeCBOR(new Map<number, CBORType>([
  [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(coordinates.x, "base64url")], [-3, Buffer.from(coordinates.y, "base64url")],
]));
const registrationOptions = z.object({ challenge: z.string().min(1), rp: z.object({ id: z.string() }), user: z.object({ id: z.string() }) });
const authenticationOptions = z.object({ challenge: z.string().min(1), rpId: z.string() });
const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest();

/** Synthetic ES256 WebAuthn device for deterministic credential round trips. */
export class Authenticator {
  private counter = 0;
  private userHandle = "";

  /** Produce a signed-key registration attestation for the supplied challenge. */
  register(options: unknown, origin: string) {
    const parsed = registrationOptions.parse(options);
    this.userHandle = parsed.user.id;
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: parsed.challenge, origin, crossOrigin: false }));
    const length = Buffer.alloc(2); length.writeUInt16BE(credential.length);
    const authData = Buffer.concat([hash(parsed.rp.id), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, credential, publicKey]);
    const attestation = encodeCBOR(new Map<string, CBORType>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
    return {
      id: credential.toString("base64url"), rawId: credential.toString("base64url"), type: "public-key",
      response: { clientDataJSON: clientDataJSON.toString("base64url"), attestationObject: Buffer.from(attestation).toString("base64url"), transports: ["internal"] },
      clientExtensionResults: {}, authenticatorAttachment: "platform",
    };
  }

  /** Sign an assertion for the challenge and increment the credential counter. */
  authenticate(options: unknown, origin: string) {
    const parsed = authenticationOptions.parse(options);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: parsed.challenge, origin, crossOrigin: false }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(++this.counter);
    const authenticatorData = Buffer.concat([hash(parsed.rpId), Buffer.from([0x05]), counter]);
    const signature = sign("sha256", Buffer.concat([authenticatorData, hash(clientDataJSON)]), key.privateKey);
    return {
      id: credential.toString("base64url"), rawId: credential.toString("base64url"), type: "public-key",
      response: { clientDataJSON: clientDataJSON.toString("base64url"), authenticatorData: authenticatorData.toString("base64url"), signature: signature.toString("base64url"), userHandle: this.userHandle },
      clientExtensionResults: {}, authenticatorAttachment: "platform",
    };
  }
}
