import { createHash, generateKeyPairSync } from "node:crypto";
import { encode } from "../../reference-server/node_modules/@simplewebauthn/server/esm/helpers/iso/isoCBOR.js";

export function registrationProof(challenge, label, transports, present = true) {
  const id = Buffer.from(label);
  const { publicKey } = generateKeyPairSync("ed25519");
  const key = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const cose = encode(new Map([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(key)]]));
  const length = Buffer.alloc(2);
  length.writeUInt16BE(id.length);
  const authData = Buffer.concat([createHash("sha256").update("localhost").digest(), Buffer.from([0x45]), Buffer.from([0, 0, 0, 1]), Buffer.alloc(16), length, id, cose]);
  const attestation = encode(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]));
  return {
    id: id.toString("base64url"), rawId: id.toString("base64url"), type: "public-key", clientExtensionResults: {},
    response: {
      clientDataJSON: Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin: "http://localhost" })).toString("base64url"),
      attestationObject: Buffer.from(attestation).toString("base64url"),
      ...(present ? { transports } : {}),
    },
  };
}
