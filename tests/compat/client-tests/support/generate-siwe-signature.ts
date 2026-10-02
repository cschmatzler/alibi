// Independent secp256k1/EIP-191 fixture for the Rust HTTP-handler test.
// Run with Bun from this workspace; Better Auth remains pinned to 1.7.6.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const secretKey = new Uint8Array(32);
secretKey[31] = 1;
const message = [
  "fixture.example wants you to sign in with your Ethereum account:",
  "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  "",
  "Sign in to the deterministic fixture — Ελληνικά",
  "",
  "URI: https://fixture.example/siwe",
  "Version: 1",
  "Chain ID: 1",
  "Nonce: GoldenNonce0001",
  "Issued At: 2026-01-01T00:00:00Z",
].join("\n");
const bytes = new TextEncoder().encode(message);
const prefix = new TextEncoder().encode(`\u0019Ethereum Signed Message:\n${bytes.length}`);
const input = new Uint8Array(prefix.length + bytes.length);
input.set(prefix);
input.set(bytes, prefix.length);
const hash = keccak_256(input);
const recovered = secp256k1.sign(hash, secretKey, { prehash: false, format: "recovered" });
const signature = new Uint8Array(65);
signature.set(recovered.subarray(1));
signature[64] = recovered[0]! + 27;
const fixture = {
  source: "@noble/curves 2.0.1, EIP-191 personal_sign, private scalar 1 (public test key)",
  nonce: "GoldenNonce0001",
  address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  message,
  signature: `0x${Buffer.from(signature).toString("hex")}`,
  digest: Buffer.from(hash).toString("hex"),
};
await Bun.write(
  new URL("../../../fixtures/siwe/eip191-noble-2.0.1.json", import.meta.url),
  `${JSON.stringify(fixture, null, 2)}\n`,
);
