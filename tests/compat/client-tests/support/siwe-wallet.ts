// EIP-191 wallet messages and signatures for public secp256k1 test scalars.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const EOA = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";
export const SECOND_EOA = "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF";
export const CONTRACT = "0x1111111111111111111111111111111111111111";

export function message(
  nonce: string,
  {
    address = EOA,
    chain = "1",
    domain = "https://FIXTURE.EXAMPLE/ignored",
    extra = "",
  }: { address?: string; chain?: string; domain?: string; extra?: string } = {},
) {
  return `${domain} wants you to sign in with your Ethereum account:\n${address}\n\nSign in — Ελληνικά\n\nURI: not-a-url\nVersion: 999\nChain ID: ${chain}\nNonce: ${nonce}\nIssued At: invalid date\n${extra}`;
}

export function signature(message: string, scalar = 1, compact = false): string {
  const key = new Uint8Array(32);
  key[31] = scalar;
  const bytes = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\u0019Ethereum Signed Message:\n${bytes.length}`);
  const input = new Uint8Array(prefix.length + bytes.length);
  input.set(prefix);
  input.set(bytes, prefix.length);
  const signed = secp256k1.sign(keccak_256(input), key, { prehash: false, format: "recovered" });
  const result = new Uint8Array(compact ? 64 : 65);
  result.set(signed.subarray(1));

  if (compact) {
    result[32]! |= signed[0]! << 7;
  } else {
    result[64] = signed[0]! + 27;
  }

  return `0x${Buffer.from(result).toString("hex")}`;
}
