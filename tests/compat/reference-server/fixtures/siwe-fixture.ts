import { Database } from "bun:sqlite";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { admin, twoFactor, username } from "better-auth/plugins";
import { siwe } from "better-auth/plugins/siwe";
import { serializeSignedCookie } from "better-call";

const CONTRACT = "0x1111111111111111111111111111111111111111";
const CONTRACT_OWNER = "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"; // public test scalar 3
const checksum = (lower: string) => {
  const hex = lower.slice(2).toLowerCase();
  const hash = Buffer.from(keccak_256(new TextEncoder().encode(hex))).toString("hex");
  return `0x${[...hex].map((character, index) => (Number.parseInt(hash[index]!, 16) >= 8 ? character.toUpperCase() : character)).join("")}`;
};

function digest(message: string): Uint8Array {
  const bytes = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\u0019Ethereum Signed Message:\n${bytes.length}`);
  const input = new Uint8Array(prefix.length + bytes.length);
  input.set(prefix);
  input.set(bytes, prefix.length);
  return keccak_256(input);
}

function recover(hash: Uint8Array, signature: string): string | null {
  try {
    if (!/^0x[0-9a-fA-F]+$/.test(signature)) {
      return null;
    }

    const bytes = Buffer.from(signature.slice(2), "hex");
    let compact: Uint8Array;
    let recovery: number;

    if (bytes.length === 65) {
      recovery = bytes[64]!;

      if (recovery === 27 || recovery === 28) {
        recovery -= 27;
      }

      if (recovery !== 0 && recovery !== 1) {
        return null;
      }

      compact = bytes.subarray(0, 64);
    } else if (bytes.length === 64) {
      compact = Uint8Array.from(bytes);
      recovery = compact[32]! >> 7;
      compact[32]! &= 127;
    } else {
      return null;
    }

    const parsed = secp256k1.Signature.fromBytes(compact);

    if (parsed.hasHighS()) {
      return null;
    }

    const point = parsed.addRecoveryBit(recovery).recoverPublicKey(hash).toBytes(false);
    return checksum(
      `0x${Buffer.from(keccak_256(point.subarray(1)))
        .subarray(12)
        .toString("hex")}`,
    );
  } catch {
    return null;
  }
}

function callData(hash: Uint8Array, signature: string): string {
  const hex = signature.slice(2);
  return `0x1626ba7e${Buffer.from(hash).toString("hex")}${"40".padStart(64, "0")}${(hex.length / 2).toString(16).padStart(64, "0")}${hex.padEnd(Math.ceil(hex.length / 64) * 64, "0")}`;
}

export async function createSiweFixture(
  database: Database,
  base: BetterAuthOptions,
  baseURL: string,
) {
  let counter = 0;
  let nonceOverride: string | null = null;
  let verifierMode = "verify";
  let ensMode = "resolve";
  let rpcMode = "verify";
  let releaseVerifier: (() => void) | null = null;
  let enteredVerifier: (() => void) | null = null;
  const inputs: unknown[] = [];
  const lookups: string[] = [];
  const rpcCalls: unknown[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of ["siwe", "siwe-email", "siwe-contract", "siwe-cookie-limit"]) {
    const path = `/__test/profiles/${name}/api/auth`;
    const options: BetterAuthOptions = {
      ...base,
      basePath: path,
      ...(name === "siwe-cookie-limit" ? { session: { ...base.session, expiresIn: 34560001 } } : {}),
      plugins: [
        admin(),
        twoFactor(),
        username(),
        siwe({
          domain: "HTTPS://Fixture.Example/ignored",
          anonymous: name !== "siwe-email",
          ...(name === "siwe-email"
            ? {
                emailDomainName: "Wallet.Fixture.Test",
                ensLookup: async ({ walletAddress }) => {
                  lookups.push(walletAddress);
                  if (ensMode === "throw") {
                    throw new Error("deterministic ENS failure");
                  }
                  return { name: "Wallet Fixture", avatar: "https://fixture.example/avatar.png" };
                },
              }
            : {}),
          getNonce: async () =>
            nonceOverride ?? `SiweFixtureNonce${String(counter++).padStart(16, "0")}`,
          verifyMessage: async (input) => {
            inputs.push(input);

            if (verifierMode === "hold") {
              await new Promise<void>((resolve) => {
                releaseVerifier = resolve;
                enteredVerifier?.();
              });
            }

            if (verifierMode === "throw") {
              throw new Error("deterministic verifier failure");
            }

            if (verifierMode === "api-error") {
              throw new APIError("FORBIDDEN", {
                message: "configured wallet policy rejected",
                code: "WALLET_POLICY_REJECTED",
              });
            }

            if (verifierMode === "false") {
              return false;
            }

            if (name !== "siwe-contract") {
              return recover(digest(input.message), input.signature) === input.address;
            }

            if (input.address !== CONTRACT || input.chainId !== 31337) {
              return false;
            }

            const response = await fetch(`${baseURL}/__test/siwe-rpc`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                jsonrpc: "2.0",
                id: 1,
                method: "eth_call",
                params: [
                  { to: input.address, data: callData(digest(input.message), input.signature) },
                  "latest",
                ],
              }),
            });
            const result = (await response.json()) as { result?: string };
            return result.result?.slice(0, 10) === "0x1626ba7e";
          },
        }),
      ],
    };
    await (await getMigrations(options)).runMigrations();
    profiles.set(path, betterAuth(options));
  }

  const primary = profiles.get("/__test/profiles/siwe/api/auth")!;
  const context = await primary.$context;
  const asDate = (value: unknown) => new Date(value as string | number).toISOString();

  function state() {
    const users = database
      .query(
        "SELECT id,name,email,emailVerified,image,role,banned,twoFactorEnabled,createdAt,updatedAt FROM user ORDER BY rowid",
      )
      .all() as Record<string, unknown>[];
    const wallets = database
      .query(
        "SELECT id,userId,address,chainId,isPrimary,createdAt FROM walletAddress ORDER BY rowid",
      )
      .all() as Record<string, unknown>[];
    const accounts = database
      .query(
        "SELECT id,userId,accountId,providerId,createdAt,updatedAt FROM account ORDER BY rowid",
      )
      .all() as Record<string, unknown>[];
    const sessions = database
      .query(
        "SELECT id,userId,token,createdAt,updatedAt,expiresAt,ipAddress,userAgent FROM session ORDER BY rowid",
      )
      .all() as Record<string, unknown>[];
    const proofs = database
      .query(
        "SELECT id,identifier,value,createdAt,updatedAt,expiresAt FROM verification WHERE identifier LIKE 'siwe%' ORDER BY rowid",
      )
      .all() as Record<string, unknown>[];
    return {
      users: users.map((row) => ({
        ...row,
        emailVerified: Boolean(row.emailVerified),
        banned: row.banned === null ? null : Boolean(row.banned),
        twoFactorEnabled: row.twoFactorEnabled === null ? null : Boolean(row.twoFactorEnabled),
        createdAt: asDate(row.createdAt),
        updatedAt: asDate(row.updatedAt),
      })),
      wallets: wallets.map((row) => ({
        ...row,
        isPrimary: Boolean(row.isPrimary),
        createdAt: asDate(row.createdAt),
      })),
      accounts: accounts.map((row) => ({
        ...row,
        createdAt: asDate(row.createdAt),
        updatedAt: asDate(row.updatedAt),
      })),
      sessions: sessions.map((row) => ({
        ...row,
        createdAt: asDate(row.createdAt),
        updatedAt: asDate(row.updatedAt),
        expiresAt: asDate(row.expiresAt),
      })),
      proofs: proofs.map((row) => ({
        ...row,
        createdAt: asDate(row.createdAt),
        updatedAt: asDate(row.updatedAt),
        expiresAt: asDate(row.expiresAt),
      })),
      inputs,
      lookups,
      rpcCalls,
    };
  }

  async function handle(request: Request): Promise<Response | null> {
    const path = new URL(request.url).pathname;

    if (path === "/__test/siwe-state" && request.method === "GET") {
      return Response.json(state());
    }

    if (path === "/__test/siwe-rpc" && request.method === "POST") {
      const body = (await request.json()) as {
        jsonrpc: string;
        id: number;
        method: string;
        params: { to: string; data: string }[];
      };
      rpcCalls.push(body);
      let valid = false;
      const call = body.params?.[0];

      if (
        rpcMode === "verify" &&
        body.method === "eth_call" &&
        call?.to === CONTRACT &&
        /^0x1626ba7e[0-9a-f]+$/i.test(call.data)
      ) {
        const bytes = call.data.slice(10);
        const hash = Buffer.from(bytes.slice(0, 64), "hex");
        const offset = Number.parseInt(bytes.slice(64, 128), 16) * 2;
        const length = Number.parseInt(bytes.slice(offset, offset + 64), 16) * 2;
        const signature = `0x${bytes.slice(offset + 64, offset + 64 + length)}`;
        valid = hash.length === 32 && recover(hash, signature) === CONTRACT_OWNER;
      }

      return Response.json({
        jsonrpc: "2.0",
        id: body.id,
        result: valid ? `0x1626ba7e${"0".repeat(56)}` : `0xffffffff${"0".repeat(56)}`,
      });
    }

    if (path !== "/__test/siwe-control" || request.method !== "POST") {
      return null;
    }

    const body = (await request.json()) as {
      operation: string;
      nonce?: string;
      value?: string;
      email?: string;
      userId?: string;
      expiresAt?: string;
      banned?: boolean;
      twoFactorEnabled?: boolean;
      verifier?: string;
      ens?: string;
      rpc?: string;
      foreign?: boolean;
    };

    if (body.operation === "preference") {
      const cookie = await serializeSignedCookie(
        "better-auth.dont_remember",
        body.value ?? "",
        body.foreign ? "foreign-siwe-cookie-secret" : String(base.secret),
        { path: "/", httpOnly: true, sameSite: "lax" },
      );
      return Response.json({ status: true }, { headers: { "set-cookie": cookie } });
    }

    if (body.operation === "wait-verifier") {
      if (!releaseVerifier) {
        await new Promise<void>((resolve) => {
          enteredVerifier = resolve;
        });
      }
      enteredVerifier = null;
      return Response.json({ status: true });
    }

    if (body.operation === "release-verifier") {
      releaseVerifier?.();
      releaseVerifier = null;
      return Response.json({ status: true });
    }

    if (body.operation === "configure") {
      if (body.nonce !== undefined) {
        nonceOverride = body.nonce;
      }

      if (body.verifier !== undefined) {
        verifierMode = body.verifier;
      }

      if (body.ens !== undefined) {
        ensMode = body.ens;
      }

      if (body.rpc !== undefined) {
        rpcMode = body.rpc;
      }

      return Response.json({ status: true });
    }

    if (body.operation === "proof") {
      await context.adapter.update({
        model: "verification",
        where: [{ field: "identifier", value: `siwe:${body.nonce}` }],
        update: {
          ...(body.value === undefined ? {} : { value: body.value }),
          ...(body.expiresAt === undefined ? {} : { expiresAt: new Date(body.expiresAt) }),
        },
      });
      return Response.json({ status: true });
    }

    if (body.operation === "create-user") {
      const user = await context.internalAdapter.createUser({
        email: body.email!,
        name: "Existing Email User",
        emailVerified: false,
      });
      return Response.json({ userId: user.id });
    }

    if (body.operation === "update-user") {
      await context.internalAdapter.updateUser(body.userId!, {
        ...(body.banned === undefined ? {} : { banned: body.banned }),
        ...(body.twoFactorEnabled === undefined ? {} : { twoFactorEnabled: body.twoFactorEnabled }),
      });
      return Response.json({ status: true });
    }

    if (body.operation === "delete-user") {
      await context.internalAdapter.deleteUser(body.userId!);
      return Response.json({ status: true });
    }

    return Response.json({ message: "Unknown SIWE fixture operation" }, { status: 400 });
  }

  return {
    profiles,
    handle,
    reset: () => {
      counter = 0;
      enteredVerifier = null;
      releaseVerifier = null;
      nonceOverride = null;
      verifierMode = "verify";
      ensMode = "resolve";
      rpcMode = "verify";
      inputs.length = 0;
      lookups.length = 0;
      rpcCalls.length = 0;
      database.query("DELETE FROM walletAddress").run();
    },
  };
}

export function verifyFixtureEip191(message: string, signature: string, address: string) {
  return recover(digest(message), signature) === address;
}
