import { expect } from "bun:test";

import { verifyPassword } from "better-auth/crypto";
import { z } from "zod";

import { cacheReceipt } from "../../../support/compact-cache-receipt";
import { compatScenario } from "../../../support/scenario";
import { issueSession, revocationObservation } from "../../../support/server-session-revocation";
import { readUserState } from "../../../support/verification";

compatScenario(
  "logical updateSession validates records before admission and preserves unconfigured session authority",
  async (ctx) => {
    const owner = await issueSession(
      ctx,
      "logical-session-owner",
      ctx.uniqueEmail("logical-session-owner"),
    );
    const foreign = await issueSession(
      ctx,
      "logical-session-foreign",
      ctx.uniqueEmail("logical-session-foreign"),
    );
    const state = async () => ({
      owner: await readUserState(ctx, owner.result.data!.user.id),
      foreign: await readUserState(ctx, foreign.result.data!.user.id),
    });
    const before = await state();
    async function invoke(body: unknown, cookie?: string) {
      const result = await ctx.rawRequest({
        path: "/__test/server-dispatch-cache/call",
        method: "POST",
        json: {
          operation: "updateSession",
          body,
          query: { disableRefresh: true },
          ...(cookie === undefined ? {} : { headers: { cookie } }),
        },
      });
      expect(result.status).toBe(200);
      return revocationObservation.passthrough().parse(result.body);
    }
    const malformed = [];
    for (const body of [null, [], 7]) {
      const denial = await invoke(body);
      expect(denial.result.status).toBe(400);
      expect(denial.result.body!.code).toBe("VALIDATION_ERROR");
      malformed.push(denial);
    }
    const guest = await invoke({ label: "guest" });
    expect(guest.result.status).toBe(401);
    const denied = [];
    for (const body of [
      {},
      {
        token: foreign.result.data!.token,
        userId: foreign.result.data!.user.id,
        expiresAt: "2099-01-01T00:00:00.000Z",
      },
    ]) {
      const result = await invoke(body, owner.headers.cookie);
      expect(result.result.status).toBe(400);
      expect(result.result.body).toEqual({ message: "No fields to update" });
      expect(result.events.find((event) => event.stage === "user-after")!.session!.user.id).toBe(
        owner.result.data!.user.id,
      );
      denied.push(result);
    }
    expect(await state()).toEqual(before);
    return { owner, foreign, before, malformed, guest, denied };
  },
);

compatScenario(
  "logical updateSession publishes configured current-token fields while preserving sibling and foreign sessions",
  async (ctx) => {
    const profile = "additional-cached-fields";
    const password = "Correct-Horse-Password-205";
    const email = ctx.uniqueEmail("logical-fields-owner");
    async function issue(name: string, email: string, signIn = false) {
      const actor = ctx.actor(name, profile);
      let headers = new Headers();
      const fetchOptions = {
        onSuccess({ response }: { response: Response }) {
          headers = new Headers(response.headers);
        },
      };
      const result = signIn
        ? await actor.client.signIn.email({ email, password, fetchOptions })
        : await actor.client.signUp.email({ email, password, name, fetchOptions });
      expect(result.error).toBeNull();
      return {
        result,
        headers: {
          cookie: headers
            .getSetCookie()
            .map((raw) => raw.split(";")[0])
            .join("; "),
        },
        publication: {
          body: result.data,
          headers: Object.fromEntries(
            [...headers].filter(([name]) => !["date", "content-length"].includes(name)),
          ),
          ...(await cacheReceipt(headers)),
        },
      };
    }
    const owner = await issue("logical-fields-owner", email);
    const sibling = await issue("logical-fields-sibling", email, true);
    const foreign = await issue(
      "logical-fields-foreign",
      ctx.uniqueEmail("logical-fields-foreign"),
    );
    const stateSchema = z
      .object({
        users: z.array(z.record(z.string(), z.unknown())),
        accounts: z.array(z.record(z.string(), z.unknown())),
        sessions: z.array(z.record(z.string(), z.unknown())),
        events: z.array(z.record(z.string(), z.unknown())),
      })
      .passthrough();
    async function hashEvidence(value: unknown) {
      if (typeof value !== "string") {
        return value;
      }
      expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);
      expect(await verifyPassword({ hash: value, password })).toBe(true);
      expect(await verifyPassword({ hash: value, password: "wrong-password" })).toBe(false);
      const [salt, key] = value.split(":");
      return {
        token: value,
        salt: { token: salt, length: salt!.length },
        derivedKey: { token: key, length: key!.length },
        encoding: "hex-lower",
      };
    }
    async function read() {
      const response = await ctx.rawRequest({
        path: "/__test/additional-fields/state?profile=cached",
      });
      expect(response.status).toBe(200);
      const state = stateSchema.parse(response.body);
      for (const account of state.accounts) {
        account.password = await hashEvidence(account.password);
      }
      for (const event of state.events) {
        if (
          event.entity === "account" &&
          typeof event.record === "object" &&
          event.record !== null
        ) {
          const record = event.record as Record<string, unknown>;
          if (Object.hasOwn(record, "password")) {
            record.password = await hashEvidence(record.password);
          }
        }
      }
      return state;
    }
    const before = await read();
    const outputSchema = z
      .object({
        response: z
          .object({
            session: z
              .object({
                id: z.string(),
                token: z.string(),
                userId: z.string(),
                label: z.object({ stored: z.string() }),
              })
              .passthrough(),
          })
          .passthrough(),
        headers: z.record(z.string(), z.string()),
        cookies: z.array(z.string()),
      })
      .passthrough();
    const updated = await ctx.rawRequest({
      path: "/__test/additional-fields/cached/update-session",
      method: "POST",
      json: {
        body: {
          label: "logical-update",
          hidden: "logical-private",
          token: foreign.result.data!.token,
          userId: foreign.result.data!.user.id,
          expiresAt: "2099-01-01T00:00:00.000Z",
        },
        headers: owner.headers,
      },
    });
    expect(updated.status).toBe(200);
    const observed = z
      .object({ result: z.object({ ok: z.literal(true), value: outputSchema }).passthrough() })
      .passthrough()
      .parse(updated.body);
    const output = observed.result.value;
    expect(output.response.session.label).toEqual({ stored: "logical-update" });
    expect(output.response.session.token).toBe(owner.result.data!.token!);
    expect(output.response.session.userId).toBe(owner.result.data!.user.id);
    expect(output.response.session).not.toHaveProperty("hidden");
    const after = await read();
    const owned = after.sessions.find((row) => row.token === owner.result.data!.token!)!;
    expect(owned).toMatchObject({ label: "logical-update", hidden: "logical-private" });
    const original = before.sessions.find((row) => row.token === owner.result.data!.token!)!;
    for (const field of ["id", "userId", "token", "expiresAt", "createdAt"]) {
      expect(owned[field]).toEqual(original[field]);
    }
    expect(after.sessions.filter((row) => row.token !== owner.result.data!.token!)).toEqual(
      before.sessions.filter((row) => row.token !== owner.result.data!.token!),
    );
    expect(after.users).toEqual(before.users);
    expect(after.accounts).toEqual(before.accounts);
    expect(output.cookies.some((raw) => raw.startsWith("better-auth.session_token="))).toBe(true);
    expect(output.cookies.some((raw) => raw.startsWith("better-auth.session_data="))).toBe(true);
    const cookie = output.cookies.map((raw) => raw.split(";")[0]).join("; ");
    const cached = await ctx.rawRequest({
      path: `/__test/profiles/${profile}/api/auth/get-session`,
      headers: { cookie },
    });
    expect(cached.status).toBe(200);
    expect(cached.body).toMatchObject({
      session: { label: { stored: "logical-update" }, token: owner.result.data!.token! },
    });
    expect((cached.body as { session: object }).session).not.toHaveProperty("hidden");
    const publication = await cacheReceipt(
      new Headers(output.cookies.map((raw) => ["set-cookie", raw])),
    );
    return {
      owner,
      sibling,
      foreign,
      before,
      updated: observed,
      publication,
      after,
      cached,
      headers: { cookie },
    };
  },
);
