import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";

import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";
import { createTracingFetch, type TraceEntry } from "../../../support/trace";

compatScenario(
  "concurrent signup admission obeys memory and shared secondary quotas without rejected mutations",
  async (ctx) => {
    const physical = async () => {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      const body = (await response.json()) as Record<string, Record<string, unknown>[]>;
      return {
        users: body.user ?? body.users!,
        accounts: body.account ?? body.accounts!,
        sessions: body.session ?? body.sessions!,
        verifications: body.verification ?? body.verifications!,
      };
    };
    const batches = [];
    for (const storage of ["memory", "secondary"] as const) {
      for (let round = 0; round < 2; round++) {
        const ip = `203.0.113.${100 + (storage === "memory" ? 0 : 10) + round}`;
        const before = await physical();
        const contenders = Array.from({ length: 12 }, (_, index) => {
          const profile: FixtureProfile =
            storage === "memory"
              ? "rate-limit-concurrent-memory"
              : index % 2 === 0
                ? "rate-limit-concurrent-secondary-a"
                : "rate-limit-concurrent-secondary-b";
          const email = ctx.uniqueEmail(`quota-${storage}-${round}-${index}`);
          const entries: TraceEntry[] = [];
          const client = createAuthClient({
            baseURL: ctx.baseURL + authProfilePath(profile),
            fetchOptions: {
              customFetchImpl: createTracingFetch(ctx.baseURL, "quota-contender", entries),
            },
          });
          return { profile, email, entries, client };
        });
        const responses = await Promise.all(
          contenders.map(async (contender) => ({
            contender,
            result: await contender.client.signUp.email({
              email: contender.email,
              password: "password123",
              name: "Concurrent Quota Owner",
              fetchOptions: { headers: { "x-forwarded-for": ip } },
            }),
          })),
        );
        if (storage === "secondary") {
          // Record both real instance destinations before normalizing their
          // equivalent routes for nondeterministic admission ordering.
          expect(
            contenders.filter((row) => row.entries[0]!.path.includes("concurrent-secondary-a"))
              .length,
          ).toBe(6);
          expect(
            contenders.filter((row) => row.entries[0]!.path.includes("concurrent-secondary-b"))
              .length,
          ).toBe(6);
        }
        const admitted = responses.filter((row) => row.result.error === null);
        const rejected = responses.filter((row) => row.result.error !== null);
        expect(admitted).toHaveLength(3);
        expect(rejected).toHaveLength(9);
        for (const row of admitted) {
          expect(row.result.data?.user.email).toBe(row.contender.email);
          expect(row.contender.entries[0]?.responseStatus).toBe(200);
          expect(Object.keys(row.contender.entries[0]!.responseCookies)).toHaveLength(1);
        }
        for (const row of rejected) {
          expect(row.result.data).toBeNull();
          expect(row.result.error).toEqual({
            status: 429,
            statusText: "Too Many Requests",
            message: "Too many requests. Please try again later.",
          });
          expect(row.contender.entries[0]?.responseCookies).toEqual({});
          expect(row.contender.entries[0]?.responseHeaders["x-retry-after"]).toBe("60");
        }
        const after = await physical();
        const winnerIds = admitted.map((row) => row.result.data!.user.id).sort();
        const emails = new Set(contenders.map((row) => row.email));
        expect(
          after.users
            .filter((row) => emails.has(String(row.email)))
            .map((row) => String(row.id))
            .sort(),
        ).toEqual(winnerIds);
        expect(after.users).toHaveLength(before.users.length + 3);
        expect(after.accounts).toHaveLength(before.accounts.length + 3);
        expect(after.sessions).toHaveLength(before.sessions.length + 3);
        expect(after.verifications).toEqual(before.verifications);
        expect(after.users.filter((row) => !winnerIds.includes(String(row.id)))).toEqual(
          before.users,
        );
        expect(
          after.accounts.filter((row) => !winnerIds.includes(String(row.userId ?? row.user_id))),
        ).toEqual(before.accounts);
        expect(
          after.sessions.filter((row) => !winnerIds.includes(String(row.userId ?? row.user_id))),
        ).toEqual(before.sessions);
        for (const row of admitted) {
          const id = row.result.data!.user.id;
          expect(
            after.accounts.filter((account) => (account.userId ?? account.user_id) === id),
          ).toHaveLength(1);
          expect(
            after.sessions.filter((session) => (session.userId ?? session.user_id) === id),
          ).toHaveLength(1);
        }
        if (storage === "secondary") {
          const response = await fetch(
            `${ctx.baseURL}/__test/rate-limit-secondary/control?key=${encodeURIComponent(`${ip}|/sign-up/email`)}`,
          );
          expect(await response.json()).toEqual({ value: "12" });
        }
        // The quota promises an admission count, not which overlapping request
        // wins. Check each real email/owner binding above before assigning local
        // outcome ranks to otherwise complete SDK responses and wire traces.
        const aliases = new Map<string, string>();
        for (const [rank, row] of admitted.entries())
          aliases.set(
            row.contender.email,
            ctx.uniqueEmail(`quota-${storage}-${round}-admitted-${rank}`),
          );
        for (const [rank, row] of rejected.entries())
          aliases.set(
            row.contender.email,
            ctx.uniqueEmail(`quota-${storage}-${round}-rejected-${rank}`),
          );
        const rankValues = (value: unknown): unknown => {
          if (typeof value === "string") return aliases.get(value) ?? value;
          if (value instanceof Date) return value;
          if (Array.isArray(value)) return value.map(rankValues);
          if (value && typeof value === "object")
            return Object.fromEntries(
              Object.entries(value).map(([key, child]) => [key, rankValues(child)]),
            );
          return value;
        };
        const authority = [];
        for (const row of admitted) {
          const session = await row.contender.client.getSession({
            fetchOptions: { headers: { "x-forwarded-for": ip } },
          });
          expect(session.data?.user.id).toBe(row.result.data!.user.id);
          expect(session.data?.user.email).toBe(row.contender.email);
          expect(session.data?.session.token).toBe(row.result.data!.token!);
          authority.push(rankValues(session));
        }
        const ordered = [...admitted, ...rejected];
        ctx.recordTransport(
          ordered.flatMap((row) =>
            row.contender.entries.map((entry) => ({
              ...entry,
              path: entry.path.replace(
                "rate-limit-concurrent-secondary-b",
                "rate-limit-concurrent-secondary-a",
              ),
              responseBody: rankValues(entry.responseBody),
            })),
          ),
        );
        const foreign = await ctx
          .actor(`quota-foreign-${storage}-${round}`, contenders[0]!.profile)
          .client.signUp.email({
            email: ctx.uniqueEmail(`quota-foreign-${storage}-${round}`),
            password: "password123",
            name: "Independent Quota Owner",
            fetchOptions: { headers: { "x-forwarded-for": `192.0.2.${100 + round}` } },
          });
        expect(foreign.error).toBeNull();
        expect(foreign.data?.user.id).not.toBeOneOf(winnerIds);
        batches.push({
          storage,
          round,
          results: ordered.map((row) => rankValues(row.result)),
          authority,
          foreign,
        });
      }
    }
    return ctx.snapshot({ batches });
  },
  ["POST /sign-up/email", "GET /get-session"],
);
