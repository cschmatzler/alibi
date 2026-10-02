/** Immutable application policies over the unchanged published server-only API. */

import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";

export const MEMBERSHIP_PROFILES = [
  "org-membership-default",
  "org-membership-none",
  "org-membership-zero",
  "org-membership-nan",
  "org-membership-one",
  "org-membership-fractional",
  "org-membership-negative",
  "org-membership-infinity",
  "org-membership-resolver-zero",
  "org-membership-resolver-nan",
  "org-membership-resolver-fractional",
  "org-membership-resolver-error",
  "org-membership-page-one",
  "org-membership-page-zero",
  "org-membership-resolver-zero-team-limit",
  "org-membership-team-limit",
  "org-membership-pending-one",
] as const;

export function organizationMembershipPolicyFixture(
  database: Database,
  shared: Parameters<typeof betterAuth>[0],
  origin: string,
) {
  const receipts: unknown[] = [];
  const normalize = (rows: Record<string, unknown>[]) =>
    rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).map(([key, value]) => [
          key,
          /(?:At)$/.test(key) && value !== null ? new Date(String(value)).toISOString() : value,
        ]),
      ),
    );

  function snapshot() {
    return {
      organizations: database
        .query("SELECT id,name,slug,logo,metadata FROM organization ORDER BY rowid")
        .all(),
      members: normalize(
        database.query("SELECT * FROM member ORDER BY rowid").all() as Record<string, unknown>[],
      ),
      invitations: normalize(
        database.query("SELECT * FROM invitation ORDER BY rowid").all() as Record<
          string,
          unknown
        >[],
      ),
      teams: normalize(
        database.query("SELECT * FROM team ORDER BY rowid").all() as Record<string, unknown>[],
      ),
    };
  }

  const profiles = new Map(
    MEMBERSHIP_PROFILES.map((name) => {
      const fixed =
        name === "org-membership-none"
          ? undefined
          : name === "org-membership-zero"
            ? 0
            : name === "org-membership-nan"
              ? NaN
              : name === "org-membership-one" || name === "org-membership-pending-one"
                ? 1
                : name === "org-membership-fractional"
                  ? 1.5
                  : name === "org-membership-negative"
                    ? -0.5
                    : name === "org-membership-infinity"
                      ? Infinity
                      : 100;
      const policy = name.includes("resolver")
        ? async (user: Record<string, unknown>, organization: Record<string, unknown>) => {
            await Promise.resolve();
            receipts.push({
              phase: "membership-limit",
              profile: name,
              user: structuredClone(user),
              organization: structuredClone(organization),
              snapshot: snapshot(),
            });

            if (name.endsWith("error")) {
              throw new APIError("BAD_REQUEST", {
                code: "MEMBERSHIP_POLICY_REJECTED",
                message: "Actual membership policy rejected",
              });
            }

            return name.includes("resolver-zero") ? 0 : name.endsWith("nan") ? NaN : 1.5;
          }
        : fixed;
      const auth = betterAuth({
        ...shared,
        database,
        baseURL: origin,
        basePath: `/__test/profiles/${name}/api/auth`,
        ...(name.includes("page-")
          ? {
              advanced: {
                ...shared.advanced,
                database: {
                  ...shared.advanced?.database,
                  defaultFindManyLimit: name.endsWith("one") ? 1 : 0,
                },
              },
            }
          : {}),
        plugins: [
          organization({
            membershipLimit: policy,
            invitationLimit: name === "org-membership-pending-one" ? 1 : 100,
            requireEmailVerificationOnInvitation: true,
            teams: {
              enabled: true,
              defaultTeam: { enabled: false },
              ...(name.endsWith("team-limit")
                ? {
                    maximumMembersPerTeam: async (context) => {
                      await Promise.resolve();
                      receipts.push({
                        phase: "team-limit",
                        context: structuredClone(context),
                        snapshot: snapshot(),
                      });
                      return 0;
                    },
                  }
                : {}),
            },
          }),
        ],
      });
      return [name, auth] as const;
    }),
  );
  return {
    profiles,
    state() {
      return Response.json({ receipts, snapshot: snapshot() });
    },
    configure() {
      receipts.length = 0;
      return Response.json({ configured: true });
    },
    async server(request: Request) {
      const input = (await request.json()) as {
        profile: (typeof MEMBERSHIP_PROFILES)[number];
        useHeaders?: boolean;
        body: Parameters<ReturnType<typeof organization>["endpoints"]["addMember"]>[0]["body"];
      };
      const auth = profiles.get(input.profile);

      if (!auth) {
        return new Response(null, { status: 404 });
      }

      try {
        return Response.json(
          await auth.api.addMember({
            body: input.body,
            ...(input.useHeaders ? { headers: request.headers } : {}),
          }),
        );
      } catch (error) {
        if (error instanceof APIError) {
          return error.body
            ? Response.json(error.body, { status: error.statusCode })
            : new Response(null, { status: error.statusCode });
        }
        return new Response(null, { status: 500 });
      }
    },
  };
}
