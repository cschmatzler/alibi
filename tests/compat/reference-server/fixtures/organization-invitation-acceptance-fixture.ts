/** Genuine published invitation callbacks with application-owned SQL and barriers. */

import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";

export function organizationInvitationAcceptanceFixture(
  database: Database,
  shared: Parameters<typeof betterAuth>[0],
  origin: string,
) {
  let mode = "off";
  const receipts: unknown[] = [];
  const gates: { release: () => void; promise: Promise<void> }[] = [];

  function snapshot() {
    return {
      invitations: database
        .query(
          "SELECT id,organizationId,email,role,teamId,status,expiresAt,createdAt,inviterId FROM invitation ORDER BY rowid",
        )
        .all(),
      members: database
        .query("SELECT id,organizationId,userId,role,createdAt FROM member ORDER BY rowid")
        .all(),
      teams: database
        .query(
          "SELECT id,name,organizationId,memberCount,createdAt,updatedAt FROM team ORDER BY rowid",
        )
        .all(),
      teamMembers: database
        .query("SELECT id,teamId,userId,membershipKey,createdAt FROM teamMember ORDER BY rowid")
        .all(),
      sessions: database
        .query(
          "SELECT id,userId,token,expiresAt,createdAt,updatedAt,ipAddress,userAgent,impersonatedBy,activeOrganizationId,activeTeamId FROM session ORDER BY rowid",
        )
        .all(),
      organizations: database
        .query("SELECT id,name,slug,logo,metadata,createdAt FROM organization ORDER BY rowid")
        .all(),
    };
  }

  type Hooks = NonNullable<NonNullable<Parameters<typeof organization>[0]>["organizationHooks"]>;
  type Before = Parameters<NonNullable<Hooks["beforeAcceptInvitation"]>>[0];
  type After = Parameters<NonNullable<Hooks["afterAcceptInvitation"]>>[0];

  async function note(phase: string, context: unknown) {
    receipts.push({
      phase,
      context: structuredClone(context),
      snapshot: snapshot(),
    });
    applicationError(phase);
  }

  function applicationError(phase: string) {
    if (mode === `${phase}-error` || (mode === "sql-reset-api" && phase === "team-limit")) {
      throw new APIError("FORBIDDEN", {
        code: "INVITATION_APPLICATION_REJECTED",
        message: `Rejected ${phase}`,
      });
    }
    if (mode === `${phase}-internal`) {
      throw new Error(`Actual ${phase} application failure`);
    }
    if (mode === `${phase}-public500`) {
      throw new APIError("INTERNAL_SERVER_ERROR", {
        code: "PUBLIC_INVITATION_500",
        message: `Explicit ${phase} error`,
      });
    }
  }

  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "org-invitation-stage",
    "org-invitation-stage-no-team",
    "org-invitation-stage-limit-two",
  ]) {
    profiles.set(
      name,
      betterAuth({
        ...shared,
        database,
        baseURL: origin,
        basePath: `/__test/profiles/${name}/api/auth`,
        plugins: [
          organization({
            membershipLimit: name.endsWith("limit-two") ? 2 : 100,
            teams: {
              enabled: !name.endsWith("no-team"),
              defaultTeam: { enabled: false },
              maximumMembersPerTeam: async (context) => {
                if (mode !== "off") {
                  const invitationStatus = database
                    .query(
                      "SELECT id,status FROM invitation WHERE organizationId=? AND email=? ORDER BY rowid",
                    )
                    .all(context.organizationId, context.session.user.email.toLowerCase());
                  receipts.push({
                    phase: "team-limit",
                    context: structuredClone(context),
                    invitationStatus,
                  });
                  applicationError("team-limit");
                }
                return mode === "team-full" ? 1 : 100;
              },
            },
            organizationHooks: {
              async beforeAcceptInvitation(context: Before) {
                if (mode === "off") {
                  return;
                }
                await note("before-accept", context);
                if (mode === "pause-before") {
                  let release!: () => void;
                  const promise = new Promise<void>((resolve) => {
                    release = resolve;
                  });
                  gates.push({ release, promise });
                  await promise;
                }
              },
              async afterAcceptInvitation(context: After) {
                if (mode !== "off") {
                  await note("after-accept", context);
                }
              },
            },
          }),
        ],
      }),
    );
  }

  const triggerNames = [
    "invitation_stage_member",
    "invitation_stage_team",
    "invitation_stage_session",
    "invitation_stage_reset",
  ];
  return {
    profiles,
    reset() {
      for (const gate of gates.splice(0)) {
        gate.release();
      }

      mode = "off";
      receipts.length = 0;

      for (const name of triggerNames) {
        database.exec(`DROP TRIGGER IF EXISTS ${name}`);
      }
    },
    async configure(body: Record<string, unknown>) {
      for (const gate of gates.splice(0)) {
        gate.release();
      }

      mode = typeof body.mode === "string" ? body.mode : "record";
      receipts.length = 0;

      for (const name of triggerNames) {
        database.exec(`DROP TRIGGER IF EXISTS ${name}`);
      }

      database.exec(
        "CREATE TABLE IF NOT EXISTS __test_invitation_stage_guard(invitationId TEXT,userId TEXT);DELETE FROM __test_invitation_stage_guard",
      );

      if (mode.startsWith("sql-")) {
        const invitationId = String(body.invitationId);
        const userId = String(body.userId);

        if (
          !database.query("SELECT id FROM invitation WHERE id=?").get(invitationId) ||
          !database.query("SELECT id FROM user WHERE id=?").get(userId)
        ) {
          throw new Error("Guard requires actual invitation and user");
        }

        database
          .query("INSERT INTO __test_invitation_stage_guard(invitationId,userId) VALUES(?,?)")
          .run(invitationId, userId);

        if (mode === "sql-member" || mode === "sql-reset") {
          database.exec(
            "CREATE TRIGGER invitation_stage_member BEFORE INSERT ON member WHEN NEW.userId=(SELECT userId FROM __test_invitation_stage_guard) BEGIN SELECT RAISE(ABORT,'actual acceptance member veto'); END",
          );
        }

        if (mode === "sql-team") {
          database.exec(
            "CREATE TRIGGER invitation_stage_team BEFORE INSERT ON teamMember WHEN NEW.userId=(SELECT userId FROM __test_invitation_stage_guard) BEGIN SELECT RAISE(ABORT,'actual acceptance team veto'); END",
          );
        }

        if (mode === "sql-session") {
          database.exec(
            "CREATE TRIGGER invitation_stage_session BEFORE UPDATE OF activeOrganizationId ON session WHEN OLD.userId=(SELECT userId FROM __test_invitation_stage_guard) AND NEW.activeOrganizationId IS NOT NULL BEGIN SELECT RAISE(ABORT,'actual acceptance session veto'); END",
          );
        }

        if (mode === "sql-reset" || mode === "sql-reset-api") {
          database.exec(
            "CREATE TRIGGER invitation_stage_reset BEFORE UPDATE OF status ON invitation WHEN OLD.id=(SELECT invitationId FROM __test_invitation_stage_guard) AND OLD.status='accepted' AND NEW.status='pending' BEGIN SELECT RAISE(ABORT,'actual pending restoration veto'); END",
          );
        }
      }

      return Response.json({ configured: true });
    },
    release() {
      const gate = gates.shift();

      if (!gate) {
        return Response.json({ released: false }, { status: 400 });
      }

      gate.release();
      return Response.json({ released: true });
    },
    async state(waitFor: string | null) {
      if (waitFor) {
        for (let n = 0; n < 100 && gates.length < Number(waitFor); n++) {
          await Bun.sleep(10);
        }
      }
      return Response.json({
        receipts,
        snapshot: snapshot(),
        waiting: gates.length,
      });
    },
  };
}
