/** Application-owned update callbacks; pinned HTTP guards and adapter remain active. */

import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";

type Actor = { id: string; email: string; name?: string | null };
type Member = { id: string; organizationId: string; userId: string; role: string; createdAt: Date };

export function organizationUpdateHooksFixture(
  database: Database,
  shared: Parameters<typeof betterAuth>[0],
  origin: string,
) {
  let mode = "record";
  const receipts: unknown[] = [];
  let release: (() => void) | undefined;
  let gate = Promise.resolve();

  function snapshot() {
    return {
      organizations: database
        .query("SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id")
        .all(),
      members: database
        .query(
          "SELECT m.id,m.organizationId,m.userId,m.role FROM member m LEFT JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.id",
        )
        .all(),
      sessions: database
        .query(
          "SELECT s.id,s.userId,s.activeOrganizationId,s.activeTeamId FROM session s JOIN user u ON u.id=s.userId ORDER BY u.email,s.createdAt,s.id",
        )
        .all(),
      users: database.query("SELECT id,email,name FROM user ORDER BY email,id").all(),
    };
  }

  function note(phase: string, context: { organization: unknown; user: Actor; member: Member }) {
    receipts.push({
      phase,
      organization: context.organization,
      user: { id: context.user.id, email: context.user.email, name: context.user.name },
      member: {
        id: context.member.id,
        organizationId: context.member.organizationId,
        userId: context.member.userId,
        role: context.member.role,
      },
      snapshot: snapshot(),
    });
    if (mode === `reject-${phase}`) {
      throw new APIError("BAD_REQUEST", {
        code: "UPDATE_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });
    }
  }

  const hooks = {
    async beforeUpdateOrganization(context: {
      organization: Record<string, unknown>;
      user: Actor;
      member: Member;
    }) {
      note("before-update", context);

      if (mode === "pause-before") {
        await gate;
      }

      if (mode === "raw-metadata") {
        const n = (context.organization.metadata as Record<string, unknown>).n;
        const numberClass =
          n === Infinity
            ? "positive-infinity"
            : n === -Infinity
              ? "negative-infinity"
              : Object.is(n, -0)
                ? "negative-zero"
                : "other";
        return {
          data: {
            name: numberClass,
            metadata: { original: n, patched: n, negativeZero: Object.is(n, -0) },
          },
        };
      }

      if (mode === "patch") {
        return {
          data: { name: "Hooked Update", logo: null, metadata: { guard: "hooked-update" } },
        };
      }

      if (mode === "null-metadata") {
        return { data: { metadata: null, logo: null } };
      }

      if (mode === "empty-metadata") {
        return { data: { metadata: {} } };
      }

      if (mode === "absent-metadata") {
        return { data: { name: "Patched Without Metadata" } };
      }

      if (mode === "empty-name") {
        return { data: { name: "" } };
      }

      const ctx = await auth.$context;

      if (mode === "mutate-authority") {
        await ctx.adapter.update({
          model: "user",
          where: [{ field: "id", value: context.user.id }],
          update: { name: "Stored New Name" },
        });
        await ctx.adapter.update({
          model: "member",
          where: [{ field: "id", value: context.member.id }],
          update: { role: "member" },
        });
      }

      if (mode === "delete-row") {
        const where = [{ field: "organizationId", value: context.member.organizationId }];
        await ctx.adapter.deleteMany({ model: "member", where });
        await ctx.adapter.deleteMany({ model: "invitation", where });
        await ctx.adapter.delete({
          model: "organization",
          where: [{ field: "id", value: context.member.organizationId }],
        });
      }
    },
    async afterUpdateOrganization(context: { organization: unknown; user: Actor; member: Member }) {
      note("after-update", context);
    },
  };
  const auth = betterAuth({
    ...shared,
    database,
    baseURL: origin,
    basePath: "/__test/profiles/org-update-hooks/api/auth",
    plugins: [organization({ organizationHooks: hooks })],
  });
  return {
    auth,
    configure(body: Record<string, unknown>) {
      release?.();
      mode = typeof body.mode === "string" ? body.mode : "record";
      receipts.length = 0;
      gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      return Response.json({ configured: true });
    },
    storage(body: Record<string, unknown>) {
      database.exec("DROP TRIGGER IF EXISTS default_organization_update");
      if (body.mode === "delete" || body.mode === "ignore" || body.mode === "veto") {
        const mode = body.mode;
        const id = String(body.organizationId).replaceAll("'", "''");
        const action =
          mode === "delete"
            ? "DELETE FROM member WHERE organizationId=OLD.id; DELETE FROM invitation WHERE organizationId=OLD.id; DELETE FROM organization WHERE id=OLD.id; SELECT RAISE(IGNORE);"
            : mode === "ignore"
              ? "SELECT RAISE(IGNORE);"
              : "SELECT RAISE(ABORT,'organization update veto');";
        database.exec(
          `CREATE TRIGGER default_organization_update BEFORE UPDATE ON organization WHEN OLD.id='${id}' BEGIN ${action} END`,
        );
      }
      return Response.json({ configured: true });
    },
    release() {
      release?.();
      return Response.json({ released: true });
    },
    async state(waitFor: string | null) {
      for (
        let attempt = 0;
        waitFor &&
        attempt < 100 &&
        !receipts.some((receipt) => (receipt as { phase: string }).phase === waitFor);
        attempt++
      ) {
        await Bun.sleep(10);
      }
      return Response.json({ receipts, snapshot: snapshot() });
    },
  };
}
