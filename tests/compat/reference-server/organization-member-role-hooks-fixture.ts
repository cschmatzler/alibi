/** Application-owned update callbacks; pinned HTTP guards and adapter remain active. */

import type { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";

type Actor = { id: string; email: string; name?: string | null };
type Member = { id: string; organizationId: string; userId: string; role: string; createdAt: Date };
export function organizationMemberRoleHooksFixture(
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
          "SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.id",
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
  function note(
    phase: string,
    context: {
      organization: unknown;
      user: Actor;
      member: Member;
      newRole?: string;
      previousRole?: string;
    },
  ) {
    receipts.push({
      phase,
      newRole: context.newRole ?? null,
      previousRole: context.previousRole ?? null,
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
    if (mode === `reject-${phase}`)
      throw new APIError("BAD_REQUEST", {
        code: "ROLE_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });
  }
  const hooks = {
    async beforeUpdateMemberRole(context: {
      organization: unknown;
      user: Actor;
      member: Member;
      newRole: string;
    }) {
      note("before-role", context);
      if (mode === "pause-before") await gate;
      const ctx = await auth.$context;
      if (mode === "delete-row")
        await ctx.adapter.delete({
          model: "member",
          where: [{ field: "id", value: context.member.id }],
        });
      if (mode === "mutate-target") {
        await ctx.adapter.update({
          model: "user",
          where: [{ field: "id", value: context.user.id }],
          update: { name: "Stored Target Name" },
        });
        await ctx.adapter.update({
          model: "member",
          where: [{ field: "id", value: context.member.id }],
          update: { role: "member" },
        });
      }
      if (mode === "patch") return { data: { role: "hook-unregistered-role" } };
      if (mode === "empty") return { data: { role: "" } };
      if (mode === "absent") return { data: {} };
    },
    async afterUpdateMemberRole(context: {
      organization: unknown;
      user: Actor;
      member: Member;
      previousRole: string;
    }) {
      note("after-role", context);
    },
  };
  const auth = betterAuth({
    ...shared,
    database,
    baseURL: origin,
    basePath: "/__test/profiles/org-member-role-hooks/api/auth",
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
      )
        await Bun.sleep(10);
      return Response.json({ receipts, snapshot: snapshot() });
    },
  };
}
