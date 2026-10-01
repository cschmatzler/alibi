/** Application callbacks observe the pinned handler and actual persisted rows. */
import { betterAuth } from "better-auth";
import { organization } from "better-auth/plugins";
import { APIError } from "better-auth/api";
import type { Database } from "bun:sqlite";
export function organizationDeletionHooksFixture(
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
        .query(
          "SELECT id,name,slug,logo,metadata FROM organization ORDER BY slug,id",
        )
        .all(),
      members: database
        .query(
          "SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN user u ON u.id=m.userId ORDER BY u.email,m.role,m.id",
        )
        .all(),
      invitations: database
        .query(
          "SELECT id,organizationId,status,email FROM invitation ORDER BY email,id",
        )
        .all(),
      teams: database
        .query("SELECT id,organizationId,name FROM team ORDER BY name,id")
        .all(),
      teamMembers: database
        .query(
          "SELECT m.id,m.teamId,m.userId FROM teamMember m JOIN team t ON t.id=m.teamId JOIN user u ON u.id=m.userId ORDER BY t.name,u.email,m.id",
        )
        .all(),
      sessions: database
        .query(
          "SELECT s.id,s.userId,s.activeOrganizationId,s.activeTeamId FROM session s JOIN user u ON u.id=s.userId ORDER BY u.email,s.createdAt,s.id",
        )
        .all(),
      users: database
        .query("SELECT id,email,name FROM user ORDER BY email,id")
        .all(),
    };
  }
  type Data = {
    organization: Record<string, unknown>;
    user: { id: string; email: string; name: string };
  };
  type Hooks = NonNullable<
    NonNullable<Parameters<typeof organization>[0]>["organizationHooks"]
  >;
  type Context = Parameters<NonNullable<Hooks["beforeDeleteOrganization"]>>[1];
  async function note(phase: string, data: Data, ctx: Context) {
    if (!ctx)
      throw new Error("Deletion hook did not receive its endpoint context");
    await Promise.resolve();
    receipts.push({
      phase,
      organization: data.organization,
      user: { id: data.user.id, email: data.user.email, name: data.user.name },
      session: ctx.context.session
        ? {
            id: ctx.context.session.session.id,
            userId: ctx.context.session.session.userId,
            activeOrganizationId:
              ctx.context.session.session.activeOrganizationId ?? null,
            activeTeamId: ctx.context.session.session.activeTeamId ?? null,
          }
        : null,
      header: ctx.headers?.get("x-delete-hook") ?? null,
      request: ctx.request
        ? {
            method: ctx.request.method,
            path: ctx.path,
            header: ctx.request.headers.get("x-delete-hook"),
          }
        : null,
      snapshot: snapshot(),
    });
    if (mode === `reject-${phase}`)
      throw new APIError("BAD_REQUEST", {
        code: "DELETION_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });
  }
  const hooks = {
    async beforeDeleteOrganization(data: Data, ctx: Context) {
      if (mode === "write-before") {
        const context = await profiles.get("org-deletion-hooks")!.$context;
        await context.adapter.update({
          model: "organization",
          where: [{ field: "id", value: String(data.organization.id) }],
          update: { name: "Written By Hook" },
        });
      }
      await note("before", data, ctx);
      if (mode === "pause-before") await gate;
    },
    async afterDeleteOrganization(data: Data, ctx: Context) {
      await note("after", data, ctx);
    },
  };
  const profiles = new Map(
    ["org-deletion-hooks", "org-deletion-hooks-disabled"].map((name) => [
      name,
      betterAuth({
        ...shared,
        database,
        baseURL: origin,
        basePath: `/__test/profiles/${name}/api/auth`,
        plugins: [
          organization({
            teams: { enabled: true },
            disableOrganizationDeletion: name.endsWith("disabled"),
            organizationHooks: hooks,
          }),
        ],
      }),
    ]),
  );
  return {
    profiles,
    configure(body: Record<string, unknown>) {
      release?.();
      mode = String(body.mode ?? "record");
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
        let i = 0;
        waitFor &&
        i < 100 &&
        !receipts.some((r) => (r as { phase: string }).phase === waitFor);
        i++
      )
        await Bun.sleep(10);
      return Response.json({ receipts, snapshot: snapshot() });
    },
    async server(body: Record<string, unknown>, supplied: Headers) {
      const profile = profiles.get(String(body.profile));
      if (!profile)
        return Response.json(
          { message: "Unknown fixture profile" },
          { status: 400 },
        );
      try {
        return Response.json(
          await profile.api.deleteOrganization({
            headers:
              body.headerCase === "mixed"
                ? Object.fromEntries(
                    [...supplied].map(([key, value]) => [
                      key === "cookie"
                        ? "Cookie"
                        : key === "x-delete-hook"
                          ? "X-Delete-Hook"
                          : key,
                      value,
                    ]),
                  )
                : supplied,
            body: { organizationId: String(body.organizationId) },
          }),
        );
      } catch (error) {
        const result = error as { statusCode?: number; body?: unknown };
        return result.body === undefined
          ? new Response(null, {
              status: result.statusCode ?? 500,
              headers: { "content-type": "application/json" },
            })
          : Response.json(result.body, { status: result.statusCode ?? 500 });
      }
    },
  };
}
