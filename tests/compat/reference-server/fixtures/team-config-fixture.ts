import type { Database } from "bun:sqlite";

import { APIError } from "better-auth/api";

export const TEAM_CONFIG_PROFILES = ["org-team-hooks", "org-team-factory"] as const;
const receipts = new Map<string, unknown[]>();
export function teamConfigSnapshot(database: Database) {
  return {
    organizations: database.query("SELECT id,name,slug FROM organization ORDER BY slug,id").all(),
    members: database
      .query(
        "SELECT m.id,m.organizationId,m.userId,m.role FROM member m JOIN organization o ON o.id=m.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,u.email,m.id",
      )
      .all(),
    teams: database
      .query(
        "SELECT t.id,t.organizationId,t.name,t.memberCount FROM team t JOIN organization o ON o.id=t.organizationId ORDER BY o.slug,t.name,t.id",
      )
      .all(),
    teamMembers: database
      .query(
        "SELECT m.id,m.teamId,m.userId FROM teamMember m JOIN team t ON t.id=m.teamId JOIN organization o ON o.id=t.organizationId JOIN user u ON u.id=m.userId ORDER BY o.slug,t.name,u.email,m.id",
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
export function teamConfigEvidence(database: Database, organizationId: string) {
  return { receipts: receipts.get(organizationId) ?? [], snapshot: teamConfigSnapshot(database) };
}
export function teamConfigOptions(name: string, database: Database) {
  const factory = name === "org-team-factory";
  const configured = name === "org-team-hooks" || factory;
  type Data = {
    organization: { id: string; name: string };
    user?: { id: string; email: string; name: string };
    team?: { id?: string; name?: string; organizationId?: string };
    teamMember?: { id?: string; teamId: string; userId: string };
    updates?: { name?: string };
  };
  async function note(phase: string, data: Data) {
    const value: Record<string, unknown> = {
      phase,
      organization: { id: data.organization.id, name: data.organization.name },
      user: data.user ? { id: data.user.id, email: data.user.email, name: data.user.name } : null,
      ...(data.team
        ? {
            team: {
              ...(data.team.id ? { id: data.team.id } : {}),
              name: data.team.name,
              organizationId: data.team.organizationId,
            },
          }
        : {}),
      ...(data.teamMember
        ? {
            teamMember: {
              ...(data.teamMember.id ? { id: data.teamMember.id } : {}),
              teamId: data.teamMember.teamId,
              userId: data.teamMember.userId,
            },
          }
        : {}),
      ...(data.updates ? { updates: data.updates } : {}),
      snapshot: teamConfigSnapshot(database),
    };
    const list = receipts.get(data.organization.id) ?? [];
    list.push(value);
    receipts.set(data.organization.id, list);
    const marker =
      data.updates?.name ?? (phase.includes("member") ? data.user?.name : data.team?.name) ?? "";
    if (marker.includes(`reject-${phase}`) || marker.includes(`error-${phase}`)) {
      // An actual application write is independent of the failing endpoint write.
      const id = crypto.randomUUID();
      database
        .query("INSERT INTO team(id,organizationId,name,createdAt,memberCount) VALUES (?,?,?,?,0)")
        .run(id, data.organization.id, `Independent:${phase}`, new Date().toISOString());
      value.independentSnapshot = teamConfigSnapshot(database);
      if (marker.includes(`error-${phase}`)) throw new Error(`Callback error ${phase}`);
      throw new APIError("BAD_REQUEST", {
        code: "TEAM_HOOK_REJECTED",
        message: `Rejected ${phase}`,
      });
    }
  }
  return {
    ...(configured
      ? {
          organizationHooks: {
            beforeCreateTeam: async (data: Data) => {
              await note("before-create", data);
              return { data: { name: `Hook:${data.team!.name}` } };
            },
            afterCreateTeam: async (data: Data) => note("after-create", data),
            beforeUpdateTeam: async (data: Data) => {
              await note("before-update", data);
              return { data: { name: `Hook:${data.updates!.name}` } };
            },
            afterUpdateTeam: async (data: Data) => note("after-update", data),
            beforeDeleteTeam: async (data: Data) => note("before-delete", data),
            afterDeleteTeam: async (data: Data) => note("after-delete", data),
            beforeAddTeamMember: async (data: Data) => {
              await note("before-add-member", data);
              return { data: { teamId: "ignored-team", userId: "ignored-user" } };
            },
            afterAddTeamMember: async (data: Data) => note("after-add-member", data),
            beforeRemoveTeamMember: async (data: Data) => note("before-remove-member", data),
            afterRemoveTeamMember: async (data: Data) => note("after-remove-member", data),
          },
        }
      : {}),
    teams: {
      enabled: true,
      allowRemovingAllTeams: true,
      defaultTeam: {
        enabled: true,
        ...(factory
          ? {
              customCreateDefaultTeam: async (
                organization: { id: string; name: string },
                ctx: any,
              ) => {
                const value = {
                  phase: "factory",
                  organization: { id: organization.id, name: organization.name },
                  user: {
                    id: ctx.context.session.user.id,
                    email: ctx.context.session.user.email,
                    name: ctx.context.session.user.name,
                  },
                  session: {
                    id: ctx.context.session.session.id,
                    userId: ctx.context.session.session.userId,
                    activeOrganizationId: ctx.context.session.session.activeOrganizationId ?? null,
                    activeTeamId: ctx.context.session.session.activeTeamId ?? null,
                  },
                  request: {
                    method: ctx.request?.method ?? null,
                    header: ctx.headers?.get("x-team-factory") ?? null,
                  },
                  basePath: ctx.context.options.basePath,
                  snapshot: teamConfigSnapshot(database),
                };
                const list = receipts.get(organization.id) ?? [];
                list.push(value);
                receipts.set(organization.id, list);
                const team = await ctx.context.adapter.create({
                  model: "team",
                  data: {
                    organizationId: organization.id,
                    name: `Factory:${organization.name}`,
                    createdAt: new Date(),
                  },
                });
                if (organization.name === "Factory error") {
                  throw new Error("Factory failed after independent write");
                }
                return team;
              },
            }
          : {}),
      },
    },
  };
}
