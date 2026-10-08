import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
import { orgActor } from "../../plugins/organization/helpers";
for (const mode of ["uuid", "serial", "custom", "false", "throw"] as const) {
  compatScenario(
    `database ID strategy ${mode} owns real signup identifiers and failure writes`,
    async (ctx) => {
      const actor = ctx.actor("owner", `id-strategy-${mode}`);
      const before = (await ctx.rawRequest({ path: `/__test/id-strategy/${mode}/state` }))
        .body as any;
      expect(before.users).toEqual([]);
      const signup = await actor.client.signUp.email({
        email: ctx.uniqueEmail("id-strategy"),
        password: "password123",
        name: "ID strategy",
      });
      let after = (await ctx.rawRequest({ path: `/__test/id-strategy/${mode}/state` })).body as any;
      if (mode === "false" || mode === "throw") {
        expect(signup.error?.status).toBe(422);
        expect(after.accounts).toEqual([]);
        expect(after.sessions).toEqual([]);
        if (mode === "throw") expect(after.users).toEqual([]);
        expect((await actor.client.getSession()).data).toBeNull();
        return ctx.snapshot({ signup, before, after });
      }
      expect(signup.error).toBeNull();
      const reset = await actor.client.requestPasswordReset({
        email: signup.data!.user.email,
        redirectTo: "/reset",
      });
      expect(reset.error).toBeNull();
      after = (await ctx.rawRequest({ path: `/__test/id-strategy/${mode}/state` })).body as any;
      expect(after.verification).toHaveLength(1);
      const session = await actor.client.getSession();
      expect(session.data!.user.id).toBe(signup.data!.user.id);
      expect(after.users).toHaveLength(1);
      expect(after.accounts).toHaveLength(1);
      expect(after.sessions).toHaveLength(1);
      expect(String(after.users[0].id)).toBe(signup.data!.user.id);
      expect(String(after.sessions[0].userId)).toBe(signup.data!.user.id);
      for (const [model, rows] of [
        ["user", after.users],
        ["account", after.accounts],
        ["session", after.sessions],
        ["verification", after.verification],
      ] as const) {
        const id = String(rows[0].id);
        if (mode === "uuid") {
          expect(id).toMatch(
            /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
          );
        } else if (mode === "serial") expect(id).toBe("1");
        else expect(id).toMatch(new RegExp(`^${model}_application_[1-4]$`));
      }
      if (mode === "custom") {
        expect(after.events.map((e: any) => e.model).sort()).toEqual([
          "account",
          "session",
          "user",
          "verification",
        ]);
      }
      let invitationPolicy: unknown;
      if (mode === "uuid" || mode === "serial") {
        const ownerOrg = orgActor(ctx, "owner", `id-strategy-${mode}`);
        const invitee = ctx.actor("invitee", `id-strategy-${mode}`);
        const invited = await invitee.client.signUp.email({
          email: ctx.uniqueEmail("id-invitee"),
          password: "password123",
          name: "Invitee",
        });
        expect(invited.error).toBeNull();
        const organization = await ownerOrg.organization.create({
          name: "ID organization",
          slug: ctx.uniqueToken("id-org"),
        });
        expect(organization.error).toBeNull();
        const invitation = await ownerOrg.organization.inviteMember({
          organizationId: organization.data!.id,
          email: invited.data!.user.email,
          role: "member",
        });
        expect(invitation.error).toBeNull();
        if (mode === "serial") expect(invitation.data!.id).toBe("1");
        else expect(invitation.data!.id).toMatch(/^[0-9a-f-]{36}$/);
        const inviteeOrg = orgActor(ctx, "invitee", `id-strategy-${mode}`);
        const lookup = await inviteeOrg.organization.getInvitation({
          query: { id: invitation.data!.id },
        });
        const accept = await inviteeOrg.organization.acceptInvitation({
          invitationId: invitation.data!.id,
        });
        if (mode === "serial") {
          expect(lookup.error).toMatchObject({
            status: 403,
            code: "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
          });
          expect(accept.error).toMatchObject({
            status: 403,
            code: "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION",
          });
        } else {
          expect(lookup.error).toBeNull();
          expect(accept.error).toBeNull();
        }
        invitationPolicy = { organization, invitation, lookup, accept };
      }
      return ctx.snapshot({ signup, session, before, after, invitationPolicy });
    },
    ["POST /sign-up/email", "GET /get-session"],
  );
}
