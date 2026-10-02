import { expect } from "bun:test";

import { apiKeyClient } from "@better-auth/api-key/client";
import { createAuthClient } from "better-auth/client";
import { z } from "zod";

import type { FixtureProfile } from "../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../support/scenario";
import { data, orgActor, state as organizationState, serverOperation, signUp } from "./helpers";

const userState = z
  .object({
    sessions: z.array(
      z
        .object({
          id: z.string(),
          token: z.string(),
          userId: z.string(),
          activeOrganizationId: z.string().nullable(),
        })
        .passthrough(),
    ),
  })
  .passthrough();

async function persisted(ctx: ScenarioContext, userId: string) {
  return userState.parse(await ctx.readUserState({ userId }));
}

const profile = "org-roles-delegated" as const;

compatScenario(
  "organization deletion retains extension rows and valid keys while clearing only its current selected token",
  async (ctx) => {
    const owner = await signUp(ctx, "delete-owner", profile);
    const foreign = await signUp(ctx, "delete-foreign", profile);

    const created = await owner.client.organization.create({
      name: "Delete target",
      slug: ctx.uniqueToken("delete-target"),
      metadata: { guard: "delete", large: 1e20 },
    });
    const org = data(created);
    const other = await foreign.client.organization.create({
      name: "Unrelated",
      slug: ctx.uniqueToken("delete-other"),
      metadata: { guard: "unrelated" },
    });
    const otherId = data(other).id;

    // A sibling session for the owner keeps the target selected; deletion must not clear it.
    const sibling = orgActor(ctx, "delete-sibling", profile);
    data(
      await sibling.signIn.email({
        email: owner.email,
        password: "password123",
      }),
    );
    data(await sibling.organization.setActive({ organizationId: org.id }));

    const invitation = await owner.client.organization.inviteMember({
      organizationId: org.id,
      email: ctx.uniqueEmail("pending-delete"),
      role: "member",
    });
    data(invitation);
    const role = await owner.client.organization.createRole({
      organizationId: org.id,
      role: "retained-role",
      permission: { team: ["create"] },
    });
    data(role);

    const keys = createAuthClient({
      baseURL: ctx.baseURL,
      plugins: [apiKeyClient()],
      fetchOptions: {
        customFetchImpl: ctx.actor("delete-owner", profile).fetch,
      },
    });
    const key = await keys.apiKey.create({
      configId: "organization",
      organizationId: org.id,
      name: "retained-org-key",
    });
    const keyData = data(key);
    const verify = async () =>
      ctx.rawRequest({
        path: "/__test/api-key/verify",
        method: "POST",
        json: { key: keyData.key, configId: "organization" },
      });
    const verifiedBefore = await verify();
    expect(verifiedBefore.body).toMatchObject({
      valid: true,
      key: { id: keyData.id, referenceId: org.id },
    });

    const before = await organizationState(ctx, org.id, profile);
    const foreignBefore = await organizationState(ctx, otherId, profile);
    const ownerBefore = await persisted(ctx, owner.user.id);
    const foreignUserBefore = await persisted(ctx, foreign.user.id);
    const selectedBefore = data(await owner.client.getSession());
    const selectedSessionId = selectedBefore.session.id;

    const deleted = await owner.client.organization.delete({
      organizationId: org.id,
    });
    const response = data(deleted);
    expect(response.id).toBe(org.id);
    expect(response.metadata).toBe('{"guard":"delete","large":100000000000000000000}');

    const after = await organizationState(ctx, org.id, profile);
    expect(after.parsed.members).toEqual([]);
    expect(after.parsed.invitations).toEqual([]);
    expect(after.parsed.teams).toEqual(before.parsed.teams);
    expect(after.parsed.teamMembers).toEqual(before.parsed.teamMembers);
    expect(after.parsed.roles).toEqual(before.parsed.roles);

    const ownerAfter = await persisted(ctx, owner.user.id);
    expect(ownerAfter.sessions).toHaveLength(2);
    expect(ownerAfter.sessions.filter((r) => r.activeOrganizationId === null)).toHaveLength(1);
    expect(ownerAfter.sessions.find((r) => r.id !== selectedSessionId)).toEqual(
      ownerBefore.sessions.find((r) => r.id !== selectedSessionId),
    );
    expect(ownerAfter.sessions.find((r) => r.id === selectedSessionId)).toMatchObject({
      activeOrganizationId: null,
    });

    const selectedAfter = data(await owner.client.getSession());
    expect(selectedAfter.session.activeOrganizationId).toBeNull();
    expect(selectedAfter.session.activeTeamId).toBe(selectedBefore.session.activeTeamId);
    expect(data(await sibling.getSession()).session.activeOrganizationId).toBe(org.id);
    expect(await persisted(ctx, foreign.user.id)).toEqual(foreignUserBefore);
    expect(await organizationState(ctx, otherId, profile)).toEqual(foreignBefore);

    // The organization key still verifies, but its owner can no longer read it.
    const verifiedAfter = await verify();
    expect(verifiedAfter.status).toBe(200);
    expect(verifiedAfter.body).toMatchObject({
      valid: true,
      key: { id: keyData.id, referenceId: org.id },
    });

    const deniedRead = await keys.apiKey.get({
      query: { configId: "organization", id: keyData.id },
    });
    expect(deniedRead.error?.status).toBe(403);

    return {
      created,
      other,
      invitation,
      role,
      key,
      verifiedBefore,
      before,
      foreignBefore,
      ownerBefore,
      selectedBefore,
      deleted,
      after,
      ownerAfter,
      selectedAfter,
      verifiedAfter,
      deniedRead,
    };
  },
  ["POST /organization/delete"],
);

compatScenario(
  "organization deletion rejects other tenants and member roles before changing any selection or record",
  async (ctx) => {
    const owner = await signUp(ctx, "permission-owner", profile);
    const member = await signUp(ctx, "permission-member", profile);
    const foreign = await signUp(ctx, "permission-foreign", profile);

    const created = await owner.client.organization.create({
      name: "Authorized",
      slug: ctx.uniqueToken("authorized"),
    });
    const id = data(created).id;
    const unrelated = await foreign.client.organization.create({
      name: "Foreign",
      slug: ctx.uniqueToken("foreign"),
    });
    const foreignId = data(unrelated).id;
    const invitation = await owner.client.organization.inviteMember({
      organizationId: id,
      email: member.email,
      role: "member",
    });
    const invitationId = data(invitation).id;
    data(await member.client.organization.acceptInvitation({ invitationId }));
    data(await member.client.organization.setActive({ organizationId: id }));

    const before = await organizationState(ctx, id, profile);
    const foreignBefore = await organizationState(ctx, foreignId, profile);
    const ownerBefore = await persisted(ctx, owner.user.id);
    const memberBefore = await persisted(ctx, member.user.id);
    const foreignUserBefore = await persisted(ctx, foreign.user.id);

    const memberDenied = await member.client.organization.delete({
      organizationId: id,
    });
    expect(memberDenied.error).toMatchObject({
      status: 403,
      code: "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION",
    });

    const foreignDenied = await foreign.client.organization.delete({
      organizationId: id,
    });
    expect(foreignDenied.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });

    const missing = await owner.client.organization.delete({
      organizationId: ctx.uniqueToken("missing"),
    });
    expect(missing.error).toMatchObject({
      status: 400,
      code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
    });

    const blank = await owner.client.organization.delete({
      organizationId: "",
    });
    expect(blank.error).toMatchObject({
      status: 400,
      code: "ORGANIZATION_NOT_FOUND",
    });

    expect(await organizationState(ctx, id, profile)).toEqual(before);
    expect(await organizationState(ctx, foreignId, profile)).toEqual(foreignBefore);
    expect(await persisted(ctx, owner.user.id)).toEqual(ownerBefore);
    expect(await persisted(ctx, member.user.id)).toEqual(memberBefore);
    expect(await persisted(ctx, foreign.user.id)).toEqual(foreignUserBefore);

    return {
      created,
      unrelated,
      invitation,
      before,
      ownerBefore,
      memberBefore,
      foreignUserBefore,
      memberDenied,
      foreignDenied,
      missing,
      blank,
    };
  },
  ["POST /organization/delete"],
);

compatScenario(
  "organization deletion body and media validation precede disabled configuration and session authentication",
  async (ctx) => {
    const observations = [];

    for (const selected of ["org-deletion-disabled", "org-teams"] as const) {
      const owner = await signUp(ctx, `validation-${selected}`, selected);
      const created = await owner.client.organization.create({
        name: "Guarded",
        slug: ctx.uniqueToken(selected),
      });
      const id = data(created).id;
      const before = await organizationState(ctx, id, selected);
      const principalBefore = await persisted(ctx, owner.user.id);

      const raw = async (body: unknown) =>
        ctx.rawRequest({
          path: `/__test/profiles/${selected}/api/auth/organization/delete`,
          method: "POST",
          json: body,
        });

      const invalid = await raw({ organizationId: 7 });
      expect(invalid.status).toBe(400);
      expect(invalid.body).toMatchObject({
        code: "VALIDATION_ERROR",
        message: "[body.organizationId] Invalid input: expected string, received number",
      });

      const missing = await raw({});
      expect(missing.status).toBe(400);
      expect(missing.body).toMatchObject({ code: "VALIDATION_ERROR" });

      const media = await ctx.rawRequest({
        path: `/__test/profiles/${selected}/api/auth/organization/delete`,
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: JSON.stringify({ organizationId: id }),
      });
      expect(media.status).toBe(415);
      expect(media.body).toMatchObject({ code: "UNSUPPORTED_MEDIA_TYPE" });

      // A well-formed request only then reaches the disabled configuration or session check.
      const guest = await raw({ organizationId: id });

      if (selected === "org-deletion-disabled") {
        expect(guest.status).toBe(404);
        expect(guest.body).toMatchObject({
          code: "ORGANIZATION_DELETION_DISABLED",
        });

        const ownerDenied = await owner.client.organization.delete({
          organizationId: id,
        });
        expect(ownerDenied.error).toMatchObject({
          status: 404,
          code: "ORGANIZATION_DELETION_DISABLED",
        });

        observations.push({ ownerDenied });
      } else {
        expect(guest.status).toBe(401);
        expect(guest.body).toBeNull();
      }

      expect(await organizationState(ctx, id, selected)).toEqual(before);
      expect(await persisted(ctx, owner.user.id)).toEqual(principalBefore);

      observations.push({
        selected,
        created,
        before,
        invalid,
        missing,
        media,
        guest,
      });
    }

    return observations;
  },
  ["POST /organization/delete"],
);

compatScenario(
  "organization deletion of a real legacy orphan clears only the authenticated token before empty missing-row rejection",
  async (ctx) => {
    const owner = await signUp(ctx, "orphan-owner", profile);
    const created = await owner.client.organization.create({
      name: "Legacy orphan",
      slug: ctx.uniqueToken("legacy-orphan"),
    });
    const id = data(created).id;

    const sibling = orgActor(ctx, "orphan-sibling", profile);
    data(
      await sibling.signIn.email({
        email: owner.email,
        password: "password123",
      }),
    );
    data(await sibling.organization.setActive({ organizationId: id }));
    const active = data(await owner.client.getSession());
    const activeSessionId = active.session.id;

    const before = await organizationState(ctx, id, profile);
    const orphan = await serverOperation(
      ctx,
      { operation: "orphan-organization", organizationId: id },
      profile,
    );
    expect(orphan.status).toBe(200);
    expect(await organizationState(ctx, id, profile)).toEqual(before);

    const sessionsBefore = await persisted(ctx, owner.user.id);
    const rejected = await owner.client.$fetch("/organization/delete", {
      method: "POST",
      body: { organizationId: id },
    });
    expect(rejected.error?.status).toBe(400);

    // The rejection still cleared the selection on the authenticated token only.
    const after = await persisted(ctx, owner.user.id);
    expect(after.sessions.find((r) => r.id === activeSessionId)).toMatchObject({
      activeOrganizationId: null,
    });
    expect(after.sessions.find((r) => r.id !== activeSessionId)).toEqual(
      sessionsBefore.sessions.find((r) => r.id !== activeSessionId),
    );
    expect(await organizationState(ctx, id, profile)).toEqual(before);

    const selectedAfter = data(await owner.client.getSession());
    expect(selectedAfter.session.activeTeamId).toBe(active.session.activeTeamId);

    return {
      created,
      active,
      before,
      orphan,
      sessionsBefore,
      rejected: ctx.snapshot(rejected),
      after,
      selectedAfter,
    };
  },
  ["POST /organization/delete"],
);

compatScenario(
  "organization deletion leaves an unrelated active organization selected when deleting another owned organization",
  async (ctx) => {
    const selected: FixtureProfile = "org-teams";
    const owner = await signUp(ctx, "unselected-owner", selected);
    const first = await owner.client.organization.create({
      name: "Delete unselected",
      slug: ctx.uniqueToken("unselected"),
    });
    const id = data(first).id;
    const second = await owner.client.organization.create({
      name: "Keep selected",
      slug: ctx.uniqueToken("selected"),
    });
    const otherId = data(second).id;

    const before = await persisted(ctx, owner.user.id);
    const otherBefore = await organizationState(ctx, otherId, selected);
    const active = data(await owner.client.getSession());

    const deleted = await owner.client.organization.delete({
      organizationId: id,
    });
    expect(data(deleted).id).toBe(id);

    expect(await persisted(ctx, owner.user.id)).toEqual(before);
    expect(data(await owner.client.getSession()).session).toEqual(active.session);
    expect(await organizationState(ctx, otherId, selected)).toEqual(otherBefore);
    expect((await organizationState(ctx, id, selected)).parsed.members).toEqual([]);

    return { first, second, before, active, otherBefore, deleted };
  },
  ["POST /organization/delete"],
);
