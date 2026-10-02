import { expect } from "bun:test";
import { z } from "zod";
import { compatScenario } from "../../support/scenario";
import {
  type CompatContext,
  data,
  orgActor,
  organizationActor,
  serverOperation,
  signUp,
  signUpUser,
  state,
} from "./helpers";

const verificationEmail = z.object({ token: z.string().min(1) });

async function readVerificationToken(ctx: CompatContext, email: string) {
  return verificationEmail.parse(await ctx.readVerificationEmail({ email })).token;
}

compatScenario(
  "organization invitation happy path covers list and accept flows",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-invite-owner", "Owner");
    const invitee = await signUpUser(ctx, "invitee", "organization-invite-invitee", "Invitee");
    const slug = ctx.uniqueToken("organization-invite-org");

    const organization = await owner.orgClient.organization.create({
      name: "Invite Org",
      slug,
    });
    const organizationId = organization.data?.id;
    const invitation = await owner.orgClient.organization.inviteMember({
      organizationId: organizationId ?? "",
      email: invitee.email,
      role: "member",
    });
    const invitationId = invitation.data?.id;
    const getInvitation = await invitee.orgClient.organization.getInvitation({
      query: {
        id: invitationId ?? "",
      },
    });
    const listInvitations = await owner.orgClient.organization.listInvitations({
      query: {
        organizationId,
      },
    });

    // The invitee cannot list their own invitations until their email is verified.
    const listUserInvitations = await invitee.orgClient.organization.listUserInvitations();
    expect(listUserInvitations.error).toMatchObject({
      status: 403,
      code: "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    });

    await invitee.client.sendVerificationEmail({ email: invitee.email });
    const verificationToken = await readVerificationToken(ctx, invitee.email);
    const verifyEmail = await invitee.client.verifyEmail({ query: { token: verificationToken } });
    expect(verifyEmail.error).toBeNull();

    const verifiedListUserInvitations = await invitee.orgClient.organization.listUserInvitations();
    expect(verifiedListUserInvitations.error).toBeNull();
    expect(verifiedListUserInvitations.data).toHaveLength(1);
    expect(verifiedListUserInvitations.data?.[0]).toMatchObject({
      id: invitationId,
      email: invitee.email,
      organizationId,
      organizationName: "Invite Org",
      status: "pending",
    });

    const acceptInvitation = await invitee.orgClient.organization.acceptInvitation({
      invitationId: invitationId ?? "",
    });
    const fullOrganizationAfterAccept = await invitee.orgClient.organization.getFullOrganization();
    expect(acceptInvitation.error).toBeNull();

    const invitationsAfterAccept = await invitee.orgClient.organization.listUserInvitations();
    expect(invitationsAfterAccept.data).toEqual([]);

    return {
      organization: ctx.snapshot(organization),
      invitation: ctx.snapshot(invitation),
      getInvitation: ctx.snapshot(getInvitation),
      listInvitations: ctx.snapshot(listInvitations),
      listUserInvitations: ctx.snapshot(listUserInvitations),
      verifyEmail: ctx.snapshot(verifyEmail),
      verifiedListUserInvitations: ctx.snapshot(verifiedListUserInvitations),
      acceptInvitation: ctx.snapshot(acceptInvitation),
      fullOrganizationAfterAccept: ctx.snapshot(fullOrganizationAfterAccept),
      invitationsAfterAccept: ctx.snapshot(invitationsAfterAccept),
    };
  },
  ["GET /organization/list-user-invitations", "POST /organization/accept-invitation"],
);

compatScenario(
  "organization user invitation listing forbids selecting another email over HTTP",
  async (ctx) => {
    const anonymous = await organizationActor(
      ctx,
      "guest",
    ).orgClient.organization.listUserInvitations();
    expect(anonymous.error).toMatchObject({
      status: 400,
      message: "Missing session headers, or email query parameter.",
    });

    const user = await signUpUser(ctx, "user", "organization-list-user-guard", "Invitation User");
    const selectingAnother = await ctx.rawRequest({
      actor: "user",
      path: `/api/auth/organization/list-user-invitations?email=${encodeURIComponent(ctx.uniqueEmail("other"))}`,
    });
    expect(selectingAnother.status).toBe(400);
    expect(selectingAnother.body).toEqual({
      message: "User email cannot be passed for client side API calls.",
    });

    const ownUnverified = await user.orgClient.organization.listUserInvitations();
    expect(ownUnverified.error).toMatchObject({
      status: 403,
      code: "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    });

    return {
      anonymous: ctx.snapshot(anonymous),
      selectingAnother: ctx.snapshot(selectingAnother),
      ownUnverified: ctx.snapshot(ownUnverified),
    };
  },
);

compatScenario(
  "organization user invitation listing retains expired pending invitations and excludes processed ones",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-list-expired-owner", "Owner");
    const invitee = await signUpUser(
      ctx,
      "invitee",
      "organization-list-expired-invitee",
      "Invitee",
    );
    await invitee.client.sendVerificationEmail({ email: invitee.email });
    const verificationToken = await readVerificationToken(ctx, invitee.email);
    await invitee.client.verifyEmail({ query: { token: verificationToken } });

    const firstOrg = await owner.orgClient.organization.create({
      name: "Expired Org",
      slug: ctx.uniqueToken("organization-list-expired"),
    });
    const expiredInvitation = await owner.orgClient.organization.inviteMember({
      organizationId: firstOrg.data?.id ?? "",
      email: invitee.email,
      role: "member",
    });
    expect(expiredInvitation.error).toBeNull();
    if (!expiredInvitation.data) {
      throw new Error("an expirable invitation must be created");
    }
    const expiredInvitationId = expiredInvitation.data.id;
    await ctx.expireInvitation({
      invitationId: expiredInvitationId,
      expiresAt: "2000-01-01T00:00:00.000Z",
    });

    const secondOrg = await owner.orgClient.organization.create({
      name: "Active Org",
      slug: ctx.uniqueToken("organization-list-active"),
    });
    const activeInvitation = await owner.orgClient.organization.inviteMember({
      organizationId: secondOrg.data?.id ?? "",
      email: invitee.email,
      role: "member",
    });
    expect(activeInvitation.error).toBeNull();

    const listed = await invitee.orgClient.organization.listUserInvitations();
    expect(listed.error).toBeNull();
    expect(listed.data).toHaveLength(2);
    expect(listed.data?.[0]).toMatchObject({
      id: expiredInvitationId,
      organizationName: "Expired Org",
      status: "pending",
    });
    expect(
      z.object({ expiresAt: z.coerce.date() }).parse(listed.data?.[0]).expiresAt.toISOString(),
    ).toBe("2000-01-01T00:00:00.000Z");
    expect(listed.data?.[1]?.id).toBe(activeInvitation.data?.id);

    const expiredAcceptance = await invitee.orgClient.organization.acceptInvitation({
      invitationId: expiredInvitationId,
    });
    expect(expiredAcceptance.error).not.toBeNull();
    const accepted = await invitee.orgClient.organization.acceptInvitation({
      invitationId: activeInvitation.data?.id ?? "",
    });
    expect(accepted.error).toBeNull();

    const afterAcceptance = await invitee.orgClient.organization.listUserInvitations();
    expect(afterAcceptance.data).toHaveLength(1);
    expect(afterAcceptance.data?.[0]?.id).toBe(expiredInvitationId);

    // A different verified user sees none of these invitations.
    const other = await signUpUser(
      ctx,
      "other",
      "organization-list-expired-other",
      "Other Invitee",
    );
    await other.client.sendVerificationEmail({ email: other.email });
    const otherVerificationToken = await readVerificationToken(ctx, other.email);
    await other.client.verifyEmail({ query: { token: otherVerificationToken } });
    const otherInvitations = await other.orgClient.organization.listUserInvitations();
    expect(otherInvitations.data).toEqual([]);

    return {
      listed: ctx.snapshot(listed),
      expiredAcceptance: ctx.snapshot(expiredAcceptance),
      accepted: ctx.snapshot(accepted),
      afterAcceptance: ctx.snapshot(afterAcceptance),
      otherInvitations: ctx.snapshot(otherInvitations),
    };
  },
  ["GET /organization/list-user-invitations", "POST /organization/accept-invitation"],
);

compatScenario(
  "organization invitation validation, reject, and cancel flows match TS",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-validate-owner", "Owner");
    const admin = await signUpUser(ctx, "admin", "organization-validate-admin", "Admin");
    const rejectUser = await signUpUser(
      ctx,
      "reject-user",
      "organization-reject-user",
      "Reject User",
    );
    const cancelUser = await signUpUser(
      ctx,
      "cancel-user",
      "organization-cancel-user",
      "Cancel User",
    );
    const slug = ctx.uniqueToken("organization-validate-org");

    const organization = await owner.orgClient.organization.create({
      name: "Validation Org",
      slug,
    });
    const organizationId = organization.data?.id ?? "";

    const adminInvitation = await owner.orgClient.organization.inviteMember({
      organizationId,
      email: admin.email,
      role: "admin",
    });
    const acceptedAdmin = await admin.orgClient.organization.acceptInvitation({
      invitationId: adminInvitation.data?.id ?? "",
    });
    const adminInvitingOwner = await admin.orgClient.organization.inviteMember({
      organizationId,
      email: ctx.uniqueEmail("organization-owner-role"),
      role: "owner",
    });
    const invalidRoleInvitation = await owner.orgClient.organization.inviteMember({
      organizationId,
      email: ctx.uniqueEmail("organization-invalid-role"),
      role: "super-invalid-role-123" as never,
    });

    const rejectInvitation = await owner.orgClient.organization.inviteMember({
      organizationId,
      email: rejectUser.email,
      role: "member",
    });
    const rejected = await rejectUser.orgClient.organization.rejectInvitation({
      invitationId: rejectInvitation.data?.id ?? "",
    });

    const cancelInvitation = await owner.orgClient.organization.inviteMember({
      organizationId,
      email: cancelUser.email,
      role: "member",
    });
    const canceled = await owner.orgClient.organization.cancelInvitation({
      invitationId: cancelInvitation.data?.id ?? "",
    });

    return {
      organization: ctx.snapshot(organization),
      adminInvitation: ctx.snapshot(adminInvitation),
      acceptedAdmin: ctx.snapshot(acceptedAdmin),
      adminInvitingOwner: ctx.snapshot(adminInvitingOwner),
      invalidRoleInvitation: ctx.snapshot(invalidRoleInvitation),
      rejectInvitation: ctx.snapshot(rejectInvitation),
      rejected: ctx.snapshot(rejected),
      cancelInvitation: ctx.snapshot(cancelInvitation),
      canceled: ctx.snapshot(canceled),
    };
  },
);

compatScenario(
  "organization server invitation listing scopes email and applies configured page limits before status filtering",
  async (ctx) => {
    const profile = "org-roles-callback" as const;
    const owner = await signUp(ctx, "list-page-owner", profile);
    const invitee = await signUp(ctx, "list-page-invitee", profile);

    const firstOrg = data(
      await owner.client.organization.create({
        name: "Processed Invitation Org",
        slug: ctx.uniqueToken("list-page-first"),
      }),
    );
    const first = data(
      await owner.client.organization.inviteMember({
        organizationId: firstOrg.id,
        email: invitee.email,
        role: "member",
      }),
    );

    // The server API matches the invitee email case-insensitively and skips the verification gate.
    const unverifiedServer = await serverOperation(
      ctx,
      { operation: "list-user-invitations", email: invitee.email.toUpperCase() },
      profile,
    );
    expect(unverifiedServer.status).toBe(200);
    expect(unverifiedServer.body).toMatchObject([
      { id: first.id, email: invitee.email, organizationName: firstOrg.name, status: "pending" },
    ]);
    const unverifiedHttp = await invitee.client.organization.listUserInvitations();
    expect(unverifiedHttp.error).toMatchObject({
      status: 403,
      code: "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
    });

    data(await owner.client.organization.cancelInvitation({ invitationId: first.id }));
    const secondOrg = data(
      await owner.client.organization.create({
        name: "Pending Invitation Org",
        slug: ctx.uniqueToken("list-page-second"),
      }),
    );
    const second = data(
      await owner.client.organization.inviteMember({
        organizationId: secondOrg.id,
        email: invitee.email,
        role: "member",
      }),
    );

    const firstState = await state(ctx, firstOrg.id, profile);
    const secondState = await state(ctx, secondOrg.id, profile);
    expect(firstState.parsed.invitations[0]).toMatchObject({ id: first.id, status: "canceled" });
    expect(secondState.parsed.invitations[0]).toMatchObject({ id: second.id, status: "pending" });

    // This profile's find-many limit of 1 applies before status filtering, so the canceled
    // invitation fills the page and the pending one is never seen.
    const limitedServer = await serverOperation(
      ctx,
      { operation: "list-user-invitations", email: invitee.email },
      profile,
    );
    expect(limitedServer).toEqual({ status: 200, body: [] });
    const normalServer = await serverOperation(
      ctx,
      { operation: "list-user-invitations", email: invitee.email },
      "org-teams",
    );
    expect(normalServer.status).toBe(200);
    expect(normalServer.body).toMatchObject([
      { id: second.id, email: invitee.email, organizationName: secondOrg.name, status: "pending" },
    ]);

    const foreignServer = await serverOperation(
      ctx,
      { operation: "list-user-invitations", email: owner.email },
      profile,
    );
    expect(foreignServer).toEqual({ status: 200, body: [] });
    const missingEmail = await serverOperation(
      ctx,
      { operation: "list-user-invitations", email: "" },
      profile,
    );
    expect(missingEmail).toEqual({
      status: 400,
      body: { message: "Missing session headers, or email query parameter." },
    });

    data(await invitee.client.sendVerificationEmail({ email: invitee.email }));
    const proofToken = await readVerificationToken(ctx, invitee.email);
    data(await invitee.client.verifyEmail({ query: { token: proofToken } }));

    const limitedHttp = await invitee.client.organization.listUserInvitations();
    expect(limitedHttp.error).toBeNull();
    expect(limitedHttp.data).toEqual([]);

    const normalClient = orgActor(ctx, "list-page-invitee", "org-teams");
    const normalSignIn = await normalClient.signIn.email({
      email: invitee.email,
      password: "password123",
    });
    expect(normalSignIn.error).toBeNull();
    const normalHttp = await normalClient.organization.listUserInvitations();
    expect(normalHttp.error).toBeNull();
    expect(normalHttp.data).toMatchObject([
      { id: second.id, email: invitee.email, status: "pending" },
    ]);

    // Listing is read-only: neither organization's stored state changed.
    expect(await state(ctx, firstOrg.id, profile)).toEqual(firstState);
    expect(await state(ctx, secondOrg.id, profile)).toEqual(secondState);

    return {
      unverifiedServer,
      unverifiedHttp,
      firstState: firstState.raw,
      secondState: secondState.raw,
      limitedServer,
      normalServer,
      foreignServer,
      missingEmail,
      limitedHttp,
      normalSignIn,
      normalHttp,
    };
  },
  ["POST /organization/cancel-invitation"],
);
