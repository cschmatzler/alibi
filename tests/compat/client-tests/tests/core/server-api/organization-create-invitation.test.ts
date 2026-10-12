import { expect } from "bun:test";

import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

const stateSchema = z.object({
  snapshot: z.object({
    invitations: z.array(z.record(z.string(), z.unknown())),
    members: z.array(z.record(z.string(), z.unknown())),
    sessions: z.array(z.record(z.string(), z.unknown())),
    organizations: z.array(z.record(z.string(), z.unknown())),
    teams: z.array(z.record(z.string(), z.unknown())),
    teamMembers: z.array(z.record(z.string(), z.unknown())),
  }),
  receipts: z.array(
    z.object({ phase: z.string(), context: z.record(z.string(), z.unknown()) }).passthrough(),
  ),
});
compatScenario(
  "organization createInvitation exposes the canonical server API and delivers a stored invitation without a request",
  async (ctx) => {
    const profile = "org-invite-limit-none";
    async function signup(name: string) {
      let cookie = "";
      const actor = ctx.actor(name, profile);
      const result = await actor.client.signUp.email({
        email: ctx.uniqueEmail(name),
        name,
        password: "Password123!",
        fetchOptions: {
          onSuccess({ response }) {
            cookie = response.headers
              .getSetCookie()
              .map((raw) => raw.split(";")[0])
              .join("; ");
          },
        },
      });
      expect(result.error).toBeNull();
      return { actor, result, headers: { cookie } };
    }
    const owner = await signup("invitation-server-owner");
    const outsider = await signup("invitation-server-outsider");
    const recipient = await signup("invitation-server-recipient");
    const created = await owner.actor.fetch(
      ctx.baseURL + authProfilePath(profile) + "/organization/create",
      {
        method: "POST",
        headers: { "content-type": "application/json", ...owner.headers },
        body: JSON.stringify({
          name: "Server invitation organization",
          slug: ctx.uniqueToken("server-invitation-org"),
        }),
      },
    );
    expect(created.status).toBe(200);
    const organization = await created.json();
    const configured = await ctx.rawRequest({
      path: "/__test/organization-invitation-life/configure",
      method: "POST",
      json: { mode: "record" },
    });
    expect(configured.status).toBe(200);
    async function state() {
      return stateSchema.parse(
        (await ctx.rawRequest({ path: "/__test/organization-invitation-life/state" })).body,
      );
    }
    const before = await state();
    async function invoke(input: Record<string, unknown>) {
      return ctx.rawRequest({
        path: "/__test/organization-invitation-life/server",
        method: "POST",
        json: input,
      });
    }
    const email = recipient.result.data!.user.email;
    const rejected = [];
    for (const [input, status, code] of [
      [{}, 400, "VALIDATION_ERROR"],
      [{ body: { email, role: 7 } }, 400, "VALIDATION_ERROR"],
      [
        { body: { email, role: "member", organizationId: organization.id } },
        400,
        "VALIDATION_ERROR",
      ],
      [
        { body: { email, role: "member", organizationId: organization.id }, headers: {} },
        401,
        "UNAUTHORIZED",
      ],
      [
        {
          body: { email, role: "member", organizationId: organization.id },
          headers: outsider.headers,
        },
        400,
        "MEMBER_NOT_FOUND",
      ],
      [
        {
          body: { email: "bad-email", role: "member", organizationId: organization.id },
          headers: owner.headers,
        },
        400,
        "INVALID_EMAIL",
      ],
    ] as const) {
      const result = await invoke(input);
      expect(result.status).toBe(status);
      expect((result.body as { code: string }).code).toBe(code);
      rejected.push(result);
    }
    expect(await state()).toEqual(before);
    const invitation = await invoke({
      body: {
        email: email.toUpperCase(),
        role: ["member", "admin"],
        organizationId: organization.id,
        inviterId: outsider.result.data!.user.id,
        status: "accepted",
      },
      query: { organizationId: "wrong-org" },
      headers: { ...owner.headers, "x-invitation-marker": "logical-only" },
    });
    expect(invitation.status).toBe(200);
    const result = invitation.body as {
      id: string;
      email: string;
      role: string;
      organizationId: string;
      inviterId: string;
      status: string;
    };
    expect(result).toMatchObject({
      email,
      role: "member,admin",
      organizationId: organization.id,
      inviterId: owner.result.data!.user.id,
      status: "pending",
    });
    const after = await state();
    expect(after.snapshot.invitations).toHaveLength(before.snapshot.invitations.length + 1);
    expect(after.snapshot.invitations.find((row) => row.id === result.id)).toMatchObject(result);
    for (const key of ["members", "sessions", "organizations", "teams", "teamMembers"] as const) {
      expect(after.snapshot[key]).toEqual(before.snapshot[key]);
    }
    expect(after.receipts.map((receipt) => receipt.phase)).toEqual([
      "before-create",
      "delivery-start",
      "delivery-end",
      "after-create",
    ]);
    expect(
      after.receipts.find((receipt) => receipt.phase === "delivery-start")!.context,
    ).toMatchObject({ id: result.id, email, request: null });
    const accepted = await recipient.actor.fetch(
      ctx.baseURL + authProfilePath(profile) + "/organization/accept-invitation",
      {
        method: "POST",
        headers: { "content-type": "application/json", ...recipient.headers },
        body: JSON.stringify({ invitationId: result.id }),
      },
    );
    expect(accepted.status).toBe(200);
    const acceptance = await accepted.json();
    expect(acceptance.member).toMatchObject({
      userId: recipient.result.data!.user.id,
      organizationId: organization.id,
      role: "member,admin",
    });
    const final = await state();
    expect(final.snapshot.invitations.find((row) => row.id === result.id)!.status).toBe("accepted");
    expect(final.snapshot.members).toHaveLength(before.snapshot.members.length + 1);
    return ctx.snapshot({
      owner: owner.result,
      outsider: outsider.result,
      recipient: recipient.result,
      organization,
      before,
      rejected,
      invitation,
      after,
      acceptance,
      final,
    });
  },
);
