import { expect } from "bun:test";
import { compatScenario } from "../../support/scenario";
import { signUpUser } from "./helpers";

compatScenario(
  "organization persisted fractional timestamps retain the official client date and ownership",
  async (ctx) => {
    const owner = await signUpUser(ctx, "owner", "organization-timestamp-owner", "Timestamp Owner");
    expect(owner.signup.error).toBeNull();
    const created = await owner.orgClient.organization.create({
      name: "Timestamp Organization",
      slug: ctx.uniqueToken("timestamp-org"),
    });
    expect(created.error).toBeNull();
    const organizationId = created.data!.id;
    const memberId = created.data!.members[0]!.id;
    const userId = owner.signup.data!.user.id;
    expect(created.data!.members[0]!).toMatchObject({ organizationId, userId, role: "owner" });

    // Rust retains this fractional precision in SQLite; JavaScript's Date stores
    // milliseconds. The SDK must receive the same instant in either runtime.
    const sourceTimestamp = "2001-02-03T04:05:06.227234Z";
    const expectedTimestamp = "2001-02-03T04:05:06.227Z";
    const persisted = await ctx.rawRequest({
      path: "/__test/organization-timestamps",
      method: "POST",
      json: { organizationId, memberId, createdAt: sourceTimestamp },
    });
    expect(persisted.status).toBe(200);
    expect(persisted.body).toEqual({
      organizationId,
      memberId,
      userId,
      organizationCreatedAtMillis: Date.parse(expectedTimestamp),
      memberCreatedAtMillis: Date.parse(expectedTimestamp),
    });

    const full = await owner.orgClient.organization.getFullOrganization({
      query: { organizationId },
    });
    expect(full.error).toBeNull();
    expect(full.data!.id).toBe(organizationId);
    expect(full.data!.createdAt).toBeInstanceOf(Date);
    expect(full.data!.createdAt.toISOString()).toBe(expectedTimestamp);
    expect(full.data!.members).toHaveLength(1);
    expect(full.data!.members[0]!).toMatchObject({
      id: memberId,
      organizationId,
      userId,
      role: "owner",
      user: { id: userId, email: owner.email },
    });
    expect(full.data!.members[0]!.createdAt).toBeInstanceOf(Date);
    expect(full.data!.members[0]!.createdAt.toISOString()).toBe(expectedTimestamp);
    const active = await owner.orgClient.organization.getActiveMember();
    expect(active.error).toBeNull();
    expect(active.data!).toMatchObject({ id: memberId, organizationId, userId, role: "owner" });
    expect(active.data!.createdAt.toISOString()).toBe(expectedTimestamp);

    return {
      created: ctx.snapshot(created),
      persisted,
      full: ctx.snapshot(full),
      active: ctx.snapshot(active),
    };
  },
);
