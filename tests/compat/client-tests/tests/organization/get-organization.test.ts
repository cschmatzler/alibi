import { expect } from "bun:test";
import { createAuthClient } from "better-auth/client";
import { organizationClient } from "better-auth/client/plugins";
import { z } from "zod";
import type { FixtureProfile } from "../../support/profiles";
import { compatScenario } from "../../support/scenario";

const persisted = z.object({
  sessions: z.array(
    z.object({
      id: z.string(),
      token: z.string(),
      userId: z.string(),
      activeOrganizationId: z.string().nullable(),
      expiresAt: z.string(),
    }),
  ),
});

for (const profile of [undefined, "org-teams"] as const satisfies readonly (
  | FixtureProfile
  | undefined
)[]) {
  compatScenario(
    `organization metadata lookup ${profile ?? "default"} scopes selectors and clears only the denied session`,
    async (ctx) => {
      function actor(name: string) {
        const source = ctx.actor(name, profile);
        return {
          ...source,
          org: createAuthClient({
            baseURL: ctx.baseURL,
            plugins: [organizationClient()],
            fetchOptions: { customFetchImpl: source.fetch },
          }),
        };
      }

      const owner = actor("metadata-owner");
      const outsider = actor("metadata-outsider");
      const otherSession = actor("metadata-outsider-other");
      const guest = actor("metadata-guest");

      const ownerSignup = await owner.client.signUp.email({
        email: ctx.uniqueEmail("metadata-owner"),
        password: "password123",
        name: "Metadata Owner",
      });
      const outsiderEmail = ctx.uniqueEmail("metadata-outsider");
      const outsiderSignup = await outsider.client.signUp.email({
        email: outsiderEmail,
        password: "password123",
        name: "Metadata Outsider",
      });
      expect(ownerSignup.error).toBeNull();
      expect(outsiderSignup.error).toBeNull();
      if (!ownerSignup.data || !outsiderSignup.data) {
        throw new Error("real principals must be created");
      }
      const ownerId = ownerSignup.data.user.id;
      const outsiderId = outsiderSignup.data.user.id;

      const noSelection = await owner.org.organization.getOrganization();
      expect(noSelection).toMatchObject({ data: null, error: null });
      const guestDenied = await guest.org.organization.getOrganization({
        query: { organizationId: "missing" },
      });
      expect(guestDenied.error).toMatchObject({ status: 401 });

      const first = await owner.org.organization.create({
        name: "Metadata Alpha",
        slug: ctx.uniqueToken("metadata-alpha"),
        metadata: {
          tier: "gold",
          fixed: 1e20,
          tiny: 3.8730639354761726e-71,
          nested: { "10": "ten", "2": "two" },
        },
      });
      const second = await owner.org.organization.create({
        name: "Metadata Beta",
        slug: ctx.uniqueToken("metadata-beta"),
      });
      expect(first.error).toBeNull();
      expect(second.error).toBeNull();
      if (!first.data || !second.data) {
        throw new Error("owned organizations must persist");
      }
      const firstId = first.data.id;
      const secondId = second.data.id;

      const empty = await owner.org.organization.create({
        name: "Metadata Empty",
        slug: ctx.uniqueToken("metadata-empty"),
        metadata: {},
        keepCurrentActiveOrganization: true,
      });
      expect(empty.error).toBeNull();
      if (!empty.data) {
        throw new Error("explicit empty metadata must persist");
      }
      const emptyId = empty.data.id;
      expect(empty.data.metadata).toEqual({});
      const emptyMetadata = await owner.org.organization.getOrganization({
        query: { organizationId: emptyId },
      });
      expect(emptyMetadata.data?.metadata).toBe("{}");

      // Renames leave absent, empty and populated metadata as they were stored.
      const updatedAbsent = await owner.org.organization.update({
        organizationId: secondId,
        data: { name: "Metadata Beta Renamed" },
      });
      expect(updatedAbsent.error).toBeNull();
      expect(updatedAbsent.data?.name).toBe("Metadata Beta Renamed");
      expect(updatedAbsent.data).not.toHaveProperty("metadata");

      const updatedEmpty = await owner.org.organization.update({
        organizationId: emptyId,
        data: { name: "Metadata Empty Renamed" },
      });
      expect(updatedEmpty.error).toBeNull();
      expect(updatedEmpty.data?.metadata).toEqual({});
      const updatedEmptyStored = await owner.org.organization.getOrganization({
        query: { organizationId: emptyId },
      });
      expect(updatedEmptyStored.data?.name).toBe("Metadata Empty Renamed");
      expect(updatedEmptyStored.data?.metadata).toBe("{}");

      const updatedPresent = await owner.org.organization.update({
        organizationId: firstId,
        data: { name: "Metadata Alpha Renamed" },
      });
      expect(updatedPresent.error).toBeNull();
      expect(updatedPresent.data?.metadata).toEqual({
        tier: "gold",
        fixed: 1e20,
        tiny: 3.8730639354761726e-71,
        nested: { "2": "two", "10": "ten" },
      });

      // The active selection, an explicit id, and a slug (which wins over the id) each resolve.
      const active = await owner.org.organization.getOrganization();
      expect(active.data?.metadata).toBeNull();
      expect(active.data?.name).toBe("Metadata Beta Renamed");
      const byId = await owner.org.organization.getOrganization({
        query: { organizationId: firstId },
      });
      expect(byId.data?.name).toBe("Metadata Alpha Renamed");
      const bySlug = await owner.org.organization.getOrganization({
        query: { organizationId: firstId, organizationSlug: second.data.slug },
      });
      expect(active.data?.id).toBe(secondId);
      expect(byId.data?.id).toBe(firstId);
      expect(bySlug.data?.id).toBe(secondId);
      expect(byId.data?.metadata).toBe(
        '{"tier":"gold","fixed":100000000000000000000,"tiny":3.8730639354761726e-71,"nested":{"2":"two","10":"ten"}}',
      );
      for (const result of [active, byId, bySlug]) {
        expect(result.error).toBeNull();
        expect(result.data).not.toHaveProperty("members");
        expect(result.data).not.toHaveProperty("invitations");
        expect(result.data).not.toHaveProperty("teams");
      }

      const full = await owner.org.organization.getFullOrganization({
        query: { organizationId: firstId },
      });
      expect(full.error).toBeNull();
      expect(full.data?.metadata).toBe(
        '{"tier":"gold","fixed":100000000000000000000,"tiny":3.8730639354761726e-71,"nested":{"2":"two","10":"ten"}}',
      );
      expect(full.data?.members.some((member) => member.userId === ownerId)).toBe(true);

      const emptySelectors = await owner.org.organization.getOrganization({
        query: { organizationSlug: "" },
      });
      expect(emptySelectors.data?.id).toBe(secondId);

      // Lookups of organizations that do not exist leave the owner's sessions untouched.
      const beforeMissing = persisted.parse(await ctx.readUserState({ userId: ownerId }));
      const missingSlug = await owner.org.organization.getOrganization({
        query: {
          organizationId: firstId,
          organizationSlug: ctx.uniqueToken("metadata-absent-slug"),
        },
      });
      expect(missingSlug.error).toMatchObject({ status: 400, code: "ORGANIZATION_NOT_FOUND" });
      const missing = await owner.org.organization.getOrganization({
        query: { organizationId: ctx.uniqueToken("metadata-absent") },
      });
      expect(missing.error).toMatchObject({ status: 400, code: "ORGANIZATION_NOT_FOUND" });
      const missingFull = await owner.org.organization.getFullOrganization({
        query: { organizationId: ctx.uniqueToken("metadata-full-absent") },
      });
      expect(missingFull.error).toMatchObject({ status: 400, code: "ORGANIZATION_NOT_FOUND" });
      const afterMissing = persisted.parse(await ctx.readUserState({ userId: ownerId }));
      expect(afterMissing).toEqual(beforeMissing);
      const preserved = await owner.org.organization.getOrganization();
      expect(preserved.data?.id).toBe(secondId);

      // The outsider has two sessions, both with their own organization selected.
      const own = await outsider.org.organization.create({
        name: "Other Principal",
        slug: ctx.uniqueToken("metadata-other"),
      });
      expect(own.error).toBeNull();
      if (!own.data) {
        throw new Error("unrelated active organization must exist");
      }
      const ownId = own.data.id;
      const extraSignin = await otherSession.client.signIn.email({
        email: outsiderEmail,
        password: "password123",
      });
      expect(extraSignin.error).toBeNull();
      const selected = await otherSession.org.organization.setActive({
        organizationId: ownId,
      });
      expect(selected.error).toBeNull();
      const current = await outsider.client.getSession();
      const other = await otherSession.client.getSession();
      const currentToken = current.data?.session.token;
      const otherToken = other.data?.session.token;
      expect(currentToken).toBeString();
      expect(otherToken).toBeString();
      expect(currentToken).not.toBe(otherToken);

      const before = persisted.parse(await ctx.readUserState({ userId: outsiderId }));
      expect(before.sessions).toHaveLength(2);
      expect(before.sessions.every((session) => session.activeOrganizationId === ownId)).toBe(true);

      // A denied lookup clears the selection on the requesting session only.
      const denied = await outsider.org.organization.getOrganization({
        query: { organizationSlug: first.data.slug },
      });
      expect(denied.error).toMatchObject({
        status: 403,
        code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
      });
      const after = persisted.parse(await ctx.readUserState({ userId: outsiderId }));
      expect(after.sessions).toHaveLength(2);
      expect(
        after.sessions.find((session) => session.token === currentToken)?.activeOrganizationId,
      ).toBeNull();
      expect(after.sessions.find((session) => session.token === otherToken)).toEqual(
        before.sessions.find((session) => session.token === otherToken),
      );
      const cleared = await outsider.org.organization.getOrganization();
      expect(cleared).toMatchObject({ data: null, error: null });
      const unaffected = await otherSession.org.organization.getOrganization();
      expect(unaffected.data?.id).toBe(ownId);

      // The same holds for a denied full-organization lookup after reselecting.
      const restored = await outsider.org.organization.setActive({ organizationId: ownId });
      expect(restored.error).toBeNull();
      const beforeFull = persisted.parse(await ctx.readUserState({ userId: outsiderId }));
      const deniedFull = await outsider.org.organization.getFullOrganization({
        query: { organizationId: firstId },
      });
      expect(deniedFull.error).toMatchObject({
        status: 403,
        code: "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
      });
      const afterFull = persisted.parse(await ctx.readUserState({ userId: outsiderId }));
      expect(
        afterFull.sessions.find((session) => session.token === currentToken)?.activeOrganizationId,
      ).toBeNull();
      expect(afterFull.sessions.find((session) => session.token === otherToken)).toEqual(
        beforeFull.sessions.find((session) => session.token === otherToken),
      );

      return ctx.snapshot({
        ownerSignup,
        outsiderSignup,
        noSelection,
        guestDenied,
        first,
        second,
        empty,
        emptyMetadata,
        updatedAbsent,
        updatedEmpty,
        updatedEmptyStored,
        updatedPresent,
        active,
        byId,
        bySlug,
        full,
        emptySelectors,
        beforeMissing,
        missingSlug,
        missing,
        missingFull,
        afterMissing,
        preserved,
        own,
        extraSignin,
        selected,
        current,
        other,
        before,
        denied,
        after,
        cleared,
        unaffected,
        restored,
        beforeFull,
        deniedFull,
        afterFull,
      });
    },
    [
      "GET /organization/get-organization",
      "GET /organization/get-full-organization",
      "POST /organization/update",
    ],
  );
}
