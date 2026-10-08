import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import { customSessionClient, multiSessionClient } from "better-auth/client/plugins";
import { z } from "zod";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

compatScenario(
  "custom device-session list rejection retains launched application work and successful list order",
  async (ctx) => {
    const profile = "custom-session-gated";
    type Event = {
      stage: string;
      token: string;
      userId: string;
      request: { path: string; method: string; marker: string };
      name?: string;
    };
    const control = async (body?: {
      operation: string;
      mode?: string;
      heldToken?: string;
      rejectToken?: string;
    }) => {
      const response = await fetch(
        `${ctx.baseURL}/__test/custom-session-work`,
        body
          ? {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            }
          : undefined,
      );
      expect(response.status).toBe(200);
      return (await response.json()) as { events: Event[] };
    };
    const waitFor = async (predicate: (events: Event[]) => boolean) => {
      const deadline = Date.now() + 5000;
      let state = await control();
      while (!predicate(state.events) && Date.now() < deadline) {
        await Bun.sleep(10);
        state = await control();
      }
      expect(predicate(state.events)).toBe(true);
      return state;
    };
    const physical = async () => {
      const response = await fetch(`${ctx.baseURL}/__test/provider-batch/sql-state`);
      expect(response.status).toBe(200);
      const body = (await response.json()) as Record<string, Record<string, unknown>[]>;
      return {
        users: body.user ?? body.users!,
        accounts: body.account ?? body.accounts!,
        sessions: body.session ?? body.sessions!,
        verifications: body.verification ?? body.verifications!,
      };
    };
    const foreign = await ctx.actor("independent-list-foreign").client.signUp.email({
      email: ctx.uniqueEmail("independent-list-foreign"),
      password: "password123",
      name: "Foreign Device Owner",
    });
    expect(foreign.error).toBeNull();
    const foreignBefore = await ctx.readUserState({ userId: foreign.data!.user.id });
    const observations = [];
    for (const mode of ["ordinary", "coded"] as const) {
      await control({ operation: "restore" });
      const name = `independent-list-${mode}`;
      const client = createAuthClient({
        baseURL: ctx.baseURL + authProfilePath(profile),
        plugins: [customSessionClient(), multiSessionClient()],
        fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
      });
      const first = await client.signUp.email({
        email: ctx.uniqueEmail(`${name}-first`),
        password: "password123",
        name: "Held Device Owner",
      });
      const second = await client.signUp.email({
        email: ctx.uniqueEmail(`${name}-second`),
        password: "password123",
        name: "Rejecting Device Owner",
      });
      expect(first.error).toBeNull();
      expect(second.error).toBeNull();
      const initial = await client.multiSession.listDeviceSessions();
      const entries = z
        .array(
          z.object({
            user: z.object({ id: z.string(), name: z.string() }),
            session: z.object({ token: z.string(), userId: z.string() }),
          }),
        )
        .parse(initial.data);
      expect(entries).toHaveLength(2);
      const held = entries[0]!;
      const rejected = entries[1]!;
      expect(held.user.id).not.toBe(rejected.user.id);
      const original = await physical();
      const marker = ctx.uniqueToken(`${name}-marker`);
      const expectedRequest = {
        path: "/multi-session/list-device-sessions",
        method: "GET",
        marker,
      };
      await control({
        operation: "arm",
        mode,
        heldToken: held.session.token,
        rejectToken: rejected.session.token,
      });
      let settled = false;
      let cookies: string[] = [];
      const pending = client.multiSession
        .listDeviceSessions({
          fetchOptions: {
            headers: { "x-device-list-marker": marker },
            onResponse: ({ response }) => {
              cookies = response.headers.getSetCookie();
            },
          },
        })
        .then((result) => {
          settled = true;
          return result;
        });
      const rejectedBeforeRelease = await waitFor((events) =>
        events.some((event) => event.stage === "rejected"),
      );
      const failed = await Promise.race([
        pending,
        Bun.sleep(5000).then(() => {
          throw new Error("Aggregate device-list rejection waited for held sibling work");
        }),
      ]);
      expect(settled).toBe(true);
      expect(failed.data).toBeNull();
      expect(failed.error).toEqual(
        mode === "ordinary"
          ? { status: 500, statusText: "Internal Server Error" }
          : {
              status: 403,
              statusText: "Forbidden",
              code: "DEVICE_LIST_REJECTED",
              message: "Application device projection rejected",
            },
      );
      expect(cookies).toEqual([]);
      expect(
        rejectedBeforeRelease.events
          .filter((event) => event.stage === "started")
          .map((event) => event.token)
          .sort(),
      ).toEqual(entries.map((entry) => entry.session.token).sort());
      expect(rejectedBeforeRelease.events.filter((event) => event.stage === "rejected")).toEqual([
        {
          stage: "rejected",
          token: rejected.session.token,
          userId: rejected.user.id,
          request: expectedRequest,
        },
      ]);
      expect(rejectedBeforeRelease.events.some((event) => event.stage === "updated")).toBe(false);
      expect(await physical()).toEqual(original);
      await control({ operation: "release" });
      const completed = await waitFor((events) =>
        events.some((event) => event.stage === "updated"),
      );
      const late = completed.events.find((event) => event.stage === "updated")!;
      const expectedName = `${marker}@${expectedRequest.path}`;
      expect(late).toEqual({
        stage: "updated",
        token: held.session.token,
        userId: held.user.id,
        request: expectedRequest,
        name: expectedName,
      });
      const committed = await physical();
      expect(committed.accounts).toEqual(original.accounts);
      expect(committed.sessions).toEqual(original.sessions);
      expect(committed.verifications).toEqual(original.verifications);
      expect(committed.users.filter((user) => user.id !== held.user.id)).toEqual(
        original.users.filter((user) => user.id !== held.user.id),
      );
      const stored = committed.users.find((user) => user.id === held.user.id)!;
      const prior = original.users.find((user) => user.id === held.user.id)!;
      expect(stored.name).toBe(expectedName);
      const stable = (user: Record<string, unknown>) =>
        Object.fromEntries(
          Object.entries(user).filter(
            ([key]) => !["name", "updatedAt", "updated_at"].includes(key),
          ),
        );
      expect(stable(stored)).toEqual(stable(prior));
      expect(await ctx.readUserState({ userId: foreign.data!.user.id })).toEqual(foreignBefore);
      const successfulMarker = ctx.uniqueToken(`${name}-success`);
      await control({
        operation: "arm",
        mode: "success",
        heldToken: held.session.token,
        rejectToken: rejected.session.token,
      });
      let successfulSettled = false;
      const successfulPending = client.multiSession
        .listDeviceSessions({
          fetchOptions: { headers: { "x-device-list-marker": successfulMarker } },
        })
        .then((result) => {
          successfulSettled = true;
          return result;
        });
      const reverse = await waitFor((events) =>
        events.some((event) => event.stage === "completed"),
      );
      expect(
        reverse.events.filter((event) => event.stage === "completed").map((event) => event.token),
      ).toEqual([rejected.session.token]);
      expect(successfulSettled).toBe(false);
      await control({ operation: "release" });
      const successful = await successfulPending;
      expect(successful.error).toBeNull();
      const listed = z
        .array(
          z.object({
            user: z.object({ id: z.string() }),
            session: z.object({ token: z.string(), userId: z.string() }),
          }),
        )
        .parse(successful.data);
      expect(
        listed.map((entry) => ({ token: entry.session.token, userId: entry.user.id })),
      ).toEqual(entries.map((entry) => ({ token: entry.session.token, userId: entry.user.id })));
      const successfulEvents = await waitFor(
        (events) => events.filter((event) => event.stage === "completed").length === 2,
      );
      expect(
        successfulEvents.events
          .filter((event) => event.stage === "completed")
          .map((event) => event.token),
      ).toEqual([rejected.session.token, held.session.token]);
      expect(await physical()).toEqual(committed);
      await control({ operation: "restore" });
      const active = await client.getSession();
      expect(active.data?.user.id).toBe(second.data!.user.id);
      observations.push({
        mode,
        first,
        second,
        initial,
        rejectedBeforeRelease,
        failed,
        completed,
        successful,
        successfulEvents,
        active,
      });
    }
    expect((await ctx.actor("independent-list-foreign").client.getSession()).data?.user.id).toBe(
      foreign.data!.user.id,
    );
    return ctx.snapshot({ foreign, observations });
  },
  ["GET /multi-session/list-device-sessions"],
);
