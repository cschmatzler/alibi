import { expect, test } from "bun:test";

import { compareValues } from "../support/compare";
import { createTracingFetch, requestWindow, type TraceEntry } from "../support/trace";

test("expired, cleared, wrong-domain and wrong-path cookies are never sent", async () => {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      if (new URL(request.url).pathname === "/issue") {
        const headers = new Headers({ "content-type": "application/json" });
        for (const cookie of [
          "expired=secret; Max-Age=0",
          "past=secret; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
          "scoped=secret; Path=/scoped",
          "foreign=secret; Domain=example.com",
          "valid=ok; Path=/; HttpOnly; SameSite=Lax",
        ]) {
          headers.append("set-cookie", cookie);
        }
        return new Response("{}", { headers });
      }
      return Response.json({ cookie: request.headers.get("cookie") });
    },
  });
  try {
    const traced = createTracingFetch(server.url.origin, "actor", []);
    await traced("/issue");
    expect(await (await traced("/elsewhere")).json()).toEqual({ cookie: "valid=ok" });
    expect((await (await traced("/scoped/child")).json()).cookie).toContain("scoped=secret");
    expect(await (await traced("/elsewhere", { credentials: "omit" })).json()).toEqual({
      cookie: null,
    });
  } finally {
    await server.stop(true);
  }
});

test("redirects capture intermediate cookies and preserve Fetch method and body semantics", async () => {
  const received: { method: string; body: string; cookie: string | null }[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);

      if (url.pathname === "/start") {
        return new Response(null, {
          status: Number(url.searchParams.get("status")),
          headers: { location: "/end", "set-cookie": "redirect=ok; Path=/" },
        });
      }

      const receipt = {
        cookie: request.headers.get("cookie"),
        body: await request.text(),
        method: request.method,
      };
      received.push(receipt);
      return Response.json(receipt);
    },
  });
  try {
    for (const [status, method] of [
      [303, "GET"],
      [303, "HEAD"],
      [303, "POST"],
      [307, "POST"],
      [308, "PUT"],
    ] as const) {
      const init = { method, ...(["GET", "HEAD"].includes(method) ? {} : { body: "payload" }) };
      await (await fetch(new URL(`/start?status=${status}`, server.url), init)).arrayBuffer();
      const reference = received.at(-1)!;
      const traces: TraceEntry[] = [];
      const traced = createTracingFetch(server.url.origin, "actor", traces);
      await (await traced(`/start?status=${status}`, init)).arrayBuffer();
      expect(received.at(-1)).toEqual({ ...reference, cookie: "redirect=ok" });
      expect(traces.map((entry) => entry.responseStatus)).toEqual([status, 200]);
      expect(
        await (
          await traced(
            new Request(new URL("/end", server.url), { method: "POST", body: "direct payload" }),
          )
        ).json(),
      ).toEqual({ cookie: "redirect=ok", body: "direct payload", method: "POST" });
    }
  } finally {
    await server.stop(true);
  }
});

test("configured authentication paths preserve Request bodies, cookie scopes and actual trace URLs", async () => {
  const profilePath = "/__test/profiles/org-teams/api/auth";
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (path === `${profilePath}/issue`) {
        return Response.json(
          {},
          { headers: { "set-cookie": `profile=valid; Path=${profilePath}; HttpOnly` } },
        );
      }
      return Response.json({
        path,
        cookie: request.headers.get("cookie"),
        body: await request.text(),
      });
    },
  });
  try {
    const traces: TraceEntry[] = [];
    const traced = createTracingFetch(server.url.origin, "profile", traces, profilePath);
    await traced("/api/auth/issue");
    const request = new Request(new URL("/api/auth/action", server.url), {
      method: "POST",
      body: "payload",
    });
    expect(await (await traced(request)).json()).toEqual({
      path: `${profilePath}/action`,
      cookie: "profile=valid",
      body: "payload",
    });
    expect(
      await (await traced("/__test/profiles/org-teams-no-default/api/auth/action")).json(),
    ).toEqual({
      path: "/__test/profiles/org-teams-no-default/api/auth/action",
      cookie: null,
      body: "",
    });
    expect(traces.map((trace) => trace.path)).toEqual([
      `${profilePath}/issue`,
      `${profilePath}/action`,
      "/__test/profiles/org-teams-no-default/api/auth/action",
    ]);
  } finally {
    await server.stop(true);
  }
});

test("organization application creation receipts retain full bodies with bounded clocks and control privacy", async () => {
  const paths = [
    "/__test/organization-membership-policy/server",
    "/__test/organization-member-addition/server",
  ];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const createdAt = new Date().toISOString();
      return Response.json(
        {
          member: {
            id: crypto.randomUUID(),
            organizationId: "organization",
            userId: "owner",
            role: "member",
            createdAt,
          },
          session: {
            id: crypto.randomUUID(),
            token: crypto.randomUUID(),
            userId: "owner",
            createdAt,
            updatedAt: createdAt,
            expiresAt: new Date(Date.parse(createdAt) + 300_000).toISOString(),
          },
          foreignRows: [
            {
              id: "foreign-member",
              organizationId: "foreign-organization",
              userId: "foreign-user",
              role: "owner",
              createdAt: "2025-01-01T00:00:00.000Z",
            },
          ],
          receipt: { applicationData: { privateMarker: "literal-application-value" } },
        },
        { status: new URL(request.url).searchParams.has("reject") ? 403 : 200 },
      );
    },
  });
  try {
    for (const path of paths) {
      const left: TraceEntry[] = [];
      const right: TraceEntry[] = [];
      const first = await (
        await createTracingFetch(server.url.origin, "owner", left)(path, { method: "POST" })
      ).json();
      await Bun.sleep(10);
      const second = await (
        await createTracingFetch(server.url.origin, "owner", right)(path, { method: "POST" })
      ).json();
      expect(left[0]!.responseBody).toEqual(first);
      expect(right[0]!.responseBody).toEqual(second);

      const context = {
        leftBaseURL: server.url.origin,
        rightBaseURL: server.url.origin,
        leftStartedAt: left[0]![requestWindow]!.startedAt,
        rightStartedAt: right[0]![requestWindow]!.startedAt,
        leftRequestWindows: left.map((entry) => entry[requestWindow]),
        rightRequestWindows: right.map((entry) => entry[requestWindow]),
      };
      const a = { observation: first, traces: left };
      const b = { observation: second, traces: right };
      expect(compareValues(a, b, context)).toEqual([]);

      for (const corrupt of [
        {
          ...second,
          member: {
            ...second.member,
            createdAt: new Date(context.rightStartedAt - 60_000).toISOString(),
          },
        },
        {
          ...second,
          session: {
            ...second.session,
            expiresAt: new Date(Date.parse(second.session.expiresAt) + 60_000).toISOString(),
          },
        },
        { ...second, foreignRows: [{ ...second.foreignRows[0], role: "member" }] },
        { ...second, receipt: { applicationData: { privateMarker: "wrong-application-value" } } },
      ]) {
        expect(
          compareValues(
            a,
            { observation: corrupt, traces: [{ ...right[0], responseBody: corrupt }] },
            context,
          ).length,
        ).toBeGreaterThan(0);
      }

      expect(
        compareValues(a, { ...b, traces: [{ ...right[0], responseStatus: 201 }] }, context).length,
      ).toBeGreaterThan(0);

      const rejected: TraceEntry[] = [];
      const body = await (
        await createTracingFetch(
          server.url.origin,
          "owner",
          rejected,
        )(`${path}?reject`, { method: "POST" })
      ).json();
      expect(rejected[0]!.responseBody).toEqual(body);
      expect(rejected[0]!.responseErrorBody).toEqual(body);
      expect(rejected[0]!.responseStatus).toBe(403);
    }
    for (const [path, method] of [
      [paths[0]!, "GET"],
      [paths[1]!, "GET"],
      [`${paths[0]}/state`, "POST"],
      ["/__test/unrelated-control", "POST"],
    ]) {
      const traces: TraceEntry[] = [];
      const response = await createTracingFetch(
        server.url.origin,
        "owner",
        traces,
      )(path!, { method });
      expect(response.status).toBe(200);
      expect(traces[0]!.responseBody).toBeUndefined();
      expect(traces[0]!.responseBodyShape).toHaveProperty("foreignRows");
    }
  } finally {
    await server.stop(true);
  }
});

test("concurrent traces retain request order when independent responses finish in reverse order", async () => {
  let releaseSlow!: () => void;
  let startedSlow!: () => void;
  const slowStarted = new Promise<void>((resolve) => {
    startedSlow = resolve;
  });
  const slowRelease = new Promise<void>((resolve) => {
    releaseSlow = resolve;
  });
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (new URL(request.url).pathname === "/slow") {
        startedSlow();
        await slowRelease;
        return Response.json({ principal: "first" });
      }
      return Response.json({ principal: "second" }, { status: 201 });
    },
  });
  try {
    const traces: TraceEntry[] = [];
    // Actors share the scenario trace, but each owns a separate cookie jar.
    const slow = createTracingFetch(server.url.origin, "first", traces)("/slow");
    await slowStarted;
    const fast = await createTracingFetch(server.url.origin, "second", traces)("/fast");
    expect(await fast.json()).toEqual({ principal: "second" });
    releaseSlow();
    expect(await (await slow).json()).toEqual({ principal: "first" });
    expect(
      traces.map(({ actor, path, responseStatus, responseBodyShape }) => ({
        actor,
        path,
        responseStatus,
        responseBodyShape,
      })),
    ).toEqual([
      {
        actor: "first",
        path: "/slow",
        responseStatus: 200,
        responseBodyShape: { principal: "string" },
      },
      {
        actor: "second",
        path: "/fast",
        responseStatus: 201,
        responseBodyShape: { principal: "string" },
      },
    ]);
  } finally {
    releaseSlow();
    await server.stop(true);
  }
});
