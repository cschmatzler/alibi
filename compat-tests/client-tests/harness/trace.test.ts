import { expect, test } from "bun:test";
import { createTracingFetch, type TraceEntry } from "../support/trace";

test("expired, cleared, wrong-domain and wrong-path cookies are never sent", async () => {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch(request) {
    if (new URL(request.url).pathname === "/issue") {
      const headers = new Headers({ "content-type": "application/json" });
      for (const cookie of ["expired=secret; Max-Age=0", "past=secret; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "scoped=secret; Path=/scoped", "foreign=secret; Domain=example.com", "valid=ok; Path=/; HttpOnly; SameSite=Lax"])
        headers.append("set-cookie", cookie);
      return new Response("{}", { headers });
    }
    return Response.json({ cookie: request.headers.get("cookie") });
  } });
  try {
    const traced = createTracingFetch(server.url.origin, "actor", []);
    await traced("/issue");
    expect(await (await traced("/elsewhere")).json()).toEqual({ cookie: "valid=ok" });
    expect((await (await traced("/scoped/child")).json()).cookie).toContain("scoped=secret");
    expect(await (await traced("/elsewhere", { credentials: "omit" })).json()).toEqual({ cookie: null });
  } finally { await server.stop(true); }
});

test("redirects capture intermediate cookies and preserve Request bodies", async () => {
  const server = Bun.serve({ hostname: "127.0.0.1", port: 0, async fetch(request) {
    if (new URL(request.url).pathname === "/start") return new Response(null, { status: 303, headers: { location: "/end", "set-cookie": "redirect=ok; Path=/" } });
    return Response.json({ cookie: request.headers.get("cookie"), body: await request.text(), method: request.method });
  } });
  try {
    const traces: TraceEntry[] = [];
    const traced = createTracingFetch(server.url.origin, "actor", traces);
    expect(await (await traced("/start", { method: "POST", body: "hello" })).json()).toEqual({ cookie: "redirect=ok", body: "", method: "GET" });
    expect(traces.map(entry => entry.responseStatus)).toEqual([303, 200]);
    expect(await (await traced(new Request(new URL("/end", server.url), { method: "POST", body: "payload" }))).json()).toEqual({ cookie: "redirect=ok", body: "payload", method: "POST" });
  } finally { await server.stop(true); }
});
