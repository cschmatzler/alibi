import { expect, test } from "bun:test";
import { chromium } from "playwright";
import { CookieJar } from "tough-cookie";

// Task-scoped TLS termination models an explicitly trusted application proxy.
// No host, trust-store or ambient service configuration is changed.
for (const [label, backend, port] of [
  ["Source", process.env.AUTH_BASE_URL_TS ?? "http://localhost:4177", 4377],
  ["Rust", process.env.AUTH_BASE_URL_RUST ?? "http://localhost:4277", 4378],
] as const) {
  for (const mode of ["cross-inferred", "cross-proxy"] as const) {
    test.serial(`${label} ${mode}: real TLS persists inferred domain cookies across subdomains and retires them`, async () => {
      const raw: unknown[] = [];
      const proxy = Bun.serve({
        hostname: "127.0.0.1", port,
        tls: { key: Bun.file(process.env.COOKIE_TLS_KEY!), cert: Bun.file(process.env.COOKIE_TLS_CERT!) },
        async fetch(request) {
          const url = new URL(request.url);
          const headers = new Headers(request.headers);
          headers.set("x-forwarded-host", url.host);
          headers.set("x-forwarded-proto", "https");
          headers.set("host", new URL(backend).host);
          const response = await fetch(backend + url.pathname + url.search, {
            method: request.method, headers,
            ...(request.method === "POST" ? { body: await request.arrayBuffer() } : {}),
            redirect: "manual",
          });
          raw.push({ url: url.href, cookie: request.headers.get("cookie"), status: response.status, setCookie: response.headers.getSetCookie() });
          return new Response(await response.arrayBuffer(), { status: response.status, headers: response.headers });
        },
      });
      const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ?? "/home/cschmatzler/.nix-profile/bin/chromium", args: ["--no-proxy-server", "--host-resolver-rules=MAP cookie177.test 127.0.0.1,MAP auth.cookie177.test 127.0.0.1"] });
      try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await context.newPage();
        const origin = `https://cookie177.test:${port}`;
        const child = `https://auth.cookie177.test:${port}`;
        const path = `/__test/profiles/physical-cookie-${mode}/api/auth`;
        await page.goto(origin + "/__health");
        const created = await page.evaluate(async ({path}) => {
          const r = await fetch(path + "/sign-up/email", {method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({email:`tls-${crypto.randomUUID()}@test.com`,password:"password123",name:"TLS cookie owner"})});
          return {status:r.status,body:await r.json()};
        }, {path});
        expect(created.status).toBe(200);
        const cookies = await context.cookies();
        const token = cookies.find(c=>c.name === "__Secure-better-auth.session_token");
        expect(token).toBeDefined();
        expect(token!.domain).toBe(".cookie177.test");
        expect(token!.secure).toBe(true);
        expect(token!.httpOnly).toBe(true);
        expect(token!.sameSite).toBe("Lax");
        expect(token!.path).toBe("/");
        const issuance = (raw as any[]).find(r=>r.url.endsWith("/sign-up/email"));
        const jar = new CookieJar();
        for (const line of issuance.setCookie) await jar.setCookie(line, origin);
        expect(await jar.getCookieString(child + path)).toContain(token!.name + "=");
        await page.goto(child + "/__health");
        await page.reload();
        const session = await page.evaluate(async path=>(await fetch(path+"/get-session")).json(),path);
        expect(session.user.id).toBe(created.body.user.id);
        const rows = await (await fetch(`${backend}/__test/physical-cookie/storage?userId=${created.body.user.id}`)).json();
        expect(rows.sessions).toHaveLength(1);
        // Inference uses the resolved hostname, not a guessed registrable domain.
        // Retire at the original issuing origin, whose Domain matches issuance.
        await page.goto(origin + "/__health");
        expect(await page.evaluate(async path=>(await fetch(path+"/sign-out",{method:"POST",headers:{"content-type":"application/json"},body:"{}"})).status,path)).toBe(200);
        const logout = (raw as any[]).find(r=>r.url.endsWith("/sign-out"));
        for (const line of logout.setCookie) await jar.setCookie(line, origin);
        expect(await jar.getCookieString(child+path)).toBe("");
        expect((await context.cookies()).some(c=>c.name===token!.name)).toBe(false);
        await page.goto(child+"/__health");
        expect(await page.evaluate(async path=>(await fetch(path+"/get-session")).json(),path)).toBeNull();
        const after = await (await fetch(`${backend}/__test/physical-cookie/storage?userId=${created.body.user.id}`)).json();
        expect(after.sessions).toHaveLength(0);
        console.log(JSON.stringify({label,mode,raw,cookies,rows,after}));
        await context.close();
      } finally { await browser.close(); proxy.stop(true); }
    }, 30000);
  }
}
