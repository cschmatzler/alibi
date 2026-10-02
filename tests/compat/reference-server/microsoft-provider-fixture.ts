import { betterAuth, type BetterAuthOptions } from "better-auth";

/** The unchanged published Microsoft factory with application-owned transport. */
export function microsoftProviderFixture(base: BetterAuthOptions) {
  let control: Record<string, unknown> = {};
  const receipts: unknown[] = [];
  const mapperReceipts: unknown[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const path = "/__test/profiles/social-microsoft-default/api/auth";
  profiles.set(path, betterAuth({ ...base, basePath: path, plugins: [], socialProviders: {
    microsoft: { clientId: "fixture-social-client", clientSecret: "fixture-social-secret" },
  } }));
  return { profiles, reset() { control = {}; receipts.length = 0; mapperReceipts.length = 0; }, async handle(request: Request) {
    const path = new URL(request.url).pathname;
    if (path === "/__test/microsoft/control" && request.method === "POST") { control = await request.json(); return Response.json({ status: true }); }
    if (path === "/__test/microsoft/receipts") return Response.json(receipts);
    if (path === "/__test/microsoft/mapper-receipts") return Response.json(mapperReceipts);
    return null;
  } };
}
