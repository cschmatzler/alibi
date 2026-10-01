import { createAuthMiddleware } from "better-auth/api";
import type { BetterAuthPlugin } from "better-auth";
/** Observe real Bun request aborts independently of the authentication callbacks. */
export function organizationTransportProbe() {
  const aborted = new Set<string>();
  const completed = new Set<string>();
  const plugin: BetterAuthPlugin = {
    id: "organization-transport-observer",
    hooks: {
      after: [
        {
          matcher: (ctx) => Boolean(ctx.headers?.get("x-continuation-marker")),
          handler: createAuthMiddleware(async (ctx) => {
            const marker = ctx.headers?.get("x-continuation-marker");
            if (marker) completed.add(marker);
          }),
        },
      ],
    },
  };
  return {
    plugin,
    observe(request: Request) {
      const marker = request.headers.get("x-continuation-marker");
      if (marker)
        request.signal.addEventListener("abort", () => aborted.add(marker), {
          once: true,
        });
    },
    async handle(request: Request, url: URL) {
      if (
        url.pathname === "/__test/organization-transport-reset" &&
        request.method === "POST"
      ) {
        aborted.clear();
        completed.clear();
        return Response.json({ reset: true });
      }
      if (url.pathname === "/__test/organization-transport-completion") {
        const marker = url.searchParams.get("marker") ?? "";
        for (let i = 0; i < 200 && !completed.has(marker); i++)
          await Bun.sleep(10);
        return Response.json({ marker, completed: completed.has(marker) });
      }
      if (url.pathname !== "/__test/organization-transport-state") return;
      const marker = url.searchParams.get("marker") ?? "";
      for (let i = 0; i < 200 && !aborted.has(marker); i++) await Bun.sleep(10);
      return Response.json({ marker, aborted: aborted.has(marker) });
    },
  };
}
