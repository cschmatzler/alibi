import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { z } from "zod";
export function apiErrorFixture(base: BetterAuthOptions) {
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const events: unknown[] = [];
  for (const mode of ["masked", "throw"]) {
    profiles.set(
      mode,
      betterAuth({
        ...base,
        basePath: `/__test/profiles/api-error-${mode}/api/auth`,
        onAPIError: { throw: mode === "throw" },
        plugins: [
          ...(base.plugins ?? []),
          {
            id: "application-failure",
            endpoints: {
              fixtureFailure: createAuthEndpoint(
                "/fixture-failure",
                { method: "POST", body: z.object({ kind: z.enum(["ordinary", "coded"]) }) },
                async (ctx) => {
                  events.push({
                    path: ctx.path,
                    method: ctx.request!.method,
                    marker: ctx.headers!.get("x-error-marker"),
                  });
                  if (ctx.body.kind === "coded") {
                    throw new APIError("FORBIDDEN", {
                      code: "APPLICATION_DENIED",
                      message: "Application handler rejected",
                    });
                  }
                  throw new Error("Application handler failed");
                },
              ),
            },
          },
        ],
      }),
    );
  }
  return {
    async handle(request: Request) {
      if (new URL(request.url).pathname !== "/__test/api-error/invoke") return null;
      const { mode, kind, marker } = await request.json();
      events.length = 0;
      const nested = new Request(
        `${base.baseURL}/__test/profiles/api-error-${mode}/api/auth/fixture-failure`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: String(base.baseURL),
            "x-error-marker": marker,
          },
          body: JSON.stringify({ kind }),
        },
      );
      try {
        const response = await profiles.get(mode)!.handler(nested);
        const text = await response.text();
        let body: unknown = text;
        try {
          body = JSON.parse(text);
        } catch {}
        return Response.json({
          outcome: "returned",
          status: response.status,
          body,
          headers: {
            "content-type": response.headers.get("content-type"),
            "set-cookie": response.headers.getSetCookie(),
          },
          events,
        });
      } catch (error: any) {
        return Response.json({
          outcome: "thrown",
          name: error.name,
          message: error.message,
          ...(error.body ? { body: error.body } : {}),
          events,
        });
      }
    },
  };
}
