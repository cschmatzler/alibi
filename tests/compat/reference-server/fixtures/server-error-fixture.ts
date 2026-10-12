import { type BetterAuthOptions, betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { kAPIErrorHeaderSymbol } from "better-call";

async function responseSnapshot(response: Response) {
  return {
    kind: "http-response",
    status: response.status,
    headers: Object.fromEntries([...response.headers].filter(([name]) => name !== "set-cookie")),
    cookies: response.headers.getSetCookie(),
    body: response.body === null ? null : await response.clone().text(),
  };
}
export function createServerErrorFixture(base: BetterAuthOptions) {
  let mode = "normal";
  const events: unknown[] = [];
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const profile of ["default", "html", "configured"]) {
    const path = `/__test/profiles/server-error-${profile}/api/auth`;
    profiles.set(
      profile,
      betterAuth<BetterAuthOptions>({
        ...base,
        basePath: path,
        onAPIError:
          profile === "configured"
            ? { errorURL: "/problem?keep=a%2Bb#error-panel", customizeDefaultErrorPage: {} }
            : profile === "html"
              ? { customizeDefaultErrorPage: {} }
              : {},
        hooks: {
          before: createAuthMiddleware(async (ctx) => {
            events.push({
              stage: "before",
              path: ctx.path,
              request: !!ctx.request,
              query: ctx.query ?? null,
            });
            ctx.setHeader("x-before", "discarded");
            if (mode === "before-return") {
              return new Response("application early", {
                status: 209,
                headers: { "content-type": "text/plain" },
              });
            }
            if (mode === "patch-query") return { context: { query: { error: "PATCHED_LOGICAL" } } };
          }),
          after: createAuthMiddleware(async (ctx) => {
            const returned = ctx.context.returned;
            events.push({
              stage: "after",
              path: ctx.path,
              request: !!ctx.request,
              query: ctx.query ?? null,
              sessionUserId: ctx.context.session?.user.id ?? null,
              returned:
                returned instanceof Response
                  ? await responseSnapshot(returned)
                  : { kind: "json", value: returned },
            });
            if (mode === "mutate-response" && returned instanceof Response) {
              returned.headers.set("x-response-mutated", "actual");
              returned.headers.append("set-cookie", "raw_a=one; Path=/");
              returned.headers.append("set-cookie", "raw_b=two; Path=/");
            }
            ctx.setHeader("x-after", "actual");
            ctx.setHeader("authorization", "request-only-header");
            ctx.setCookie("application_a", "first", { path: "/", httpOnly: true });
            ctx.setCookie("application_b", "second", { path: "/", httpOnly: true });
            if (mode === "replace-json") return { replacement: true };
          }),
        },
      }),
    );
  }
  return {
    async control(request: Request): Promise<Response | null> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/server-error/events") return Response.json(events);
      const physicalProfile =
        /^\/__test\/profiles\/server-error-(default|html|configured)\/api\/auth\//.exec(
          url.pathname,
        )?.[1];
      if (physicalProfile) {
        mode = url.searchParams.get("application_mode") ?? "normal";
        events.length = 0;
        return profiles.get(physicalProfile)!.handler(request);
      }
      if (url.pathname !== "/__test/server-error/call" || request.method !== "POST") return null;
      const physical = request.clone();
      const input = (await request.json()) as {
        profile?: string;
        mode?: string;
        physicalRequest?: boolean;
        query?: unknown;
        body?: unknown;
        headers?: Record<string, string>;
        asResponse?: boolean;
      };
      mode = input.mode ?? "normal";
      events.length = 0;
      try {
        const args = {
          asResponse: input.asResponse ?? false,
          returnHeaders: true,
          returnStatus: true,
          ...(input.physicalRequest ? { request: physical } : {}),
          ...(Object.hasOwn(input, "query") ? { query: input.query } : {}),
          ...(Object.hasOwn(input, "body") ? { body: input.body } : {}),
          ...(input.headers ? { headers: new Headers(input.headers) } : {}),
        };
        const value: unknown = await profiles.get(input.profile ?? "default")!.api.error(args);
        if (value instanceof Response) {
          return Response.json({
            events: [...events],
            result: { kind: "forwarded", response: await responseSnapshot(value) },
          });
        }
        const metadata = value as { response: unknown; headers: Headers; status?: number };
        return Response.json({
          events: [...events],
          result: {
            kind: "metadata",
            headers: Object.fromEntries(
              [...metadata.headers].filter(([name]) => name !== "set-cookie"),
            ),
            cookies: metadata.headers.getSetCookie(),
            ...(Object.hasOwn(metadata, "status") ? { status: metadata.status } : {}),
            response:
              metadata.response instanceof Response
                ? await responseSnapshot(metadata.response)
                : { kind: "json", value: metadata.response },
          },
        });
      } catch (error) {
        const failure = error as Error & { statusCode?: number; [kAPIErrorHeaderSymbol]?: Headers };
        return Response.json({
          events: [...events],
          result: {
            kind: "failure",
            api: typeof failure.statusCode === "number",
            message: failure.message,
            hasHeaders: !!failure[kAPIErrorHeaderSymbol],
          },
        });
      }
    },
  };
}
