const ingressBodies = new WeakMap<Request, unknown>();
/** Capture physical input before the actual router consumes its request stream. */
export async function capturePasswordlessRequest(request: Request) {
  if (request.headers.get("x-callback-probe") === "issue207")
    ingressBodies.set(request, await request.clone().json());
}

/** Capture actual callback inputs and query the initialized adapter at callback time. */
export async function callbackSnapshot(
  ctx:
    | {
        request?: Request;
        path?: string;
        body?: unknown;
        context: {
          options: { basePath?: string };
          internalAdapter: { findVerificationValue(identifier: string): Promise<unknown> };
        };
      }
    | undefined,
  identifier: string,
) {
  if (ctx?.request?.headers.get("x-callback-probe") !== "issue207") return undefined;
  return {
    method: ctx.request.method,
    path: new URL(ctx.request.url).pathname,
    marker: ctx.request.headers.get("x-callback-probe"),
    body: ingressBodies.get(ctx.request),
    basePath: ctx.context.options.basePath,
    proofExists: !!(await ctx.context.internalAdapter.findVerificationValue(identifier)),
  };
}
