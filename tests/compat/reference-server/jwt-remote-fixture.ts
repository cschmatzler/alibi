import { betterAuth, type BetterAuthOptions } from "better-auth";
import { jwt, signJWT } from "better-auth/plugins/jwt";
import { APIError } from "better-auth/api";
import { CompactSign } from "jose";
const secret = "remote-jwt-application-secret-minimum-32-characters";
function capture(value: any): any {
  if (value === undefined) return { $undefined: true };
  if (
    typeof value === "number" &&
    (!Number.isFinite(value) || Object.is(value, -0))
  )
    return { $number: Object.is(value, -0) ? "-0" : String(value) };
  if (Array.isArray(value)) return value.map(capture);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, capture(item)]),
    );
  return value;
}
/** Genuine application signer: callback receipts precede real HS256 signing. */
export function createRemoteJwtFixture(base: BetterAuthOptions) {
  const events: any[] = [];
  let failure: string | null = null;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const options = new Map<string, any>();
  for (const mode of ["raw", "configured", "result", "error"]) {
    const name = `jwt-remote-${mode}`;
    const signing = {
      ...(mode === "raw"
        ? {
            issuer: "remote-application-issuer",
            audience: "remote-application-audience",
          }
        : {}),
      ...(mode === "configured"
        ? {
            issuer: "application-issuer",
            audience: ["application-audience", "alternate-audience"],
            expirationTime: "60s",
          }
        : {}),
      ...(mode === "error"
        ? {
            definePayload: (session) =>
              Object.fromEntries(
                Object.entries({
                  ...session.user,
                  createdAt: session.user.createdAt.toISOString(),
                  updatedAt: session.user.updatedAt.toISOString(),
                  ...(failure ? { applicationError: failure } : {}),
                }).sort(([left], [right]) =>
                  left < right ? -1 : left > right ? 1 : 0,
                ),
              ),
          }
        : {}),
      sign: async (payload: any, header: any, overrides: any) => {
        events.push({
          payload: capture(payload),
          ownKeys: Object.keys(payload),
          header: capture(header),
          options: capture(overrides),
        });
        const error = payload.applicationError;
        if (error === "ordinary") throw new Error("application signer failed");
        if (error === "api")
          throw new APIError("FORBIDDEN", {
            code: "APPLICATION_SIGNING_DENIED",
            message: "application denied signing",
          });
        if (mode === "result" && typeof payload.customResult === "string")
          return payload.customResult;
        return new CompactSign(
          new TextEncoder().encode(JSON.stringify(payload)),
        )
          .setProtectedHeader({
            ...header,
            alg: "HS256",
            kid: "application-remote-key",
          })
          .sign(new TextEncoder().encode(secret));
      },
    };
    const pluginOptions = {
      jwks: {
        remoteUrl: "https://keys.fixture.test/remote-jwks",
        keyPairConfig: { alg: "EdDSA", crv: "Ed25519" },
      },
      jwt: signing,
    };
    options.set(name, pluginOptions);
    profiles.set(
      name,
      betterAuth({
        ...base,
        basePath: `/__test/profiles/${name}/api/auth`,
        plugins: [
          ...base.plugins!.filter((plugin) => plugin.id === "username"),
          jwt(pluginOptions),
        ],
      }),
    );
  }
  return {
    profiles,
    async handle(request: Request) {
      if (new URL(request.url).pathname !== "/__test/jwt-remote") return null;
      if (request.method === "GET")
        return Response.json({ events: [...events] });
      const body = (await request.json()) as any;
      if (body.operation === "clear") {
        events.length = 0;
        failure = null;
        return Response.json({ changed: true });
      }
      if (body.operation === "failure") {
        failure = body.failure;
        return Response.json({ changed: true });
      }
      const profile = body.profile ?? "jwt-remote-raw";
      const auth = profiles.get(profile)!;
      const payload = body.payload;
      for (const key of body.nanFields ?? []) payload[key] = Number.NaN;
      try {
        const token = await signJWT({ context: await auth.$context } as any, {
          options: options.get(profile),
          payload,
          header: body.header ?? {},
          signingKeyId: body.signingKeyId,
          signingAlgorithm: body.signingAlgorithm,
        });
        return Response.json({ token });
      } catch (error) {
        if (error instanceof APIError)
          return Response.json(
            { error: { status: error.statusCode, body: error.body } },
            { status: error.statusCode },
          );
        if (error instanceof Error)
          return Response.json(
            { error: { message: error.message } },
            { status: 500 },
          );
        throw error;
      }
    },
  };
}
