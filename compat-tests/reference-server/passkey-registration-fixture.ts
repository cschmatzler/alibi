import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { passkey } from "@better-auth/passkey";
import { username } from "better-auth/plugins";
import { SignJWT, jwtVerify } from "jose";

/** An application enrollment controller authorizes the existing owner before passkey-first enrollment. */
export function passkeyRegistrationFixture(
  options: Parameters<typeof betterAuth>[0],
) {
  const secret = new TextEncoder().encode(options.secret as string);
  const events: unknown[] = [];
  const denied = () =>
    new APIError("FORBIDDEN", {
      code: "ENROLLMENT_DENIED",
      message: "Enrollment proof is invalid",
    });
  async function proof(headers: Headers | undefined) {
    try {
      const token = headers
        ?.get("cookie")
        ?.split(";")
        .map((part) => part.trim())
        .find((part) => part.startsWith("passkey_enrollment="))
        ?.slice("passkey_enrollment=".length);
      if (!token) throw denied();
      const { payload } = await jwtVerify(token, secret, {
        algorithms: ["HS256"],
      });
      if (
        typeof payload.userId !== "string" ||
        typeof payload.context !== "string" ||
        typeof payload.mode !== "string"
      )
        throw denied();
      return {
        userId: payload.userId,
        context: payload.context,
        mode: payload.mode,
      };
    } catch {
      throw denied();
    }
  }
  const configured = passkey({
    registration: {
      requireSession: false,
      async resolveUser({ ctx, context }) {
        const enrollment = await proof(ctx.headers);
        if (enrollment.context !== context) throw denied();
        events.push({ stage: "resolved", context, userId: enrollment.userId });
        if (enrollment.mode === "resolver-invalid-id")
          return { id: "", name: "Passkey Applicant" };
        if (enrollment.mode === "resolver-invalid-name")
          return { id: `pending:${enrollment.userId}`, name: "" };
        if (enrollment.mode === "resolver-throw")
          throw new Error("resolver failed");
        if (enrollment.mode === "resolver-api")
          throw new APIError("FORBIDDEN", {
            code: "RESOLVER_DENIED",
            message: "Resolver denied enrollment",
          });
        return {
          id: `pending:${enrollment.userId}`,
          name: "Passkey Applicant",
          displayName: "Passkey Applicant",
        };
      },
      async afterVerification({
        ctx,
        verification,
        user,
        clientData,
        context,
      }) {
        const enrollment = await proof(ctx.headers);
        if (
          enrollment.context !== context ||
          (user.id.startsWith("pending:") &&
            user.id !== `pending:${enrollment.userId}`)
        )
          throw denied();
        const info = verification.registrationInfo!;
        events.push({
          stage: "verified",
          context,
          user,
          userId: enrollment.userId,
          credentialID: info.credential.id,
          publicKey: Buffer.from(info.credential.publicKey).toString("base64"),
          counter: info.credential.counter,
          aaguid: info.aaguid,
          deviceType: info.credentialDeviceType,
          backedUp: info.credentialBackedUp,
          clientData,
        });
        if (enrollment.mode === "after-dynamic-api")
          throw new APIError("INTERNAL_SERVER_ERROR", {
            code: "APPLICATION_POLICY_DENIED",
            message: `Application enrollment denied: ${context}`,
          });
        if (enrollment.mode === "after-forbidden")
          throw new APIError("FORBIDDEN", {
            message: "session creation cancelled by database hook",
          });
        if (enrollment.mode === "after-validation")
          throw new APIError("BAD_REQUEST", {
            message: "Validation error: Callback validation rejected",
          });
        if (enrollment.mode === "after-throw")
          throw new Error("after verification failed");
        if (enrollment.mode === "after-api")
          throw new APIError("FORBIDDEN", {
            code: "CALLBACK_DENIED",
            message: "Callback denied enrollment",
          });
        return {
          userId:
            enrollment.mode === "missing-user"
              ? "missing-passkey-owner"
              : enrollment.userId,
          name: " \uFEFFCallback Label\uFEFF ",
        };
      },
    },
  });
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of ["passkey-first", "passkey-first-missing", "passkey-first-trusted-origin", "passkey-first-configured-origin"]) {
    const path = `/__test/profiles/${name}/api/auth`;
    profiles.set(
      path,
      betterAuth({
        ...options,
        basePath: path,
        ...(name.endsWith("origin")?{trustedOrigins:[...(Array.isArray(options.trustedOrigins)?options.trustedOrigins:[]),"http://localhost:49190"]}:{}),
        databaseHooks: {
          session: {
            create: {
              before: async (_session, ctx) => {
                const policy = ctx?.headers?.get("x-passkey-policy");
                if (policy === "session-error")
                  throw new APIError("FORBIDDEN", {
                    message: "session creation cancelled by database hook",
                  });
                return policy === "session-deny" ? false : undefined;
              },
            },
          },
        },
        plugins: [
          name === "passkey-first-configured-origin"
            ? passkey({...configured.options,origin:options.baseURL as string})
            : name !== "passkey-first-missing"
            ? configured
            : passkey({ registration: { requireSession: false } }),
          username(),
        ],
      }),
    );
  }
  return {
    profiles,
    reset() { events.length = 0; },
    async handle(request: Request): Promise<Response | null> {
      const path = new URL(request.url).pathname;
      if (path === "/__test/passkey-registration-state") {
        const database=options.database as import("bun:sqlite").Database;
        const userId=new URL(request.url).searchParams.get("userId")??"";
        return Response.json({rows:database.query("SELECT * FROM passkey WHERE userId=? ORDER BY rowid").all(userId).map(value=>{const row=value as Record<string,unknown>;return {...row,createdAt:new Date(String(row.createdAt)).toISOString()};})});
      }
      if (path === "/__test/passkey-registration-events")
        return Response.json({ events: events.splice(0) });
      if (path !== "/__test/passkey-enrollment" || request.method !== "POST")
        return null;
      const session = await profiles
        .get("/__test/profiles/passkey-first/api/auth")!
        .api.getSession({ headers: request.headers });
      if (!session)
        return Response.json(
          { code: "UNAUTHORIZED", message: "Unauthorized" },
          { status: 401 },
        );
      const body = (await request.json()) as { context: string; mode?: string };
      if (!body.context || typeof body.context !== "string")
        return Response.json(
          { message: "Invalid enrollment context" },
          { status: 400 },
        );
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({
        userId: session.user.id,
        context: body.context,
        mode: body.mode ?? "normal",
      })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt(now)
        .setExpirationTime(body.mode === "expired" ? now - 1 : now + 300)
        .sign(secret);
      return Response.json(
        { token, userId: session.user.id },
        {
          headers: {
            "set-cookie": `passkey_enrollment=${token}; Max-Age=300; Path=/; HttpOnly; SameSite=Lax`,
          },
        },
      );
    },
  };
}
