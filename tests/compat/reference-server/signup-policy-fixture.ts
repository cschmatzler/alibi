/** Application options exercised through the actual pinned signup/password routes. */
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { emailOTP, username } from "better-auth/plugins";
import type { Database } from "bun:sqlite";

export function createSignupPolicyFixture(database: Database, shared: BetterAuthOptions) {
  const events: Record<string, unknown>[] = [];
  let mode = "normal";
  let releaseExisting: (() => void) | undefined;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of ["signup-standard", "signup-disabled", "signup-password-disabled",
    "signup-no-auto", "signup-required", "signup-custom", "signup-policy", "signup-zero-policy",
    "signup-username", "signup-otp", "signup-background"]) {
    const basePath = `/__test/profiles/${name}/api/auth`;
    const requireEmailVerification = name === "signup-required" || name === "signup-otp";
    const autoSignIn = !["signup-no-auto", "signup-custom", "signup-username", "signup-background"].includes(name);
    const instance = betterAuth({
      ...shared, database, basePath,
      databaseHooks:{user:{create:{before:async()=>{
        if(mode==="user-forbidden") {
          events.push({stage:"user-create-denied"});
          throw new APIError("FORBIDDEN",{code:"USER_CREATION_DENIED",message:"Configured user creation denied"});
        }
        if(mode==="user-cancel") {events.push({stage:"user-create-cancelled"});return false;}
        if(mode==="user-error") {events.push({stage:"user-create-error"});throw new Error("Actual configured user creation failed");}
      }}}},
      plugins: [
        ...(name === "signup-username" ? [username()] : []),
        ...(name === "signup-otp" ? [emailOTP({ overrideDefaultEmailVerification: true,
          async sendVerificationOTP(delivery) { events.push({stage: "otp", ...delivery}); },
        })] : []),
      ],
      advanced: {...shared.advanced, ...(name === "signup-background" ? {
        backgroundTasks: { handler(completion: Promise<unknown>) {
          events.push({stage: "background-register"});
          void completion;
          if (mode === "background-error") throw new Error("Actual background observer failed");
        } },
      } : {})},
      emailVerification: name === "signup-otp" ? {sendOnSignUp:true,autoSignInAfterVerification:false} : { ...shared.emailVerification,
        async sendVerificationEmail({user, url, token}) {
          events.push({stage: "verification-email", user, url, token});
        },
      },
      emailAndPassword: {
        ...shared.emailAndPassword,
        enabled: name !== "signup-password-disabled",
        disableSignUp: name === "signup-disabled", autoSignIn, requireEmailVerification,
        minPasswordLength: name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 10 : 8,
        maxPasswordLength: name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 20 : 128,
        resetPasswordTokenExpiresIn: name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 90 : 3600,
        revokeSessionsOnPasswordReset: name === "signup-policy",
        password: {
          async hash(password) {
            events.push({stage: "hash-enter", password});
            const hash = await hashPassword(password);
            events.push({stage: "hash-result", password, hash});
            if (mode === "hash-error") throw new Error("Actual configured hash failed");
            if (mode === "hash-api") throw new APIError("FORBIDDEN", {code: "HASH_REJECTED", message: "Configured hash rejected"});
            return hash;
          },
          async verify({hash, password}) {
            events.push({stage: "verify-enter", hash, password});
            const valid = await verifyPassword({hash, password});
            events.push({stage: "verify-result", hash, password, valid});
            if (mode === "verify-error") throw new Error("Actual configured verifier failed");
            if (mode === "verify-api") throw new APIError("FORBIDDEN", {code: "VERIFY_REJECTED", message: "Configured verifier rejected"});
            return valid;
          },
        },
        async onExistingUserSignUp({user}, request) {
          events.push({stage: "existing-user", user, request: request ? {
            method: request.method, path: new URL(request.url).pathname.slice(basePath.length),
            marker: request.headers.get("x-test-policy-marker"),
            contentType: request.headers.get("content-type"),
          } : null});
          if (mode === "existing-block") await new Promise<void>((resolve) => { releaseExisting = resolve; });
          if (mode === "existing-error") throw new Error("Actual existing-user callback failed");
          if (mode === "existing-api") throw new APIError("FORBIDDEN", {code: "EXISTING_REJECTED", message: "Configured existing-user rejected"});
          events.push({stage: "existing-complete"});
        },
        ...(name === "signup-custom" ? {
          customSyntheticUser({coreFields, additionalFields, id}) {
            events.push({stage: "synthetic-user", coreFields, additionalFields, id});
            if (mode === "synthetic-error") throw new Error("Actual synthetic-user callback failed");
            if (mode === "synthetic-api") throw new APIError("FORBIDDEN", {code: "SYNTHETIC_REJECTED", message: "Configured synthetic-user rejected"});
            return {...coreFields, id, name: `Synthetic ${coreFields.name}`, emailVerified: true,
              image: "https://images.example/synthetic.png", role: "admin", privateCredential: "unreturned-application-data"};
          },
        } : {}),
        async sendResetPassword({user, url, token}, request) {
          events.push({stage: "reset-delivery", user, url, token,
            request: request ? {method: request.method, path: new URL(request.url).pathname.slice(basePath.length),
              marker: request.headers.get("x-test-policy-marker"), contentType: request.headers.get("content-type")} : null});
          if (mode === "reset-sender-error") throw new Error("Actual configured reset sender failed");
        },
        async onPasswordReset({user}, request) {
          events.push({stage: "password-reset", user,
            request: request ? {method: request.method, path: new URL(request.url).pathname.slice(basePath.length),
              marker: request.headers.get("x-test-policy-marker"), contentType: request.headers.get("content-type")} : null});
          if (mode === "reset-callback-error") throw new Error("Actual configured reset callback failed");
          if (mode === "reset-callback-api") throw new APIError("FORBIDDEN", {code: "RESET_REJECTED", message: "Configured reset callback rejected"});
        },
      },
    });
    profiles.set(name, instance);
  }
  return {profiles,
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/signup-policy/state") {
        const profile = profiles.get(url.searchParams.get("profile") ?? "signup-standard");
        if (!profile) return Response.json({message: "unknown fixture profile"}, {status: 400});
        const context = await profile.$context;
        const read = (model: "user" | "account" | "session" | "verification") =>
          context.adapter.findMany<Record<string, unknown>>({model, sortBy: {field: "createdAt", direction: "asc"}});
        return Response.json({users: await read("user"), accounts: await read("account"),
          sessions: await read("session"), verifications: await read("verification"), events});
      }
      if (url.pathname !== "/__test/signup-policy" || request.method !== "POST") return;
      const body = await request.json() as {operation?: string; mode?: string; profile?: string; accountId?: string; stage?: string; password?: string};
      if (body.operation === "mode") {
        mode = body.mode ?? "normal"; events.length = 0;
        return Response.json({status: true, mode});
      }
      if (body.operation === "release-existing") {
        releaseExisting?.(); releaseExisting = undefined;
        return Response.json({status: true});
      }
      if (body.operation === "wait-stage") {
        const deadline = Date.now() + 4000;
        while (!events.some(event => event.stage === body.stage)) {
          if (Date.now() >= deadline) return Response.json({message:"application callback did not reach requested stage"},{status:408});
          await Bun.sleep(5);
        }
        return Response.json({events});
      }
      if (body.operation === "clear-password") {
        const context = await profiles.get(body.profile ?? "signup-standard")!.$context;
        await context.internalAdapter.updateAccount(body.accountId!, {password: body.password ?? null});
        return Response.json({status: true});
      }
      return Response.json({message: "unknown fixture operation"}, {status: 400});
    },
  };
}
