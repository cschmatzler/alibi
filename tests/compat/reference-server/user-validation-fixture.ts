/** Trusted application policy; all receipts originate in the pinned runtime. */
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError } from "better-auth/api";
import { hashPassword } from "better-auth/crypto";
import { getMigrations } from "better-auth/db/migration";
import { admin, anonymous, emailOTP, magicLink, oneTap, phoneNumber } from "better-auth/plugins";
import { siwe } from "better-auth/plugins/siwe";
import { verifyFixtureEip191 } from "./siwe-fixture";

export async function createUserValidationFixture(database: Database, shared: BetterAuthOptions) {
  const events: Record<string, unknown>[] = [];
  const deliveries = new Map<string, unknown>();
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  let mode = "normal", sequence = 0;
  let release: (() => void) | undefined;
  const snapshot = (value: unknown) => JSON.parse(JSON.stringify(value));
  for (const name of ["validation", "validation-no-auto", "validation-required", "validation-disabled", "validation-no-policy"]) {
    const basePath = `/__test/profiles/${name}/api/auth`;
    const options: BetterAuthOptions = {
      ...shared, database, basePath,
      account: {...shared.account, accountLinking: {...shared.account?.accountLinking,
        enabled: true, trustedProviders: ["google", "gitlab"]}},
      socialProviders: {
        google: {clientId: "google-default-client", clientSecret: "local-google-default-secret"},
        gitlab: {clientId: "fixture-social-client", clientSecret: "fixture-social-secret",
          issuer: `${shared.baseURL}/__test/social-provider/gitlab`},
      },
      user: {...shared.user, ...(name === "validation-no-policy" ? {} : {
        async validateUserInfo(data, context) {
          const policyMode = mode;
          events.push({stage: "validation", ...snapshot(data), context: {
            path: context.path, body: snapshot(context.body ?? null),
            request: context.request ? {method: context.request.method,
              path: new URL(context.request.url).pathname.slice(basePath.length),
              marker: context.request.headers.get("x-test-validation-marker"),
              contentType: context.request.headers.get("content-type")} : null,
          }});
          if (policyMode === "hold") await new Promise<void>(resolve => {release = resolve;});
          if (policyMode === "deny" || policyMode === "hold" || policyMode === "deny-empty-name" && data.user.name === "") return {error: "identity_denied", errorDescription: "Configured identity rejected"};
          if (mode === "deny-default") return {error: "identity_denied"};
          if (mode === "empty-error") return {error: "", errorDescription: "Unused description"};
          if (mode === "throw") throw new Error("Private application exception");
          if (mode === "api-error") throw new APIError("UNAUTHORIZED", {code: "PRIVATE_CALLBACK_CODE", message: "Private callback detail"});
          if (mode === "mutate") {
            data.user.name = "Validated Identity";
            data.user.email = "MUTATED@VALIDATION.FIXTURE.TEST";
            data.user.emailVerified = true;
            data.user.image = "https://images.example/validated.png";
            data.user.createdAt = new Date("2001-01-01T00:00:00.000Z");
          }
        },
      })},
      databaseHooks: {user: {create: {before: async (user, context) => {
        events.push({stage: "user-create-before", user: snapshot(user), path: context?.path ?? null});
        if (mode === "hook-deny") return false;
      }, after: async (user, context) => {
        events.push({stage: "user-create-after", userId: user.id, path: context?.path ?? null});
      }}}, account: {create: {before: async (account, context) => {
        events.push({stage: "account-create-before", path: context?.path ?? null});
      }}}, session: {create: {before: async (session, context) => {
        events.push({stage: "session-create-before", path: context?.path ?? null});
      }}}},
      emailAndPassword: {...shared.emailAndPassword, enabled: true,
        autoSignIn: name !== "validation-no-auto", requireEmailVerification: name === "validation-required",
        disableSignUp: name === "validation-disabled", password: {
          async hash(password) {events.push({stage: "hash-enter", password}); const hash = await hashPassword(password);
            events.push({stage: "hash-result", password, hash}); return hash;},
        }},
      emailVerification: {...shared.emailVerification, sendOnSignUp: false},
      plugins: [admin(), anonymous({generateName: async () => "Configured Anonymous",
        generateRandomEmail: () => `Anonymous-${++sequence}@Validation.Fixture.Test`}),
        magicLink({async sendMagicLink(delivery) {deliveries.set(`magic:${delivery.email}`, delivery);}}),
        emailOTP({async sendVerificationOTP(delivery) {deliveries.set(`otp:${delivery.type}:${delivery.email}`, delivery);}}),
        phoneNumber({async sendOTP(delivery) {deliveries.set(`phone:${delivery.phoneNumber}`, delivery);},
          signUpOnVerification: {getTempEmail: phone => `${phone}@Phone.Validation.Fixture.Test`, getTempName: phone => phone}}),
        oneTap({clientId: "one-tap-plugin-client"}),
        siwe({domain: "HTTPS://Fixture.Example/ignored", anonymous: false,
          emailDomainName: "Wallet.Fixture.Test", getNonce: async () => `ValidationNonce${String(sequence++).padStart(16,"0")}`,
          verifyMessage: async input => verifyFixtureEip191(input.message, input.signature, input.address)}),
      ],
    };
    if (name === "validation") await (await getMigrations(options)).runMigrations();
    profiles.set(name, betterAuth(options));
  }
  return {profiles, reset() {mode = "normal"; sequence = 0; events.length = 0; deliveries.clear();},
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/user-validation/state") {
        const context = await profiles.get("validation")!.$context;
        const read = (model: "user" | "account" | "session" | "verification" | "walletAddress") =>
          context.adapter.findMany<Record<string, unknown>>({model, sortBy: {field: "createdAt", direction: "asc"}});
        return Response.json({users: await read("user"), accounts: await read("account"), sessions: await read("session"),
          verifications: await read("verification"), wallets: await read("walletAddress"), events});
      }
      if (url.pathname === "/__test/user-validation/delivery") return Response.json(deliveries.get(url.searchParams.get("key") ?? "") ?? null);
      if (url.pathname !== "/__test/user-validation" || request.method !== "POST") return;
      const body = await request.json() as {operation?: string; mode?: string; stage?: string; profile?: string; source?: unknown; email?: string; identifier?: string; expiresAt?: string};
      if (body.operation === "mode") {mode = body.mode ?? "normal"; events.length = 0; return Response.json({status: true, mode});}
      if (body.operation === "release") {release?.(); release = undefined; return Response.json({status: true});}
      if (body.operation === "wait-stage") {
        const deadline = Date.now() + 4000;
        while (!events.some(event => event.stage === body.stage)) {
          if (Date.now() >= deadline) return Response.json({message: "application callback did not reach requested stage"}, {status: 408});
          await Bun.sleep(5);
        }
        return Response.json({events});
      }
      if (body.operation === "proof-expiry") {
        const context = await profiles.get("validation")!.$context;
        await context.adapter.update({model: "verification", where: [{field: "identifier", value: body.identifier!}], update: {expiresAt: new Date(body.expiresAt!)}});
        return Response.json({status: true});
      }
      if (body.operation === "server-create") {
        const context = await profiles.get(body.profile ?? "validation")!.$context;
        try {return Response.json(await context.internalAdapter.createUser({name: "Server Candidate", email: body.email!, emailVerified: false}, body.source as never));}
        catch (error) {if (error instanceof APIError) return Response.json(error.body, {status: 403}); throw error;}
      }
      return Response.json({message: "unknown fixture operation"}, {status: 400});
    },
  };
}
