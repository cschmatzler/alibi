import { expect } from "bun:test";

import { createAuthClient } from "better-auth/client";
import {
  anonymousClient,
  emailOTPClient,
  magicLinkClient,
  phoneNumberClient,
  siweClient,
} from "better-auth/client/plugins";
import { verifyPassword } from "better-auth/crypto";
import { decodeJwt } from "jose";

import { credential } from "../../../support/id-token";
import { authProfilePath, type FixtureProfile } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";
import { EOA, message, SECOND_EOA, signature } from "../../../support/siwe-wallet";
import { oneTap } from "../../plugins/one-tap/helpers";

type Row = Record<string, any>;

type State = {
  users: Row[];
  accounts: Row[];
  sessions: Row[];
  verifications: Row[];
  wallets: Row[];
  events: Row[];
};

async function configure(ctx: ScenarioContext, mode: string) {
  const response = await ctx.rawRequest({
    path: "/__test/user-validation",
    method: "POST",
    json: { operation: "mode", mode },
  });
  expect(response.status).toBe(200);
  return response;
}

async function state(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/user-validation/state" });
  expect(response.status).toBe(200);
  return response.body as State;
}

function identities(value: State) {
  return {
    users: value.users,
    accounts: value.accounts,
    sessions: value.sessions,
    wallets: value.wallets,
  };
}

function hash(value: unknown) {
  if (typeof value !== "string" || value === "") {
    return value;
  }

  expect(value).toMatch(/^[a-f0-9]{32}:[a-f0-9]{128}$/);

  const [salt, derived] = value.split(":");
  return {
    token: value,
    salt: { token: salt, length: salt!.length },
    derivedKey: { token: derived, length: derived!.length },
    encoding: "hex-lower",
  };
}

function observed(value: State) {
  return {
    ...value,
    accounts: value.accounts.map((row) => ({ ...row, password: hash(row.password) })),
    verifications: value.verifications.map((row) => {
      if (typeof row.value === "string" && /^\d{6}:\d+$/.test(row.value)) {
        return {
          ...row,
          value: {
            token: row.value.split(":")[0],
            attempts: row.value.split(":")[1],
            separator: ":",
          },
        };
      }
      if (typeof row.value === "string" && row.identifier.startsWith("magic-link:")) {
        return {
          ...row,
          identifier: {
            token: row.identifier.slice("magic-link:".length),
            namespace: "magic-link:",
            length: row.identifier.length,
          },
        };
      }
      return row;
    }),
    events: value.events.map((event) => {
      if (event.stage === "hash-result") {
        return { ...event, hash: hash(event.hash) };
      }
      if (event.stage === "validation" && event.context?.body) {
        const body = { ...event.context.body };
        for (const field of ["otp", "code"]) {
          if (typeof body[field] === "string" && /^\d{6}$/.test(body[field])) {
            body[field] = { token: body[field], length: body[field].length, encoding: "decimal" };
          }
        }
        return { ...event, context: { ...event.context, body } };
      }
      return event;
    }),
  };
}

async function foreign(ctx: ScenarioContext) {
  await configure(ctx, "normal");
  const signup = await ctx.actor("foreign", "validation").client.signUp.email({
    email: ctx.uniqueEmail("validation-foreign"),
    name: "Foreign Identity",
    password: "foreign-password123",
  });
  expect(signup.error).toBeNull();

  return { signup, state: await ctx.readUserState({ userId: signup.data!.user.id }) };
}

async function unchangedForeign(ctx: ScenarioContext, other: Awaited<ReturnType<typeof foreign>>) {
  expect(await ctx.readUserState({ userId: other.signup.data!.user.id })).toEqual(other.state);
}

function validations(value: State) {
  return value.events.filter((event) => event.stage === "validation");
}

function client(ctx: ScenarioContext, name: string, profile: FixtureProfile = "validation") {
  return createAuthClient({
    baseURL: ctx.baseURL + authProfilePath(profile),
    plugins: [
      anonymousClient(),
      emailOTPClient(),
      magicLinkClient(),
      phoneNumberClient(),
      siweClient(),
    ],
    fetchOptions: { customFetchImpl: ctx.actor(name, profile).fetch },
  });
}

async function delivery(ctx: ScenarioContext, key: string) {
  const response = await ctx.rawRequest({
    path: `/__test/user-validation/delivery?key=${encodeURIComponent(key)}`,
  });
  expect(response.status).toBe(200);
  expect(response.body).not.toBeNull();

  return response.body as Row;
}

function observedDelivery(row: Row) {
  return {
    ...row,
    ...(typeof row.otp === "string" ? { otp: { token: row.otp, length: row.otp.length } } : {}),
    ...(typeof row.code === "string" ? { code: { token: row.code, length: row.code.length } } : {}),
  };
}

const proofRoutes = {
  anonymous: "POST /sign-in/anonymous",
  "magic-link": "GET /magic-link/verify",
  "email-otp": "POST /sign-in/email-otp",
  "phone-number": "POST /phone-number/verify",
  siwe: "POST /siwe/verify",
} as const;

type ProofMethod = keyof typeof proofRoutes;

function proofFlow(ctx: ScenarioContext, method: ProofMethod, label: string) {
  const actor = client(ctx, label);
  const email = ctx.uniqueEmail(label);
  const phone = "+15550001239";
  return {
    async issue() {
      if (method === "anonymous") {
        return { proof: null, issued: null, delivery: null };
      }

      if (method === "magic-link") {
        const issued = await actor.signIn.magicLink({
          email,
          name: "Proof Identity",
          metadata: { gate: "identity-validation" },
        });
        expect(issued.error).toBeNull();

        const sent = await delivery(ctx, `magic:${email}`);
        return { proof: sent.token as string, issued, delivery: observedDelivery(sent) };
      }

      if (method === "email-otp") {
        const issued = await actor.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
        expect(issued.error).toBeNull();

        const sent = await delivery(ctx, `otp:sign-in:${email}`);
        return { proof: sent.otp as string, issued, delivery: observedDelivery(sent) };
      }

      if (method === "phone-number") {
        const issued = await actor.phoneNumber.sendOtp({ phoneNumber: phone });
        expect(issued.error).toBeNull();

        const sent = await delivery(ctx, `phone:${phone}`);
        return { proof: sent.code as string, issued, delivery: observedDelivery(sent) };
      }

      const issued = await actor.siwe.nonce();
      expect(issued.error).toBeNull();

      return { proof: message((issued.data as { nonce: string }).nonce), issued, delivery: null };
    },
    async submit(proof: string | null) {
      if (method === "anonymous") {
        return actor.signIn.anonymous();
      }

      if (method === "magic-link") {
        return ctx.rawRequest({
          actor: label,
          path: `${authProfilePath("validation")}/magic-link/verify?token=${encodeURIComponent(proof!)}`,
          redirect: "manual",
        });
      }

      if (method === "email-otp") {
        return actor.signIn.emailOtp({ email, otp: proof!, name: "Proof Identity" });
      }

      if (method === "phone-number") {
        return actor.phoneNumber.verify({ phoneNumber: phone, code: proof! });
      }

      return actor.siwe.verify({ message: proof!, signature: signature(proof!), email });
    },
  };
}

function observedProof(
  method: ProofMethod,
  value: Awaited<ReturnType<ReturnType<typeof proofFlow>["issue"]>>,
) {
  return {
    ...value,
    proof:
      value.proof && method !== "siwe"
        ? { token: value.proof, length: value.proof.length }
        : value.proof,
  };
}

compatScenario(
  "identity validation owns normalized signup admission, mutation, callback errors and database hook ordering",
  async (ctx) => {
    const other = await foreign(ctx);
    const observations = [];

    for (const mode of [
      "deny",
      "deny-default",
      "throw",
      "api-error",
      "empty-error",
      "normal",
      "mutate",
    ]) {
      const configured = await configure(ctx, mode);
      const before = await state(ctx);
      const email = ctx.uniqueEmail(`validation-${mode}`);
      const signup = await ctx
        .actor(mode, "validation")
        .client.signUp.email(
          { email: email.toUpperCase(), name: "Requested Identity", password: "password123" },
          { headers: { "x-test-validation-marker": `actual-${mode}` } },
        );
      const after = await state(ctx);
      const events = after.events;
      expect(events.slice(0, 3).map((event) => event.stage)).toEqual([
        "hash-enter",
        "hash-result",
        "validation",
      ]);
      expect(validations(after)).toHaveLength(1);
      expect(events[2]).toMatchObject({
        user: { email, name: "Requested Identity", emailVerified: false },
        source: { method: "email-password", action: "create-user" },
        context: {
          path: "/sign-up/email",
          body: { email: email.toUpperCase(), name: "Requested Identity", password: "password123" },
          request: {
            method: "POST",
            path: "/sign-up/email",
            marker: `actual-${mode}`,
            contentType: "application/json",
          },
        },
      });
      expect(events[2]!.user.createdAt).toBeString();
      expect(events[2]!.user.updatedAt).toBeString();
      expect(events[2]!.user).not.toHaveProperty("id");
      expect(events[2]!.user).not.toHaveProperty("role");

      if (["deny", "deny-default", "throw", "api-error"].includes(mode)) {
        expect(signup.error).toMatchObject({
          status: 403,
          code:
            mode.endsWith("error") || mode === "throw" ? "validation_failed" : "identity_denied",
          message:
            mode.endsWith("error") || mode === "throw"
              ? "User validation failed"
              : mode === "deny-default"
                ? "identity_denied"
                : "Configured identity rejected",
        });
        expect(identities(after)).toEqual(identities(before));
        expect(events).toHaveLength(3);
      } else {
        expect(signup.error).toBeNull();

        const id = signup.data!.user.id;
        const stored = after.users.find((row) => row.id === id)!;
        expect(after.accounts.filter((row) => row.userId === id)).toHaveLength(1);
        expect(after.sessions.filter((row) => row.userId === id)).toHaveLength(1);
        expect(
          await verifyPassword({
            hash: after.accounts.find((row) => row.userId === id)!.password,
            password: "password123",
          }),
        ).toBe(true);
        expect(events.map((event) => event.stage)).toEqual([
          "hash-enter",
          "hash-result",
          "validation",
          "user-create-before",
          "account-create-before",
          "session-create-before",
          "user-create-after",
        ]);
        expect(events[3]!.user.role).toBe("user");
        expect(events[6]!.userId).toBe(id);

        if (mode === "mutate") {
          expect(stored).toMatchObject({
            name: "Validated Identity",
            email: "MUTATED@VALIDATION.FIXTURE.TEST",
            emailVerified: true,
            image: "https://images.example/validated.png",
            createdAt: "2001-01-01T00:00:00.000Z",
          });
          expect(events[3]!.user).toMatchObject({
            name: stored.name,
            email: stored.email,
            emailVerified: stored.emailVerified,
            image: stored.image,
            createdAt: stored.createdAt,
          });
        } else {
          expect(stored).toMatchObject({ email, name: "Requested Identity", emailVerified: false });
        }
      }

      await unchangedForeign(ctx, other);
      observations.push({
        mode,
        configured,
        before: observed(before),
        signup,
        after: observed(after),
      });
    }

    return { foreign: other, observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "enumeration-safe signup preserves validation denial synthesis and skips validation for duplicate or returning password identity",
  async (ctx) => {
    const other = await foreign(ctx);
    const observations = [];

    for (const profile of ["validation-no-auto", "validation-required"] as const) {
      const configured = await configure(ctx, "deny");
      const before = await state(ctx);
      const actor = ctx.actor(profile, profile);
      const email = ctx.uniqueEmail(profile);
      const denied = await actor.client.signUp.email({
        email,
        name: "Synthetic Candidate",
        password: "password123",
      });
      expect(denied.error).toBeNull();
      expect(denied.data?.token).toBeNull();
      expect(denied.data?.user).toMatchObject({ email, name: "Synthetic Candidate" });

      const after = await state(ctx);
      expect(identities(after)).toEqual(identities(before));
      expect(after.users.some((row) => row.id === denied.data!.user.id)).toBe(false);
      expect(after.events.map((event) => event.stage)).toEqual([
        "hash-enter",
        "hash-result",
        "validation",
      ]);

      observations.push({
        profile,
        configured,
        before: observed(before),
        denied,
        after: observed(after),
      });
    }

    const normal = await configure(ctx, "normal");
    const owner = ctx.actor("owner", "validation-no-auto");
    const email = ctx.uniqueEmail("existing-validation");
    const signup = await owner.client.signUp.email({
      email,
      name: "Existing Owner",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const denied = await configure(ctx, "deny");
    const before = await state(ctx);
    const duplicate = await owner.client.signUp.email({
      email,
      name: "Synthetic Duplicate",
      password: "duplicate-password123",
    });
    expect(duplicate.error).toBeNull();
    expect(duplicate.data?.user.id).not.toBe(signup.data!.user.id);

    const signed = await owner.client.signIn.email({ email, password: "password123" });
    expect(signed.error).toBeNull();
    expect(signed.data?.user.id).toBe(signup.data!.user.id);

    const after = await state(ctx);
    expect(validations(after)).toEqual([]);
    expect(after.users).toEqual(before.users);
    expect(after.accounts).toEqual(before.accounts);

    const disabledConfig = await configure(ctx, "deny");
    const disabled = await ctx.actor("disabled", "validation-disabled").client.signUp.email({
      email: ctx.uniqueEmail("disabled-validation"),
      name: "Disabled",
      password: "password123",
    });
    expect(disabled.error?.status).toBe(400);
    expect((await state(ctx)).events).toEqual([]);

    await unchangedForeign(ctx, other);
    return {
      foreign: other,
      observations,
      normal,
      signup,
      denied,
      before: observed(before),
      duplicate,
      signed,
      after: observed(after),
      disabledConfig,
      disabled,
    };
  },
  ["POST /sign-up/email", "POST /sign-in/email"],
);

for (const method of ["anonymous", "magic-link", "email-otp", "phone-number", "siwe"] as const) {
  compatScenario(
    `identity validation ${method} creation rejects before identity writes and consumes only genuine applicable proof`,
    async (ctx) => {
      const other = await foreign(ctx);
      const actor = client(ctx, "identity");
      const email = ctx.uniqueEmail(`validation-${method}`);
      const phone = "+15550001234";
      const preparation: unknown[] = [];

      async function issue(second = false) {
        if (method === "anonymous") {
          return { proof: null, delivery: null };
        }

        if (method === "magic-link") {
          const issued = await actor.signIn.magicLink({
            email: second ? ctx.uniqueEmail("magic-second") : email,
            name: "Mailbox Identity",
            metadata: { gate: "identity-validation" },
          });
          expect(issued.error).toBeNull();

          const sent = await delivery(
            ctx,
            `magic:${second ? ctx.uniqueEmail("magic-second") : email}`,
          );
          return { proof: sent.token as string, delivery: sent, issued };
        }

        if (method === "email-otp") {
          const selected = second ? ctx.uniqueEmail("otp-second") : email;
          const issued = await actor.emailOtp.sendVerificationOtp({
            email: selected,
            type: "sign-in",
          });
          expect(issued.error).toBeNull();

          const sent = await delivery(ctx, `otp:sign-in:${selected}`);
          return { proof: sent.otp as string, delivery: sent, issued };
        }

        if (method === "phone-number") {
          const selected = second ? "+15550001235" : phone;
          const issued = await actor.phoneNumber.sendOtp({ phoneNumber: selected });
          expect(issued.error).toBeNull();

          const sent = await delivery(ctx, `phone:${selected}`);
          return { proof: sent.code as string, delivery: sent, issued };
        }

        const issued = await actor.siwe.nonce();
        expect(issued.error).toBeNull();

        return {
          proof: message((issued.data as { nonce: string }).nonce, {
            address: second ? SECOND_EOA : EOA,
          }),
          delivery: null,
          issued,
        };
      }

      async function submit(
        issued: Awaited<ReturnType<typeof issue>>,
        second = false,
        wrong = false,
      ) {
        if (method === "anonymous") {
          return actor.signIn.anonymous();
        }

        if (method === "magic-link") {
          return ctx.rawRequest({
            actor: "identity",
            path: `${authProfilePath("validation")}/magic-link/verify?token=${encodeURIComponent(wrong ? "wrong-actual-proof" : issued.proof!)}`,
            redirect: "manual",
            headers: { "x-test-validation-marker": "actual-proof" },
          });
        }

        if (method === "email-otp") {
          return actor.signIn.emailOtp(
            {
              email: second ? ctx.uniqueEmail("otp-second") : email,
              otp: wrong ? "wrong-actual-proof" : issued.proof!,
              name: "Mailbox Identity",
            },
            { headers: { "x-test-validation-marker": "actual-proof" } },
          );
        }

        if (method === "phone-number") {
          return actor.phoneNumber.verify(
            {
              phoneNumber: second ? "+15550001235" : phone,
              code: wrong ? "wrong-actual-proof" : issued.proof!,
            },
            { headers: { "x-test-validation-marker": "actual-proof" } },
          );
        }

        return actor.siwe.verify(
          {
            message: issued.proof!,
            signature: signature(issued.proof!, wrong ? 3 : second ? 2 : 1),
            email: second ? ctx.uniqueEmail("siwe-second") : email,
          },
          { headers: { "x-test-validation-marker": "actual-proof" } },
        );
      }

      let prepared = await issue();
      const configured = await configure(ctx, "deny");
      const before = await state(ctx);

      if (method !== "anonymous") {
        const wrong = await submit(prepared, false, true);
        const rejected = await state(ctx);
        expect(validations(rejected)).toEqual([]);
        expect(identities(rejected)).toEqual(identities(before));

        preparation.push({
          wrong,
          proof: method === "siwe" ? prepared.proof : null,
          rejected: observed(rejected),
        });

        // SIWE consumes the nonce before signature verification, including a genuine
        // rejected signature. Admission therefore requires a newly issued nonce.
        if (method === "siwe") {
          prepared = await issue();
        }
      }

      const denied = await submit(prepared);
      const after = await state(ctx);
      expect(validations(after)).toHaveLength(1);
      expect(validations(after)[0]).toMatchObject({ source: { method, action: "create-user" } });

      if (method === "email-otp") {
        expect(validations(after)[0]!.context.body.otp).toBe(prepared.proof);
      }

      if (method === "phone-number") {
        expect(validations(after)[0]!.context.body.code).toBe(prepared.proof);
      }

      if (method === "siwe") {
        expect(validations(after)[0]!.context.body).toMatchObject({
          message: prepared.proof,
          signature: signature(prepared.proof!),
        });
      }

      if (method === "magic-link") {
        expect((denied as any).status).toBe(302);
        expect(new URL((denied as any).location).searchParams.get("error")).toBe("identity_denied");
        expect(new URL((denied as any).location).searchParams.get("error_description")).toBe(
          "Configured identity rejected",
        );
      } else {
        expect((denied as any).error).toMatchObject({
          status: 403,
          code: "identity_denied",
          message: "Configured identity rejected",
        });
      }

      expect(identities(after)).toEqual(identities(before));
      expect(after.events.map((event) => event.stage)).toEqual(["validation"]);

      let replay: unknown = null;
      let replayed: State | null = null;

      if (method !== "anonymous") {
        replay = await submit(prepared);
        replayed = await state(ctx);
        expect(validations(replayed)).toHaveLength(1);
        expect(identities(replayed)).toEqual(identities(before));
      }

      const acceptedConfig = await configure(ctx, "normal");
      const fresh = await issue(true);
      const accepted = await submit(fresh, true);
      const stored = await state(ctx);

      if (method === "magic-link") {
        expect((accepted as any).status).toBe(200);
      } else {
        expect((accepted as any).error).toBeNull();
      }

      expect(validations(stored)).toHaveLength(1);
      expect(validations(stored)[0]).toMatchObject({ source: { method, action: "create-user" } });
      expect(stored.users).toHaveLength(before.users.length + 1);
      expect(stored.sessions).toHaveLength(before.sessions.length + 1);

      const existingConfig = await configure(ctx, "deny");
      let returning: unknown = null;

      if (method === "anonymous") {
        returning = await actor.signIn.anonymous();
        expect((returning as any).error).not.toBeNull();
      } else {
        const again = await issue(true);
        returning = await submit(again, true);
        if (method === "magic-link") {
          expect((returning as any).status).toBe(200);
        } else {
          expect((returning as any).error).toBeNull();
        }
      }

      const returned = await state(ctx);
      expect(validations(returned)).toEqual([]);

      if (method === "phone-number") {
        expect(returned.users).toHaveLength(stored.users.length);
        for (const before of stored.users) {
          const after = returned.users.find((row) => row.id === before.id)!;
          if (before.phoneNumber === "+15550001235") {
            expect(after).toEqual({ ...before, updatedAt: after.updatedAt });
            expect(Date.parse(after.updatedAt)).toBeGreaterThanOrEqual(
              Date.parse(before.updatedAt),
            );
          } else {
            expect(after).toEqual(before);
          }
        }
      } else {
        expect(returned.users).toEqual(stored.users);
      }

      expect(returned.accounts).toEqual(stored.accounts);
      expect(returned.wallets).toEqual(stored.wallets);

      const mutationFlow = proofFlow(ctx, method, `mutation-${method}`);
      const policyObservations = [];

      for (const mode of ["throw", "mutate"]) {
        const config = await configure(ctx, mode);
        const proof = await mutationFlow.issue();
        const beforePolicy = await state(ctx);
        const result = await mutationFlow.submit(proof.proof);
        const afterPolicy = await state(ctx);
        expect(validations(afterPolicy)).toHaveLength(1);
        expect(validations(afterPolicy)[0]!.source).toEqual({ method, action: "create-user" });

        if (mode === "throw") {
          if (method === "magic-link") {
            expect((result as any).status).toBe(302);
            expect(new URL((result as any).location).searchParams.get("error")).toBe(
              "validation_failed",
            );
            expect(new URL((result as any).location).searchParams.get("error_description")).toBe(
              "User validation failed",
            );
          } else {
            expect((result as any).error).toMatchObject({
              status: 403,
              code: "validation_failed",
              message: "User validation failed",
            });
          }
          expect(identities(afterPolicy)).toEqual(identities(beforePolicy));
          expect(afterPolicy.events).toHaveLength(1);
        } else {
          if (method === "magic-link") {
            expect((result as any).status).toBe(200);
          } else {
            expect((result as any).error).toBeNull();
          }

          const admitted = afterPolicy.users.find(
            (row) => row.email === "MUTATED@VALIDATION.FIXTURE.TEST",
          )!;
          expect(admitted).toMatchObject({
            name: "Validated Identity",
            emailVerified: true,
            image: "https://images.example/validated.png",
            createdAt: "2001-01-01T00:00:00.000Z",
          });
          expect(afterPolicy.users).toHaveLength(beforePolicy.users.length + 1);
          expect(afterPolicy.sessions).toHaveLength(beforePolicy.sessions.length + 1);
          expect(
            afterPolicy.events.find((event) => event.stage === "user-create-before")?.user,
          ).toMatchObject({
            name: admitted.name,
            email: admitted.email,
            emailVerified: admitted.emailVerified,
            image: admitted.image,
            createdAt: admitted.createdAt,
          });
        }

        policyObservations.push({
          mode,
          config,
          proof: observedProof(method, proof),
          before: observed(beforePolicy),
          result,
          after: observed(afterPolicy),
        });
      }

      await unchangedForeign(ctx, other);
      return {
        foreign: other,
        prepared: {
          ...prepared,
          delivery: prepared.delivery ? observedDelivery(prepared.delivery) : null,
          proof:
            method === "magic-link" || method === "email-otp" || method === "phone-number"
              ? { token: prepared.proof }
              : prepared.proof,
        },
        configured,
        before: observed(before),
        preparation,
        denied,
        after: observed(after),
        replay,
        replayed: replayed ? observed(replayed) : null,
        acceptedConfig,
        fresh: {
          ...fresh,
          delivery: fresh.delivery ? observedDelivery(fresh.delivery) : null,
          proof:
            method === "magic-link" || method === "email-otp" || method === "phone-number"
              ? { token: fresh.proof }
              : fresh.proof,
        },
        accepted,
        stored: observed(stored),
        existingConfig,
        returning,
        returned: observed(returned),
        policyObservations,
      };
    },
    [proofRoutes[method]],
  );
}

for (const transport of ["google-id-token", "one-tap"] as const) {
  compatScenario(
    `identity validation ${transport} admits actual signed provider identity and gates returning account writes`,
    async (ctx) => {
      const other = await foreign(ctx);
      const owner = ctx.actor("provider", "validation");
      const email = ctx.uniqueEmail("validated-provider");
      const subject = ctx.uniqueToken("provider-subject");
      const claims = {
        aud: transport === "one-tap" ? "one-tap-plugin-client" : "google-default-client",
        sub: subject,
        email: email.toUpperCase(),
        email_verified: true,
        name: "Fresh Provider",
        picture: "https://images.example/provider.png",
        applicationClaim: { stage: "raw-provider" },
      };
      const token = await credential(claims);
      const wrong = await credential(claims, {}, true);
      const submit = (proof: string) =>
        transport === "one-tap"
          ? oneTap(ctx, proof, "validation", "provider").then((value) => value.response as any)
          : owner.client.signIn.social(
              { provider: "google", idToken: { token: proof, accessToken: "fresh-access-token" } },
              { headers: { "x-test-validation-marker": "actual-provider" } },
            );
      const deniedConfig = await configure(ctx, "deny");
      const before = await state(ctx);
      const wrongResult = await submit(wrong);
      const wrongState = await state(ctx);
      expect(wrongResult.error).not.toBeNull();
      expect(validations(wrongState)).toEqual([]);
      expect(identities(wrongState)).toEqual(identities(before));

      const denied = await submit(token);
      const after = await state(ctx);
      expect(denied.error).toMatchObject({
        status: 403,
        code: "identity_denied",
        message: "Configured identity rejected",
      });
      expect(identities(after)).toEqual(identities(before));
      expect(validations(after)).toHaveLength(1);
      expect(validations(after)[0]).toMatchObject({
        user: { email, name: "Fresh Provider", emailVerified: true },
        source: {
          method: "oauth",
          action: "create-user",
          oauth: { providerId: "google", profile: decodeJwt(token) },
        },
      });
      expect(validations(after)[0]!.user).not.toHaveProperty("id");

      const normal = await configure(ctx, "normal");
      const accepted = await submit(token);
      expect(accepted.error).toBeNull();

      const id = accepted.data!.user.id;
      const created = await state(ctx);
      expect(created.accounts.find((row) => row.userId === id)).toMatchObject({
        providerId: "google",
        accountId: subject,
        idToken: token,
      });
      expect(validations(created)).toHaveLength(1);

      const changed = await credential({
        ...claims,
        name: "Fresh Changed Provider",
        picture: "https://images.example/changed.png",
      });
      const returningConfig = await configure(ctx, "deny");
      const returningBefore = await state(ctx);
      const returning = await submit(changed);
      const returningAfter = await state(ctx);
      expect(returning.error).toMatchObject({ status: 403, code: "identity_denied" });
      expect(identities(returningAfter)).toEqual(identities(returningBefore));
      expect(validations(returningAfter)).toHaveLength(1);
      expect(validations(returningAfter)[0]).toMatchObject({
        user: { id, email, name: "Fresh Changed Provider" },
        source: {
          method: "oauth",
          action: "sign-in",
          oauth: { providerId: "google", profile: decodeJwt(changed) },
        },
      });

      const mutateConfig = await configure(ctx, "mutate");
      const mutated = await submit(changed);
      const mutatedState = await state(ctx);
      expect(mutated.error).toBeNull();
      expect(mutatedState.users.find((row) => row.id === id)).toMatchObject({
        email,
        name: "Fresh Provider",
      });
      expect(mutatedState.accounts.find((row) => row.userId === id)?.idToken).toBe(changed);

      const noNameToken = await credential({
        aud: claims.aud,
        sub: ctx.uniqueToken("missing-provider-name"),
        email: ctx.uniqueEmail("missing-provider-name"),
        email_verified: true,
      });
      const missingName = [];

      for (const mode of ["deny", "normal"]) {
        const configured = await configure(ctx, mode);
        const before = await state(ctx);
        const result = await submit(noNameToken);
        const after = await state(ctx);
        expect(validations(after)).toHaveLength(1);
        expect(validations(after)[0]!.user.name).toBe("");
        expect(validations(after)[0]!.source.oauth.profile).toEqual(decodeJwt(noNameToken));

        if (mode === "deny") {
          expect(result.error).toMatchObject({ status: 403, code: "identity_denied" });
          expect(identities(after)).toEqual(identities(before));
        } else {
          expect(result.error).toBeNull();
          expect(after.users.find((row) => row.id === result.data!.user.id)?.name).toBe("");
        }

        missingName.push({
          mode,
          configured,
          before: observed(before),
          result,
          after: observed(after),
        });
      }

      const noNameClaims = decodeJwt(noNameToken);
      const changedNoNameToken = await credential({
        ...noNameClaims,
        applicationClaim: { stage: "returning-missing-name" },
      });
      const namePolicy = await configure(ctx, "deny-empty-name");
      const nameBefore = await state(ctx);
      const nameDenied = await submit(changedNoNameToken);
      const nameAfter = await state(ctx);
      expect(nameDenied.error).toMatchObject({ status: 403, code: "identity_denied" });
      expect(validations(nameAfter)).toHaveLength(1);
      expect(validations(nameAfter)[0]).toMatchObject({
        user: { name: "" },
        source: { action: "sign-in", oauth: { profile: decodeJwt(changedNoNameToken) } },
      });
      expect(identities(nameAfter)).toEqual(identities(nameBefore));

      await unchangedForeign(ctx, other);
      return {
        foreign: other,
        claims,
        token,
        wrong,
        deniedConfig,
        before: observed(before),
        wrongResult,
        wrongState: observed(wrongState),
        denied,
        after: observed(after),
        normal,
        accepted,
        created: observed(created),
        changed,
        returningConfig,
        returningBefore: observed(returningBefore),
        returning,
        returningAfter: observed(returningAfter),
        mutateConfig,
        mutated,
        mutatedState: observed(mutatedState),
        noNameToken,
        missingName,
        changedNoNameToken,
        namePolicy,
        nameBefore: observed(nameBefore),
        nameDenied,
        nameAfter: observed(nameAfter),
      };
    },
    [transport === "one-tap" ? "POST /one-tap/callback" : "POST /sign-in/social"],
  );
}

compatScenario(
  "identity validation requires trusted source and actual endpoint context for server creation",
  async (ctx) => {
    const other = await foreign(ctx);
    const configured = await configure(ctx, "normal");
    const before = await state(ctx);
    const observations = [];

    for (const source of [
      undefined,
      { method: "" },
      { method: "oauth" },
      { method: "oauth", oauth: { providerId: "" } },
      { method: "sso-oidc" },
      { method: "email-password" },
    ]) {
      const result = await ctx.rawRequest({
        path: "/__test/user-validation",
        method: "POST",
        json: {
          operation: "server-create",
          email: ctx.uniqueEmail("server-validation"),
          ...(source ? { source } : {}),
        },
      });
      expect(result.status).toBe(403);
      expect(result.body).toMatchObject({
        code:
          source?.method === "email-password"
            ? "validation_context_missing"
            : "validation_source_missing",
      });

      const after = await state(ctx);
      expect(identities(after)).toEqual(identities(before));
      expect(after.events).toEqual([]);

      observations.push({ source: source ?? null, result, after: observed(after) });
    }

    await unchangedForeign(ctx, other);
    return { foreign: other, configured, before: observed(before), observations };
  },
  ["POST /sign-up/email"],
);

compatScenario(
  "expired identity proofs reject before validation and cannot be replayed into creation",
  async (ctx) => {
    const other = await foreign(ctx);
    const observations = [];

    for (const method of ["magic-link", "email-otp", "phone-number", "siwe"] as const) {
      const configured = await configure(ctx, "deny");
      const flow = proofFlow(ctx, method, `expired-${method}`);
      const before = await state(ctx);
      const proof = await flow.issue();
      const issued = await state(ctx);
      const rows = issued.verifications.filter(
        (row) => !before.verifications.some((previous) => previous.id === row.id),
      );
      expect(rows).toHaveLength(1);

      const expiredAt = "2001-01-01T00:00:00.000Z";
      const expired = await ctx.rawRequest({
        path: "/__test/user-validation",
        method: "POST",
        json: {
          operation: "proof-expiry",
          identifier: rows[0]!.identifier,
          expiresAt: expiredAt,
        },
      });
      expect(expired.status).toBe(200);

      const expiredState = await state(ctx);
      expect(expiredState.verifications.find((row) => row.id === rows[0]!.id)?.expiresAt).toBe(
        expiredAt,
      );

      const result = await flow.submit(proof.proof);
      const after = await state(ctx);
      const replay = await flow.submit(proof.proof);
      const replayed = await state(ctx);

      if (method === "magic-link") {
        for (const response of [result, replay]) {
          expect((response as any).status).toBe(302);
          expect(new URL((response as any).location).searchParams.get("error")).toBe(
            "INVALID_TOKEN",
          );
        }
      } else {
        expect((result as any).error?.code).toBe(
          method === "siwe" ? "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" : "OTP_EXPIRED",
        );
        expect((replay as any).error).not.toBeNull();
      }

      expect(after.events).toEqual([]);
      expect(replayed.events).toEqual([]);
      expect(identities(after)).toEqual(identities(before));
      expect(identities(replayed)).toEqual(identities(before));
      expect(after.verifications.some((row) => row.id === rows[0]!.id)).toBe(false);
      expect(replayed.verifications).toEqual(after.verifications);

      await unchangedForeign(ctx, other);
      observations.push({
        method,
        configured,
        before: observed(before),
        proof: observedProof(method, proof),
        issued: observed(issued),
        expired,
        expiredState: observed(expiredState),
        result,
        after: observed(after),
        replay,
        replayed: observed(replayed),
      });
    }

    return { foreign: other, observations };
  },
  [
    proofRoutes["magic-link"],
    proofRoutes["email-otp"],
    proofRoutes["phone-number"],
    proofRoutes.siwe,
  ],
);

compatScenario(
  "concurrent email OTP consumption admits only one actual validation callback and retains foreign authority",
  async (ctx) => {
    const other = await foreign(ctx);
    const actor = client(ctx, "concurrent");
    const second = client(ctx, "concurrent-second");
    const email = ctx.uniqueEmail("concurrent-validation");
    const issued = await actor.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
    expect(issued.error).toBeNull();

    const sent = await delivery(ctx, `otp:sign-in:${email}`);
    const configured = await configure(ctx, "hold");
    const before = await state(ctx);
    const pending = actor.signIn.emailOtp({ email, otp: sent.otp, name: "Held Identity" });
    const reached = await ctx.rawRequest({
      path: "/__test/user-validation",
      method: "POST",
      json: { operation: "wait-stage", stage: "validation" },
    });
    expect(reached.status).toBe(200);

    const rejected = await second.signIn.emailOtp({
      email,
      otp: sent.otp,
      name: "Concurrent Identity",
    });
    expect(rejected.error).toMatchObject({ status: 400, code: "INVALID_OTP" });

    const held = await state(ctx);
    expect(validations(held)).toHaveLength(1);
    expect(validations(held)[0]!.user.name).toBe("Held Identity");
    expect(held.verifications).toEqual([]);
    expect(identities(held)).toEqual(identities(before));

    const foreignSession = await ctx.actor("foreign", "validation").client.getSession();
    expect(foreignSession.data?.user.id).toBe(other.signup.data!.user.id);

    const released = await ctx.rawRequest({
      path: "/__test/user-validation",
      method: "POST",
      json: { operation: "release" },
    });
    expect(released.status).toBe(200);

    const denied = await pending;
    expect(denied.error).toMatchObject({ status: 403, code: "identity_denied" });

    const after = await state(ctx);
    expect(validations(after)).toHaveLength(1);
    expect(identities(after)).toEqual(identities(before));
    expect(after.verifications).toEqual([]);

    await unchangedForeign(ctx, other);
    return {
      foreign: other,
      issued,
      sent: observedDelivery(sent),
      configured,
      before: observed(before),
      reached: {
        ...reached,
        body: observed({ ...held, events: (reached.body as State).events }).events,
      },
      rejected,
      held: observed(held),
      foreignSession,
      released,
      denied,
      after: observed(after),
    };
  },
  [proofRoutes["email-otp"], "GET /get-session"],
);

compatScenario(
  "admin identity admission uses physical authority before policy and hashes credentials only after creation",
  async (ctx) => {
    const other = await foreign(ctx);
    const owner = ctx.actor("administrator", "validation");
    const email = ctx.uniqueEmail("validation-administrator");
    const signup = await owner.client.signUp.email({
      email,
      name: "Administrator",
      password: "password123",
    });
    expect(signup.error).toBeNull();

    const promoted = await ctx.promoteAdmin({ email });
    const configured = await configure(ctx, "deny");
    const before = await state(ctx);
    const request = {
      email: ctx.uniqueEmail("admin-validation"),
      name: "Administrative Candidate",
      password: "short",
      role: "user" as const,
    };
    const guest = await ctx.actor("guest", "validation").client.admin.createUser(request);
    const ordinary = await ctx.actor("foreign", "validation").client.admin.createUser(request);
    expect(guest.error?.status).toBe(401);
    expect(ordinary.error?.status).toBe(403);
    expect((await state(ctx)).events).toEqual([]);
    expect(identities(await state(ctx))).toEqual(identities(before));

    const overlong = await owner.client.admin.createUser({ ...request, password: "🔒".repeat(65) });
    expect(overlong.error).toMatchObject({ status: 400, code: "PASSWORD_TOO_LONG" });
    expect((await state(ctx)).events).toEqual([]);

    const observations = [];

    for (const mode of ["deny", "throw", "normal", "mutate"]) {
      const config = await configure(ctx, mode);
      const prior = await state(ctx);
      const body = { ...request, email: ctx.uniqueEmail(`admin-${mode}`).toUpperCase() };
      const result = await owner.client.admin.createUser(body, {
        headers: { "x-test-validation-marker": "administrative-policy" },
      });
      const after = await state(ctx);
      expect(validations(after)).toHaveLength(1);
      expect(validations(after)[0]).toMatchObject({
        user: { email: body.email.toLowerCase(), name: body.name, role: "user" },
        source: { method: "admin", action: "create-user" },
        context: {
          path: "/admin/create-user",
          body,
          request: { method: "POST", marker: "administrative-policy" },
        },
      });
      expect(validations(after)[0]!.user).not.toHaveProperty("banned");
      expect(validations(after)[0]!.user).not.toHaveProperty("isAnonymous");
      expect(validations(after)[0]!.user).not.toHaveProperty("metadata");

      if (mode === "deny" || mode === "throw") {
        expect(result.error).toMatchObject({
          status: 403,
          code: mode === "deny" ? "identity_denied" : "validation_failed",
        });
        expect(identities(after)).toEqual(identities(prior));
        expect(after.events).toHaveLength(1);
      } else {
        expect(result.error).toBeNull();

        const id = result.data!.user.id;
        const row = after.users.find((user) => user.id === id)!;
        expect(after.events.map((event) => event.stage)).toEqual([
          "validation",
          "user-create-before",
          "user-create-after",
          "hash-enter",
          "hash-result",
          "account-create-before",
        ]);
        expect(after.sessions).toEqual(prior.sessions);
        expect(after.accounts.filter((account) => account.userId === id)).toHaveLength(1);
        expect(
          await verifyPassword({
            hash: after.accounts.find((account) => account.userId === id)!.password,
            password: body.password,
          }),
        ).toBe(true);
        expect(row).toMatchObject({
          email: mode === "mutate" ? "MUTATED@VALIDATION.FIXTURE.TEST" : body.email.toLowerCase(),
          name: mode === "mutate" ? "Validated Identity" : body.name,
          role: "user",
        });

        if (mode === "mutate") {
          expect(row.createdAt).toBe("2001-01-01T00:00:00.000Z");
        }
      }

      await unchangedForeign(ctx, other);
      observations.push({ mode, config, before: observed(prior), result, after: observed(after) });
    }

    return {
      foreign: other,
      signup,
      promoted,
      configured,
      before: observed(before),
      guest,
      ordinary,
      overlong,
      observations,
    };
  },
  ["POST /admin/create-user"],
);

async function providerControl(ctx: ScenarioContext, profile: Row) {
  const response = await ctx.rawRequest({
    path: "/__test/social-provider/profile",
    method: "POST",
    json: profile,
  });
  expect(response.status).toBe(200);
  return response;
}

async function providerReceipts(ctx: ScenarioContext) {
  const response = await ctx.rawRequest({ path: "/__test/social-provider/state" });
  expect(response.status).toBe(200);
  return (response.body as { receipts: Row[] }).receipts;
}

function observedReceipts(rows: Row[]) {
  return rows.map((row) => ({
    ...row,
    body: row.body?.code_verifier
      ? {
          ...row.body,
          code_verifier: {
            token: row.body.code_verifier,
            length: row.body.code_verifier.length,
            encoding: "base64url",
          },
        }
      : row.body,
  }));
}

async function browserProvider(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  link = false,
) {
  const started = await (link
    ? actor.client.linkSocial({
        provider: "gitlab",
        callbackURL: "/validation-complete",
        disableRedirect: true,
      })
    : actor.client.signIn.social({
        provider: "gitlab",
        callbackURL: "/validation-complete",
        disableRedirect: true,
      }));
  expect(started.error).toBeNull();

  const issued = new URL(started.data!.url!);
  const state = issued.searchParams.get("state");
  expect(state).toBeString();

  const path = `${authProfilePath("validation")}/callback/gitlab?${new URLSearchParams({ code: "fixture-code", state: state! })}`;
  const response = await actor.fetch(path, {
    redirect: "manual",
    headers: { "x-test-validation-marker": "actual-browser-provider" },
  });
  return {
    started,
    path,
    result: {
      status: response.status,
      location: response.headers.get("location"),
      body: await response.text(),
    },
  };
}

function providerError(
  result: Awaited<ReturnType<typeof browserProvider>>["result"],
  code: string,
  description?: string,
) {
  expect(result.status).toBe(302);

  const url = new URL(result.location!);
  expect(url.searchParams.get("error")).toBe(code);
  expect(url.searchParams.get("error_description")).toBe(description ?? null);
}

async function replayBrowser(
  ctx: ScenarioContext,
  actor: ReturnType<ScenarioContext["actor"]>,
  path: string,
) {
  const before = await state(ctx);
  const receiptsBefore = await providerReceipts(ctx);
  const response = await actor.fetch(path, { redirect: "manual" });
  const result = {
    status: response.status,
    location: response.headers.get("location"),
    body: await response.text(),
  };
  providerError(result, "state_mismatch");
  const after = await state(ctx);
  const receiptsAfter = await providerReceipts(ctx);
  expect(after).toEqual(before);
  expect(receiptsAfter).toEqual(receiptsBefore);

  return {
    before: observed(before),
    receiptsBefore: observedReceipts(receiptsBefore),
    result,
    after: observed(after),
    receiptsAfter: observedReceipts(receiptsAfter),
  };
}

for (const stage of ["creation", "implicit linking", "explicit linking"] as const) {
  compatScenario(
    `browser OAuth creation and linking validate fresh mapped identity with complete raw provider context at the Source guards: ${stage}`,
    async (ctx) => {
      const other = await foreign(ctx);
      const web = ctx.actor("browser", "validation");
      const observations = [];
      const profile = {
        id: 1831,
        email: ctx.uniqueEmail("browser-provider").toUpperCase(),
        name: null,
        username: "Mapped Browser Name",
        avatar_url: "https://images.example/gitlab-raw.png",
        email_verified: true,
        state: "active",
        locked: false,
        applicationClaim: { only: "unmapped-provider-record" },
      };
      const controlled = await providerControl(ctx, profile);

      if (stage === "creation") {
        for (const mode of ["deny", "throw", "mutate"]) {
          const configured = await configure(ctx, mode);
          const before = await state(ctx);
          const receiptsBefore = await providerReceipts(ctx);
          const completed = await browserProvider(ctx, web);
          const after = await state(ctx);
          const receiptsAfter = await providerReceipts(ctx);
          expect(receiptsAfter).toHaveLength(receiptsBefore.length + 2);
          expect(validations(after)).toHaveLength(1);
          expect(validations(after)[0]).toMatchObject({
            user: {
              email: profile.email.toLowerCase(),
              name: profile.username,
              image: profile.avatar_url,
              emailVerified: true,
            },
            source: {
              method: "oauth",
              action: "create-user",
              oauth: { providerId: "gitlab", profile },
            },
            context: {
              path: "/callback/:id",
              body: null,
              request: {
                method: "GET",
                path: "/callback/gitlab",
                marker: "actual-browser-provider",
              },
            },
          });
          expect(validations(after)[0]!.user).not.toHaveProperty("applicationClaim");
          expect(validations(after)[0]!.user).not.toHaveProperty("id");

          if (mode !== "mutate") {
            providerError(
              completed.result,
              mode === "throw" ? "validation_failed" : "identity_denied",
              mode === "throw" ? "User validation failed" : "Configured identity rejected",
            );
            expect(identities(after)).toEqual(identities(before));
            expect(after.events).toHaveLength(1);
          } else {
            expect(completed.result).toMatchObject({
              status: 302,
              location: "/validation-complete",
            });
            expect(after.users).toHaveLength(before.users.length + 1);

            const admitted = after.users.find(
              (row) => row.email === "MUTATED@VALIDATION.FIXTURE.TEST",
            )!;
            expect(admitted).toMatchObject({
              name: "Validated Identity",
              createdAt: "2001-01-01T00:00:00.000Z",
              emailVerified: true,
            });
            expect(after.accounts.find((row) => row.providerId === "gitlab")).toMatchObject({
              accountId: "1831",
              userId: admitted.id,
            });
            expect(after.events.filter((event) => event.stage === "validation")).toHaveLength(1);
          }

          const replay = await replayBrowser(ctx, web, completed.path);
          await unchangedForeign(ctx, other);
          observations.push({
            mode,
            configured,
            before: observed(before),
            receiptsBefore: observedReceipts(receiptsBefore),
            started: completed.started,
            completed: completed.result,
            after: observed(after),
            receiptsAfter: observedReceipts(receiptsAfter),
            replay,
          });
        }

        return {
          foreign: other,
          controlled,
          observations,
          receipts: observedReceipts(await providerReceipts(ctx)),
        };
      }

      const normal = await configure(ctx, "normal");
      const unverified = ctx.actor("unverified-link", "validation");
      const unverifiedSignup = await unverified.client.signUp.email({
        email: ctx.uniqueEmail("unverified-link"),
        name: "Unverified Local",
        password: "password123",
      });
      expect(unverifiedSignup.error).toBeNull();

      const unverifiedProfile = {
        ...profile,
        id: 1832,
        email: unverifiedSignup.data!.user.email.toUpperCase(),
      };
      const unverifiedControl = await providerControl(ctx, unverifiedProfile);
      if (stage === "implicit linking") {
        const unverifiedConfig = await configure(ctx, "deny");
        const unverifiedBefore = await state(ctx);
        const guarded = await browserProvider(ctx, ctx.actor("implicit-guard", "validation"));
        const unverifiedAfter = await state(ctx);
        providerError(guarded.result, "account_not_linked");
        expect(validations(unverifiedAfter)).toEqual([]);
        expect(identities(unverifiedAfter)).toEqual(identities(unverifiedBefore));

        const guardedReplay = await replayBrowser(
          ctx,
          ctx.actor("implicit-guard", "validation"),
          guarded.path,
        );
        const verifiedConfig = await configure(ctx, "normal");
        const verifiedFlow = proofFlow(ctx, "email-otp", "verified-local");
        const verifiedProof = await verifiedFlow.issue();
        const verified = await verifiedFlow.submit(verifiedProof.proof);
        expect((verified as any).error).toBeNull();

        const verifiedId = (verified as any).data.user.id;
        const verifiedEmail = ctx.uniqueEmail("verified-local");
        const implicitProfile = { ...profile, id: 1833, email: verifiedEmail.toUpperCase() };
        const implicitControl = await providerControl(ctx, implicitProfile);
        const implicit = [];

        for (const mode of ["deny", "mutate"]) {
          const configured = await configure(ctx, mode);
          const before = await state(ctx);
          const completed = await browserProvider(ctx, ctx.actor(`implicit-${mode}`, "validation"));
          const after = await state(ctx);
          expect(validations(after)).toHaveLength(1);
          expect(validations(after)[0]).toMatchObject({
            user: { id: verifiedId, email: verifiedEmail, name: profile.username },
            source: {
              method: "oauth",
              action: "link-account",
              oauth: { providerId: "gitlab", profile: implicitProfile },
            },
          });

          if (mode === "deny") {
            providerError(completed.result, "identity_denied", "Configured identity rejected");
            expect(identities(after)).toEqual(identities(before));
          } else {
            expect(completed.result.location).toBe("/validation-complete");
            expect(after.users).toEqual(before.users);
            expect(
              after.accounts.filter(
                (row) => row.userId === verifiedId && row.providerId === "gitlab",
              ),
            ).toEqual([expect.objectContaining({ accountId: "1833", userId: verifiedId })]);
            expect(after.sessions).toHaveLength(before.sessions.length + 1);
          }

          const replay = await replayBrowser(
            ctx,
            ctx.actor(`implicit-${mode}`, "validation"),
            completed.path,
          );
          implicit.push({
            mode,
            configured,
            before: observed(before),
            started: completed.started,
            completed: completed.result,
            after: observed(after),
            replay,
          });
        }

        await unchangedForeign(ctx, other);
        return {
          foreign: other,
          controlled,
          normal,
          unverifiedSignup,
          unverifiedControl,
          unverifiedConfig,
          unverifiedBefore: observed(unverifiedBefore),
          guarded: guarded.result,
          guardedReplay,
          unverifiedAfter: observed(unverifiedAfter),
          verifiedConfig,
          verifiedProof: observedProof("email-otp", verifiedProof),
          verified,
          implicitControl,
          implicit,
          receipts: observedReceipts(await providerReceipts(ctx)),
        };
      }

      const mismatchProfile = {
        ...profile,
        id: 1834,
        email: ctx.uniqueEmail("explicit-mismatch").toUpperCase(),
      };
      const mismatchControl = await providerControl(ctx, mismatchProfile);
      const explicit = [];

      for (const mode of ["deny", "normal"]) {
        const configured = await configure(ctx, mode);
        const before = await state(ctx);
        const completed = await browserProvider(ctx, unverified, true);
        const after = await state(ctx);
        expect(validations(after)).toHaveLength(1);
        expect(validations(after)[0]).toMatchObject({
          user: { id: unverifiedSignup.data!.user.id, email: mismatchProfile.email },
          source: {
            method: "oauth",
            action: "link-account",
            oauth: { providerId: "gitlab", profile: mismatchProfile },
          },
        });

        providerError(
          completed.result,
          mode === "deny" ? "identity_denied" : "email_does_not_match",
          mode === "deny" ? "Configured identity rejected" : undefined,
        );
        expect(identities(after)).toEqual(identities(before));

        const replay = await replayBrowser(ctx, unverified, completed.path);
        explicit.push({
          mode,
          configured,
          before: observed(before),
          started: completed.started,
          completed: completed.result,
          after: observed(after),
          replay,
        });
      }

      const matchingControl = await providerControl(ctx, unverifiedProfile);
      const matchingConfig = await configure(ctx, "mutate");
      const matchingBefore = await state(ctx);
      const linked = await browserProvider(ctx, unverified, true);
      const matchingAfter = await state(ctx);
      expect(linked.result.location).toBe("/validation-complete");
      expect(matchingAfter.users).toEqual(matchingBefore.users);
      expect(matchingAfter.sessions).toEqual(matchingBefore.sessions);
      expect(
        matchingAfter.accounts.filter(
          (row) => row.userId === unverifiedSignup.data!.user.id && row.providerId === "gitlab",
        ),
      ).toEqual([
        expect.objectContaining({ accountId: "1832", userId: unverifiedSignup.data!.user.id }),
      ]);
      expect(validations(matchingAfter)).toHaveLength(1);
      expect(validations(matchingAfter)[0]!.user.email).toBe(unverifiedProfile.email);

      const linkReplay = await replayBrowser(ctx, unverified, linked.path);
      await unchangedForeign(ctx, other);
      return {
        foreign: other,
        controlled,
        normal,
        unverifiedSignup,
        unverifiedControl,
        mismatchControl,
        explicit,
        matchingControl,
        matchingConfig,
        matchingBefore: observed(matchingBefore),
        linked: { started: linked.started, result: linked.result },
        matchingAfter: observed(matchingAfter),
        linkReplay,
        receipts: observedReceipts(await providerReceipts(ctx)),
      };
    },
    stage === "explicit linking"
      ? ["POST /link-social", "GET /callback/{}"]
      : ["POST /sign-in/social", "GET /callback/{}"],
  );
}
