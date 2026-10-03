/** Immutable real application callbacks; the published plugin owns all mutations. */
import type { Database } from "bun:sqlite";

import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { organization } from "better-auth/plugins";

import { invitationSnapshot } from "./organization-invitation-acceptance-fixture";

export const invitationLifecycleProfiles = [
  "org-invite-life",
  "org-invite-reinvite",
  "org-invite-background",
  "org-invite-limit-none",
  "org-invite-limit-zero",
  "org-invite-limit-fractional",
  "org-invite-limit-negative",
  "org-invite-limit-nan",
  "org-invite-limit-infinity",
  "org-invite-limit-resolver",
  "org-invite-page-one",
  "org-invite-expiry-zero",
  "org-invite-expiry-negative",
  "org-invite-expiry-fractional",
  "org-invite-expiry-nan",
] as const;

export function organizationInvitationLifecycleFixture(
  database: Database,
  shared: Parameters<typeof betterAuth>[0],
  origin: string,
) {
  let mode = "off";
  const receipts: unknown[] = [];
  let gates: (() => void)[] = [];
  const completions: Promise<unknown>[] = [];
  let limit = 1;
  async function note(phase: string, context: unknown) {
    if (mode === "off") return;
    receipts.push({
      phase,
      context: structuredClone(context),
      snapshot: invitationSnapshot(database),
    });
    if (mode === `${phase}-error`) {
      throw new APIError("FORBIDDEN", {
        code: "INVITATION_APPLICATION_REJECTED",
        message: `Rejected ${phase}`,
      });
    }
    if (
      mode === `${phase}-internal` ||
      (phase === "delivery-end" && mode === "hold-delivery-end-internal")
    ) {
      throw new Error(`Actual ${phase} application failure`);
    }
  }
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  for (const name of invitationLifecycleProfiles) {
    const fixed = name.endsWith("zero")
      ? 0
      : name.endsWith("fractional")
        ? 1.5
        : name.endsWith("negative")
          ? -0.5
          : name.endsWith("nan")
            ? NaN
            : name.endsWith("infinity")
              ? Infinity
              : 1;
    profiles.set(
      name,
      betterAuth({
        ...shared,
        database,
        baseURL: origin,
        basePath: `/__test/profiles/${name}/api/auth`,
        advanced: {
          ...shared.advanced,
          database: {
            ...shared.advanced?.database,
            ...(name === "org-invite-page-one" ? { defaultFindManyLimit: 1 } : {}),
          },
          ...(name === "org-invite-background"
            ? {
                backgroundTasks: {
                  handler(promise: Promise<unknown>) {
                    completions.push(promise);
                    if (mode === "hold-delivery-observer-error") {
                      throw new Error("Actual background observer failure");
                    }
                  },
                },
              }
            : {}),
        },
        plugins: [
          organization({
            invitationLimit:
              name === "org-invite-limit-resolver"
                ? async (context) => {
                    await note("limit", context);
                    return limit;
                  }
                : name === "org-invite-limit-none"
                  ? undefined
                  : name.includes("expiry")
                    ? 100
                    : fixed,
            invitationExpiresIn: name.includes("expiry")
              ? name.endsWith("fractional")
                ? 0.125
                : fixed
              : 7200,
            cancelPendingInvitationsOnReInvite: name === "org-invite-reinvite",
            teams: { enabled: true, defaultTeam: { enabled: false } },
            async sendInvitationEmail(delivery, request) {
              if (mode === "off") return;
              await note("delivery-start", {
                ...delivery,
                request: request
                  ? {
                      method: request.method,
                      path: new URL(request.url).pathname,
                      marker: request.headers.get("x-invitation-marker"),
                    }
                  : null,
              });
              if (mode.startsWith("hold-delivery")) {
                await new Promise<void>((resolve) => {
                  gates.push(resolve);
                });
              }
              await note("delivery-end", { id: delivery.id, email: delivery.email });
            },
            organizationHooks: {
              async beforeCreateInvitation(context) {
                await note("before-create", context);
                if (mode === "patch-role") return { data: { role: "admin" } };
                if (mode === "patch-persisted") {
                  return {
                    data: {
                      id: `trusted-${context.invitation.organizationId}`,
                      role: "admin",
                      email: context.invitation.email.toUpperCase(),
                      status: "rejected",
                      createdAt: new Date("2020-01-02T03:04:05.123Z"),
                      expiresAt: new Date("2020-01-03T03:04:05.456Z"),
                    },
                  };
                }
              },
              async afterCreateInvitation(context) {
                await note("after-create", context);
              },
              async beforeRejectInvitation(context) {
                await note("before-reject", context);
              },
              async afterRejectInvitation(context) {
                await note("after-reject", context);
              },
              async beforeCancelInvitation(context) {
                await note("before-cancel", context);
              },
              async afterCancelInvitation(context) {
                await note("after-cancel", context);
              },
            },
          }),
        ],
      }),
    );
  }
  return {
    profiles,
    reset() {
      mode = "off";
      receipts.length = 0;
      gates.splice(0).forEach((release) => release());
      completions.length = 0;
      limit = 1;
    },
    configure(body: Record<string, unknown>) {
      mode = String(body.mode ?? "record");
      limit =
        typeof body.limit === "number"
          ? body.limit
          : body.limit === "nan"
            ? NaN
            : body.limit === "infinity"
              ? Infinity
              : 1;
      receipts.length = 0;
      return Response.json({ configured: true });
    },
    async state(wait: string | null) {
      if (wait) for (let n = 0; n < 100 && !gates.length; n++) await Bun.sleep(10);
      return Response.json({
        receipts,
        snapshot: invitationSnapshot(database),
        waiting: gates.length,
      });
    },
    async release() {
      gates.splice(0).forEach((release) => release());
      await Promise.all(completions.splice(0));
      return Response.json({ released: true });
    },
  };
}
