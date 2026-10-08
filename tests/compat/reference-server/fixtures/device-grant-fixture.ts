import { Database } from "bun:sqlite";

import { betterAuth, type BetterAuthOptions } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { openAPI } from "better-auth/plugins";
import { deviceAuthorization, redeemDeviceCode } from "better-auth/plugins/device-authorization";
import { z } from "zod";
export async function deviceGrantFixture(base: BetterAuthOptions) {
  const db = new Database(":memory:");
  const events: unknown[] = [];
  db.exec("CREATE TABLE application_grant_receipts (row_id TEXT, owner_id TEXT, audience TEXT)");
  const grant = {
    requestSchemaFields: { audience: z.string().min(1), nonce: z.string().min(1) },
    requestErrorCodes: ["invalid_audience", "application_invalid_request"],
    requestOpenAPIResponses: { 422: { description: "Application audience rejected" } },
    onRequestValidationError(issues: readonly unknown[]) {
      events.push({ phase: "validation", issueCount: issues.length });
      throw new APIError("BAD_REQUEST", {
        error: "application_invalid_request",
        error_description: "Application audience and nonce are required",
      });
    },
    deviceCodeSchemaFields: {
      grantAudience: { type: "string" as const, required: false },
      grantNonce: { type: "string" as const, required: false },
    },
    async authorizeRequest({ request }: any) {
      events.push({ phase: "authorize", audience: request.audience, nonce: request.nonce });
      if (request.audience !== "application-api")
        throw new APIError("UNPROCESSABLE_ENTITY", {
          error: "invalid_audience",
          error_description: "Audience is not allowed",
        });
      return {
        clientId: "application-client",
        deviceCodeFields: { grantAudience: request.audience, grantNonce: request.nonce },
      };
    },
    async assertSessionRedemption({ deviceCode }: any) {
      events.push({ phase: "session-redemption", nonce: deviceCode.grantNonce });
      throw new APIError("BAD_REQUEST", {
        error: "invalid_grant",
        error_description: "Application grant cannot issue a standalone session",
      });
    },
    getVerificationContext(row: any) {
      events.push({ phase: "verification", nonce: row.grantNonce });
      return { audience: row.grantAudience, nonce: row.grantNonce };
    },
    verificationOpenAPIProperties: { audience: { type: "string" }, nonce: { type: "string" } },
  };
  const extension = {
    id: "application-device-grant",
    endpoints: {
      applicationToken: createAuthEndpoint(
        "/device/application-token",
        {
          method: "POST",
          body: z.object({
            device_code: z.string(),
            claimNonce: z.string(),
            prepareFailure: z.boolean().optional(),
          }),
        },
        async (ctx) => {
          const result = await redeemDeviceCode({
            ctx,
            deviceCode: ctx.body.device_code,
            authorizeRedemption: async (row) => {
              events.push({ phase: "redemption-authorize", nonce: row.grantNonce });
              return {
                ownershipWhere: { field: "grantNonce", value: ctx.body.claimNonce },
                context: { nonce: row.grantNonce },
              };
            },
            prepareRedemption: async (row, authorization) => {
              events.push({ phase: "prepare", nonce: authorization.nonce });
              if (ctx.body.prepareFailure)
                throw new APIError("FORBIDDEN", {
                  code: "APPLICATION_PREPARE_REJECTED",
                  message: "Application preparation rejected",
                });
              return { audience: row.grantAudience };
            },
          });
          db.query(
            "INSERT INTO application_grant_receipts (row_id,owner_id,audience) VALUES (?,?,?)",
          ).run(
            result.claimedDeviceCode.id,
            result.user.id,
            String(result.redemptionContext.audience),
          );
          events.push({ phase: "completed", nonce: result.authorizationContext.nonce });
          return ctx.json({
            userId: result.user.id,
            audience: result.redemptionContext.audience,
            nonce: result.authorizationContext.nonce,
          });
        },
      ),
    },
  };
  const options: BetterAuthOptions = {
    ...base,
    database: db,
    basePath: "/__test/profiles/device-grant/api/auth",
    plugins: [deviceAuthorization({ interval: "0s", grant }), extension, openAPI()],
  };
  await (await getMigrations(options)).runMigrations();
  const auth = betterAuth(options);
  return {
    async reset() {
      events.length = 0;
      for (const table of [
        "application_grant_receipts",
        "deviceCode",
        "session",
        "account",
        "verification",
        "user",
      ])
        db.query(`DELETE FROM "${table}"`).run();
    },
    async handle(request: Request) {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/__test/profiles/device-grant/api/auth/"))
        return auth.handler(request);
      if (url.pathname === "/__test/device-grant/control") {
        if (request.method === "POST") {
          const input = await request.json();
          if (input.expiresAt)
            db.query('UPDATE deviceCode SET "expiresAt"=? WHERE "deviceCode"=?').run(
              new Date(input.expiresAt).getTime(),
              input.deviceCode,
            );
        }
        const rows = db
          .query(
            'SELECT id, "deviceCode", "userCode", "userId", status, "clientId", "grantAudience" AS audience,"grantNonce" AS nonce FROM deviceCode WHERE "deviceCode"=?',
          )
          .all(url.searchParams.get("deviceCode"));
        return Response.json({
          rows,
          events,
          receipts: db
            .query(
              "SELECT row_id AS rowId,owner_id AS userId,audience FROM application_grant_receipts",
            )
            .all(),
        });
      }
      return null;
    },
  };
}
