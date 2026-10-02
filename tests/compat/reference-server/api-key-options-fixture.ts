import type { Database } from "bun:sqlite";
import { apiKey } from "@better-auth/api-key";
import { betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { username } from "better-auth/plugins";
import configurations from "../api-key-options.json";

type Data = Record<string, any>;
function number(value: unknown, fallback: number): number {
  if (value === undefined) return fallback;
  return typeof value === "number" ? value : Number(value);
}
function numeric(value: number) {
  return { value: Number.isFinite(value) ? value : null, text: String(value) };
}

export function createApiKeyOptionsFixture(
  database: Database,
  options: Parameters<typeof betterAuth>[0],
) {
  const path = "/__test/profiles/api-key-options/api/auth";
  const events: Data[] = [];
  let mode = "normal",
    serial = 0,
    getterCalls = 0;
  function failure(stage: string) {
    const selected = mode.replace("-handler-", "-");
    if (selected === `${stage}-ordinary`) throw new Error(`Private ${stage} failure`);
    if (selected === `${stage}-api`)
      throw new APIError("FORBIDDEN", {
        code: `APPLICATION_${stage.toUpperCase()}_DENIED`,
        message: `Application ${stage} denied`,
      });
    if (selected === `${stage}-public-500`)
      throw new APIError("INTERNAL_SERVER_ERROR", {
        code: `APPLICATION_${stage.toUpperCase()}_FAILED`,
        message: `Application ${stage} failed`,
      });
  }
  function context(ctx: any) {
    return {
      requestPresent: !!ctx.request,
      method: ctx.request?.method ?? null,
      marker: ctx.request?.headers.get("x-options-marker") ?? null,
      body: ctx.body ?? null,
    };
  }
  const auth = betterAuth({
    ...options,
    basePath: path,
    plugins: [
      username(),
      apiKey(
        configurations.map((entry: Data) => ({
          configId: entry.id,
          defaultKeyLength: number(entry.keyLength, 16),
          defaultPrefix: entry.prefix ?? "optKEY_",
          apiKeyHeaders: `x-options-${entry.id}`,
          enableSessionForAPIKeys: entry.session ?? true,
          disableKeyHashing: entry.hash === false,
          startingCharactersConfig: {
            shouldStore: entry.storeStart ?? true,
            charactersLength: number(entry.start, 6),
          },
          minimumPrefixLength: number(entry.minPrefix, 1),
          maximumPrefixLength: number(entry.maxPrefix, 32),
          minimumNameLength: number(entry.minName, 1),
          maximumNameLength: number(entry.maxName, 32),
          keyExpiration: {
            defaultExpiresIn: entry.expiration === undefined ? null : number(entry.expiration, 0),
            minExpiresIn: number(entry.minExpiration, 0),
            maxExpiresIn: number(entry.maxExpiration, 365),
          },
          rateLimit: { enabled: false },
          enableMetadata: true,
          ...(entry.custom
            ? {
                async customKeyGenerator(input: { length: number; prefix: string | undefined }) {
                  events.push({
                    kind: "generator",
                    configId: entry.id,
                    length: numeric(input.length),
                    prefix: input.prefix ?? null,
                    mode,
                  });
                  failure("generator");
                  return `${input.prefix ?? ""}application-owned-secret-${String(++serial).padStart(6, "0")}`;
                },
              }
            : {}),
          ...(entry.validator
            ? {
                async customAPIKeyValidator({ ctx, key }: any) {
                  events.push({
                    kind: "validator",
                    configId: entry.id,
                    key,
                    mode,
                    ...context(ctx),
                  });
                  failure("validator");
                  return mode !== "validator-deny";
                },
              }
            : {}),
          ...(entry.getter
            ? {
                customAPIKeyGetter(ctx: any) {
                  const key = ctx.headers?.get("x-options-getter-session") ?? null;
                  if (key !== null) {
                    events.push({ kind: "getter", configId: entry.id, key, mode, ...context(ctx) });
                    getterCalls++;
                    if (!mode.startsWith("getter-handler-") || getterCalls === 2) failure("getter");
                  }
                  return key;
                },
              }
            : {}),
        })),
      ),
    ],
  });
  async function controlled(operation: () => Promise<unknown>) {
    try {
      const value = await operation();
      return Response.json({
        value: value instanceof Response ? await value.json() : value,
        error: null,
      });
    } catch (error: any) {
      return Response.json({
        value: null,
        error: {
          api: error instanceof APIError,
          status: error.statusCode ?? null,
          body: error.body ?? null,
          message: error.message,
        },
      });
    }
  }
  return {
    path,
    auth,
    async control(request: Request): Promise<Response | null> {
      const url = new URL(request.url),
        action = url.pathname.replace("/__test/api-key-options/", "");
      if (!url.pathname.startsWith("/__test/api-key-options/")) return null;
      if (action === "events") return Response.json(events.splice(0));
      if (action === "mode") {
        const input = await request.json();
        mode = input.mode;
        getterCalls = 0;
        if (input.reset) {
          serial = 0;
          events.length = 0;
        }
        return Response.json({ mode });
      }
      if (action === "state")
        return Response.json({
          keys: database
            .query(
              "SELECT *,hex(CAST(start AS BLOB)) AS startHex,typeof(start) AS startType FROM apikey ORDER BY name,id",
            )
            .all()
            .map((raw: any) => {
              const row = {
                ...raw,
                enabled: !!raw.enabled,
                rateLimitEnabled: !!raw.rateLimitEnabled,
              };
              for (const field of [
                "createdAt",
                "updatedAt",
                "expiresAt",
                "lastRequest",
                "lastRefillAt",
              ])
                if (row[field] !== null) row[field] = new Date(row[field]).toISOString();
              return row;
            }),
        });
      const body = await request.json();
      if (action === "install") {
        for (const [field, value] of Object.entries(body.patch)) {
          if (!["permissions", "referenceId", "configId"].includes(field))
            throw new Error("Unsupported installed field");
          database.query(`UPDATE apikey SET "${field}"=? WHERE id=?`).run(value as any, body.keyId);
        }
        return Response.json({ success: true });
      }
      if (action === "create") return controlled(() => auth.api.createApiKey({ body }));
      if (action === "update") return controlled(() => auth.api.updateApiKey({ body }));
      if (action === "verify")
        return controlled(() =>
          auth.api.verifyApiKey({
            body: body.input,
            ...(body.request ? { request, headers: request.headers } : {}),
          }),
        );
      return null;
    },
  };
}
