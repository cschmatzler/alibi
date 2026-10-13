import { apiKey } from "@better-auth/api-key";
import { getAuthTables } from "@better-auth/core/db";
import { oauthProvider } from "@better-auth/oauth-provider";
import { passkey } from "@better-auth/passkey";
import { sso } from "@better-auth/sso";
import {
  admin,
  anonymous,
  phoneNumber,
  lastLoginMethod,
  organization,
  username,
  twoFactor,
  deviceAuthorization,
  jwt,
  siwe,
} from "better-auth/plugins";
export const plugins = [
  sso({ domainVerification: { enabled: true } }),
  admin(),
  anonymous(),
  phoneNumber(),
  lastLoginMethod({ storeInDatabase: true }),
  organization({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }),
  username(),
  twoFactor(),
  deviceAuthorization(),
  jwt(),
  siwe({ domain: "localhost" }),
  apiKey(),
  passkey(),
  oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
];
export const config = { plugins, rateLimit: { storage: "database" } };
const tables = getAuthTables(config);
const schema = Object.fromEntries(
  Object.entries(tables).map(([key, table]) => [
    key,
    {
      modelName: table.modelName,
      fields: Object.fromEntries(
        Object.entries(table.fields).map(([name, field]) => [
          name,
          {
            type: field.type,
            required: field.required !== false,
            ...(field.bigint ? { bigint: true } : {}),
            ...(field.fieldName ? { fieldName: field.fieldName } : {}),
            ...(field.defaultValue !== undefined
              ? {
                  defaultValue:
                    typeof field.defaultValue === "function" ? "runtime" : field.defaultValue,
                }
              : {}),
            ...(field.unique ? { unique: true } : {}),
            ...(field.index ? { index: true } : {}),
            ...(field.references ? { references: field.references } : {}),
          },
        ]),
      ),
      ...(table.indexes ? { indexes: table.indexes } : {}),
    },
  ]),
);
export const snapshot = { version: "1.7.7", tables: schema };
if (import.meta.main) console.log(JSON.stringify(snapshot, null, 2));
