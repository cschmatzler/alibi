/** Author-time source port. Run: bun run port-openapi-annotations.ts.
 * Reads pinned factories/Zod declarations; never invokes a handler or generator.
 * Documents still derive from actual Rust registrations and application config.
 */

import { createHash } from "node:crypto";
import { readFile, unlink, writeFile } from "node:fs/promises";

import { apiKey } from "@better-auth/api-key";
import { passkey } from "@better-auth/passkey";
import * as plugins from "better-auth/plugins";

const root = new URL("../../../", import.meta.url);
const source = await readFile(
  new URL("node_modules/better-auth/dist/plugins/open-api/generator.mjs", import.meta.url),
  "utf8",
);
// Conversion helpers only. Complete generator(), tables, registrations, default
// responses and document assembly are excluded from this author-time module.
const helpers = source.slice(
  source.indexOf("const OPEN_API_SCHEMA_TYPES"),
  source.indexOf("function getResponse("),
);
const scratch = new URL(".port-openapi-schema.tmp.mjs", import.meta.url);
await writeFile(
  scratch,
  'import * as z from "zod";\n' + helpers + "\nexport {getParameters,getRequestBody};\n",
);
try {
  const { getParameters, getRequestBody } = await import(scratch.href);
  const factories = [
    plugins.admin(),
    plugins.multiSession(),
    plugins.organization({ teams: { enabled: true }, dynamicAccessControl: { enabled: true } }),
    plugins.username(),
    plugins.twoFactor(),
    plugins.anonymous(),
    plugins.jwt(),
    plugins.oneTimeToken(),
    plugins.oneTap({ clientId: "openapi-one-tap-client" }),
    plugins.emailOTP({ sendVerificationOTP: async () => {} }),
    plugins.magicLink({ sendMagicLink: async () => {} }),
    plugins.phoneNumber({ sendOTP: async () => {} }),
    plugins.deviceAuthorization({ verificationUri: "https://app.invalid/device" }),
    plugins.genericOAuth({ config: [] }),
    plugins.lastLoginMethod({ storeInDatabase: true }),
    plugins.siwe({
      domain: "app.invalid",
      getNonce: async () => "nonce1234",
      verifyMessage: async () => false,
    }),
    apiKey(),
    passkey(),
  ];
  const json = (value: unknown) => JSON.stringify(value);
  const optional = (value: string | undefined) =>
    value === undefined ? "None" : `Some(${json(value)}.into())`;
  const header = `//! Source-backed Better Auth 1.7.7 declarations.\n//! Author-time port: tests/compat/reference-server/port-openapi-annotations.ts.\n//! Conversion helpers SHA256: ${createHash("sha256").update(helpers).digest("hex")}.\n//! No generated document or fixture response was captured.\nuse serde_json::json;\n`;
  let endpoints =
    header +
    "use super::OpenApiEndpoint;\npub(super) fn endpoint(plugin:&str,path:&str)->Option<OpenApiEndpoint>{Some(match(plugin,path){\n";
  let models =
    header +
    "use super::{OpenApiField,OpenApiModel};\npub(super) fn models(plugin:&str)->Option<Vec<OpenApiModel>>{Some(match plugin{\n";
  let count = 0;
  for (const plugin of factories) {
    if (plugin.version !== "1.7.7") {
      throw new Error(`Wrong pinned ${plugin.id} version: ${plugin.version}`);
    }
    for (const value of Object.values(plugin.endpoints ?? {})) {
      const endpoint = value as { path?: string; options: Record<string, any> };
      if (!endpoint.path) {
        continue;
      }
      const opts = endpoint.options;
      const metadata = opts.metadata?.openapi ?? {};
      const body = getRequestBody(opts);
      const parameters = getParameters(opts);
      endpoints += `(${json(plugin.id)},${json(endpoint.path)})=>OpenApiEndpoint{operation_id:${optional(metadata.operationId)},description:${optional(metadata.description)},tags:${metadata.tags === undefined ? "None" : `Some(vec![${metadata.tags.map((tag: string) => json(tag) + ".into()").join(",")}])`},parameters:vec![${parameters.map((parameter: unknown) => `json!(${json(parameter)})`).join(",")}],request_body:${body === undefined ? "None" : `Some(json!(${json(body)}))`},responses:[${Object.entries(
        metadata.responses ?? {},
      )
        .map(([code, response]) => `(${json(code)}.into(),json!(${json(response)}))`)
        .join(
          ",",
        )}].into_iter().collect(),server_only:${!!opts.metadata?.SERVER_ONLY},..Default::default()},\n`;
      count++;
    }
    models += `${json(plugin.id)}=>vec![\n`;
    for (const [name, model] of Object.entries(plugin.schema ?? {}) as [
      string,
      { fields: Record<string, any> },
    ][]) {
      models += `OpenApiModel::new(${json(name[0]!.toUpperCase() + name.slice(1))},vec![\n`;
      for (const [name, field] of Object.entries(model.fields)) {
        if (!field) {
          continue;
        }
        const array =
          typeof field.type === "string" ? /^(string|number)\[\]$/.exec(field.type) : null;
        const schema: any = array
          ? { type: "array", items: { type: array[1] } }
          : {
              type: field.type === "date" ? "string" : field.type,
              ...(field.type === "date" ? { format: "date-time" } : {}),
            };
        if (field.defaultValue !== undefined && typeof field.defaultValue !== "function") {
          schema.default = field.defaultValue;
        }
        models += `OpenApiField::new(${json(name)},json!(${json(schema)}),${field.required === true})${field.input === false ? ".read_only()" : ""}${field.returned === false ? ".hidden()" : ""},\n`;
      }
      models += "]),\n";
    }
    models += "],\n";
  }
  endpoints += "_=>return None,})}\n";
  models += "_=>return None,})}\n";
  await writeFile(new URL("crates/core/src/openapi/source_endpoints.rs", root), endpoints);
  await writeFile(new URL("crates/core/src/openapi/source_models.rs", root), models);
  console.log(
    `Ported ${count} endpoint declarations and ${factories.length} plugin schemas from pinned factories.`,
  );
} finally {
  await unlink(scratch);
}
