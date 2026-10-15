import { expect } from "bun:test";

import { compatScenario } from "../../../support/scenario";
compatScenario(
  "SCIM User PATCH bounds its final normalized document using UTF-16 length",
  async (ctx) => {
    const invoke = (operation: string, input: unknown) =>
      ctx.rawRequest({
        path: `/__test/server-api/scim?operation=${operation}`,
        method: "POST",
        json: input,
      });
    const results = [];
    for (const [size, variant] of [
      [65535, "plain"],
      [65536, "plain"],
      [65535, "unknown"],
      [65535, "padded"],
      [65535, "unicode"],
    ] as const) {
      const created = await invoke("createSCIMUser", {
        body: {
          schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
          userName: ctx.uniqueEmail(`patch-size-${size}-${variant}`),
        },
        token: "group-reader",
      });
      expect(created.status).toBe(201);
      const initial = created.body as any;
      const item = { value: "x".repeat(1024), display: "x".repeat(1024) };
      const changes: any = {
        roles: Array.from({ length: 10 }, () => ({ ...item })),
        entitlements: Array.from({ length: 10 }, () => ({ ...item })),
        addresses: Array.from({ length: 10 }, () => ({
          formatted: item.value,
          streetAddress: item.value,
        })),
        phoneNumbers: Array.from({ length: 10 }, () => ({ value: "x".repeat(250) })),
      };
      changes.phoneNumbers[9].value = "";
      const document = {
        schemas: initial.schemas,
        userName: initial.userName,
        displayName: initial.displayName,
        active: initial.active,
        name: initial.name,
        emails: initial.emails,
        ...changes,
      };
      changes.phoneNumbers[9].value = "x".repeat(size - JSON.stringify(document).length);
      expect(JSON.stringify(document).length).toBe(size);
      if (variant === "unknown") {
        changes.roles[0].ignored = "x".repeat(70000);
      }
      if (variant === "padded") {
        changes.roles[0].value = ` ${"x".repeat(1024)} `;
      }
      if (variant === "unicode") {
        changes.roles[0].value = "🦀".repeat(512);
      }
      const result = await invoke("patchSCIMUser", {
        params: { userId: initial.id },
        body: {
          schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          Operations: [{ value: changes }],
        },
        token: "group-reader",
      });
      expect(result.status).toBe(size <= 65535 ? 200 : 400);
      if (size > 65535) {
        expect(result.body).toMatchObject({
          detail: "User: SCIM User attributes exceed the supported serialized size",
          scimType: "invalidValue",
        });
      } else {
        const value = result.body as any;
        expect(value.id).toBe(initial.id);
        expect(value.roles).toHaveLength(10);
        expect(value.roles[0]).not.toHaveProperty("ignored");
        expect(value.roles[0].value).toBe(
          variant === "unicode" ? "🦀".repeat(512) : "x".repeat(1024),
        );
        expect(JSON.stringify(value).length).toBeGreaterThan(size);
      }
      const current = await invoke("getSCIMUser", {
        params: { userId: initial.id },
        query: {},
        token: "group-reader",
      });
      expect(current.status).toBe(200);
      expect(current.body).toEqual(size <= 65535 ? result.body : created.body);
      results.push({ size, variant, created, result, current });
    }
    return ctx.snapshot({ results });
  },
  ["PATCH /scim/v2/Users/{}"],
);
