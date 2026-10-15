import { expect } from "vitest";

import { compatScenario } from "../../../support/scenario";

compatScenario(
  "SCIM User size admission measures validated input before authentication and canonical storage",
  async (ctx) => {
    const results = [];
    for (const size of [65534, 65535, 65536, 65000]) {
      const item = { value: "x".repeat(1024), display: "x".repeat(1024) };
      const input = {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
        userName: ctx.uniqueEmail("scim-size-owner"),
        roles: Array.from({ length: 10 }, () => ({ ...item })),
        entitlements: Array.from({ length: 10 }, () => ({ ...item })),
        addresses: Array.from({ length: 10 }, () => ({
          formatted: item.value,
          streetAddress: item.value,
        })),
        phoneNumbers: Array.from({ length: 10 }, () => ({ value: "x".repeat(250) })),
      };
      input.phoneNumbers[9]!.value = "";
      const length = JSON.stringify(input).length;
      input.phoneNumbers[9]!.value = "x".repeat(size - length);
      expect(JSON.stringify(input).length).toBe(size);
      for (const operation of ["createSCIMUser", "replaceSCIMUser"]) {
        const result = await ctx.rawRequest({
          path: `/__test/server-api/scim?operation=${operation}`,
          method: "POST",
          json: { body: input, params: { userId: "missing" } },
        });
        expect(result.status).toBe(size <= 65535 ? 401 : 400);
        if (size > 65535) {
          expect(result.body).toMatchObject({
            detail: "[body] SCIM User attributes exceed the supported serialized size",
            scimType: "invalidValue",
          });
        }
        results.push({ size, operation, result });
      }
      if (size === 65535) {
        const unknown = { ...structuredClone(input), ignored: "x".repeat(70000) };
        Object.assign(unknown.roles[0]!, { ignored: "x".repeat(70000) });
        const padded = structuredClone(input);
        padded.userName = ` ${input.userName} `;
        padded.roles[0]!.value = ` ${"x".repeat(1024)} `;
        const scalar: any = { ...structuredClone(input), title: "bounded" };
        const delta = JSON.stringify(scalar).length - size;
        scalar.phoneNumbers[9].value = scalar.phoneNumbers[9].value.slice(delta);
        scalar.title = [" bounded "];
        const unicode = structuredClone(input);
        unicode.roles[0]!.value = "🦀".repeat(512);
        for (const [index, variant] of [unknown, padded, scalar, unicode].entries()) {
          for (const operation of ["createSCIMUser", "replaceSCIMUser"]) {
            const result = await ctx.rawRequest({
              path: `/__test/server-api/scim?operation=${operation}`,
              method: "POST",
              json: { body: variant, params: { userId: "missing" } },
            });
            expect(result.status).toBe(401);
            results.push({ index, operation, result });
          }
        }
      }
      const authenticated = await ctx.rawRequest({
        path: "/__test/server-api/scim?operation=createSCIMUser",
        method: "POST",
        json: { body: input, token: "group-reader" },
      });
      expect(authenticated.status, JSON.stringify({ size, body: authenticated.body })).toBe(
        size === 65000 ? 201 : size <= 65535 ? 500 : 400,
      );
      if (size === 65000) {
        expect(authenticated.body).toMatchObject({ userName: input.userName });
        expect((authenticated.body as any).roles).toHaveLength(10);
      } else if (size <= 65535) {
        expect(authenticated.body).toMatchObject({
          detail: "Stored SCIM User attribute state is invalid",
        });
      }
      results.push({ size, authenticated });
    }
    const state = await ctx.rawRequest({
      path: "/__test/server-api/scim?operation=user-create-state",
      method: "POST",
    });
    expect(state.status).toBe(200);
    expect((state.body as any).users).toHaveLength(1);
    expect((state.body as any).subjects).toBe(1);
    return ctx.snapshot({ results, state });
  },
  ["POST /scim/v2/Users", "PUT /scim/v2/Users/{}"],
);
