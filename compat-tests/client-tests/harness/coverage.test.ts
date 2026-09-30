import { expect, test } from "bun:test";
import { collectCoverage } from "../support/coverage";
import type { TraceEntry } from "../support/trace";

function trace(path: string, status: number): TraceEntry {
  return { actor: "reader", method: "GET", path, requestBodyShape: null, responseStatus: status, responseHeaders: {}, responseCookies: {}, responseBodyShape: null };
}

test("numbered algorithm profiles retain success and authorization evidence", () => {
  const output = collectCoverage("managed key transitions", [
    trace("/__test/profiles/jwt-es256/api/auth/jwks", 200),
    trace("/__test/profiles/jwt-es512/api/auth/jwks", 200),
    trace("/__test/profiles/jwt-rs256/api/auth/token", 401),
    trace("/__test/profiles/jwt-ps256/api/auth/token", 401),
  ], ["GET /jwks"]);
  expect(output).toEqual({
    "GET /jwks": { success: ["managed key transitions"], state: ["managed key transitions"] },
    "GET /token": { rejection: ["managed key transitions"], authorization: ["managed key transitions"] },
  });
});

test("fixture control paths cannot manufacture authentication evidence", () => {
  expect(collectCoverage("control call", [
    trace("/__test/jwt", 200),
    trace("/__test/profiles/jwt-es256/jwks", 200),
    trace("/arbitrary/api/auth/jwks", 200),
  ], ["GET /jwks"])).toEqual({});
});
