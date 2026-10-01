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

test("Source default OAuth error redirects record admission denial without counting them as successful callbacks", () => {
  const baseURL = "http://fixture.local:42921";
  const scenario = "actual OAuth admission";
  const rejected = ["email_does_not_match", "unable_to_get_user_info", "state_mismatch"].map(error => ({
    ...trace("/__test/profiles/social-gitlab-issuer/api/auth/callback/gitlab?code=issued&state=issued", 302),
    responseHeaders: { location: `${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=${error}` },
  }));
  expect(collectCoverage(scenario, rejected, ["GET /callback/{}"], baseURL)).toEqual({
    "GET /callback/{}": { rejection: [scenario], authorization: [scenario], state: [scenario] },
  });
  const defaultCallback = {...trace("/api/auth/callback/google", 302), responseHeaders: {location:"/api/auth/error?error=email_does_not_match"}};
  expect(collectCoverage(scenario, [defaultCallback], [], baseURL)).toEqual({
    "GET /callback/{}": { rejection: [scenario], authorization: [scenario] },
  });
  // Location alone cannot provide origin ownership without actual request context.
  expect(collectCoverage(scenario, rejected, [])).toEqual({ "GET /callback/{}": {success:[scenario]} });
  const nonDenials: Partial<TraceEntry>[] = [
    {responseStatus:200}, {responseStatus:301}, {method:"POST"},
    {path:"/api/auth/sign-in/social"}, {path:"/api/auth/callback/gitlab/extra"},
    {responseHeaders:{}}, {responseHeaders:{location:"http://[broken"}},
    {responseHeaders:{location:`${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/callback/gitlab?error=state_mismatch`}},
    {responseHeaders:{location:`${baseURL}/api/auth/error?error=state_mismatch`}},
    {responseHeaders:{location:"http://foreign.local:42921/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch"}},
    {responseHeaders:{location:"http://user:secret@fixture.local:42921/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch"}},
    {responseHeaders:{location:`${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch#fragment`}},
    {responseHeaders:{location:`${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch#`}},
    {responseHeaders:{location:`${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=state_mismatch&error=state_mismatch`}},
    {responseHeaders:{location:`${baseURL}/__test/profiles/social-gitlab-issuer/api/auth/error?error=unknown`}},
    {responseHeaders:{location:`${baseURL}/gitlab-done`}},
  ];
  for(const changed of nonDenials) {
    const output = collectCoverage(scenario, [{...rejected[0]!,...changed}], [], baseURL);
    for(const record of Object.values(output)) {
      expect(record.authorization).toBeUndefined();
      expect(record.rejection).toBeUndefined();
      expect(record.success).toEqual([scenario]);
    }
  }
  expect(collectCoverage(scenario, [defaultCallback], ["state"], baseURL)["GET /callback/{}"]?.state).toBeUndefined();
});
