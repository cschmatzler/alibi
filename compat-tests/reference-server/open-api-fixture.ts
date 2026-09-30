import {betterAuth} from "better-auth";
import {openAPI, jwt} from "better-auth/plugins";
import type { Database } from "bun:sqlite";

// Explicit equivalent application configuration: this profile documents the public
// session API while disabling unrelated core endpoint families.
const disabledPaths = [
  "/sign-in/social",
  "/callback/:id",
  "/sign-up/email",
  "/sign-in/email",
  "/reset-password",
  "/verify-password",
  "/verify-email",
  "/send-verification-email",
  "/change-email",
  "/change-password",
  "/update-session",
  "/update-user",
  "/delete-user",
  "/request-password-reset",
  "/reset-password/:token",
  "/link-social",
  "/list-accounts",
  "/delete-user/callback",
  "/unlink-account",
  "/refresh-token",
  "/get-access-token",
  "/account-info"
];
export const OPEN_API_PROFILES=["openapi-default","openapi-configured","openapi-disabled","openapi-jwt"] as const;
export function openApiProfiles(port:number,database:Database) {
 return new Map(OPEN_API_PROFILES.map(name=> {
  const options=name==="openapi-configured" ? {path:"/docs",theme:"moon",nonce:"fixture-reference-nonce"} : name==="openapi-disabled" ? {disableDefaultReference:true} : {};
  const extra=name==="openapi-jwt" ? [jwt()] : [];
  const auth=betterAuth({baseURL:`http://localhost:${port}`,basePath:`/__test/profiles/${name}/api/auth`,secret:"fixture-open-api-only-secret-at-least-32-chars",database,disabledPaths:[...disabledPaths,...(name==="openapi-configured" ? ["/error"] : []),...(name==="openapi-jwt" ? ["/jwks","/token"] : [])],plugins:[...extra,openAPI(options)]});
  return [name,auth] as const;
 }));
}
