import {betterAuth} from "better-auth";
import {openAPI, jwt} from "better-auth/plugins";
import type { Database } from "bun:sqlite";

// The pending update-session prerequisite is explicitly disabled in both runtimes.
const disabledPaths = ["/update-session"];
export const OPEN_API_PROFILES=["openapi-default","openapi-configured","openapi-disabled","openapi-jwt"] as const;
export function openApiProfiles(port:number,database:Database) {
 return new Map(OPEN_API_PROFILES.map(name=> {
  const options=name==="openapi-configured" ? {path:"/docs",theme:"moon",nonce:"fixture-reference-nonce"} : name==="openapi-disabled" ? {disableDefaultReference:true} : {};
  const extra=name==="openapi-jwt" ? [jwt()] : [];
  const auth=betterAuth({baseURL:`http://localhost:${port}`,basePath:`/__test/profiles/${name}/api/auth`,secret:"fixture-open-api-only-secret-at-least-32-chars",database,emailAndPassword:{enabled:true},user:{changeEmail:{enabled:true},deleteUser:{enabled:true}},disabledPaths:[...disabledPaths,...(name==="openapi-configured" ? ["/error"] : []),...(name==="openapi-jwt" ? ["/jwks","/token"] : [])],plugins:[...extra,openAPI(options)]});
  return [name,auth] as const;
 }));
}
