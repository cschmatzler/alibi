import {betterAuth} from "better-auth";
import {openAPI, oneTap, jwt, username, admin, organization, twoFactor, deviceAuthorization, phoneNumber, multiSession, siwe} from "better-auth/plugins";
import {apiKey} from "@better-auth/api-key";
import {passkey} from "@better-auth/passkey";
import type { Database } from "bun:sqlite";

export const OPEN_API_PROFILES=["openapi-default","openapi-configured","openapi-disabled","openapi-jwt","openapi-username","openapi-custom-schema","openapi-plugins","openapi-plugins-teams","openapi-plugins-configured"] as const;
export function openApiProfiles(port:number,database:Database) {
 // A real app-owned storage field: the custom schema profile documents this column.
 if(!database.query<{name:string},[]>("PRAGMA table_info(user)").all().some(column=>column.name==="metadata")) database.exec("ALTER TABLE user ADD COLUMN metadata TEXT");
 return new Map(OPEN_API_PROFILES.map(name=> {
  const options=name==="openapi-configured" ? {path:"/docs",theme:"moon" as const,nonce:"fixture-reference-nonce"} : name==="openapi-disabled" ? {disableDefaultReference:true} : {};
  const extra=name==="openapi-jwt" ? [jwt()] : name==="openapi-username" ? [username()] : name.startsWith("openapi-plugins") ? [oneTap({clientId:"openapi-one-tap-client"}),admin(),organization({teams:{enabled:name==="openapi-plugins-teams"},dynamicAccessControl:{enabled:name==="openapi-plugins-teams"}}),twoFactor(),apiKey(name==="openapi-plugins-configured" ? {rateLimit:{maxRequests:43,timeWindow:7654321}} : {}),passkey(),deviceAuthorization(),jwt(),multiSession(),phoneNumber({sendOTP:async()=>{throw new Error("Documentation profile has no phone delivery provider");}}),siwe({domain:"localhost",getNonce:async()=>"OpenApiDocumentationNonce",verifyMessage:async()=>false})] : [];
  const auth=betterAuth({baseURL:`http://localhost:${port}`,basePath:`/__test/profiles/${name}/api/auth`,secret:"fixture-open-api-only-secret-at-least-32-chars",database,emailAndPassword:{enabled:true},user:{...(name==="openapi-custom-schema" ? {additionalFields:{metadata:{type:"json",required:true,input:false,returned:false,defaultValue:null}}} : {}),changeEmail:{enabled:true},deleteUser:{enabled:true}},disabledPaths:[...(name==="openapi-configured" ? ["/error"] : []),...(name==="openapi-jwt" ? ["/jwks","/token"] : [])],plugins:[...extra,openAPI(options)]});
  return [name,auth] as const;
 }));
}
