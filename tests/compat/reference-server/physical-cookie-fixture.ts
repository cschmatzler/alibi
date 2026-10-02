import {betterAuth,type BetterAuthOptions} from "better-auth";
import type {Database} from "bun:sqlite";

/** Actual configured producers; every header comes from installed auth routes. */
export function physicalCookieProfiles(base:BetterAuthOptions,database:Database){
  const profiles=new Map<string,ReturnType<typeof betterAuth>>();
  for(const mode of ["default","attributes","secure","none","short","legacy","legacy-alias"] as const){
    const path=`/__test/profiles/physical-cookie-${mode}/api/auth`;
    const attributes=mode==="attributes"?{httpOnly:false,sameSite:"strict" as const,path,domain:"localhost"}:mode==="secure"?{secure:true}:mode==="none"?{sameSite:"none" as const,secure:false}:{};
    profiles.set(path,betterAuth({...base,basePath:path,plugins:[],session:{...base.session,expiresIn:mode==="short"?60:604800,cookieCache:{enabled:false}},advanced:{...base.advanced,useSecureCookies:false,defaultCookieAttributes:attributes,...mode==="attributes"?{cookies:{session_token:{name:"physical_session"},dont_remember:{name:"physical_preference",attributes:{maxAge:121}}}}:mode==="legacy"||mode==="legacy-alias"?{cookies:{session_token:{name:mode==="legacy"?"customsession":"some.alias"}}}:{}}}));
  }
  return {profiles,control(request:Request):Response|null{
    const url=new URL(request.url);if(url.pathname!=="/__test/physical-cookie/storage")return null;
    const id=url.searchParams.get("userId");if(!id)return Response.json({message:"userId required"},{status:400});
    // All declared core columns, physically read with an independently scoped bind.
    return Response.json({user:database.query('SELECT id,name,email,emailVerified,image,createdAt,updatedAt FROM user WHERE id=?').all(id),accounts:database.query('SELECT * FROM account WHERE userId=? ORDER BY providerId,accountId,id').all(id),sessions:database.query('SELECT id,expiresAt,token,createdAt,updatedAt,ipAddress,userAgent,userId FROM session WHERE userId=? ORDER BY createdAt,id').all(id)});
  }};
}
