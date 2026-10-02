import {Database} from "bun:sqlite";
import {betterAuth} from "better-auth";
import {getMigrations} from "better-auth/db/migration";
import {getCookieCache} from "better-auth/cookies";
import {expect,test} from "bun:test";
import {compareValues,type ComparisonContext} from "../support/compare";
const secret="compact-chunk-source-fixture-secret-32";
async function observed(baseURL:string,uuid:boolean){
  const database=new Database(":memory:"),version={current:"1"};
  const options={baseURL,secret,database,rateLimit:{enabled:false},emailAndPassword:{enabled:true},session:{cookieCache:{enabled:true,strategy:"compact" as const,maxAge:300,version:()=>version.current}},...(uuid?{advanced:{database:{generateId:()=>crypto.randomUUID()}}}:{})};
  await(await getMigrations(options)).runMigrations();const auth=betterAuth(options),start=Date.now();
  const response=await auth.handler(new Request(baseURL+"/api/auth/sign-up/email",{method:"POST",headers:{origin:baseURL,"content-type":"application/json"},body:JSON.stringify({email:"chunk-owner@fixture.test",name:"x".repeat(6000),password:"password123"})}));
  expect(response.status).toBe(200);const signup=await response.json();
  const observe=async(headers:Headers)=>{
    const rawCookies=headers.getSetCookie().filter(value=>value.startsWith("better-auth.session_data"));
    const token=rawCookies.filter(value=>value.split(";")[0]!.split("=")[1]).map(value=>decodeURIComponent(value.split(";")[0]!.slice(value.indexOf("=")+1))).join("");
    const envelope=JSON.parse(Buffer.from(token,"base64url").toString()),observedAt=Date.now();
    const decoded=await getCookieCache(new Headers({cookie:rawCookies.map(value=>value.split(";")[0]).join("; ")}),{secret,strategy:"compact",isSecure:false});expect(decoded).not.toBeNull();
    return {token,envelope,decoded,observedAt,effectiveMaxAgeSeconds:300,rawCookies};
  };
  const compactSessionCache=await observe(response.headers);expect(compactSessionCache.rawCookies.length).toBeGreaterThan(1);
  version.current="2";
  const renewed=await auth.handler(new Request(baseURL+"/api/auth/get-session",{headers:{cookie:response.headers.getSetCookie().map(value=>value.split(";")[0]).join("; ")}}));expect(renewed.status).toBe(200);
  const renewedCache=await observe(renewed.headers);expect(renewedCache.rawCookies.some(cookie=>cookie.startsWith("better-auth.session_data=;"))).toBe(true);
  const end=Date.now();database.close();return {signup,compactSessionCache,renewed:{compactSessionCache:renewedCache},start,end};
}
function ctx(left:Awaited<ReturnType<typeof observed>>,right:Awaited<ReturnType<typeof observed>>):ComparisonContext{return {compactSessionCacheSecret:secret,leftBaseURL:"http://localhost:3100",rightBaseURL:"http://localhost:3200",leftStartedAt:left.start,rightStartedAt:right.start,leftFinishedAt:left.end,rightFinishedAt:right.end};}
function value(input:Awaited<ReturnType<typeof observed>>){return {signup:input.signup,compactSessionCache:input.compactSessionCache,renewed:input.renewed};}

test("published compact writer preserves every raw chunk and tombstone across actual default32 and UUID36 identities",async()=>{
  const left=await observed("http://localhost:3100",false),right=await observed("http://localhost:3200",true);
  expect(left.signup.user.id.length).toBe(32);expect(right.signup.user.id.length).toBe(36);
  expect(left.compactSessionCache.rawCookies.at(-1)!.length).not.toBe(right.compactSessionCache.rawCookies.at(-1)!.length);
  expect(compareValues(value(left),value(right),ctx(left,right))).toEqual([]);
  const original=right.compactSessionCache;
  const corruptions=[original.rawCookies.slice(1),[...original.rawCookies,original.rawCookies[0]!],[...original.rawCookies].reverse(),original.rawCookies.map((cookie,index)=>index===0?cookie.replace("session_data.0=","session_data.00="):cookie),original.rawCookies.map((cookie,index)=>index===0?cookie.replace(/=(.)/,"="):cookie),original.rawCookies.map(cookie=>cookie.replace("HttpOnly","Secure")),original.rawCookies.map(cookie=>cookie.replace("Path=/","Path=/foreign")),original.rawCookies.map(cookie=>cookie+"; Priority=High")];
  for(const rawCookies of corruptions)expect(compareValues(value(left),{...value(right),compactSessionCache:{...original,rawCookies}},ctx(left,right)).length).toBeGreaterThan(0);
  const omitted={...original} as Record<string,unknown>;delete omitted.rawCookies;
  expect(compareValues(value(left),{...value(right),compactSessionCache:omitted},ctx(left,right)).length).toBeGreaterThan(0);
  const changedTombstone=structuredClone(right.renewed.compactSessionCache);changedTombstone.rawCookies[0]=changedTombstone.rawCookies[0]!.replace("Path=/","Path=/foreign");
  expect(compareValues(value(left),{...value(right),renewed:{compactSessionCache:changedTombstone}},ctx(left,right)).length).toBeGreaterThan(0);
});
