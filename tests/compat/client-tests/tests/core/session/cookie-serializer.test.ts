import { expect, test } from "bun:test";
import { createHmac } from "node:crypto";
import { Cookie, CookieJar } from "tough-cookie";
import { RUST_BASE_URL, TS_BASE_URL, requireHealthy } from "../../../support/config";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const password = "password123";
for (const [label, base] of [["Source",TS_BASE_URL],["Rust",RUST_BASE_URL]] as const) {
  for (const mode of ["serializer-valid","serializer-host","serializer-age-boundary","serializer-age-limit","serializer-expiry-limit"] as const) {
    test.serial(`${label} ${mode}: actual emission preserves attributes or rejects at the persisted owner stage`,async()=>{
      await requireHealthy(base,label);
      const path=`/__test/profiles/physical-cookie-${mode}/api/auth`;
      const email=`serializer-${crypto.randomUUID()}@test.com`;
      const call=async(path:string,body:unknown,cookie?:string)=>{
        const r=await fetch(base+path,{method:"POST",headers:{"content-type":"application/json",origin:base,...(cookie?{cookie}:{})},body:JSON.stringify(body)});
        return {status:r.status,raw:r.headers.getSetCookie(),text:await r.text()};
      };
      const state=async(email:string)=>await (await fetch(`${base}/__test/physical-cookie/storage?email=${encodeURIComponent(email)}`)).json();
      const issued=await call(path+"/sign-up/email",{email,password,name:"Serializer owner"});
      const rows=await state(email);
      if(mode.endsWith("limit")){
        expect(issued).toEqual({status:500,raw:[],text:""});
        expect(rows).toEqual({user:[],accounts:[],sessions:[]});
        // Source sign-in has no signup transaction: the already committed
        // account and newly created session survive the serializer failure.
        const seedEmail=`signin-${crypto.randomUUID()}@test.com`;
        const seed=await call("/__test/profiles/physical-cookie-default/api/auth/sign-up/email",{email:seedEmail,password,name:"Committed owner"});
        expect(seed.status).toBe(200);
        const before=await state(seedEmail);
        const failed=await call(path+"/sign-in/email",{email:seedEmail,password});
        expect(failed).toEqual({status:500,raw:[],text:""});
        const after=await state(seedEmail);
        expect(after.user).toEqual(before.user);
        expect(after.accounts).toEqual(before.accounts);
        expect(after.sessions).toHaveLength(before.sessions.length+1);
        console.log(JSON.stringify({label,mode,issued,rows,seed,before,failed,after}));
      }else{
        expect(issued.status).toBe(200);
        expect(rows.user).toHaveLength(1);expect(rows.accounts).toHaveLength(1);expect(rows.sessions).toHaveLength(1);
        const raw=issued.raw[0]!;
        const name=mode==="serializer-host"?"__Host-policy":"better-auth.session_token";
        const ttl=mode==="serializer-age-boundary"?34560000:604800;
        const scope=mode==="serializer-host"?"; Path=/":`; Domain=localhost; Path=${path}`;
        expect(raw.slice(raw.indexOf(";"))).toBe(`; Max-Age=${ttl}${scope}; Expires=Fri, 01 Jan 2027 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict; Partitioned`);
        expect(raw.startsWith(name+"=")).toBe(true);
        const signed=decodeURIComponent(Cookie.parse(raw)!.value);const dot=signed.lastIndexOf(".");
        expect(signed.slice(dot+1)).toBe(createHmac("sha256",secret).update(signed.slice(0,dot)).digest("base64"));
        expect(rows.sessions[0].token).toBe(signed.slice(0,dot));
        const jar=new CookieJar();await jar.setCookie(raw,base+path);
        const read=await fetch(base+path+"/get-session",{headers:{cookie:await jar.getCookieString(base+path)}});
        expect((await read.json()).user.id).toBe(rows.user[0].id);
        const preference=await call(path+"/sign-in/email",{email,password,rememberMe:false});
        expect(preference.status).toBe(200);
        const pref=preference.raw.find(raw=>raw.startsWith("better-auth.dont_remember="))!;
        expect(Cookie.parse(pref)!.maxAge).toBe(121);
        expect(Cookie.parse(preference.raw.find(raw=>raw.startsWith(name+"="))!)!.maxAge).toBeNull();
        const logout=await call(path+"/sign-out",{},await jar.getCookieString(base+path));
        expect(logout.status).toBe(200);
        const clear=logout.raw.find(raw=>raw.startsWith(name+"="))!;
        expect(clear).toBe(`${name}=; Max-Age=0${scope}; Expires=Fri, 01 Jan 2027 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict; Partitioned`);
        await jar.setCookie(clear,base+path);expect(await jar.getCookieString(base+path)).toBe("");
        console.log(JSON.stringify({label,mode,issued,rows,preference,logout,after:await state(email)}));
      }
    },30000);
  }
}

for(const [label,base] of [["Source",TS_BASE_URL],["Rust",RUST_BASE_URL]] as const){
  test.serial(`${label} inferred cookie domain keeps hostname spelling without ports`,async()=>{
    const observations=[];
    for(const [mode,domain] of [["cross-localhost","localhost"],["cross-ipv6","[::1]"]] as const){
      const path=`/__test/profiles/physical-cookie-${mode}/api/auth`;
      const r=await fetch(base+path+"/sign-up/email",{method:"POST",headers:{"content-type":"application/json",origin:base},body:JSON.stringify({email:`domain-${crypto.randomUUID()}@test.com`,password,name:"URL hostname owner"})});
      expect(r.status).toBe(200);const raw=r.headers.getSetCookie();const body=await r.json();
      expect(raw[0]!).toContain(`; Domain=${domain};`);
      expect(raw[0]!.startsWith("__Secure-better-auth.session_token=")).toBe(true);
      const rows=await (await fetch(`${base}/__test/physical-cookie/storage?userId=${body.user.id}`)).json();
      expect(rows.sessions[0].userId).toBe(body.user.id);
      observations.push({mode,raw,body,rows});
    }
    console.log(JSON.stringify({label,observations}));
  },30000);
}
