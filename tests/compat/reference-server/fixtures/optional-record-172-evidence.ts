/** Pinned 1.7.6 no-database handlers; private record controls remain in fixture. */
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
const secret = "optional-record-172-secret-at-least-32-characters";
const origin = "http://localhost:43173";
const options = { secret, baseURL: origin, emailAndPassword: { enabled: true }, plugins: [twoFactor({ skipVerificationOnEnable: true }), passkey()] };
const auth = betterAuth(options);
const context = await auth.$context;
const trace: unknown[] = [];
async function call(path: string, body?: unknown, cookie = "") {
  const response = await auth.handler(new Request(`${origin}/api/auth${path}`, {
    method: body ? "POST" : "GET", headers: { origin, "content-type": "application/json", cookie },
    body: body ? JSON.stringify(body) : undefined,
  }));
  const raw = await response.text();
  trace.push({ path, status: response.status, body: raw, cookies: response.headers.getSetCookie() });
  return { response, body: raw ? JSON.parse(raw) : null };
}
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(";")[0]).join("; ");
const signup = await call("/sign-up/email", { name: "Owner", email: "optional172@fixture.test", password: "Password123!" });
const userId = signup.body.user.id;
const ownerCookie = cookies(signup.response);
const other = await call("/sign-up/email", { name: "Other", email: "other172@fixture.test", password: "Password456!" });
const otherCookie = cookies(other.response);
const enabled = await call("/two-factor/enable", { password: "Password123!" }, ownerCookie);
const enabledCookie = cookies(enabled.response);
const factor = await context.adapter.findOne({model:"twoFactor",where:[{field:"userId",value:userId}]});
const backupCode = enabled.body.backupCodes[0];
await call("/two-factor/verify-backup-code", { code: backupCode }, enabledCookie);
const consumed = await context.adapter.findOne({model:"twoFactor",where:[{field:"userId",value:userId}]});
await call("/two-factor/verify-backup-code", { code: backupCode }, enabledCookie);
const key = await context.adapter.create({model:"passkey",data:{ userId, name:"Original", credentialID:"Y3JlZGVudGlhbDE3Mg", publicKey:"fixture-public-key", counter:1, deviceType:"singleDevice", backedUp:false, transports:"internal", createdAt:new Date() }});
await call("/passkey/list-user-passkeys", undefined, enabledCookie);
await call("/passkey/update-passkey", {id:key.id,name:"Stolen"}, otherCookie);
await call("/passkey/delete-passkey", {id:key.id}, otherCookie);
const unchanged = await context.adapter.findOne({model:"passkey",where:[{field:"id",value:key.id}]});
await call("/passkey/update-passkey", {id:key.id,name:"Renamed"}, enabledCookie);
await call("/passkey/delete-passkey", {id:key.id}, enabledCookie);
await call("/two-factor/disable", {password:"Password123!"}, enabledCookie);
const factorAfter = await context.adapter.findOne({model:"twoFactor",where:[{field:"userId",value:userId}]});
// Real memory adapter semantics differ from SQL NULL arithmetic.
const nullable = await context.adapter.create({model:"twoFactor",data:{userId, secret:"nullable-secret",backupCodes:"nullable-backup",verified:false,failedVerificationCount:null}});
const incremented = await context.adapter.incrementOne({model:"twoFactor",where:[{field:"id",value:nullable.id}],increment:{failedVerificationCount:1}});
const fresh = await betterAuth(options).$context;
const restartFactor = await fresh.adapter.findOne({model:"twoFactor",where:[{field:"userId",value:userId}]});
const restartPasskeys = await fresh.adapter.findMany({model:"passkey",where:[{field:"userId",value:userId}]});
console.log(JSON.stringify({version:"1.7.6",trace,state:{factor,consumed,unchanged,factorAfter,nullable,incremented,restartFactor,restartPasskeys}},null,2));
