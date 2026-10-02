import { betterAuth, type BetterAuthOptions } from "better-auth";
import { emailOTP, twoFactor } from "better-auth/plugins";
const old = "managed-old-reader-key-at-least-32-characters";
const current = "compat-test-only-key-not-real-minimum-32chars";
const legacy = "managed-legacy-reader-key-at-least-32-characters";
export function createManagedSecretsFixture(base: BetterAuthOptions) {
  let counter=0;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();
  const deliveries = new Map<string, string>();
  for (const mode of ["old", "retained", "retired", "legacy", "bare"]) {
    const path = `/__test/profiles/managed-${mode}/api/auth`;
    const secrets = mode === "bare" ? undefined : mode === "old" ? [{version:0,value:old}] : [{version:2,value:current}, ...(mode !== "retired" ? [{version:0,value:old}] : [])];
    profiles.set(path, betterAuth({
      ...base, basePath: path, secret: mode === "bare" || mode === "legacy" ? legacy : undefined, secrets,
      rateLimit: {enabled:false},
      databaseHooks:{session:{create:{async before(session){return {data:{...session,token:`managed${String(++counter).padStart(25,"0")}`}}}}}},
      plugins:[emailOTP({storeOTP:"encrypted", async sendVerificationOTP({email,otp}) {deliveries.set(email,otp);}}), twoFactor({skipVerificationOnEnable:true,backupCodeOptions:{customBackupCodesGenerate:()=>["backup-one","backup-two"]}})],
    }));
  }
  return {profiles,async handle(request:Request) {
    const url = new URL(request.url);
    if(url.pathname!=="/__test/managed-secrets/delivery")return null;
    const otp=deliveries.get(url.searchParams.get("email")??"");
    return otp ? Response.json({otp}) : Response.json({error:"No delivery"},{status:404});
  }};
}
