import assert from "node:assert/strict";
import { readdir, readFile, writeFile } from "node:fs/promises";
import { socialProviders } from "../reference-server/node_modules/@better-auth/core/dist/social-providers/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/core/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const names = ["roblox", "salesforce", "slack", "spotify", "twitch", "twitter", "vercel", "vk", "zoom", "facebook-graph", "facebook-limited", "microsoft", "discord", "tiktok", "paybin", "polar", "railway", "reddit", "notion", "atlassian", "line-token", "line-http", "naver", "paypal", "cloudflare", "cognito-token", "cognito-http", "gitlab", "apple", "wechat"];
const addedFactories = ["dropbox", "figma", "github", "google", "huggingface", "kakao", "kick", "linear", "linkedin"];
names.push(...addedFactories);
const factoryName = name => name.startsWith("facebook-") ? "facebook" : name.startsWith("cognito-") ? "cognito" : name.startsWith("line-") ? "line" : name;
const pin = JSON.parse(await readFile(new URL("../upstream-source.json", import.meta.url)));
assert.equal(pin.commit, "38f43e390920faa400d51ff0bd18570a424d05ce");
const sourceFiles = await readdir(`${process.env.BETTER_AUTH_SOURCE ?? "/tmp/alibi-upstream-1.7.18"}/packages/core/src/social-providers`);
const sourceFactories = sourceFiles.filter(file => file.endsWith(".ts") && !file.endsWith(".test.ts") && file !== "index.ts")
  .map(file => file.slice(0, -3).replace("microsoft-entra-id", "microsoft")).sort();
assert.deepEqual([...new Set(names.map(factoryName))].sort(), sourceFactories);
assert.equal(sourceFactories.length, 36);
const modes = ["missing", "null", "false", "empty", "utf16", "mapped"];
const cases = [];
const fetch = globalThis.fetch;
try {
  for (const name of names) {
    const providerModes = [...modes];
    if (addedFactories.includes(name)) providerModes.push("zero", "true", "object", "array");
    if (["github", "huggingface", "kakao"].includes(name)) providerModes.push("fallback");
    if (name === "github") providerModes.push("verification-object", "verification-array", "selected-email-object", "selected-email-array");
    for (const mode of providerModes) {
      if (name === "tiktok" && mode === "mapped") continue;
      const profile = {
        dropbox: { account_id: "subject" },
        figma: { id: "subject" },
        github: { id: "subject" },
        google: { sub: "subject" },
        huggingface: { sub: "subject" },
        kakao: { id: "subject", kakao_account: { profile: {} } },
        kick: { data: [{ user_id: "subject" }] },
        linear: { data: { viewer: { id: "subject" } } },
        linkedin: { sub: "subject" },
        roblox: { sub: "subject" },
        salesforce: { user_id: "subject" },
        slack: { "https://slack.com/user_id": "subject" },
        spotify: { id: "subject", images: [] },
        twitch: { sub: "subject" },
        twitter: { data: { id: "subject" } },
        vercel: { sub: "subject" },
        vk: { user: { user_id: "subject", email: "vk@fixture.test" } },
        zoom: { id: "subject" },
        "facebook-graph": { id: "1", picture: { data: {} } },
        "facebook-limited": { sub: "subject" },
        microsoft: { oid: "subject" },
        discord: { id: "subject", avatar: "avatar" },
        tiktok: { data: { user: { open_id: "subject" } } },
        paybin: { sub: "subject" },
        polar: { id: "subject" },
        railway: { sub: "subject" },
        reddit: { id: "subject" },
        notion: { bot: { owner: { user: { id: "subject" } } } },
        atlassian: { account_id: "subject" },
        "line-token": { sub: "subject" },
        "line-http": { sub: "subject" },
        naver: { resultcode: "00", response: { id: "subject" } },
        paypal: { sub: "subject", user_id: "subject" },
        cloudflare: { success: true, result: { id: "subject" } },
        "cognito-token": { sub: "subject" },
        "cognito-http": { sub: "subject" },
        gitlab: { id: "subject", state: "active" },
        apple: { sub: "subject" },
        wechat: { openid: "subject" },
      }[name];
      if (mode !== "missing" && mode !== "mapped") {
        const value = {
          null: null, false: false, empty: "", utf16: "\ud800", zero: 0, true: true,
          object: { text: "\udfff" }, array: ["\ud800", null], fallback: false,
          "verification-object": { text: "\udfff" }, "verification-array": ["\ud800", null],
          "selected-email-object": { text: "\udfff" }, "selected-email-array": ["\ud800", null],
        }[mode];
        const fields = {
          dropbox: ["email", "email_verified", "profile_photo_url"],
          figma: ["handle", "email", "img_url"],
          github: ["name", "login", "email", "avatar_url"],
          google: ["name", "email", "picture", "email_verified"],
          huggingface: ["name", "preferred_username", "email", "picture", "email_verified"],
          kakao: ["name", "email", "is_email_valid", "is_email_verified"],
          kick: ["name", "email", "profile_picture"],
          linear: ["name", "email", "avatarUrl"],
          linkedin: ["name", "email", "picture", "email_verified"],
          roblox: ["nickname", "preferred_username", "picture"],
          salesforce: ["name", "email", "email_verified"],
          slack: ["name", "email", "email_verified", "picture", "https://slack.com/user_image_512"],
          spotify: ["display_name", "email"],
          twitch: ["preferred_username", "email", "picture", "email_verified"],
          twitter: ["name", "email", "profile_image_url"],
          vercel: ["name", "preferred_username", "email", "picture", "email_verified"],
          vk: ["first_name", "last_name", "birthday", "sex", "avatar"],
          zoom: ["display_name", "email", "pic_url", "verified"],
          "facebook-graph": ["name", "email", "email_verified"],
          "facebook-limited": ["name", "email", "picture"],
          microsoft: ["name", "email", "picture", "email_verified"],
          discord: ["global_name", "username", "email", "verified"],
          tiktok: ["display_name", "username", "email", "avatar_large_url"],
          paybin: ["name", "preferred_username", "email", "picture", "email_verified"],
          polar: ["public_name", "username", "email", "avatar_url", "email_verified"],
          railway: ["name", "email", "picture"],
          reddit: ["name", "icon_img"],
          notion: ["name", "avatar_url"],
          atlassian: ["name", "email", "picture"],
          "line-token": ["name", "email", "picture"],
          "line-http": ["name", "email", "picture"],
          naver: ["name", "nickname", "email", "profile_image"],
          paypal: ["name", "email", "picture", "email_verified"],
          cloudflare: ["first_name", "last_name", "email"],
          "cognito-token": ["name", "given_name", "username", "email", "picture", "email_verified"],
          "cognito-http": ["name", "given_name", "username", "email", "picture", "email_verified"],
          gitlab: ["name", "username", "email", "avatar_url", "email_verified"],
          apple: ["name", "email", "email_verified"],
          wechat: ["nickname", "email", "headimgurl"],
        }[name];
        const receiver = name === "kakao" ? profile.kakao_account : name === "kick" ? profile.data[0] : name === "linear" ? profile.data.viewer : name === "vk" ? profile.user : name === "twitter" ? profile.data : name === "tiktok" ? profile.data.user : name === "notion" ? profile.bot.owner.user : name === "naver" ? profile.response : name === "cloudflare" ? profile.result : profile;
        for (const field of fields) receiver[field] = value;
        if (name === "dropbox") profile.name = { display_name: value };
        if (name === "kakao") receiver.profile = { nickname: value, profile_image_url: value, thumbnail_image_url: value };
        if (mode === "fallback") {
          if (name === "github") profile.login = "\udfff";
          if (name === "huggingface") profile.preferred_username = "\udfff";
          if (name === "kakao") {
            receiver.name = "\udfff";
            receiver.profile.thumbnail_image_url = "\ud800";
            receiver.is_email_valid = "truthy";
            receiver.is_email_verified = [];
          }
        }
        if (name === "salesforce") profile.photos = { picture: value, thumbnail: value };
        if (name === "spotify") profile.images = [{ url: value }];
        if (name === "facebook-graph") profile.picture.data.url = value;
        if (name === "notion") receiver.person = { email: value };
        if (name === "reddit" && mode === "false") profile.icon_img = "";
      }
      const mapping = mode === "mapped"
        ? { id: "mapped", name: "\udfff", email: "mapped@fixture.test", extra: { text: "\ud800" } }
        : null;
      const mappingUndefined = mode === "mapped" ? ["image", "extraUndefined"] : [];
      const selectedEmail = mode.startsWith("selected-email-");
      const verification = profile.email;
      if (mode.startsWith("verification-") || selectedEmail) profile.email = "";
      const emails = name === "github" ? [
        { email: selectedEmail ? verification : "secondary@fixture.test", primary: false, verified: false },
        {
          email: selectedEmail ? verification : "primary@fixture.test",
          primary: true,
          verified: mode === "missing" || mode === "mapped" || selectedEmail ? true : verification,
        },
        ...(profile.email ? [{ email: profile.email, primary: false, verified: verification }] : []),
      ] : null;
      const fetched = [];
      let mapCalls = 0;
      const observedProfiles = [];
      globalThis.fetch = async input => {
        const url = String(input instanceof Request ? input.url : input);
        fetched.push(url);
        const body = url.endsWith("/user/emails") ? emails : url.includes("user.fields=confirmed_email") ? { data: {} }
          : url.includes("/debug_token") ? { data: { is_valid: true, app_id: "client", user_id: "1" } }
          : profile;
        return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
      };
      const factory = factoryName(name);
      const provider = socialProviders[factory]({
        clientId: "client", clientSecret: "secret", disableProfilePhoto: true,
        domain: "example.com", region: "us-east-1", userPoolId: "us-east-1_pool",
        ...(mapping ? { mapProfileToUser: async observed => {
          ++mapCalls;
          observedProfiles.push(structuredClone(observed));
          return { ...mapping, ...Object.fromEntries(mappingUndefined.map(key => [key, undefined])) };
        } } : {}),
      });
      const idToken = `h.${Buffer.from(JSON.stringify(profile)).toString("base64url")}.s`;
      const response = await provider.getUserInfo({ accessToken: "access", ...(["facebook-graph", "cognito-http", "line-http"].includes(name) ? {} : { idToken }), openid: "subject" });
      assert.ok(response, `${name}/${mode}`);
      if (name === "github") assert.deepEqual(fetched.sort(), ["https://api.github.com/user", "https://api.github.com/user/emails"]);
      if (name === "google") assert.deepEqual(fetched, []);
      assert.equal(mapCalls, mapping ? 1 : 0);
      assert.deepEqual(observedProfiles, mapping ? [response.data] : []);
      assert.deepEqual(response.data, name === "discord"
        ? { ...profile, image_url: "https://cdn.discordapp.com/avatars/subject/avatar.png" }
        : name === "notion" ? profile.bot.owner.user
        : name === "cloudflare" ? profile.result
        : name === "kick" ? profile.data[0]
        : name === "linear" ? profile.data.viewer
        : name === "github" ? { ...profile, email: profile.email || emails.find(email => email.primary).email }
        : name === "apple" || name === "cognito-token" ? { ...profile, name: profile.name || profile.given_name || profile.username || "" }
        : profile);
      const subject = await provider.accountSubject({ profile: response.data });
      assert.equal(typeof subject, "string");
      cases.push({
        provider: name, factory, mode, profile, ...(emails ? { emails } : {}), mapping, mapping_undefined: mappingUndefined,
        expected_data: response.data,
        subject,
        expected: response.user,
        wire: JSON.stringify(response.user),
        keys: Object.keys(response.user),
        undefined: Object.keys(response.user).filter(key => response.user[key] === undefined),
      });
    }
  }
  for (const profile of [42, "profile", []]) {
    globalThis.fetch = async () => new Response(JSON.stringify(profile), {
      headers: { "content-type": "application/json" },
    });
    const response = await socialProviders.paypal({ clientId: "client", clientSecret: "secret" })
      .getUserInfo({ accessToken: "access" });
    assert.deepEqual(response.data, profile);
    assert.deepEqual(Object.keys(response.user), ["name", "email", "image", "emailVerified"]);
    assert.ok(Object.values(response.user).every(value => value === undefined));
    assert.equal(JSON.stringify(response.user), "{}");
  }
} finally {
  globalThis.fetch = fetch;
}
const metadata = {
  source_revision: pin.commit,
  node: process.version,
  factories: [...new Set(cases.map(test => test.factory))].sort(),
  branches: Object.fromEntries(names.map(name => [name, cases.filter(test => test.provider === name).length])),
  factory_count: new Set(cases.map(test => test.factory)).size,
  branch_count: new Set(cases.map(test => test.provider)).size,
  case_count: cases.length,
};
assert.equal(metadata.factory_count, 36);
assert.equal(metadata.branch_count, 39);
assert.equal(metadata.case_count, 276);
assert.deepEqual(metadata.factories, sourceFactories);
assert.equal(Object.values(metadata.branches).reduce((sum, count) => sum + count, 0), metadata.case_count);
await writeFile(new URL("../../../crates/plugins/src/oauth/providers/remaining_profile_own_fields_cases.json", import.meta.url),
  JSON.stringify({ better_auth: pkg.version, metadata, cases }).replaceAll('},{"provider":', '},\n{"provider":') + "\n");
console.log(`${metadata.case_count} cases / ${metadata.branch_count} branches / ${metadata.factory_count} factories from Better Auth ${pkg.version}, ${process.version}`);
