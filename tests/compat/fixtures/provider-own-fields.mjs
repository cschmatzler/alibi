import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { socialProviders } from "../reference-server/node_modules/@better-auth/core/dist/social-providers/index.mjs";

const pkg = JSON.parse(await readFile(new URL("../reference-server/node_modules/@better-auth/core/package.json", import.meta.url)));
assert.equal(pkg.version, "1.7.18");
const names = ["roblox", "salesforce", "slack", "spotify", "twitch", "twitter", "vercel", "vk", "zoom", "facebook-graph", "facebook-limited", "microsoft", "discord", "tiktok", "paybin", "polar", "railway", "reddit", "notion", "atlassian", "line-token", "line-http", "naver", "paypal", "cloudflare", "cognito-token", "cognito-http", "gitlab", "apple", "wechat"];
const modes = ["missing", "null", "false", "empty", "utf16", "mapped"];
const cases = [];
const fetch = globalThis.fetch;
try {
  for (const name of names) {
    for (const mode of modes) {
      if (name === "tiktok" && mode === "mapped") continue;
      const profile = {
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
        const value = { null: null, false: false, empty: "", utf16: "\ud800" }[mode];
        const fields = {
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
        const receiver = name === "vk" ? profile.user : name === "twitter" ? profile.data : name === "tiktok" ? profile.data.user : name === "notion" ? profile.bot.owner.user : name === "naver" ? profile.response : name === "cloudflare" ? profile.result : profile;
        for (const field of fields) receiver[field] = value;
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
      let mapCalls = 0;
      const observedProfiles = [];
      globalThis.fetch = async input => {
        const url = String(input instanceof Request ? input.url : input);
        const body = url.includes("user.fields=confirmed_email") ? { data: {} }
          : url.includes("/debug_token") ? { data: { is_valid: true, app_id: "client", user_id: "1" } }
          : profile;
        return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
      };
      const factory = name.startsWith("facebook-") ? "facebook" : name.startsWith("cognito-") ? "cognito" : name.startsWith("line-") ? "line" : name;
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
      assert.equal(mapCalls, mapping ? 1 : 0);
      assert.deepEqual(observedProfiles, mapping ? [response.data] : []);
      assert.deepEqual(response.data, name === "discord"
        ? { ...profile, image_url: "https://cdn.discordapp.com/avatars/subject/avatar.png" }
        : name === "notion" ? profile.bot.owner.user
        : name === "cloudflare" ? profile.result
        : name === "apple" || name === "cognito-token" ? { ...profile, name: profile.name || profile.given_name || profile.username || "" }
        : profile);
      const subject = await provider.accountSubject({ profile: response.data });
      assert.equal(typeof subject, "string");
      cases.push({
        provider: name, mode, profile, mapping, mapping_undefined: mappingUndefined,
        expected_data: response.data,
        subject,
        expected: response.user,
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
assert.equal(cases.length, 179);
await writeFile(new URL("../../../crates/plugins/src/oauth/providers/remaining_profile_own_fields_cases.json", import.meta.url),
  JSON.stringify({ better_auth: pkg.version, cases }).replaceAll('},{"provider":', '},\n{"provider":') + "\n");
console.log(`${cases.length} provider own-field cases from Better Auth ${pkg.version}`);
