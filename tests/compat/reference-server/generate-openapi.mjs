#!/usr/bin/env bun

import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const parseArgs = (argv) => {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];

    if (!token.startsWith("--")) {
      throw new Error(`Unknown argument: ${token}`);
    }

    const key = token.slice(2);
    const value = argv[i + 1];

    if (!value || value.startsWith("--")) {
      throw new Error(`Missing value for --${key}`);
    }

    result[key] = value;
    i += 1;
  }
  return result;
};

const args = parseArgs(process.argv.slice(2));
const profile = args.profile;
const outputPath = args.output ? resolve(args.output) : null;

if (!profile) {
  throw new Error("Missing --profile");
}

if (!outputPath) {
  throw new Error("Missing --output");
}

const { betterAuth } = await import("better-auth/minimal");
const barrel = await import("better-auth/plugins");

// apiKey left the `better-auth/plugins` barrel in better-auth 1.5.0.
const plugins = { ...barrel };

if (typeof plugins.apiKey !== "function") {
  const { apiKey } = await import("@better-auth/api-key");
  plugins.apiKey = apiKey;
}

const { passkey } = await import("@better-auth/passkey");

const requiredPlugin = (name, ...factoryArgs) => {
  const factory = plugins[name];
  if (typeof factory !== "function") {
    throw new Error(`Plugin '${name}' is not exported by better-auth/plugins`);
  }
  return factory(...factoryArgs);
};

const optionalPlugin = (name, ...factoryArgs) => {
  const factory = plugins[name];
  if (typeof factory !== "function") {
    console.warn(`[warn] plugin '${name}' is unavailable on this ref, skipped`);
    return null;
  }
  return factory(...factoryArgs);
};

const pushIf = (target, plugin) => {
  if (plugin) {
    target.push(plugin);
  }
};

const noopAsync = async () => {};

const profiles = {
  core: () => [requiredPlugin("openAPI")],
  "aligned-rs": () => [
    requiredPlugin("openAPI"),
    requiredPlugin("admin"),
    requiredPlugin("apiKey", { enableSessionForAPIKeys: true }),
    requiredPlugin("twoFactor"),
    requiredPlugin("organization"),
    requiredPlugin("username"),
    requiredPlugin("oneTimeToken"),
    requiredPlugin("jwt"),
    passkey(),
  ],
  "all-in": () => {
    const selected = [requiredPlugin("openAPI")];

    pushIf(selected, optionalPlugin("admin"));
    pushIf(selected, optionalPlugin("anonymous"));
    pushIf(selected, optionalPlugin("apiKey", { enableSessionForAPIKeys: true }));
    pushIf(selected, optionalPlugin("bearer"));
    pushIf(
      selected,
      optionalPlugin("captcha", {
        provider: "cloudflare-turnstile",
        secretKey: "dummy-captcha-secret",
      }),
    );
    pushIf(
      selected,
      optionalPlugin("customSession", async ({ user, session }) => ({ user, session })),
    );
    pushIf(selected, optionalPlugin("deviceAuthorization"));
    pushIf(
      selected,
      optionalPlugin("emailOTP", {
        sendVerificationOTP: noopAsync,
      }),
    );
    pushIf(
      selected,
      optionalPlugin("genericOAuth", {
        config: [
          {
            providerId: "dummy-oauth",
            clientId: "dummy-client-id",
            clientSecret: "dummy-client-secret",
            authorizationUrl: "https://example.com/oauth/authorize",
            tokenUrl: "https://example.com/oauth/token",
            userInfoUrl: "https://example.com/oauth/userinfo",
            scopes: ["openid", "profile", "email"],
          },
        ],
      }),
    );
    pushIf(selected, optionalPlugin("haveIBeenPwned"));
    pushIf(selected, optionalPlugin("jwt"));
    pushIf(selected, optionalPlugin("lastLoginMethod"));
    pushIf(
      selected,
      optionalPlugin("magicLink", {
        sendMagicLink: noopAsync,
      }),
    );
    pushIf(selected, optionalPlugin("multiSession"));
    pushIf(selected, optionalPlugin("oAuthProxy"));
    const oidcProviderPlugin = optionalPlugin("oidcProvider", {
      loginPage: "/login",
    });

    if (oidcProviderPlugin) {
      pushIf(selected, oidcProviderPlugin);
    } else {
      pushIf(
        selected,
        optionalPlugin("mcp", {
          loginPage: "/login",
        }),
      );
    }

    pushIf(
      selected,
      optionalPlugin("oneTap", {
        clientId: "dummy-client-id",
      }),
    );
    pushIf(selected, optionalPlugin("oneTimeToken"));
    pushIf(
      selected,
      optionalPlugin("organization", {
        teams: { enabled: true },
        dynamicAccessControl: { enabled: true },
      }),
    );
    pushIf(selected, optionalPlugin("phoneNumber"));
    pushIf(
      selected,
      optionalPlugin("siwe", {
        domain: "localhost",
        getNonce: async () => "dummy-nonce",
        verifyMessage: async () => true,
      }),
    );
    pushIf(selected, optionalPlugin("twoFactor"));
    pushIf(selected, optionalPlugin("username"));
    selected.push(passkey());

    return selected;
  },
};

const buildPlugins = profiles[profile];

if (typeof buildPlugins !== "function") {
  throw new Error(`Unsupported profile '${profile}'. Allowed: ${Object.keys(profiles).join(", ")}`);
}

const makeAuth = (selectPlugins) =>
  betterAuth({
    secret: "better-auth-rs-openapi-alignment-script-secret-32-bytes",
    baseURL: "http://localhost:3000",
    trustedOrigins: ["http://localhost:3000"],
    emailAndPassword: {
      enabled: true,
    },
    socialProviders: {},
    plugins: selectPlugins(),
  });

const auth = makeAuth(buildPlugins);

if (!auth.api || typeof auth.api.generateOpenAPISchema !== "function") {
  throw new Error("generateOpenAPISchema is not available. Ensure openAPI() is enabled.");
}

const schema =
  args.format === "routes"
    ? // Plugins can replace endpoint metadata (for example customSession narrows
      // get-session to GET). Union profiles so overrides cannot hide core methods.
      [
        ...new Set(
          [
            auth,
            ...(profile === "all-in"
              ? [makeAuth(profiles.core), makeAuth(profiles["aligned-rs"])]
              : []),
          ].flatMap((instance) =>
            Object.values(instance.api).flatMap((endpoint) => {
              if (!endpoint.path || endpoint.options?.metadata?.SERVER_ONLY) {
                return [];
              }
              const methods = endpoint.options?.method ?? "GET";
              return (Array.isArray(methods) ? methods : [methods]).map(
                (method) => `${method} ${endpoint.path.replace(/:[^/]+|\{[^}]+\}/g, "{}")}`,
              );
            }),
          ),
        ),
      ].sort()
    : await auth.api.generateOpenAPISchema();

await writeFile(outputPath, JSON.stringify(schema, null, 2), "utf8");
console.log(`[ok] ${profile} -> ${outputPath}`);
