import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Namespace from "alchemy/Namespace";
import * as Railway from "alchemy/Railway";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

export const Docs = Effect.gen(function* () {
  const domain = yield* Config.String("DOCS_DOMAIN").pipe(Config.withDefault(""));
  // Keep the project in the website's resource namespace.
  const project = yield* Railway.Project("Project", {
    name: "better-auth-rs",
  }).pipe(Namespace.push("Docs"));

  return yield* Railway.Website.Astro("Docs", {
    project,
    rootDir: "./docs",
    domain: domain || undefined,
    astro: {
      output: "static",
      site: domain ? `https://${domain}` : undefined,
    },
    assets: { notFoundHandling: "404-page" },
  });
});

export default Alchemy.Stack(
  "BetterAuthDocs",
  {
    providers: Cloudflare.providers().pipe(Layer.provideMerge(Railway.providers())),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const docs = yield* Docs;
    return { url: docs.url };
  }),
);
