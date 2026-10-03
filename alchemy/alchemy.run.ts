import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import * as Railway from "alchemy/Railway";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

export const Docs = Effect.gen(function* () {
  const domain = yield* Config.String("DOCS_DOMAIN").pipe(Config.withDefault(""));

  return yield* Railway.Website.Astro("Docs", {
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
