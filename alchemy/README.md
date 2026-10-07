# Docs deployment

[Docs URL](https://alibi.schmatzler.com). Alchemy manages Railway and Cloudflare DNS. The deployment uses this hostname for canonical URLs and the sitemap.

```sh
devenv shell
bun install
bun run docs:plan
bun run docs:deploy
```

Edit the encrypted credentials directly with `sops secrets.production.sops.json` inside the development shell. Cloudflare needs Zone Read, DNS Edit, and state-store access; Railway needs an account token. Domain and zone settings are in `.env.production`.

Keep the existing `BetterAuthDocs` stack name, resource IDs, and `better-auth-rs` Alchemy profile when deploying this rename. These identify the existing deployment state; changing them would provision a separate stack instead of updating the current site. The Railway project display name becomes `alibi`.
