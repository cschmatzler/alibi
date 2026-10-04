# Docs deployment

[Live docs](https://better-auth-rs.schmatzler.com). Alchemy manages Railway and Cloudflare DNS.

```sh
devenv shell
bun install
bun run docs:plan
bun run docs:deploy
```

Edit SOPS credentials with `bun run docs:secrets:edit`. Cloudflare needs Zone Read, DNS Edit, and state-store access; Railway needs an account token. Domain and zone settings are in `.env.production`.
