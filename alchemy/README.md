# Docs deployment

[Live docs](https://better-auth-rs.schmatzler.com). Alchemy manages Railway and Cloudflare DNS.

```sh
devenv shell
pnpm install
pnpm docs:plan
pnpm docs:deploy
```

Edit SOPS credentials with `pnpm docs:secrets:edit`. Cloudflare needs Zone Read, DNS Edit, and state-store access; Railway needs an account token. Domain and zone settings are in `.env.production`.
