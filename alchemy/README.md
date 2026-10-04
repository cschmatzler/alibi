# Docs deployment

The Starlight site uses [Alchemy's Railway Astro resource](https://alchemy.run/railway/frontend/astro/) in static mode. Alchemy builds the site locally, uploads its generated container to Railway, and returns the public URL. Unknown routes serve the built `404.html` with HTTP 404.

## Secrets

Deployment follows [Reverie's infrastructure PR](https://github.com/cschmatzler/reverie/pull/282): SOPS encrypts credentials with the recipients in `.sops.yaml`, and Varlock decrypts and validates them once before running Alchemy. The encrypted file contains only `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, and `RAILWAY_API_TOKEN`.

Install dependencies with `pnpm install` and enter `devenv shell` for Bun and SOPS. Use an authorized age identity via SOPS's default key file or `SOPS_AGE_KEY_FILE`. Edit credentials with:

```bash
pnpm docs:secrets:edit
```

Use a Railway account token; the stack manages the `better-auth-rs` project. The Cloudflare token needs Zone Read and DNS Edit permissions for `schmatzler.com`, in addition to its existing state-store permissions. Cloudflare hosts Alchemy's encrypted state under the `better-auth-rs` profile. Keep this profile and the `prod` stage consistent when planning, deploying, and destroying.

## Deploy

Run from the repository root:

```bash
pnpm docs:infra:check
pnpm docs:check
pnpm docs:plan
pnpm docs:deploy
```

The first command that accesses remote state may bootstrap Alchemy's Cloudflare state store. Deployment creates the Railway project and docs service. The docs are live at [better-auth-rs.schmatzler.com](https://better-auth-rs.schmatzler.com).

The production hostname is configured as `DOCS_DOMAIN=better-auth-rs.schmatzler.com` in `.env.production`. To override it, set `DOCS_DOMAIN=docs.example.com` in `.env.production.local` before planning. Set `DOCS_DNS_ZONE_ID` to the existing Cloudflare zone containing that hostname when overriding the domain. Alchemy attaches the domain, uses it as Astro's canonical site URL, and manages the CNAME and ownership TXT records from Railway's required DNS values. The CNAME uses DNS-only mode so Railway can verify ownership and issue HTTPS certificates. Use the same domain and zone configuration on later deployments.

To remove the docs deployment:

```bash
pnpm docs:destroy
```

This removes the docs resources; the account's shared Cloudflare state store is managed separately by Alchemy.
