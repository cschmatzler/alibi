---
title: "Contributing"
description: "Run the Rust checks and work on the Starlight documentation."
---

Install [devenv](https://devenv.sh/getting-started/) and
[direnv](https://direnv.net/docs/hook.html) with its shell hook enabled.
The repository's `.envrc` activates the development environment automatically.
Allow it once, then run the complete test gate:

```bash
direnv allow
devenv shell -- ./scripts/check.sh
```

You can also enter the environment manually with `devenv shell`.
Rust tooling and lint rules come from the private `cschmatzler/rust` flake.
Local development requires GitHub SSH access; CI uses the `RUST_STYLE_TOKEN`
secret to fetch the locked revision. `devenv.lock` pins the environment.

See [Tests](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/README.md) for the unit, integration and compat tiers, and
[Compatibility testing](https://github.com/cschmatzler/better-auth-rs/blob/main/tests/compat/README.md) for focused checks and the
compatibility contract.

## Documentation

From the repository root:

```bash
pnpm install
pnpm docs:dev
```

Run `pnpm docs:check` for Astro diagnostics and `pnpm docs:build` for the static build and search index. Content lives in `docs/src/content/docs`; navigation is configured in `docs/astro.config.mjs`.

Keep explanations brief and show complete Rust setup, including plugin registration. Link to the official Better Auth docs for frontend usage. Check examples against this repository's API and the pinned compatibility target, 1.7.6.
