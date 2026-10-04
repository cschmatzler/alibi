# Alchemy Railway Astro routing

`alchemy@2.0.0-beta.80` accepts `assets.notFoundHandling` and `assets.htmlHandling` on the Astro resource but does not pass them to its Node build target. Fully static sites therefore use the target's SPA fallback and return the homepage with HTTP 200 for unknown paths.

The patch forwards both options through `targetConfig`, mapping `single-page-application` to the target's `spa` value. It covers the source and compiled entrypoints. Remove it when an upstream release forwards these options.

Verify the generated `serve-node.mjs` returns the built `404.html` with status 404, then check an unknown path on the deployed site.

The Railway website helper also omits a service name override. The patch adds `serviceName` to its framework props and forwards it to `Railway.Service`, allowing the docs stack to rename the existing service to `docs` without changing its resource identity. It covers source, compiled JavaScript, and declarations. Remove this part when upstream exposes a service name override.

The DNS record provider compares names after resolving them against the zone, so a relative name and its FQDN do not trigger replacement of the same physical record. The docs TXT record uses a full hostname for future deployments.
