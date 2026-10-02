# CAPTCHA middleware (#134)

Base: actual main c7fc2aa9029f4bef50baa718517676c02a79bbbe.

## Authoring gate

The public behavior is request admission at the physical HTTP plugin phase. The pinned Better Auth 1.7.6 factory runs after disabled paths and rate limiting, before router/body/origin/endpoint middleware. Existing native endpoint hooks run too late and no CAPTCHA configuration exists.

Retain the earlier actual Source fixture and 22 SDK owners, adapted onto current main. Owners exercise real configured auth instances, full provider HTTP bodies, callback events, complete physical owner/foreign rows and real sign-in admission. The unchanged-base native counterfactual registers an ordinary real auth profile without CAPTCHA, so missing response produces a real authenticated session instead of Source rejection; missing fixture 404 or build failure is not product evidence.

Provider controls cover all five implementations, rejection without authentication writes, action/hostname/score, exact encoded token/IP/site-key transport, malformed provider replies, configured bypass/empty/default/wildcard paths, disabled precedence, and BotID callback errors/verified bots. Test only configuration and observation live in fixture servers; native admission must use a public production plugin. No comparer changes or private production seams are planned.

## Source audit

Literal JSON errors have message then code and text/plain;charset=UTF-8. Verification timeout is 10 seconds. Invalid JSON HTTP-success replies remain truthy text then fail success validation (403); null and failed HTTP replies become 500. Turnstile sends ordered JSON; other HTTP providers send ordered URLencoded form, with CaptchaFox remoteIp spelling. BotID does not require a token/secret and its timeout must not cancel the application promise. Runtime path normalization collapses repeated slash and trims a terminal slash before Source wildcard matching. IP uses the configured existing native IP policy. Secrets/tokens are sent only to the configured application-controlled verifier.

## Evidence

Pending actual unchanged-base native before owner, fresh Source control, native implementation, independent review, capability measurement and canonical checks. This audit checkpoint is not completion evidence.
