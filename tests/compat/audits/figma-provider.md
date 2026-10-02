# Figma provider (issue #145)

Read-only authority: the installed unchanged Better Auth 1.7.6 public Figma
factory, declared FigmaProfile/FigmaOptions, authorization/code/refresh helpers
and OAuth Basic credential encoder. Actual application registration must call
that factory and redirect only its fixed remote HTTP destinations.

The factory requires client ID, client secret and a PKCE verifier, defaults to
current_user:read and www.figma.com/oauth, preserves configured/requested scope
order and duplicates, omits loginHint, and uses trusted authorize/redirect
configuration. Both code exchange and refresh target api.figma.com/v1/oauth/token
with form-encoded client credentials in HTTP Basic, not body credentials.
client_key belongs only in code exchange. Profile retrieval is bearer GET at
api.figma.com/v1/me; raw id owns account admission while handle/email/img_url map
the public user and verified-email defaults false. A mapper receives the original
profile. This factory supplies no ID-token verifier/JWKS/issuer/remote logout.

Authoring gate: the real public SDK owner protects missing factory defaults,
Basic code/refresh protocol, bearer GET, raw id binding and Figma field mapping.
Generic and Dropbox POST owners cannot exercise this actual initialization.
Configured factory modes extend one table; complete observed HTTP forms, real
SQL rows, foreign principals, callback replay, token rotation and local sign-out
remain in snapshots. Explicit account linking and existing account-info are
separate public operations. Controls return remote responses and observe actual
HTTP; they never fabricate successful admission or physical writes. No new
production seam exists only for tests. Unsupported general callback/projection,
malformed complex transport and advanced policies remain #181/#184/#188/#193.

Implementation, actual generic-parent before failure, independent review,
capability evidence and all final gates remain pending. No Source/comparer edit,
dependency patch or hook bypass is authorized.
