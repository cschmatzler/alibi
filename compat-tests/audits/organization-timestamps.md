# Organization timestamp precision

Owner: behavior audit. Base: the pinned 1.7.6 oracle and the email-verification
prerequisite. This change adds no routes to the authentication API.

The official client parser in `better-auth/dist/client/parser.mjs` interprets
all fractional digits as milliseconds. Chrono's automatic precision can emit
`2001-02-03T04:05:06.227234Z`, which that client reads as
`2001-02-03T04:08:53.234Z`. The TypeScript runtime emits exactly three fractional
digits. Organization response DTOs and the existing organization, member, and
invitation entities now use the common millisecond serializer.

Evidence:

- A differential official-client scenario creates a real organization and
  owner membership, writes and rereads the actual persisted rows through a
  private fixture control, then checks their dates and ownership through
  `getFullOrganization` and `getActiveMember`. The pre-fix implementation fails
  with the shifted date above; the fixed implementation passes.
- A public AuthBuilder/SQLite integration test proves the raw route response
  and typed server projections preserve the persisted instant. Its assertions
  also cover core organization/member/invitation serialization, the four
  organization DTOs, and unchanged IDs, role, and source precision in storage.
- Focused validation passes: one native integration test, three SDK scenarios
  including the existing invitation flows, TypeScript checking, formatting,
  and strict Clippy for the integration test.

The full canonical gate is pending on the managed-JWT descendant, which must
include this prerequisite before claiming its final integrated validation.
