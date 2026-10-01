# Individual API-key rejection deletion against Better Auth 1.7.6

This API policy depends on the separately frozen non-mutating atomic exhaustion
prerequisite ab00b5c2 and automatic hot cleanup c8bee0bf. It owns database-mode
individual expiry and initial zero/no-refill exhaustion deletion, with existing
ApiKeyConfig.defer_updates and AuthConfig.background_tasks; no new public
configuration, store methods, routes, migration or schema.

## Pinned stages and actual probes

Published @better-auth/api-key1.7.6 index.mjs validateApiKey1637–1691 reads issuing
configuration, rejects disabled credentials, handles expiration before permission
checks, then checks required permissions before initially observed
remaining===0/refillAmount===null. Those initial rejection branches delete exactly
the selected stored ID. A positive-snapshot atomic-consumption loser only rejects;
its zero row remains, as documented/proven in the prerequisite audit.

With deferUpdates=false, actual individual deletion is awaited and its errors
propagate. With true, the original async delete starts immediately, its failure
is caught/logged, and the hot completion is passed to the application handler.
The credential rejects before a pending deletion finishes. Ignoring/rejecting
observation cannot cancel already started work. This is independent of the bulk
module throttle and does not admit a bulk job or update its timestamp on rejection.

Fresh actual pinned runtime probes in /tmp/api-key-individual-deletion-probe.mjs
use migrated SQLite, real signups and trusted public key generation. A wrapper
acknowledges/gates the original adapter.delete. Expired and exhausted, awaited
and deferred, middleware/trusted, ignore/observe, ordinary/application errors,
and actual SQL ABORT cases are retained in /tmp/api-key-individual-*-probe.log.
Deferred cases return KEY_EXPIRED401/USAGE_EXCEEDED429 before adapter release;
awaited cases have not returned at its genuine entry receipt. Source ordinary
handler throw yields empty500, while APIError403 survives. Deferred SQL ABORT
keeps the row and fulfills the caught completion. Awaited SQL error yields empty
middleware500 or trusted {valid:false,error:{code:INVALID_API_KEY,
message:{code:INVALID_API_KEY,message:"Invalid API key."}},key:null}.

## Production shape

The shared private hot-work launcher is extracted from c8bee without changing its
first poll, store ownership, framework request-hook context, tracing span/subscriber,
Tokio lifetime, or completion contract. Automatic bulk cleanup still performs its
original admission before calling it. Deferred individual deletion captures only
its actual store/row ID, catches/logs store failure, launches owned work, and then
registers completion. Default individual deletion simply awaits the store operation.
Expiration keeps its prior ordering; the explicit snapshot-zero/no-refill check is
after permission checking and before atomic quota consumption.

Only the source middleware verification stage maps ordinary/internal failures to
empty500. Typed Api/Upstream application errors retain their original response.
Trusted native verification continues returning its existing typed error rather
than inventing an HTTP interface. Fixture server-only encoding projects those
actual errors into the pinned trusted envelope. No string-based error classification,
quota weakening, blanket global mapping, or fake successful callback is added.

## Primary owners and meaningful failure

Seven official-client owners reuse the existing actual background application
fixture and its two profiles. Both users sign up and publicly generate real keys;
foreign key lookup rejects. Bound fixture SQL establishes only expiry/quota after
those real writes. Application gates wrap real individual DELETE, emit its actual
entry/result, and preserve full ID relationships as key:{id}; nothing simulates
authentication or expected persistence. Complete requests, response/cookie/header
transport, application receipts and stored rows/dates remain in the comparison.

Deferred expiry/exhaustion returns its rejection while the row still exists and
while all user/account/session state is unchanged. Ignore mode then releases actual
deletion, preserves the complete foreign row and denies retired-key replay.
Awaited owners observe the real gate, retained row/state and no response/completion
registration until release. SQL ABORT owners prove caught fulfillment and retained
rows, an awaited retry's genuine failure, then removal of just the selected key
once the actual trigger is removed. Ordinary and genuine403 application errors
exercise two real hot deletions, which finish even though neither observer accepts
them. The application releases each actual serial separately and awaits its genuine
SQL completion before releasing the next, retaining full receipts while controlling
its own gate ordering. The first full run retained both jobs but their naturally
concurrent completion order differed (52pass/1failure, initial family log); that
fixture scheduling observation is preserved separately, not hidden by sorting or
comparison policy. Trusted permission denial at exhausted quota produces no deletion/registration;
trusted failure controls retain the exact envelope and actual retry state.

The unchanged c8 individual-expiration route is measured with the equivalent
real controlled fixture in /tmp/api-key-individual-old-await-before.log: configured
defer=true still has httpCompleted:false after actual row-delete entry; release
returns KEY_EXPIRED401. The binary is built from ab00 with the prior c8 API policy
and only the same application fixture controls, using its own actual TCP port.
This independently demonstrates the before behavior, not a timer expectation.
The separately frozen storage owner has its own precise missing-row before-failure.

Final pinned self-control passes7 owners/490 assertions in
/tmp/api-key-individual-source-controlled-release-final.log. Earlier self-controls
first exposed a fixture identity shape keyId (corrected losslessly to key:{id})
and one wrongly guessed permission-message literal (actual "API Key not found").
Those setup failures remain in their original logs and are excluded as production
regression evidence. No comparator or published source was changed.

The complete focused API-key SDK family passes53 owners/2672 assertions in
/tmp/api-key-individual-family-controlled-final.log. All52 API native tests pass
in /tmp/api-key-individual-api-native-final.log. Locked fixture build,
client/reference TypeScript, strict production/fixture Clippy, downstream consumer
compilation, formatting and diff checks are recorded in
/tmp/api-key-individual-*-final.log.
Coordinator owns independent review, shared inventory, gates and publication.
No full gate is claimed. An exploratory core all-target Clippy invocation found
unchanged core unit-test restriction warnings; canonical strict library checks
are run separately. Test-audit external autoreview executables are unavailable.

Secondary storage/fallback and deferred secondary quota merges remain separate
capabilities. Expiration equality/malformed dates, deliberate adapter APIError
at default deletion, runtime shutdown survival, arbitrary task locals, and
application-created changes between lookup/delete are not universally exercised.
Source deletes by the original observed row ID without a current-state condition;
this policy intentionally retains that behavior. Existing individual public CRUD
and bulk cleanup still have their own authorization and phase owners.
