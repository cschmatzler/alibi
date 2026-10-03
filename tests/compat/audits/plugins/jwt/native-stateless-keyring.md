# Native NoDB keyring portion of #172

`StatelessStore` previously inherited all three unsupported `JwkStore` methods.
The real `/jwks` regression returned 501 with `JWKS storage is not supported by
this store`. The repair keeps typed JWK rows behind the existing instance lock;
it does not introduce SQL models or derive key authority from cookie caches.
Creation preserves supplied IDs and metadata, generates missing IDs, rejects
primary-ID collisions, and retains encrypted private bytes without interpreting
them. A fresh store has no keys. SQL adapters are unchanged.

The primary regression owner is `tests/integration/storage/native_jwks.rs`.
Existing SQL row tests cover raw persistence but cannot catch a missing native
implementation or handler lifecycle. The new test exercises public JWKS,
signup and token handlers plus trusted sign/verify endpoints on SQLx SQLite,
SeaORM SQLite and true NoDB. It checks unauthorized issuance, encrypted private
records, public-key-only responses, JWT key-ID reuse and rotation, public
retirement, retained verification, secret mismatch, and restart isolation.
These protect credible failures in provisioning, selection, secret authority
and instance lifetime through existing public APIs; no production test seam
was added.

A direct probe of the authentic published BetterAuth 1.7.6 package exercised the
same HTTP sequence and its server APIs. The actual memory adapter was shared
only for the secret and grace-period controls. All three native workflows
matched the source HTTP statuses and lifecycle effects. Signing expiry prevents
reuse, public JWKS applies expiry plus grace, and server verification still
accepts a token using a retained row after public retirement. Public retirement
does not delete the row. A fresh NoDB instance cannot verify the old token,
even after provisioning a new key. SQL reconstruction still verifies it.
The grace control uses zero seconds after actual signing expiry.

Validation:

- `RUST_MIN_STACK=16777216 cargo test --test integration --features seaorm storage::native_jwks -- --nocapture`: 3 passed.
- `cargo clippy -p better-auth-core --lib --locked -- -D warnings`: passed after removing one pre-existing redundant `must_use` annotation on a `Result` accessor.
- Targeted rustfmt and `git diff --check`: passed.
- Security self-review traced token session admission, private-key decryption,
  public serialization and the instance-local store lock; no new authorization
  or data-exposure defect found.

Raw source/native responses, baseline and final logs, the source probe and
comparison output are retained in `/tmp/jwk172-evidence`. The first debug run
also hit the default test-thread stack limit on SQLx; the final run used the
larger stack above. PostgreSQL, the full suite and CI were not run. Actions are
disabled. The package pin, comparator allowances and existing exclusions were
unchanged. Organization and other remaining #172 scope stay open.
