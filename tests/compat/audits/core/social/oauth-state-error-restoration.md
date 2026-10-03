# OAuth cookie nonce rejection restores the saved error callback

Pinned reference: fresh npm `better-auth@1.7.6`; native baseline `556f30a7`.

The production gap was in the cookie-strategy nonce rejection after successful decryption. Native discarded the decoded `errorURL`; published `parseGenericState` attaches it to `StateError`, and `parseState` uses it for the redirect. The native repair uses the existing redirect builder and returns before clearing cookies, deleting state, dispatching a provider, or recovering authenticated server context.

## Focused proof

The regression issues state through `AuthBuilder` / `handle_request`, then sends the intact cookie with a foreign callback nonce. It instantiates the concrete bundled SQLx and SeaORM SQLite schemas and stores; this is compile-time adapter selection, with no environment label standing in for another store.

Both regressions failed on the baseline with native `Location: http://localhost:42619/api/auth/error?error=state_mismatch`. Both pass after repair. Each also checks the database strategy: mismatch preserves the actual state row, and the subsequent correct request admits the original flow, returns its saved `no_code` error, clears the cookie, and removes the row. Cookie ciphertext tampering cannot recover the saved redirect.

Commands (only the named tests run):

```sh
cargo test --locked --no-default-features --features rustls,sqlx --test integration cookie_nonce_rejection_restores_saved_error -- --nocapture
cargo test --locked --no-default-features --features rustls,sqlx,axum --test integration consumed_oauth_context_requires_actual_capture_and_a_proof_bound_to_the_issued_state -- --nocapture
cargo clippy --locked -p better-auth-api --lib --no-default-features --features rustls -- -D warnings
```

## Published decoder observations

Raw issued native cookies were passed to the fresh published `parseGenericState`, using the published Better Call `createInternalContext` cookie parser/signature verifier. Cookie ciphertext was also passed directly to published `symmetricDecrypt`. Database payloads came from each real native store; the controlled Source storage interface supplied those captured bytes to the published parser. The Source interface records find/delete effects; it does not claim a Source database integration test.

All four receipts decoded. Cookie state used `better-auth.oauth_state`, Max-Age=600, and no state row. Database state used `better-auth.state`, Max-Age=300, with a bare state identifier and an intact saved payload. The tested attributes were Path=/, HttpOnly, SameSite=Lax.

The exact Source rejection Location was `/saved-error?flow=original&error=state_mismatch`. The exact repaired native Location was `http://localhost:42619/saved-error?flow=original&error=state_mismatch`. The existing native redirect builder resolves relative targets; these raw headers differ. This change restores the saved target without claiming literal relative/absolute header equivalence.

Raw receipts, decoded payloads, and Source rejection effects follow. Random nonces and timestamps are observations, not golden values.

```json
[
  {
    "adapter": "seaorm",
    "strategy": "Cookie",
    "native": {
      "state": "Floed4dhxCMTbGSWf4m7DfVrlb1cQyOA",
      "cookie": "better-auth.oauth_state=7bef061074c864ad449a5c91ee7f758d19955f419be9fb6848a7640d85c91e03cb1b2b2b8341557bea40369ce694f006c0248ad7ca9300a2b8272d2c181cc43fa1560fbe67359791c31f944f5d302c06c72fe58ba5c6af24e652ca7141cd13ca99d42c793c554c65c91fcf7b897f80897cf628601654b32a73bf8410ea25533cbcbeb5ebd290ffe9b08ffd3a30fd4b0526f5ab1ce760fc3a1292cf4ae4ff8534a9cf57404158a2783941e637c6d3dbf5bf1b86cfa7455df738072f307e6a828f37a91587d1fdf007b70159dc474bbf0ab018217533405d1e6ab472626217e1e75be171794d5eae522edd7c9dd12f4cba4f761aeef9e17457a0490a66c968a03ba9f6418b1df141c10404b75a209dc45c89e470aca981b9a4662826763287827c8d8f9077a926c45d9b326df773b58e91497d592c360ffe0e03b0f0b108cbba826d29dc9193e63310; Max-Age=600; Path=/; HttpOnly; SameSite=Lax",
      "rowValue": null,
      "rejectedLocation": "http://localhost:42619/saved-error?flow=original&error=state_mismatch",
      "admittedLocation": "http://localhost:42619/saved-error?flow=original&error=no_code",
      "clearedCookies": [
        "better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
      ]
    },
    "decoded": {
      "callbackURL": "/completed",
      "codeVerifier": "no58E6Y_tobdx9NJYIcUOCeStRiVWDsW95b0N8wfigMc0_sRKnFb4eN7HzqVl1ObyDb2DTzO8cbA_0GJCU9M7QGX6-2OT7E8ziP18qgA9k8o4tx0TpsBlYDY3yOipN64",
      "errorURL": "/saved-error?flow=original",
      "expiresAt": 1791056184788,
      "oauthState": "Floed4dhxCMTbGSWf4m7DfVrlb1cQyOA"
    },
    "sourceRejectionLocation": "/saved-error?flow=original&error=state_mismatch",
    "sourceRejectEffects": []
  },
  {
    "adapter": "seaorm",
    "strategy": "Database",
    "native": {
      "state": "aqR5S5g75G_b7AnjI2CRnQL9PC_nE9me",
      "cookie": "better-auth.state=aqR5S5g75G_b7AnjI2CRnQL9PC_nE9me.1OCL1Bn%2B0%2Fci4wIBb7X%2FOPYg8q2h%2F3nFJEx3LltZYl0%3D; Max-Age=300; Path=/; HttpOnly; SameSite=Lax",
      "rowValue": "{\"callbackURL\":\"/completed\",\"codeVerifier\":\"OIWHsjkNBSBfvLKIsUwXzPMgeqygYERxG2yAgHx9F-4HyZD5jiBdIp-J-c2Px7uNJxy40-dyuwvf6RNtDD6UTPztgPjGZEaRNJqtnKNBBr8BdKPWdYQX4yWzEpYGUik_\",\"errorURL\":\"/saved-error?flow=original\",\"expiresAt\":1791056184797,\"oauthState\":\"aqR5S5g75G_b7AnjI2CRnQL9PC_nE9me\"}",
      "rejectedLocation": "http://localhost:42619/saved-error?flow=original&error=state_mismatch",
      "admittedLocation": "http://localhost:42619/saved-error?flow=original&error=no_code",
      "clearedCookies": [
        "better-auth.state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
      ]
    },
    "decoded": {
      "callbackURL": "/completed",
      "codeVerifier": "OIWHsjkNBSBfvLKIsUwXzPMgeqygYERxG2yAgHx9F-4HyZD5jiBdIp-J-c2Px7uNJxy40-dyuwvf6RNtDD6UTPztgPjGZEaRNJqtnKNBBr8BdKPWdYQX4yWzEpYGUik_",
      "errorURL": "/saved-error?flow=original",
      "expiresAt": 1791056184797,
      "oauthState": "aqR5S5g75G_b7AnjI2CRnQL9PC_nE9me"
    },
    "sourceRejectionLocation": "/saved-error?flow=original&error=state_mismatch",
    "sourceRejectEffects": [
      [
        "find",
        "aqR5S5g75G_b7AnjI2CRnQL9PC_nE9me"
      ]
    ]
  },
  {
    "adapter": "sqlx",
    "strategy": "Cookie",
    "native": {
      "state": "DuAC4gjxmutJUYHVKb-c0vbgVl1xJqCb",
      "cookie": "better-auth.oauth_state=afafa59f3d02fba2912165b3a5ced35401278ff9ae13a3636f035cf09cea7a468837be81b3550d6b257eefcbdcaddabeed2a3e39f2e4deea34e35061d992011de641ca96b33cdec8ce516dda2377ab4f085ba7a13bed5ca4c8fa192341f581898fd6e8add12b99e5fbf78aec54ab35d37a61c167c208ec7ed09e6d652b9a46743829fb9e259f09eb8820405ac2db372fd8a4c7ea3359f40b2a93fe9b3e532169c8d3b9b028d5dd44b648243caa412ad996e828e7766ef7ab885f81c6f1e567a506f3ba0298c6e62e1f6ea52c8723e6aea1b40b3bf3709dea191d1249f9b8c9c72bd9be4d98d9d47a93c7dc38403dbd863c13ef999b7ba03b94d3ba9240baaf511791eac91f2c4a0be41b6e8cb723dff6e6252c7025c392abdf7bc2183dee3248fe6676772faf7ecfee199baa603673e11eccef1337db642f794b951a1fa6fd9909270642e210409f; Max-Age=600; Path=/; HttpOnly; SameSite=Lax",
      "rowValue": null,
      "rejectedLocation": "http://localhost:42619/saved-error?flow=original&error=state_mismatch",
      "admittedLocation": "http://localhost:42619/saved-error?flow=original&error=no_code",
      "clearedCookies": [
        "better-auth.oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
      ]
    },
    "decoded": {
      "callbackURL": "/completed",
      "codeVerifier": "TiYGhjLlrHDWp_Dq9f9NINRWmpjyq_rgcQ5jUB04KrvmS0zkVND4ijbzmYbICLwLCbnxiRfkXHL-IL15Bw52qS_50fmO2MH4Vrd1uiUUwKC_BfiPkTzbvD0FKU2ECi76",
      "errorURL": "/saved-error?flow=original",
      "expiresAt": 1791056184782,
      "oauthState": "DuAC4gjxmutJUYHVKb-c0vbgVl1xJqCb"
    },
    "sourceRejectionLocation": "/saved-error?flow=original&error=state_mismatch",
    "sourceRejectEffects": []
  },
  {
    "adapter": "sqlx",
    "strategy": "Database",
    "native": {
      "state": "XD_YzQMyAzHTMXhYxY37LaIs8_i5s4v1",
      "cookie": "better-auth.state=XD_YzQMyAzHTMXhYxY37LaIs8_i5s4v1.3I4J8OYc0WaMHKWl17y8oUq1MB0zmlFDpeW3iNaOIEE%3D; Max-Age=300; Path=/; HttpOnly; SameSite=Lax",
      "rowValue": "{\"callbackURL\":\"/completed\",\"codeVerifier\":\"HwD0G1aPgOhkUmoFbML1C-wo-sfpqD0XdIGA-CwE-wtMAZxJvpDGYIOZrcRGfX5FIkId5i3x0ggqIbWAD23B9JMfuZXBwRoL-Q0UUFsP2RvJKW6xo7EVjQ5HwBPAsyOA\",\"errorURL\":\"/saved-error?flow=original\",\"expiresAt\":1791056184790,\"oauthState\":\"XD_YzQMyAzHTMXhYxY37LaIs8_i5s4v1\"}",
      "rejectedLocation": "http://localhost:42619/saved-error?flow=original&error=state_mismatch",
      "admittedLocation": "http://localhost:42619/saved-error?flow=original&error=no_code",
      "clearedCookies": [
        "better-auth.state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
      ]
    },
    "decoded": {
      "callbackURL": "/completed",
      "codeVerifier": "HwD0G1aPgOhkUmoFbML1C-wo-sfpqD0XdIGA-CwE-wtMAZxJvpDGYIOZrcRGfX5FIkId5i3x0ggqIbWAD23B9JMfuZXBwRoL-Q0UUFsP2RvJKW6xo7EVjQ5HwBPAsyOA",
      "errorURL": "/saved-error?flow=original",
      "expiresAt": 1791056184790,
      "oauthState": "XD_YzQMyAzHTMXhYxY37LaIs8_i5s4v1"
    },
    "sourceRejectionLocation": "/saved-error?flow=original&error=state_mismatch",
    "sourceRejectEffects": [
      [
        "find",
        "XD_YzQMyAzHTMXhYxY37LaIs8_i5s4v1"
      ]
    ]
  }
]
```

## Remaining bounds

This closes one missing restoration behavior within #189. It does not close the whole issue or establish every codec, attribute, key-rotation, cookie-less restoration, duplicate-row selection, expiry, concurrency, provider/link-owner, anonymous/proxy/popup, or replay bound. Cryptography, raw nonce comparison, saved link data, ID-token nonce policy, and server-only context authentication are unchanged. The existing authenticated-context owner regression is a separate focused check.

Production API strict Clippy passed. Strict Clippy on the integration target was attempted and is blocked by pre-existing warnings in unrelated test modules; no whole-target lint pass is claimed. The new fixture uses the adjacent tests’ explicit fail-fast `unwrap_used` allowance.

GitHub Actions were disabled (`enabled:false`); no hosted CI, full suite, coverage gate, or `devenv test` result is claimed. Local detailed logs and the published helper driver are retained in `/tmp/state189-evidence` after resource cleanup.
