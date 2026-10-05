# Registry migration vectors

`registry-migration.json` contains independent Node crypto/OpenSSL signatures
generated with the existing `CertificateDevice` in
`tests/compat/client-tests/tests/plugins/passkey/certificate-device.ts`.
The fixtures require no JavaScript runtime when tests run.

The public test CA and real leaf certificates cover packed, U2F, Android Key,
Apple, TPM and SafetyNet attestations. Client data deliberately includes
`crossOrigin: true` where supported. SafetyNet uses its existing
`timestamp-omitted` fixture mode, whose pinned policy has no wall-clock freshness
bound; its certificate is still validated. Test certificates expire in 2046.

The RSA fixture uses a genuine SHA-384 signature and public exponent 3. Its
`storedCredential` was serialized by the old `better-auth-webauthn-rs` fork
before removal, using the public credential types and the vector's COSE key.
Registry `Passkey` deserialization rejects that one-byte exponent. The native
test must read those historical bytes, verify the independently signed assertion,
update its counter, preserve the key and reject a modified signature/replay.

The verifier unit boundary supplies the recorded server challenge. Handler tests
separately exercise freshly generated challenges and delivered cookies.
