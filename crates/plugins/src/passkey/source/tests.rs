//! Independent signatures and the pre-migration codec own the adapter boundary.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    reason = "fixed cryptographic vectors must contain their documented fields"
)]
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/passkey/registry-migration.json"
    ))
    .unwrap()
}

fn verifier(fixture: &Value, trusted: bool) -> Verifier {
    let mut policy = SourcePolicy::default();
    let root = if trusted {
        fixture["root"].as_str().unwrap().to_owned()
    } else {
        // A real unrelated CA, not malformed certificate bytes.
        fixture["untrustedRoot"].as_str().unwrap().to_owned()
    };
    for format in [
        "packed",
        "fido-u2f",
        "tpm",
        "apple",
        "android-key",
        "android-safetynet",
    ] {
        _ = policy.roots.insert(format.into(), vec![root.clone()]);
    }
    let origin = Url::parse(fixture["origin"].as_str().unwrap()).unwrap();
    let rp = fixture["rpId"].as_str().unwrap();
    let core = WebauthnCore::new_unsafe_experts_only(
        "Native migration",
        rp,
        vec![origin.clone()],
        std::time::Duration::from_secs(60),
        Some(false),
        Some(false),
    );
    Verifier::new(core, rp, origin, policy)
}

fn registration_state(fixture: &Value, verifier: &Verifier) -> RegistrationState {
    let builder = verifier
        .new_challenge_register_builder(b"fixture-owner", "Owner", "Owner")
        .unwrap()
        .credential_algorithms(vec![COSEAlgorithm::ES256, COSEAlgorithm::RS384])
        .user_verification_policy(UserVerificationPolicy::Preferred);
    let (_, state) = verifier.generate_challenge_register(builder).unwrap();
    let mut state = serde_json::to_value(state).unwrap();
    // This unit boundary verifies a previously issued ceremony. Fix only the
    // persisted challenge to the independent signer's vector, not its verdict.
    state["challenge"] = fixture["challenge"].clone();
    serde_json::from_value(state).unwrap()
}

fn authentication_state(fixture: &Value, verifier: &Verifier) -> AuthenticationState {
    let builder = verifier
        .new_challenge_authenticate_builder(vec![], Some(UserVerificationPolicy::Preferred))
        .unwrap();
    let (_, state) = verifier.generate_challenge_authenticate(builder).unwrap();
    let mut state = serde_json::to_value(state).unwrap();
    state["challenge"] = fixture["challenge"].clone();
    serde_json::from_value(state).unwrap()
}

#[test]
fn certificate_formats_verify_original_bytes_and_configured_trust() {
    let fixture = fixture();
    let verifier = verifier(&fixture, true);
    let untrusted = self::verifier(&fixture, false);
    let state = registration_state(&fixture, &verifier);
    for case in fixture["cases"].as_array().unwrap() {
        let registration: RegisterPublicKeyCredential =
            serde_json::from_value(case["registration"].clone()).unwrap();
        let key = verifier
            .register_credential(&registration, &state)
            .unwrap_or_else(|error| panic!("{}: {error:?}", case["format"]));
        assert_eq!(key.cred_id().as_slice(), registration.raw_id.as_slice());
        assert!(!key.cred.user_verified, "UV-absent enrollment is permitted");
        assert!(
            untrusted
                .register_credential(&registration, &state)
                .is_err(),
            "{}: foreign root",
            case["format"]
        );

        // Keep policy fields intact; changing only a signed opaque field must
        // invalidate the proof. A parser that re-serializes client data fails.
        let mut tampered = registration.clone();
        let mut client: Value =
            serde_json::from_slice(tampered.response.client_data_json.as_ref()).unwrap();
        client["opaque"] = json!("modified after signing");
        tampered.response.client_data_json = serde_json::to_vec(&client).unwrap().into();
        assert!(
            verifier.register_credential(&tampered, &state).is_err(),
            "{}: signed bytes",
            case["format"]
        );

        let authentication: PublicKeyCredential =
            serde_json::from_value(case["authentication"].clone()).unwrap();
        let result = verifier
            .authenticate_credential(
                &authentication,
                &authentication_state(&fixture, &verifier),
                &key.cred,
            )
            .unwrap();
        assert_eq!(result.cred_id(), key.cred_id());
        assert_eq!(result.counter(), 1);
    }
}

#[test]
fn pre_migration_rsa_credential_retains_exponent_and_authenticates() {
    let fixture = fixture();
    let verifier = verifier(&fixture, true);
    // These JSON bytes were serialized by the old fork before removing it.
    let persisted = &fixture["rsa"]["storedCredential"];
    assert_eq!(persisted["cred"]["cred"]["key"]["RSA"]["e"], json!([3]));
    assert!(serde_json::from_value::<webauthn_rs::prelude::Passkey>(persisted.clone()).is_err());
    let crate::passkey::raw_none::StoredCredential::Core(mut key) =
        serde_json::from_value(persisted.clone()).unwrap()
    else {
        panic!("existing core codec")
    };
    let authentication: PublicKeyCredential =
        serde_json::from_value(fixture["rsa"]["authentication"].clone()).unwrap();
    let state = authentication_state(&fixture, &verifier);
    let result = verifier
        .authenticate_credential(&authentication, &state, &key.cred)
        .unwrap();
    assert_eq!(result.cred_id(), key.cred_id());
    assert_eq!(key.update_credential(&result), Some(true));
    let updated = serde_json::to_value(&key).unwrap();
    assert_eq!(updated["cred"]["cred"], persisted["cred"]["cred"]);
    assert_eq!(updated["cred"]["counter"], 1);
    assert!(
        verifier
            .authenticate_credential(&authentication, &state, &key.cred)
            .is_err(),
        "counter replay"
    );
    let mut bad = authentication;
    let mut signature = bad.response.signature.as_ref().to_vec();
    signature[0] ^= 1;
    bad.response.signature = signature.into();
    key.cred.counter = 0;
    assert!(matches!(
        verifier.authenticate_credential(&bad, &state, &key.cred),
        Err(WebauthnError::AuthenticationFailure)
    ));

    let registration: RegisterPublicKeyCredential =
        serde_json::from_value(fixture["rsa"]["registration"].clone()).unwrap();
    let enrolled = verifier
        .register_credential(&registration, &registration_state(&fixture, &verifier))
        .unwrap();
    assert_eq!(
        serde_json::to_value(&enrolled.cred.cred).unwrap(),
        persisted["cred"]["cred"]
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(enrolled.cred_id().as_ref()),
        fixture["rsa"]["registration"]["id"]
    );
}
