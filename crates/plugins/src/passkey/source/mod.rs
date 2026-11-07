//! Better Auth ceremony policy layered on registry `WebAuthn` protocol/crypto types.
//! Registry code supplies protocol types. These extensions retain
//! original signed bytes and the persisted credential format. See README.md.
mod attestation;
pub(super) mod credential;
pub(super) mod crypto;
pub(super) mod data;
pub(super) mod policy;
mod tpm;

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
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
    fn rsa_registration_retains_exponent_and_authenticates() {
        let fixture = fixture();
        let verifier = verifier(&fixture, true);
        let registration: RegisterPublicKeyCredential =
            serde_json::from_value(fixture["rsa"]["registration"].clone()).unwrap();
        let mut key = verifier
            .register_credential(&registration, &registration_state(&fixture, &verifier))
            .unwrap();
        let original_key = serde_json::to_value(&key.cred.cred).unwrap();
        assert_eq!(original_key["key"]["RSA"]["e"], json!([3]));
        let authentication: PublicKeyCredential =
            serde_json::from_value(fixture["rsa"]["authentication"].clone()).unwrap();
        let state = authentication_state(&fixture, &verifier);
        let result = verifier
            .authenticate_credential(&authentication, &state, &key.cred)
            .unwrap();
        assert_eq!(result.cred_id(), key.cred_id());
        assert_eq!(key.update_credential(&result), Some(true));
        let updated = serde_json::to_value(&key).unwrap();
        assert_eq!(updated["cred"]["cred"], original_key);
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
            original_key
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(enrolled.cred_id().as_ref()),
            fixture["rsa"]["registration"]["id"]
        );
    }
}

// LCOV_EXCL_STOP

use base64urlsafedata::HumanBinaryData;
use credential::{Credential, Passkey};
use crypto::COSEKey;
use data::AttestationObject;
use policy::SourcePolicy;
use serde::Deserialize;
use std::ops::Deref;
use url::Url;
use webauthn_rs_core::{
    WebauthnCore,
    crypto::compute_sha256,
    error::WebauthnError,
    proto::{
        AttestationFormat, AttestationMetadata, Authentication, AuthenticationResult,
        AuthenticationState, COSEAlgorithm, CredentialID, ExtnState, ParsedAttestation,
        ParsedAttestationData, PublicKeyCredential, RegisterPublicKeyCredential,
        RegisteredExtensions, Registration, RegistrationState, RequestRegistrationExtensions,
        UserVerificationPolicy,
    },
};

pub(super) struct Verifier {
    core: WebauthnCore,
    rp_id_hash: [u8; 32],
    origin: Url,
    policy: SourcePolicy,
}

impl Deref for Verifier {
    type Target = WebauthnCore;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

// State serialization is already our persisted contract, pinned to registry
// 0.5.4. Deserialize the policy the issuer actually stored, never client claims.
#[derive(Deserialize)]
struct RegistrationPolicy {
    policy: UserVerificationPolicy,
    exclude_credentials: Vec<CredentialID>,
    challenge: HumanBinaryData,
    credential_algorithms: Vec<COSEAlgorithm>,
    extensions: RequestRegistrationExtensions,
    allow_synchronised_authenticators: bool,
}
#[derive(Deserialize)]
struct AuthenticationPolicy {
    policy: UserVerificationPolicy,
    challenge: HumanBinaryData,
    appid: Option<String>,
}

impl Verifier {
    pub(super) fn new(core: WebauthnCore, rp_id: &str, origin: Url, policy: SourcePolicy) -> Self {
        Self {
            core,
            rp_id_hash: compute_sha256(rp_id.as_bytes()),
            origin,
            policy,
        }
    }
    pub(super) fn with_source_policy(mut self, policy: SourcePolicy) -> Self {
        self.policy = policy;
        self
    }

    pub(super) fn register_credential(
        &self,
        registration: &RegisterPublicKeyCredential,
        state: &RegistrationState,
    ) -> Result<Passkey, WebauthnError> {
        let state: RegistrationPolicy = serde_json::from_value(serde_json::to_value(state)?)?;
        let client = policy::client_data(
            registration.response.client_data_json.as_ref(),
            "not-supported",
        )?;
        if client.type_ != "webauthn.create" {
            return Err(WebauthnError::InvalidClientDataType);
        }
        if client.challenge.as_slice() != state.challenge.as_slice() {
            return Err(WebauthnError::MismatchedChallenge);
        }
        if client.origin != self.origin {
            return Err(WebauthnError::InvalidRPOrigin);
        }
        let object = AttestationObject::<Registration>::from_source(
            registration.response.attestation_object.as_ref(),
        )?;
        let data = &object.auth_data;
        if data.rp_id_hash != self.rp_id_hash {
            return Err(WebauthnError::InvalidRPIDHash);
        }
        if !data.user_present {
            return Err(WebauthnError::UserNotPresent);
        }
        if state.policy == UserVerificationPolicy::Required && !data.user_verified {
            return Err(WebauthnError::UserNotVerified);
        }
        let format = AttestationFormat::try_from(object.fmt.as_str())
            .map_err(|()| WebauthnError::AttestationNotSupported)?;
        let acd = data
            .acd
            .as_ref()
            .ok_or(WebauthnError::MissingAttestationCredentialData)?;
        SourcePolicy::check_leaf(&object)?;
        let hash = compute_sha256(registration.response.client_data_json.as_ref());
        let (attested, metadata) = match format {
            AttestationFormat::None => (ParsedAttestationData::None, AttestationMetadata::None),
            AttestationFormat::Packed => attestation::packed(acd, &object, &hash)?,
            AttestationFormat::Tpm => tpm::verify(acd, &object, &hash)?,
            AttestationFormat::FIDOU2F => (
                SourcePolicy::verify_u2f(acd, &object, &hash)?,
                AttestationMetadata::None,
            ),
            AttestationFormat::AppleAnonymous => SourcePolicy::verify_apple(acd, &object, &hash)?,
            AttestationFormat::AndroidKey => self.policy.verify_android_key(acd, &object, &hash)?,
            AttestationFormat::AndroidSafetyNet => self.policy.verify_safetynet(&object, &hash)?,
        };
        self.policy.verify_path(&object.fmt, &attested)?;
        let key = COSEKey::try_from(&acd.credential_pk)?;
        if !state.credential_algorithms.contains(&key.type_) {
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }
        if (!state.allow_synchronised_authenticators && data.backup_eligible)
            || (data.backup_state && !data.backup_eligible)
        {
            return Err(WebauthnError::CredentialMayNotBeHardwareBound);
        }
        if state.exclude_credentials.contains(&acd.credential_id) {
            return Err(WebauthnError::CredentialAlteredAlgFromRequest);
        }
        Ok(Passkey {
            cred: Credential {
                cred_id: acd.credential_id.clone(),
                cred: key,
                counter: data.counter,
                transports: if matches!(format, AttestationFormat::Packed | AttestationFormat::Tpm)
                {
                    registration.response.transports.clone()
                } else {
                    None
                },
                user_verified: data.user_verified,
                backup_eligible: data.backup_eligible,
                backup_state: data.backup_state,
                registration_policy: state.policy,
                extensions: RegisteredExtensions {
                    cred_protect: if state.extensions.cred_protect.is_some() {
                        ExtnState::Ignored
                    } else {
                        ExtnState::NotRequested
                    },
                    hmac_create_secret: if state.extensions.hmac_create_secret.is_some() {
                        ExtnState::Ignored
                    } else {
                        ExtnState::NotRequested
                    },
                    appid: ExtnState::NotRequested,
                    cred_props: match (
                        registration.extensions.cred_props.as_ref(),
                        state.extensions.cred_props.is_some(),
                    ) {
                        (Some(value), _) => ExtnState::Unsigned(value.clone()),
                        (None, true) => ExtnState::Ignored,
                        (None, false) => ExtnState::NotRequested,
                    },
                },
                attestation: ParsedAttestation {
                    data: attested,
                    metadata,
                },
                attestation_format: format,
            },
        })
    }

    pub(super) fn authenticate_credential(
        &self,
        authentication: &PublicKeyCredential,
        state: &AuthenticationState,
        credential: &Credential,
    ) -> Result<AuthenticationResult, WebauthnError> {
        if authentication.raw_id.as_slice() != credential.cred_id.as_slice() {
            return Err(WebauthnError::CredentialNotFound);
        }
        let state: AuthenticationPolicy = serde_json::from_value(serde_json::to_value(state)?)?;
        let client = policy::client_data(
            authentication.response.client_data_json.as_ref(),
            "notSupported",
        )?;
        if client.type_ != "webauthn.get" {
            return Err(WebauthnError::InvalidClientDataType);
        }
        if client.challenge.as_slice() != state.challenge.as_slice() {
            return Err(WebauthnError::MismatchedChallenge);
        }
        if client.origin != self.origin {
            return Err(WebauthnError::InvalidRPOrigin);
        }
        let bytes = authentication.response.authenticator_data.as_ref();
        let data = data::AuthenticatorData::<Authentication>::from_source(bytes)?;
        let appid_hash = if authentication.extensions.appid.unwrap_or(false) {
            state.appid.map(|id| compute_sha256(id.as_bytes()))
        } else {
            None
        };
        if data.rp_id_hash != self.rp_id_hash && Some(data.rp_id_hash) != appid_hash {
            return Err(WebauthnError::InvalidRPIDHash);
        }
        if !data.user_present {
            return Err(WebauthnError::UserNotPresent);
        }
        if state.policy == UserVerificationPolicy::Required && !data.user_verified {
            return Err(WebauthnError::UserNotVerified);
        }
        if data.backup_state && !data.backup_eligible {
            return Err(WebauthnError::CredentialMayNotBeHardwareBound);
        }
        let mut signed = bytes.to_vec();
        signed.extend_from_slice(&compute_sha256(
            authentication.response.client_data_json.as_ref(),
        ));
        if !credential
            .cred
            .verify_signature(authentication.response.signature.as_ref(), &signed)?
        {
            return Err(WebauthnError::AuthenticationFailure);
        }
        if (data.counter > 0 || credential.counter > 0) && data.counter <= credential.counter {
            return Err(WebauthnError::CredentialPossibleCompromise);
        }
        // AuthenticationResult exposes its established serialization contract,
        // but no constructor. Preserve the public callback type across migration.
        serde_json::from_value(serde_json::json!({
            "cred_id":credential.cred_id,
            "needs_update":data.counter > credential.counter || data.backup_state != credential.backup_state,
            "user_verified":data.user_verified,"backup_state":data.backup_state,
            "backup_eligible":data.backup_eligible,"counter":data.counter,"extensions":{},
        })).map_err(Into::into)
    }
}
