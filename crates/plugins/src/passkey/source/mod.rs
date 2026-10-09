//! Better Auth ceremony policy layered on registry `WebAuthn` protocol/crypto types.
//! Registry code owns options and legacy ceremonies. These extensions retain
//! original signed bytes and the persisted credential format. See README.md.
mod attestation;
pub(super) mod credential;
pub(super) mod crypto;
pub(super) mod data;
pub(super) mod policy;
mod tpm;

// LCOV_EXCL_START
#[cfg(test)]
mod tests;
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
        self.policy.check_leaf(&object)?;
        let hash = compute_sha256(registration.response.client_data_json.as_ref());
        let (attested, metadata) = match format {
            AttestationFormat::None => (ParsedAttestationData::None, AttestationMetadata::None),
            AttestationFormat::Packed => attestation::packed(acd, &object, &hash)?,
            AttestationFormat::Tpm => tpm::verify(acd, &object, &hash)?,
            AttestationFormat::FIDOU2F => (
                self.policy.verify_u2f(acd, &object, &hash)?,
                AttestationMetadata::None,
            ),
            AttestationFormat::AppleAnonymous => self.policy.verify_apple(acd, &object, &hash)?,
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
