//! Existing credential codec, retaining the fork's variable-length RSA exponent.
//! MPL-2.0; see LICENSE.md. Registry fields are reused except for the extended key.
use super::crypto::COSEKey;
use serde::{Deserialize, Serialize};
use webauthn_rs_core::{
    error::WebauthnError,
    proto::{
        AttestationFormat, AuthenticationResult, AuthenticatorTransport, Counter, CredentialID,
        ParsedAttestation, RegisteredExtensions, UserVerificationPolicy,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::passkey) struct Credential {
    pub cred_id: CredentialID,
    pub cred: COSEKey,
    pub counter: Counter,
    pub transports: Option<Vec<AuthenticatorTransport>>,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub registration_policy: UserVerificationPolicy,
    pub extensions: RegisteredExtensions,
    pub attestation: ParsedAttestation,
    pub attestation_format: AttestationFormat,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::passkey) struct Passkey {
    pub cred: Credential,
}
impl Passkey {
    pub(in crate::passkey) fn cred_id(&self) -> &CredentialID {
        &self.cred.cred_id
    }
    pub(in crate::passkey) fn to_registry(
        &self,
    ) -> Result<webauthn_rs::prelude::Passkey, WebauthnError> {
        // Legacy ceremonies were issued by the registry verifier. Its serialized
        // format remains the boundary; new Source ceremonies never take this path.
        serde_json::from_value(serde_json::to_value(self)?).map_err(Into::into)
    }
    pub(in crate::passkey) fn update_credential(
        &mut self,
        result: &AuthenticationResult,
    ) -> Option<bool> {
        if result.cred_id() != self.cred_id() {
            return None;
        }
        let mut changed = false;
        if result.counter() > self.cred.counter {
            self.cred.counter = result.counter();
            changed = true;
        }
        if result.backup_state() != self.cred.backup_state {
            self.cred.backup_state = result.backup_state();
            changed = true;
        }
        if result.backup_eligible() && !self.cred.backup_eligible {
            self.cred.backup_eligible = true;
            changed = true;
        }
        Some(changed)
    }
}
impl From<webauthn_rs::prelude::Passkey> for Passkey {
    fn from(passkey: webauthn_rs::prelude::Passkey) -> Self {
        let key = webauthn_rs_core::proto::Credential::from(passkey);
        Self {
            cred: Credential {
                cred_id: key.cred_id,
                cred: key.cred.into(),
                counter: key.counter,
                transports: key.transports,
                user_verified: key.user_verified,
                backup_eligible: key.backup_eligible,
                backup_state: key.backup_state,
                registration_policy: key.registration_policy,
                extensions: key.extensions,
                attestation: key.attestation,
                attestation_format: key.attestation_format,
            },
        }
    }
}
