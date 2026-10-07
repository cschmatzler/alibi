use super::PasskeyConfig;
use super::source::{
    Verifier, credential::Passkey as WebauthnPasskey, crypto::COSEKeyType, data::AuthenticatorData,
};
use alibi_core::{AuthConfig, AuthError, AuthRequest, AuthResult};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::seq::IndexedRandom as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, CredentialID, DiscoverableAuthentication,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};
use webauthn_rs_core::{
    WebauthnCore,
    error::WebauthnError,
    proto::{
        Authentication, AuthenticationResult, AuthenticationState, EDDSACurve, Registration,
        RegistrationState, UserVerificationPolicy,
    },
};

const OPTIONS_TIMEOUT_MS: u64 = 60_000;

const GENERATED_USER_ID_LENGTH: usize = 32;

const GENERATED_USER_ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug)]
pub(super) struct RegisteredPasskeyMetadata {
    pub public_key: String,
    pub aaguid: Option<String>,
}

#[derive(Debug)]
pub(super) struct PasskeySnapshot {
    pub serialized: String,
    pub counter: u64,
    pub backed_up: bool,
    pub backup_eligible: bool,
}

impl PasskeySnapshot {
    pub(super) const fn device_type(&self) -> &'static str {
        if self.backup_eligible {
            "multiDevice"
        } else {
            "singleDevice"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::plugins) struct StoredRegistrationState {
    pub user_id: String,
    #[serde(default)]
    pub user: Option<super::PasskeyRegistrationUser>,
    #[serde(default)]
    pub context: Option<String>,
    pub state: StoredRegistrationVerifier,
}

/// The legacy state shape stays readable for already-issued challenges.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub(in crate::plugins) enum StoredRegistrationVerifier {
    Source(StoredCoreRegistrationState),
    Legacy(webauthn_rs::prelude::PasskeyRegistration),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(in crate::plugins) enum StoredCoreRegistrationState {
    Core {
        state: RegistrationState,
    },
    CoreRawNone {
        state: RegistrationState,
        policy: super::raw_none::RawNonePolicy,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(in crate::plugins) enum StoredAuthenticationState {
    CoreRaw {
        state: AuthenticationState,
        challenge: String,
    },
    /// Source policy for newly issued ceremonies. Older variants remain readable.
    Core {
        state: AuthenticationState,
    },
    Passkey {
        state: webauthn_rs::prelude::PasskeyAuthentication,
    },
    Discoverable {
        state: DiscoverableAuthentication,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeCookieClaims {
    token: String,
    exp: usize,
    iat: usize,
}

pub(super) fn resolve_origin(config: &PasskeyConfig, req: &AuthRequest) -> Option<String> {
    if config.origin.is_empty() {
        req.headers.get("origin").cloned()
    } else {
        Some(config.origin.clone())
    }
}

pub(super) fn get_cookie_value(req: &AuthRequest, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
    header.split(';').find_map(|cookie| {
        let trimmed = cookie.trim();
        let (cookie_name, cookie_value) = trimmed.split_once('=')?;
        (cookie_name == name).then_some(cookie_value.to_owned())
    })
}

pub(super) fn challenge_cookie_name(auth_config: &AuthConfig, config: &PasskeyConfig) -> String {
    auth_config
        .session
        .cookie_name
        .strip_suffix("session_token")
        .map_or_else(
            || config.web_authn_challenge_cookie.clone(),
            |prefix| format!("{prefix}{}", config.web_authn_challenge_cookie),
        )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn resolve_rp_id(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
) -> AuthResult<String> {
    if config.rp_id.is_empty() {
        Url::parse(&auth_config.base_url)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| AuthError::config("Missing passkey RP ID".to_owned()))
    } else {
        Ok(config.rp_id.clone())
    }
}

/// Core verification for newly issued ceremonies, retaining RP configuration
/// checks and requiring the exact configured origin in the original client data.
///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn build_verification_core(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
    origin: &str,
) -> AuthResult<Verifier> {
    // Retain the high-level builder's RP/origin configuration validation.
    drop(build_webauthn(config, auth_config, origin)?);
    let rp_id = resolve_rp_id(config, auth_config)?;
    let parsed_origin = Url::parse(origin)
        .map_err(|error| AuthError::bad_request(format!("Invalid passkey origin: {error}")))?;
    let mut policy = super::source::policy::SourcePolicy::default();
    if let Some(roots) = &config.attestation_root_certificates {
        policy.roots.extend(roots.clone());
    }
    let core = WebauthnCore::new_unsafe_experts_only(
        &config.rp_name,
        &rp_id,
        vec![parsed_origin.clone()],
        Duration::from_millis(OPTIONS_TIMEOUT_MS),
        Some(false),
        Some(false),
    );
    Ok(Verifier::new(core, &rp_id, parsed_origin, policy))
}

/// Keep certificate URL fetching in the API's configured HTTP/TLS stack.
pub(super) async fn build_registration_core(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
    origin: &str,
    registration: &RegisterPublicKeyCredential,
) -> AuthResult<Verifier> {
    let mut policy = super::source::policy::SourcePolicy::default();
    if let Some(roots) = &config.attestation_root_certificates {
        policy.roots.extend(roots.clone());
    }
    policy
        .check_revocations(
            registration.response.attestation_object.as_ref(),
            |url| async move {
                reqwest::get(url)
                    .await
                    .ok()?
                    .bytes()
                    .await
                    .ok()
                    .map(|bytes| bytes.to_vec())
            },
        )
        .await
        .map_err(|error| AuthError::internal(error.to_string()))?;
    Ok(build_verification_core(config, auth_config, origin)?.with_source_policy(policy))
}

// The pinned verifier uses different legacy spellings in the two ceremonies.
// Validate the original client data without altering the bytes covered by the signature.
fn validate_token_binding(
    client_data: &alibi_core::utils::json::JsValue,
    unsupported_status: &str,
) -> Result<(), WebauthnError> {
    use alibi_core::utils::json::JsValue;

    let Some(binding) = client_data.get("tokenBinding") else {
        return Ok(());
    };
    let truthy = match binding {
        JsValue::Null => false,
        JsValue::Bool(value) => *value,
        JsValue::Number(value) => *value != 0.0 && !value.is_nan(),
        JsValue::String(value) => !value.is_empty(),
        JsValue::Array(_) | JsValue::Object(_) => true,
    };
    if truthy
        && !binding
            .get("status")
            .and_then(JsValue::as_str)
            .is_some_and(|status| {
                matches!(status, "present" | "supported") || status == unsupported_status
            })
    {
        return Err(WebauthnError::ParseNOMFailure);
    }
    Ok(())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn finish_core_registration(
    core: &Verifier,
    registration: &RegisterPublicKeyCredential,
    state: &RegistrationState,
    origin: &str,
) -> Result<WebauthnPasskey, WebauthnError> {
    let client_data = alibi_core::utils::json::from_slice::<alibi_core::utils::json::JsValue>(
        registration.response.client_data_json.as_ref(),
    )?;
    if client_data
        .get("origin")
        .and_then(|origin_2| origin_2.as_str())
        != Some(origin)
    {
        return Err(WebauthnError::InvalidRPOrigin);
    }
    validate_token_binding(&client_data, "not-supported")?;
    // Source's packed self-attestation verifier accepts only Ed25519 OKP.
    // None attestation still permits a genuine Ed448 credential to enroll.
    let attestation: serde_cbor_2::Value =
        super::raw_none::decode_first(registration.response.attestation_object.as_ref())?.0;
    if let serde_cbor_2::Value::Map(object) = &attestation
        && object.get(&serde_cbor_2::Value::Text("fmt".into()))
            == Some(&serde_cbor_2::Value::Text("packed".into()))
        && let Some(serde_cbor_2::Value::Map(statement)) =
            object.get(&serde_cbor_2::Value::Text("attStmt".into()))
        && !statement.contains_key(&serde_cbor_2::Value::Text("x5c".into()))
        && let Some(serde_cbor_2::Value::Bytes(bytes)) =
            object.get(&serde_cbor_2::Value::Text("authData".into()))
    {
        let data = AuthenticatorData::<Registration>::from_source(bytes.as_slice())?;
        if let Some(acd) = data.acd
            && let serde_cbor_2::Value::Map(key) = acd.credential_pk
            && key.get(&serde_cbor_2::Value::Integer(1)) == Some(&serde_cbor_2::Value::Integer(1))
            && key.get(&serde_cbor_2::Value::Integer(3)) == Some(&serde_cbor_2::Value::Integer(-8))
            && key.get(&serde_cbor_2::Value::Integer(-1)) != Some(&serde_cbor_2::Value::Integer(6))
        {
            return Err(WebauthnError::COSEKeyEDDSAInvalidCurve);
        }
    }
    // The original attestation bytes are verified once, without weaker retries.
    core.register_credential(registration, state)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn finish_core_authentication(
    core: &Verifier,
    authentication: &PublicKeyCredential,
    state: AuthenticationState,
    stored_passkey: &WebauthnPasskey,
    current_counter: u32,
    origin: &str,
) -> Result<AuthenticationResult, WebauthnError> {
    let client_data = alibi_core::utils::json::from_slice::<alibi_core::utils::json::JsValue>(
        authentication.response.client_data_json.as_ref(),
    )?;
    if client_data
        .get("origin")
        .and_then(|origin_2| origin_2.as_str())
        != Some(origin)
    {
        return Err(WebauthnError::InvalidRPOrigin);
    }
    validate_token_binding(&client_data, "notSupported")?;
    super::raw_none::validate_assertion_data(authentication.response.authenticator_data.as_ref())?;
    let data = AuthenticatorData::<Authentication>::from_source(
        authentication.response.authenticator_data.as_ref(),
    )?;
    if !data.user_present {
        return Err(WebauthnError::UserNotPresent);
    }
    if data.backup_state && !data.backup_eligible {
        return Err(WebauthnError::CredentialMayNotBeHardwareBound);
    }
    let mut credential = stored_passkey.cred.clone();
    // Source rejects unsupported stored OKP curves before its signature check.
    if matches!(&credential.cred.key, COSEKeyType::EC_OKP(key) if key.curve != EDDSACurve::ED25519)
    {
        return Err(WebauthnError::COSEKeyEDDSAInvalidCurve);
    }
    // Only verifier policy fields are normalized on this disposable clone.
    // Neither the key/ID nor the original verified owner comes from the request.
    credential.registration_policy = UserVerificationPolicy::Preferred;
    credential.user_verified = false;
    credential.backup_eligible = data.backup_eligible;
    credential.counter = current_counter;
    // Verify the original signed bytes once. Parsing flags never grants authority.
    core.authenticate_credential(authentication, &state, &credential)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn build_webauthn(
    config: &PasskeyConfig,
    auth_config: &AuthConfig,
    origin: &str,
) -> AuthResult<Webauthn> {
    let rp_id = resolve_rp_id(config, auth_config)?;
    let parsed_origin = Url::parse(origin)
        .map_err(|error| AuthError::bad_request(format!("Invalid passkey origin: {error}")))?;

    WebauthnBuilder::new(&rp_id, &parsed_origin)
        .map_err(|error| AuthError::config(format!("Invalid passkey config: {error}")))?
        .rp_name(&config.rp_name)
        .timeout(Duration::from_millis(OPTIONS_TIMEOUT_MS))
        .allow_any_port(true)
        .build()
        .map_err(|error| AuthError::config(format!("Invalid passkey config: {error}")))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn create_challenge_cookie(
    auth_config: &AuthConfig,
    ttl_secs: i64,
    token: &str,
    config: &PasskeyConfig,
) -> AuthResult<String> {
    let now = Utc::now();
    let claims = ChallengeCookieClaims {
        token: token.to_owned(),
        exp: usize::try_from((now + chrono::Duration::seconds(ttl_secs)).timestamp()).map_err(
            |_error| AuthError::internal("JWT timestamp exceeds the supported integer range"),
        )?,
        iat: usize::try_from(now.timestamp()).map_err(|_error| {
            AuthError::internal("JWT timestamp exceeds the supported integer range")
        })?,
    };
    let signed = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(auth_config.current_secret().as_bytes()),
    )?;
    alibi_core::utils::cookie_utils::create_cookie(
        &challenge_cookie_name(auth_config, config),
        &signed,
        ttl_secs,
        auth_config,
    )
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn decode_challenge_cookie(
    auth_config: &AuthConfig,
    raw_cookie: &str,
) -> AuthResult<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    Ok(decode::<ChallengeCookieClaims>(
        raw_cookie,
        &DecodingKey::from_secret(auth_config.current_secret().as_bytes()),
        &validation,
    )?
    .claims
    .token)
}

pub(super) fn generate_ts_user_handle() -> String {
    let mut rng = rand::rng();
    let handle: String = (0..GENERATED_USER_ID_LENGTH)
        .map(|_| {
            char::from(
                GENERATED_USER_ID_ALPHABET
                    .choose(&mut rng)
                    .copied()
                    .unwrap_or(b'a'),
            )
        })
        .collect();
    URL_SAFE_NO_PAD.encode(handle.as_bytes())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn registration_options_json(
    options: CreationChallengeResponse,
    generated_user_handle: &str,
    authenticator_attachment: Option<&str>,
) -> AuthResult<Value> {
    let mut value = serde_json::to_value(options.public_key)?;
    let Some(root) = value.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey registration options must serialize as an object",
        ));
    };

    let Some(user) = root.get_mut("user").and_then(Value::as_object_mut) else {
        return Err(AuthError::internal(
            "Passkey registration options missing user object",
        ));
    };
    drop(user.insert(
        "id".to_owned(),
        Value::String(generated_user_handle.to_owned()),
    ));

    if !root.contains_key("excludeCredentials") {
        drop(root.insert("excludeCredentials".to_owned(), Value::Array(Vec::new())));
    }

    drop(root.insert(
        "pubKeyCredParams".to_owned(),
        json!([
            { "alg": -8, "type": "public-key" },
            { "alg": -7, "type": "public-key" },
            { "alg": -257, "type": "public-key" }
        ]),
    ));

    let selection = root
        .entry("authenticatorSelection".to_owned())
        .or_insert_with(|| json!({}));
    let Some(selection) = selection.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey registration options missing authenticatorSelection object",
        ));
    };
    drop(selection.insert(
        "userVerification".to_owned(),
        Value::String("preferred".to_owned()),
    ));
    drop(selection.insert(
        "residentKey".to_owned(),
        Value::String("preferred".to_owned()),
    ));
    drop(selection.insert("requireResidentKey".to_owned(), Value::Bool(false)));
    if let Some(authenticator_attachment) = authenticator_attachment {
        drop(selection.insert(
            "authenticatorAttachment".to_owned(),
            Value::String(authenticator_attachment.to_owned()),
        ));
    }

    drop(root.insert("hints".to_owned(), Value::Array(Vec::new())));
    drop(root.insert("extensions".to_owned(), json!({ "credProps": true })));
    drop(root.insert(
        "timeout".to_owned(),
        Value::Number(OPTIONS_TIMEOUT_MS.into()),
    ));
    Ok(value)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn authentication_options_json(options: RequestChallengeResponse) -> AuthResult<Value> {
    let mut value = serde_json::to_value(options.public_key)?;
    let Some(root) = value.as_object_mut() else {
        return Err(AuthError::internal(
            "Passkey authentication options must serialize as an object",
        ));
    };

    if root
        .get("allowCredentials")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        drop(root.remove("allowCredentials"));
    }

    drop(root.remove("extensions"));
    drop(root.insert(
        "timeout".to_owned(),
        Value::Number(OPTIONS_TIMEOUT_MS.into()),
    ));
    drop(root.insert(
        "userVerification".to_owned(),
        Value::String("preferred".to_owned()),
    ));
    drop(root.remove("hints"));
    Ok(value)
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn decode_credential_id(credential_id: &str) -> AuthResult<CredentialID> {
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_id)
        .or_else(|_| URL_SAFE.decode(credential_id))
        .or_else(|_| STANDARD.decode(credential_id))
        .map_err(|_error| AuthError::bad_request("Invalid passkey credential id"))?;
    Ok(bytes.into())
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn extract_passkey_snapshot_fields(value: &Value) -> AuthResult<(u64, bool, bool)> {
    // webauthn-rs does not expose stable accessors for all persisted passkey
    // attributes we need at registration time. We intentionally depend on the
    // current 0.5.x serialized shape here and fail closed if it drifts.
    let Some(cred) = value.get("cred").and_then(Value::as_object) else {
        return Err(AuthError::internal(
            "Stored passkey JSON missing credential payload",
        ));
    };
    let counter = cred
        .get("counter")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing counter"))?;
    let backed_up = cred
        .get("backup_state")
        .and_then(Value::as_bool)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing backup_state"))?;
    let backup_eligible = cred
        .get("backup_eligible")
        .and_then(Value::as_bool)
        .ok_or_else(|| AuthError::internal("Stored passkey JSON missing backup_eligible"))?;

    Ok((counter, backed_up, backup_eligible))
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn snapshot_passkey(passkey: &impl Serialize) -> AuthResult<PasskeySnapshot> {
    let serialized = serde_json::to_string(passkey)?;
    let value: Value = serde_json::from_str(&serialized)?;
    let (counter, backed_up, backup_eligible) = extract_passkey_snapshot_fields(&value)?;

    Ok(PasskeySnapshot {
        serialized,
        counter,
        backed_up,
        backup_eligible,
    })
}

///
/// # Errors
/// Returns an error when validation, storage, or an application callback fails.
pub(super) fn extract_registration_metadata(
    registration: &RegisterPublicKeyCredential,
) -> AuthResult<RegisteredPasskeyMetadata> {
    let attestation_bytes = registration.response.attestation_object.as_ref();
    let attestation: serde_cbor_2::Value = super::raw_none::decode_first(attestation_bytes)
        .map(|(value, _)| value)
        .map_err(|error| AuthError::internal(format!("Invalid attestation CBOR: {error}")))?;
    let serde_cbor_2::Value::Map(attestation_map) = attestation else {
        return Err(AuthError::internal("Attestation object must be a CBOR map"));
    };
    let auth_data = attestation_map
        .get(&serde_cbor_2::Value::Text("authData".to_owned()))
        .and_then(|value| match value {
            serde_cbor_2::Value::Bytes(bytes) => Some(bytes.as_slice()),
            serde_cbor_2::Value::Null
            | serde_cbor_2::Value::Bool(_)
            | serde_cbor_2::Value::Integer(_)
            | serde_cbor_2::Value::Float(_)
            | serde_cbor_2::Value::Text(_)
            | serde_cbor_2::Value::Array(_)
            | serde_cbor_2::Value::Map(_)
            | serde_cbor_2::Value::Tag(..)
            | serde_cbor_2::Value::__Hidden => None,
        })
        .ok_or_else(|| AuthError::internal("Attestation object missing authData"))?;

    if auth_data.len() < 55 {
        return Err(AuthError::internal("Attestation authData is too short"));
    }

    let mut offset = 37;
    let aaguid_bytes = auth_data
        .get(offset..offset + 16)
        .ok_or_else(|| AuthError::internal("Attestation authData missing AAGUID"))?;
    offset += 16;

    let credential_id_length = auth_data
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or_else(|| AuthError::internal("Attestation authData missing credential length"))?;
    offset += 2;
    offset += credential_id_length;

    let credential_public_key = auth_data
        .get(offset..)
        .ok_or_else(|| AuthError::internal("Attestation authData missing credential public key"))?;
    let mut deserializer = serde_cbor_2::de::Deserializer::from_slice(credential_public_key);
    drop(
        serde_cbor_2::Value::deserialize(&mut deserializer).map_err(|error| {
            AuthError::internal(format!("Invalid credential public key CBOR: {error}"))
        })?,
    );
    let public_key_length = deserializer.byte_offset();
    let public_key = credential_public_key
        .get(..public_key_length)
        .ok_or_else(|| AuthError::internal("Credential public key length is invalid"))?;

    Ok(RegisteredPasskeyMetadata {
        public_key: STANDARD.encode(public_key),
        aaguid: Uuid::from_slice(aaguid_bytes)
            .ok()
            .map(|uuid| uuid.to_string()),
    })
}

pub(super) fn transports_to_csv(transports: Option<&[String]>) -> Option<String> {
    transports
        .filter(|transports| !transports.is_empty())
        .map(|transports| transports.join(","))
}

pub(super) fn parse_transports_csv(transports: &str) -> Vec<String> {
    transports.split(',').map(str::to_owned).collect()
}

pub(super) fn credential_id_from_authentication(authentication: &PublicKeyCredential) -> String {
    if !authentication.id.is_empty() {
        return authentication.id.clone();
    }

    let raw_id: &Base64UrlSafeData = &authentication.raw_id;
    URL_SAFE_NO_PAD.encode(raw_id.as_ref())
}
