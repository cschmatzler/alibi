use super::PasskeyHandlerOutcome;
use super::PasskeyHandlerResult;
use super::challenge_not_found;
use super::generation_origin;
use super::passkey_registration_failure;
use super::registration_value;
use super::response_code;
use super::response_null;
use crate::passkey::PasskeyConfig;
use crate::passkey::PasskeyRegistrationUser;
use crate::passkey::types::VerifyRegistrationRequest;
use crate::passkey::webauthn::StoredAuthenticationState;
use crate::passkey::webauthn::StoredCoreRegistrationState;
use crate::passkey::webauthn::StoredRegistrationState;
use crate::passkey::webauthn::StoredRegistrationVerifier;
use crate::passkey::webauthn::build_verification_core;
use crate::passkey::webauthn::build_webauthn;
use crate::passkey::webauthn::challenge_cookie_name;
use crate::passkey::webauthn::create_challenge_cookie;
use crate::passkey::webauthn::decode_challenge_cookie;
use crate::passkey::webauthn::decode_credential_id;
use crate::passkey::webauthn::extract_registration_metadata;
use crate::passkey::webauthn::finish_core_registration;
use crate::passkey::webauthn::generate_ts_user_handle;
use crate::passkey::webauthn::get_cookie_value;
use crate::passkey::webauthn::parse_transports_csv;
use crate::passkey::webauthn::registration_options_json;
use crate::passkey::webauthn::snapshot_passkey;
use crate::passkey::webauthn::transports_to_csv;
use alibi_core::AuthContext;
use alibi_core::AuthError;
use alibi_core::AuthPasskey;
use alibi_core::AuthResult;
use alibi_core::AuthUser;
use alibi_core::CreatePasskey;
use alibi_core::CreateVerification;
use base64::Engine;
use chrono::Duration;
use chrono::Utc;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::RegisterPublicKeyCredential;
use webauthn_rs_core::error::WebauthnError;
use webauthn_rs_core::proto::AttestationConveyancePreference;
use webauthn_rs_core::proto::COSEAlgorithm;
use webauthn_rs_core::proto::RequestRegistrationExtensions;
use webauthn_rs_core::proto::UserVerificationPolicy;
pub(in crate::passkey) async fn generate_register_options_core(
    user: &PasskeyRegistrationUser,
    requested_context: Option<&str>,
    passkey_name: Option<&str>,
    authenticator_attachment: Option<&str>,
    extensions: Option<Value>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
) -> AuthResult<(Value, String)> {
    let core = build_verification_core(config, &ctx.config, &generation_origin(config, ctx))?;
    let existing_passkeys = ctx.database.list_passkeys_by_user(&user.id).await?;
    let exclude_credentials = existing_passkeys
        .iter()
        .filter_map(|passkey| decode_credential_id(passkey.credential_id()).ok())
        .collect::<Vec<_>>();
    let exclude_credentials_json = existing_passkeys
        .iter()
        .map(|passkey| {
            let mut descriptor = json!({
                "id": passkey.credential_id(),
                "type": "public-key",
            });
            if let Some(transports) = passkey.transports().map(parse_transports_csv)
                && let Some(object) = descriptor.as_object_mut()
            {
                _ = object.insert("transports".to_owned(), json!(transports));
            }
            descriptor
        })
        .collect::<Vec<_>>();

    let user_name = passkey_name
        .filter(|name| !name.is_empty())
        .unwrap_or(&user.name)
        .to_owned();
    let user_display_name = user
        .display_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&user.name)
        .to_owned();
    let user_uuid = Uuid::new_v4();
    let builder = core
        .new_challenge_register_builder(user_uuid.as_bytes(), &user_name, &user_display_name)
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate register options: {error}"))
        })?
        .attestation(AttestationConveyancePreference::None)
        .credential_algorithms(vec![
            COSEAlgorithm::EDDSA,
            COSEAlgorithm::ES256,
            COSEAlgorithm::RS256,
            COSEAlgorithm::ES512,
            COSEAlgorithm::PS256,
            COSEAlgorithm::PS384,
            COSEAlgorithm::PS512,
            COSEAlgorithm::RS384,
            COSEAlgorithm::RS512,
            COSEAlgorithm::INSECURE_RS1,
        ])
        .require_resident_key(
            config.authenticator_selection.resident_key.as_deref() == Some("required"),
        )
        .user_verification_policy(
            match config.authenticator_selection.user_verification.as_deref() {
                Some("required") => UserVerificationPolicy::Required,
                Some("discouraged") => UserVerificationPolicy::Discouraged_DO_NOT_USE,
                _ => UserVerificationPolicy::Preferred,
            },
        )
        .reject_synchronised_authenticators(false)
        .exclude_credentials(Some(exclude_credentials))
        .extensions(Some(RequestRegistrationExtensions {
            cred_props: Some(true),
            ..Default::default()
        }));
    let (options, state) = core.generate_challenge_register(builder).map_err(|error| {
        AuthError::internal(format!("Failed to generate register options: {error}"))
    })?;

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let serialized_state = serde_json::to_string(&StoredRegistrationState {
        user_id: user.id.clone(),
        user: Some(user.clone()),
        context: requested_context.map(str::to_owned),
        state: StoredRegistrationVerifier::Source(StoredCoreRegistrationState::CoreRawNone {
            policy: super::super::raw_none::RawNonePolicy {
                challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(options.public_key.challenge.as_ref()),
                rp_id: super::super::webauthn::resolve_rp_id(config, &ctx.config)?,
                origin: generation_origin(config, ctx),
            },
            state,
        }),
    })?;
    _ = ctx
        .verifications()
        .create(CreateVerification {
            identifier: token.clone(),
            value: serialized_state,
            expires_at,
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token, config)?;
    let mut response = registration_options_json(
        options,
        &generate_ts_user_handle(),
        authenticator_attachment,
    )?;
    if let Some(selection) = response
        .get_mut("authenticatorSelection")
        .and_then(Value::as_object_mut)
    {
        let policy = &config.authenticator_selection;
        for (name, value) in [
            ("residentKey", &policy.resident_key),
            ("userVerification", &policy.user_verification),
            ("authenticatorAttachment", &policy.authenticator_attachment),
        ] {
            if let Some(value) = value {
                _ = selection.insert(name.into(), json!(value));
            }
        }
        if let Some(resident_key) = &policy.resident_key {
            _ = selection.insert(
                "requireResidentKey".into(),
                json!(resident_key == "required"),
            );
        }
    }
    if let Some(attachment) = authenticator_attachment
        && let Some(selection) = response
            .get_mut("authenticatorSelection")
            .and_then(Value::as_object_mut)
    {
        _ = selection.insert("authenticatorAttachment".into(), json!(attachment));
    }
    if let Some(mut extensions) = extensions {
        let object = extensions
            .as_object_mut()
            .ok_or_else(|| AuthError::bad_request("Passkey extensions must be an object"))?;
        _ = object.insert("credProps".into(), json!(true));
        if let Some(object) = response.as_object_mut() {
            _ = object.insert("extensions".into(), extensions);
        }
    }
    if let Some(object) = response.as_object_mut() {
        _ = object.insert(
            "excludeCredentials".to_owned(),
            Value::Array(exclude_credentials_json),
        );
    }
    Ok((response, cookie))
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep challenge consumption, credential verification, and registration callbacks in protocol order"
)]
pub(in crate::passkey) async fn verify_registration_core<S: alibi_core::AuthSchema>(
    body: &VerifyRegistrationRequest,
    req: &alibi_core::AuthRequest,
    authenticated_owner: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<S>,
) -> PasskeyHandlerResult<Value> {
    use super::super::registration::{
        PasskeyRegistrationContext, VerifiedPasskeyRegistration, trim_name,
    };

    let Some(response) = body.response.as_ref() else {
        return response_null(400);
    };

    let Some(origin) = super::super::webauthn::ceremony_origin(config, req, body.response.as_ref())
    else {
        return response_null(400);
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config, config))
    else {
        return challenge_not_found();
    };
    let Ok(token) = decode_challenge_cookie(&ctx.config, &cookie_value) else {
        return challenge_not_found();
    };

    let Some(verification) = ctx.verifications().consume(&token).await? else {
        return challenge_not_found();
    };

    let stored_state: StoredRegistrationState = match serde_json::from_str(verification.value()?) {
        Ok(state) => state,
        Err(_)
            if serde_json::from_str::<StoredAuthenticationState>(verification.value()?).is_ok() =>
        {
            return challenge_not_found();
        }
        Err(_) => return passkey_registration_failure(),
    };
    let optional_session_owner = if config.registration.require_session {
        None
    } else {
        match ctx.require_cached_session(req).await {
            Ok((user, _)) => Some(user.id().into_owned()),
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => None,
            Err(error) => return Err(error),
        }
    };
    let authenticated_owner = authenticated_owner.or(optional_session_owner.as_deref());
    if authenticated_owner.is_some_and(|owner| stored_state.user_id != owner) {
        return response_code(
            401,
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            "You are not allowed to register this passkey",
        );
    }

    let mut parsed_response = response.clone();
    if matches!(stored_state.state, StoredRegistrationVerifier::Source(_)) {
        // Source treats transports as persistence metadata, never authenticator
        // admission. Keep the original callback input and signed bytes intact.
        if let alibi_core::utils::json::JsValue::Object(response) = &mut parsed_response
            && let Some(alibi_core::utils::json::JsValue::Object(authenticator)) =
                response.get_mut("response")
        {
            _ = authenticator.shift_remove("transports");
        }
    }
    let registration: RegisterPublicKeyCredential =
        match alibi_core::utils::json::from_value(parsed_response) {
            Ok(registration) => registration,
            Err(_) => return passkey_registration_failure(),
        };

    let raw_registration = match &stored_state.state {
        StoredRegistrationVerifier::Source(StoredCoreRegistrationState::CoreRawNone {
            policy,
            ..
        }) => {
            match super::super::raw_none::register_raw_key(&registration, response, policy, &origin)
            {
                Ok(value) => value,
                Err(WebauthnError::AttestationStatementSigInvalid) => {
                    return response_code(
                        400,
                        "FAILED_TO_VERIFY_REGISTRATION",
                        "Failed to verify registration",
                    );
                }
                Err(_) => return passkey_registration_failure(),
            }
        }
        StoredRegistrationVerifier::Source(_) | StoredRegistrationVerifier::Legacy(_) => None,
    };
    let (snapshot, metadata, credential_id) = if let Some(raw) = raw_registration {
        let metadata = super::super::webauthn::RegisteredPasskeyMetadata {
            public_key: base64::engine::general_purpose::STANDARD.encode(raw.public_key()),
            aaguid: Some(Uuid::from_bytes(raw.aaguid()).to_string()),
        };
        (
            raw.snapshot()?,
            metadata,
            super::super::raw_none::raw_credential_id(&raw),
        )
    } else {
        let verified_passkey: super::super::source::credential::Passkey = match &stored_state.state
        {
            StoredRegistrationVerifier::Legacy(state) => {
                let Ok(webauthn) = build_webauthn(config, &ctx.config, &origin) else {
                    return passkey_registration_failure();
                };
                match webauthn.finish_passkey_registration(&registration, state) {
                    Ok(passkey) => passkey.into(),
                    Err(_) => return passkey_registration_failure(),
                }
            }
            StoredRegistrationVerifier::Source(
                StoredCoreRegistrationState::Core { state }
                | StoredCoreRegistrationState::CoreRawNone { state, .. },
            ) => {
                let Ok(core) = super::super::webauthn::build_registration_core(
                    config,
                    &ctx.config,
                    &origin,
                    &registration,
                )
                .await
                else {
                    return passkey_registration_failure();
                };
                match finish_core_registration(&core, &registration, state, &origin) {
                    Ok(passkey) => passkey,
                    // Source returns false for an invalid signature, including an
                    // invalid Ed25519 length; malformed ES256 DER throws instead.
                    Err(WebauthnError::AttestationStatementSigInvalid) => {
                        return response_code(
                            400,
                            "FAILED_TO_VERIFY_REGISTRATION",
                            "Failed to verify registration",
                        );
                    }
                    Err(_) => return passkey_registration_failure(),
                }
            }
        };
        let Ok(snapshot) = snapshot_passkey(&verified_passkey) else {
            return passkey_registration_failure();
        };
        let Ok(metadata) = extract_registration_metadata(&registration) else {
            return passkey_registration_failure();
        };
        let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(verified_passkey.cred_id().as_ref());
        (snapshot, metadata, credential_id)
    };

    let source_transports = matches!(stored_state.state, StoredRegistrationVerifier::Source(_));
    let transports = if source_transports {
        use alibi_core::utils::json::JsValue;
        match response
            .get("response")
            .and_then(|response| response.get("transports"))
        {
            None | Some(JsValue::Null) => Ok(None),
            Some(JsValue::Array(values)) => match values
                .iter()
                .map(|value| {
                    if value.is_null() {
                        Ok(String::new())
                    } else {
                        value.coerce_string()
                    }
                })
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(values) => Ok(Some(values)),
                Err(_) => Err(AuthError::internal("Invalid transports")),
            },
            Some(_) => Err(AuthError::internal("Invalid transports")),
        }
    } else {
        Ok(registration.response.transports.as_ref().map(|transports| {
            transports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        }))
    };

    let verified = VerifiedPasskeyRegistration {
        credential_id: credential_id.clone(),
        public_key: base64::engine::general_purpose::STANDARD
            .decode(&metadata.public_key)
            .map_err(|error| AuthError::internal(error.to_string()))?,
        counter: snapshot.counter,
        aaguid: metadata.aaguid.clone(),
        device_type: snapshot.device_type().to_owned(),
        backed_up: snapshot.backed_up,
    };
    let resolved_user = stored_state
        .user
        .unwrap_or_else(|| PasskeyRegistrationUser {
            id: stored_state.user_id.clone(),
            name: stored_state.user_id.clone(),
            display_name: None,
        });
    let mut input = CreatePasskey {
        user_id: stored_state.user_id,
        name: body
            .name
            .as_ref()
            .and_then(alibi_core::utils::json::JsValue::as_str)
            .map(trim_name)
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        credential_id,
        public_key: metadata.public_key,
        counter: snapshot.counter,
        device_type: snapshot.device_type().to_owned(),
        backed_up: snapshot.backed_up,
        transports: None,
        credential: snapshot.serialized,
        aaguid: metadata.aaguid,
    };
    let callback = config.registration.after_verification.clone();
    let client_data = response.clone();
    let stored_context = stored_state.context;
    let authenticated_owner = authenticated_owner.map(str::to_owned);
    let request = req.clone();
    let auth_config = std::sync::Arc::clone(&ctx.config);
    let extensions = ctx.extensions.clone();
    let apply_policy = move |mut input_2: CreatePasskey| async move {
        if let Some(callback) = callback {
            let callback_context = PasskeyRegistrationContext {
                request: &request,
                auth_config: &auth_config,
                extensions: &extensions,
            };
            if let Some(result) = callback
                .after_verification(
                    &callback_context,
                    &verified,
                    &resolved_user,
                    &client_data,
                    stored_context.as_deref(),
                )
                .await?
            {
                if let Some(user_id) = result.user_id.filter(|id| !id.is_empty()) {
                    if authenticated_owner
                        .as_ref()
                        .is_some_and(|owner| owner != &user_id)
                    {
                        return Err(AuthError::Upstream {
                            status: 401,
                            code: "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
                            message: "You are not allowed to register this passkey",
                        });
                    }
                    input_2.user_id = user_id;
                }
                if input_2.name.is_none() {
                    input_2.name = result
                        .name
                        .as_deref()
                        .map(trim_name)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned);
                }
            }
        }
        // Source joins transport metadata after the verification callback.
        let transports = transports?;
        input_2.transports = if source_transports {
            Some(transports.unwrap_or_default().join(","))
        } else {
            transports_to_csv(transports.as_deref())
        };
        if input_2.user_id.is_empty() {
            return Err(AuthError::Upstream {
                status: 400,
                code: "RESOLVED_USER_INVALID",
                message: "Resolved user is invalid",
            });
        }
        Ok(input_2)
    };
    let outcome: AuthResult<Value> = if body.create_session.as_bool() == Some(true) {
        let meta = alibi_core::RequestMeta::from_request(req);
        let expires_at = Utc::now() + ctx.config.session.expires_in;
        let committed = ctx
            .database
            .transaction_boxed(Box::new(move |transaction| {
                Box::pin(async move {
                    input = apply_policy(input).await?;
                    let user = transaction
                        .get_user_by_id_record(&input.user_id)
                        .await?
                        .ok_or(AuthError::Upstream {
                            status: 500,
                            code: "USER_NOT_FOUND",
                            message: "User not found",
                        })?;
                    let user_id = input.user_id.clone();
                    let passkey = transaction.create_passkey(input).await?;
                    let session = transaction
                        .create_session_record(alibi_core::CreateSession {
                            additional_fields: alibi_core::field_policy::FieldValues::default(),
                            token: None,
                            user_id,
                            expires_at,
                            ip_address: meta.ip_address,
                            user_agent: meta.user_agent,
                            impersonated_by: None,
                            active_organization_id: None,
                            active_team_id: None,
                        })
                        .await
                        .map_err(|error| match error {
                            AuthError::SessionCreationCancelled => AuthError::Upstream {
                                status: 500,
                                code: "UNABLE_TO_CREATE_SESSION",
                                message: "Unable to create session",
                            },
                            other @ (AuthError::Api { .. }
                            | AuthError::Upstream { .. }
                            | AuthError::BadRequest(_)
                            | AuthError::InvalidRequest(_)
                            | AuthError::Validation(_)
                            | AuthError::InvalidCredentials
                            | AuthError::Unauthenticated
                            | AuthError::AuthenticationFailed(_)
                            | AuthError::SessionNotFound
                            | AuthError::Forbidden(_)
                            | AuthError::BannedUser(_)
                            | AuthError::Unauthorized
                            | AuthError::UserNotFound
                            | AuthError::NotFound(_)
                            | AuthError::Conflict(_)
                            | AuthError::MethodNotAllowed(_)
                            | AuthError::PayloadTooLarge(_)
                            | AuthError::UnprocessableEntity(_)
                            | AuthError::RateLimited { .. }
                            | AuthError::NotImplemented(_)
                            | AuthError::Config(_)
                            | AuthError::Database(_)
                            | AuthError::Serialization(_)
                            | AuthError::Plugin { .. }
                            | AuthError::CallbackFailure(_)
                            | AuthError::Internal(_)
                            | AuthError::Encryption(_)
                            | AuthError::PasswordHash(_)
                            | AuthError::UserCreationCancelled
                            | AuthError::Jwt(_)) => other,
                        })?;
                    Ok::<alibi_core::store::BoxedTransactionValue, AuthError>(Box::new((
                        passkey, user, session,
                    )))
                })
            }))
            .await;
        match committed {
            Ok(value) => {
                let (passkey, user, session) = *value
                    .downcast::<(
                        alibi_core::Passkey,
                        alibi_core::AdapterRecord<S::User>,
                        alibi_core::AdapterRecord<S::Session>,
                    )>()
                    .map_err(|_error| {
                        AuthError::internal("invalid passkey registration transaction result")
                    })?;
                let mut result = registration_value(&passkey)?;
                if let Some(object) = result.as_object_mut() {
                    _ = object.insert("user".into(), serde_json::to_value(ctx.user_view(&user))?);
                    _ = object.insert(
                        "session".into(),
                        serde_json::to_value(ctx.session_view(&session))?,
                    );
                }
                Ok(result)
            }
            Err(error) => Err(error),
        }
    } else {
        match apply_policy(input).await {
            Ok(input) => ctx
                .database
                .create_passkey(input)
                .await
                .and_then(|passkey| registration_value(&passkey)),
            Err(error) => Err(error),
        }
    };
    match outcome {
        Ok(value) => Ok(PasskeyHandlerOutcome::Success(value)),
        Err(error) if super::super::registration::is_application_error(&error) => Err(error),
        Err(_) => passkey_registration_failure(),
    }
}
