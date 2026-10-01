use base64::Engine;

use better_auth_core::entity::{AuthPasskey, AuthSession, AuthUser, AuthVerification};

use better_auth_core::types::UpdatePasskeyAuthentication;

use better_auth_core::wire::PasskeyView;

use better_auth_core::{AuthContext, AuthError, AuthResult, CreatePasskey, CreateVerification};

use chrono::{Duration, Utc};

use serde_json::{Value, json};

use uuid::Uuid;

use webauthn_rs::prelude::{DiscoverableKey, PublicKeyCredential, RegisterPublicKeyCredential};

use webauthn_rs_core::{
    error::WebauthnError,
    proto::{
        AttestationConveyancePreference, COSEAlgorithm, RequestRegistrationExtensions,
        UserVerificationPolicy,
    },
};

use crate::plugins::StatusResponse;

use crate::plugins::helpers::{SessionIssueError, issue_user_session};

use super::types::{
    DeletePasskeyRequest, PasskeyResponse, SessionResponse, UpdatePasskeyRequest,
    VerifyAuthenticationRequest, VerifyRegistrationRequest,
};

use super::webauthn::{
    StoredAuthenticationState, StoredCoreRegistrationState, StoredRegistrationState,
    StoredRegistrationVerifier, authentication_options_json, build_verification_core,
    build_webauthn, challenge_cookie_name, create_challenge_cookie,
    credential_id_from_authentication, decode_challenge_cookie, decode_credential_id,
    extract_registration_metadata, finish_core_authentication, finish_core_registration,
    generate_ts_user_handle, get_cookie_value, parse_stored_passkey, parse_transports_csv,
    registration_options_json, resolve_origin, snapshot_passkey, transports_to_csv,
};

use super::{PasskeyConfig, PasskeyRegistrationUser};

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(better_auth_core::AuthResponse),
}

fn response_message<T>(status: u16, message: &str) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(status, &json!({ "message": message }))
            .map_err(AuthError::from)?,
    ))
}

fn response_code<T>(status: u16, code: &str, message: &str) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(status, &json!({ "code": code, "message": message }))?,
    ))
}

fn challenge_not_found<T>() -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(
            400,
            &json!({ "code": "CHALLENGE_NOT_FOUND", "message": "Challenge not found" }),
        )?,
    ))
}

fn response_null<T>(status: u16) -> PasskeyHandlerResult<T> {
    Ok(PasskeyHandlerOutcome::Response(
        better_auth_core::AuthResponse::json(status, &Value::Null).map_err(AuthError::from)?,
    ))
}

fn generation_origin(
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> String {
    if config.origin.is_empty() {
        ctx.config.base_url.clone()
    } else {
        config.origin.clone()
    }
}

fn passkey_registration_failure<T>() -> PasskeyHandlerResult<T> {
    response_code(
        500,
        "FAILED_TO_VERIFY_REGISTRATION",
        "Failed to verify registration",
    )
}

fn passkey_authentication_failure<T>() -> PasskeyHandlerResult<T> {
    response_code(400, "AUTHENTICATION_FAILED", "Authentication failed")
}

fn passkey_not_found<T>() -> PasskeyHandlerResult<T> {
    response_code(401, "PASSKEY_NOT_FOUND", "Passkey not found")
}

pub(super) async fn generate_register_options_core(
    user: &PasskeyRegistrationUser,
    requested_context: Option<&str>,
    passkey_name: Option<&str>,
    authenticator_attachment: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
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
                drop(object.insert("transports".to_owned(), json!(transports)));
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
        ])
        .require_resident_key(false)
        .user_verification_policy(UserVerificationPolicy::Preferred)
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
            policy: super::raw_none::RawNonePolicy {
                challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(options.public_key.challenge.as_ref()),
                rp_id: super::webauthn::resolve_rp_id(config, &ctx.config)?,
                origin: generation_origin(config, ctx),
            },
            state,
        }),
    })?;
    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier: token.clone(),
                value: serialized_state,
                expires_at,
            })
            .await?,
    );

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = registration_options_json(
        options,
        &generate_ts_user_handle(),
        authenticator_attachment,
    )?;
    if let Some(object) = response.as_object_mut() {
        drop(object.insert(
            "excludeCredentials".to_owned(),
            Value::Array(exclude_credentials_json),
        ));
    }
    Ok((response, cookie))
}

pub(super) async fn generate_authenticate_options_core<U: AuthUser>(
    maybe_user: Option<&U>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(Value, String)> {
    let core = build_verification_core(config, &ctx.config, &generation_origin(config, ctx))?;

    let stored_passkeys = if let Some(user) = maybe_user {
        ctx.database.list_passkeys_by_user(&user.id()).await?
    } else {
        Vec::new()
    };
    let allow_credentials_json = stored_passkeys
        .iter()
        .map(|passkey| {
            let mut descriptor = json!({
                "id": passkey.credential_id(),
                "type": "public-key",
            });
            if let Some(transports) = passkey.transports().map(parse_transports_csv)
                && let Some(object) = descriptor.as_object_mut()
            {
                drop(object.insert("transports".to_owned(), json!(transports)));
            }
            descriptor
        })
        .collect::<Vec<_>>();

    // Source's allowCredentials is a browser hint; verification selects the real
    // current stored credential by its ID and authenticates that credential owner.
    let builder = core
        .new_challenge_authenticate_builder(Vec::new(), Some(UserVerificationPolicy::Preferred))
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate authenticate options: {error}"))
        })?
        .allow_backup_eligible_upgrade(true);
    let (options, state) = core
        .generate_challenge_authenticate(builder)
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate authenticate options: {error}"))
        })?;
    let state = StoredAuthenticationState::Core { state };

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    drop(
        ctx.database
            .create_verification(CreateVerification {
                identifier: token.clone(),
                value: serde_json::to_string(&state)?,
                expires_at,
            })
            .await?,
    );

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = authentication_options_json(options)?;
    if let Some(object) = response.as_object_mut() {
        if allow_credentials_json.is_empty() {
            drop(object.remove("allowCredentials"));
        } else {
            drop(object.insert(
                "allowCredentials".to_owned(),
                Value::Array(allow_credentials_json),
            ));
        }
    }
    Ok((response, cookie))
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep challenge consumption, credential verification, and registration callbacks in protocol order"
)]
pub(super) async fn verify_registration_core<S: better_auth_core::AuthSchema>(
    body: &VerifyRegistrationRequest,
    req: &better_auth_core::AuthRequest,
    authenticated_owner: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<S>,
) -> PasskeyHandlerResult<Value> {
    use super::registration::{PasskeyRegistrationContext, VerifiedPasskeyRegistration, trim_name};

    let Some(origin) = resolve_origin(config, req) else {
        return response_null(400);
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config)) else {
        return challenge_not_found();
    };
    let Ok(token) = decode_challenge_cookie(&ctx.config, &cookie_value) else {
        return challenge_not_found();
    };

    let Some(verification) = ctx
        .database
        .consume_verification_by_identifier(&token)
        .await?
    else {
        return challenge_not_found();
    };

    let stored_state: StoredRegistrationState = match serde_json::from_str(verification.value()) {
        Ok(state) => state,
        Err(_)
            if serde_json::from_str::<StoredAuthenticationState>(verification.value()).is_ok() =>
        {
            return challenge_not_found();
        }
        Err(_) => return passkey_registration_failure(),
    };
    let optional_session_owner = if config.registration.require_session {
        None
    } else {
        match ctx.require_session(req).await {
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

    let registration: RegisterPublicKeyCredential =
        match better_auth_core::utils::json::from_value(body.response.clone()) {
            Ok(registration) => registration,
            Err(_) => return passkey_registration_failure(),
        };

    let raw_registration = match &stored_state.state {
        StoredRegistrationVerifier::Source(StoredCoreRegistrationState::CoreRawNone {
            policy,
            ..
        }) => {
            match super::raw_none::register_raw_none(&registration, &body.response, policy, &origin)
            {
                Ok(value) => value,
                Err(_) => return passkey_registration_failure(),
            }
        }
        StoredRegistrationVerifier::Source(_) | StoredRegistrationVerifier::Legacy(_) => None,
    };
    let (snapshot, metadata, credential_id) = if let Some(raw) = raw_registration {
        let metadata = super::webauthn::RegisteredPasskeyMetadata {
            public_key: base64::engine::general_purpose::STANDARD.encode(raw.public_key()),
            aaguid: Some(Uuid::from_bytes(raw.aaguid()).to_string()),
        };
        (
            raw.snapshot()?,
            metadata,
            super::raw_none::raw_credential_id(&raw),
        )
    } else {
        let verified_passkey = match &stored_state.state {
            StoredRegistrationVerifier::Legacy(state) => {
                let Ok(webauthn) = build_webauthn(config, &ctx.config, &origin) else {
                    return passkey_registration_failure();
                };
                match webauthn.finish_passkey_registration(&registration, state) {
                    Ok(passkey) => passkey,
                    Err(_) => return passkey_registration_failure(),
                }
            }
            StoredRegistrationVerifier::Source(
                StoredCoreRegistrationState::Core { state }
                | StoredCoreRegistrationState::CoreRawNone { state, .. },
            ) => {
                let Ok(core) = build_verification_core(config, &ctx.config, &origin) else {
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

    let transports = registration.response.transports.as_ref().map(|transports| {
        transports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    });

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
            .as_deref()
            .map(trim_name)
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        credential_id,
        public_key: metadata.public_key,
        counter: snapshot.counter,
        device_type: snapshot.device_type().to_owned(),
        backed_up: snapshot.backed_up,
        transports: transports_to_csv(transports.as_deref()),
        credential: snapshot.serialized,
        aaguid: metadata.aaguid,
    };
    let callback = config.registration.after_verification.clone();
    let client_data = body.response.clone();
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
        let meta = better_auth_core::RequestMeta::from_request(req);
        let expires_at = Utc::now() + ctx.config.session.expires_in;
        let committed = ctx
            .database
            .transaction_boxed(Box::new(move |transaction| {
                Box::pin(async move {
                    input = apply_policy(input).await?;
                    let user = transaction.get_user_by_id(&input.user_id).await?.ok_or(
                        AuthError::Upstream {
                            status: 500,
                            code: "USER_NOT_FOUND",
                            message: "User not found",
                        },
                    )?;
                    let user_id = input.user_id.clone();
                    let passkey = transaction.create_passkey(input).await?;
                    let session = transaction
                        .create_session(better_auth_core::CreateSession {
                            additional_fields: better_auth_core::field_policy::FieldValues::default(
                            ),
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
                            | AuthError::RateLimited
                            | AuthError::NotImplemented(_)
                            | AuthError::Config(_)
                            | AuthError::Database(_)
                            | AuthError::Serialization(_)
                            | AuthError::Plugin { .. }
                            | AuthError::Internal(_)
                            | AuthError::PasswordHash(_)
                            | AuthError::Jwt(_)) => other,
                        })?;
                    Ok::<better_auth_core::store::BoxedTransactionValue, AuthError>(Box::new((
                        passkey, user, session,
                    )))
                })
            }))
            .await;
        match committed {
            Ok(value) => {
                let (passkey, user, session) = *value
                    .downcast::<(better_auth_core::Passkey, S::User, S::Session)>()
                    .map_err(|_error| {
                        AuthError::internal("invalid passkey registration transaction result")
                    })?;
                let mut result = serde_json::to_value(PasskeyView::from(&passkey))?;
                if let Some(object) = result.as_object_mut() {
                    drop(object.insert("user".into(), serde_json::to_value(ctx.user_view(&user))?));
                    drop(object.insert(
                        "session".into(),
                        serde_json::to_value(ctx.session_view(&session))?,
                    ));
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
                .and_then(|passkey| {
                    serde_json::to_value(PasskeyView::from(&passkey)).map_err(AuthError::from)
                }),
            Err(error) => Err(error),
        }
    };
    match outcome {
        Ok(value) => Ok(PasskeyHandlerOutcome::Success(value)),
        Err(error) if super::registration::is_application_error(&error) => Err(error),
        Err(_) => passkey_registration_failure(),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Keep credential verification, counter updates, and session callbacks in protocol order"
)]
pub(super) async fn verify_authentication_core(
    body: &VerifyAuthenticationRequest,
    req: &better_auth_core::AuthRequest,
    config: &PasskeyConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<(Value, String)> {
    let Some(origin) = resolve_origin(config, req) else {
        return response_message(400, "origin missing");
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config)) else {
        return challenge_not_found();
    };
    let Ok(token) = decode_challenge_cookie(&ctx.config, &cookie_value) else {
        return challenge_not_found();
    };

    let Some(verification) = ctx
        .database
        .consume_verification_by_identifier(&token)
        .await?
    else {
        return challenge_not_found();
    };

    let stored_state: StoredAuthenticationState = match serde_json::from_str(verification.value()) {
        Ok(state) => state,
        Err(_) if serde_json::from_str::<StoredRegistrationState>(verification.value()).is_ok() => {
            return challenge_not_found();
        }
        Err(_) => return passkey_authentication_failure(),
    };
    let authentication: PublicKeyCredential =
        match serde_json::from_value(body.response.to_json_value()?) {
            Ok(authentication) => authentication,
            Err(_) => return passkey_authentication_failure(),
        };
    let credential_id = credential_id_from_authentication(&authentication);

    let Some(passkey) = ctx
        .database
        .get_passkey_by_credential_id(&credential_id)
        .await?
    else {
        return passkey_not_found();
    };

    let Ok(mut stored_passkey) = parse_stored_passkey(passkey.credential()) else {
        return passkey_authentication_failure();
    };
    let Ok(webauthn) = build_webauthn(config, &ctx.config, &origin) else {
        return passkey_authentication_failure();
    };

    let authentication_result = match stored_state {
        StoredAuthenticationState::Core { state } => {
            let Ok(counter) = u32::try_from(passkey.counter()) else {
                return passkey_authentication_failure();
            };
            // Public saved counter is authoritative, even if application code
            // changed it independently of the opaque verifier credential.
            let mut current = webauthn_rs_core::proto::Credential::from(stored_passkey.clone());
            current.counter = counter;
            stored_passkey = current.into();
            let Ok(core) = build_verification_core(config, &ctx.config, &origin) else {
                return passkey_authentication_failure();
            };
            finish_core_authentication(
                &core,
                &authentication,
                state,
                &stored_passkey,
                counter,
                &origin,
            )
        }
        StoredAuthenticationState::Passkey { state } => {
            webauthn.finish_passkey_authentication(&authentication, &state)
        }
        StoredAuthenticationState::Discoverable { state } => {
            let discoverable_key = DiscoverableKey::from(stored_passkey.clone());
            webauthn.finish_discoverable_authentication(&authentication, state, &[discoverable_key])
        }
    };
    let authentication_result = match authentication_result {
        Ok(result) => result,
        Err(WebauthnError::AuthenticationFailure) => {
            return response_code(401, "AUTHENTICATION_FAILED", "Authentication failed");
        }
        Err(_) => return passkey_authentication_failure(),
    };

    // Verification selected this owner before application code runs. A callback
    // may reassign the stored credential, but cannot change this authentication.
    let verified_owner = passkey.user_id().into_owned();
    let mut public_backed_up = passkey.backed_up();
    let mut public_device_type = passkey.device_type().to_owned();
    if let Some(callback) = &config.authentication.after_verification {
        let context = super::PasskeyAuthenticationContext {
            request: req,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
        };
        let verified = super::VerifiedPasskeyAuthentication {
            result: authentication_result.clone(),
            origin: origin.clone(),
            rp_id: super::webauthn::resolve_rp_id(config, &ctx.config)?,
        };
        match callback
            .after_verification(&context, &verified, &body.response)
            .await
        {
            Ok(()) => {}
            Err(error) if super::registration::is_application_error(&error) => return Err(error),
            Err(_) => return passkey_authentication_failure(),
        }
        // Source's counter-only update preserves application writes made by the
        // callback. Refresh the public metadata the store update must carry.
        // An absent row still follows the existing update failure path below.
        match ctx.database.get_passkey_by_id(passkey.id().as_ref()).await {
            Ok(Some(current)) => {
                public_backed_up = current.backed_up();
                current.device_type().clone_into(&mut public_device_type);
            }
            Ok(None) => {}
            Err(_) => return passkey_authentication_failure(),
        }
    }

    if stored_passkey
        .update_credential(&authentication_result)
        .is_none()
    {
        return passkey_authentication_failure();
    }

    let Ok(snapshot) = snapshot_passkey(&stored_passkey) else {
        return passkey_authentication_failure();
    };
    match ctx
        .database
        .update_passkey_authentication(
            passkey.id().as_ref(),
            UpdatePasskeyAuthentication {
                credential: snapshot.serialized,
                counter: snapshot.counter,
                // Pinned authentication persists only the new counter. Keep
                // current public snapshots, including callback writes, while
                // updating the opaque verifier credential's real backup state.
                backed_up: public_backed_up,
                device_type: public_device_type,
            },
        )
        .await
    {
        Ok(_) => {}
        Err(_) => return passkey_authentication_failure(),
    }

    let Some(user) = ctx.database.get_user_by_id(&verified_owner).await? else {
        return response_message(500, "User not found");
    };

    let session = match issue_user_session(ctx, &user.id(), ip_address, user_agent)
        .await
        .map_err(SessionIssueError::into_auth_error)
    {
        Ok(issued) => issued.session,
        Err(error) => return Err(error),
    };

    Ok(PasskeyHandlerOutcome::Success((
        serde_json::to_value(SessionResponse {
            session: ctx.session_view(&session),
            user: ctx.user_view(&user),
        })?,
        session.token().to_owned(),
    )))
}

pub(super) async fn list_user_passkeys_core(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<Vec<PasskeyView>> {
    let passkeys = ctx.database.list_passkeys_by_user(&user.id()).await?;
    Ok(passkeys.iter().map(PasskeyView::from).collect())
}

pub(super) async fn delete_passkey_core(
    body: &DeletePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<StatusResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Ok(PasskeyHandlerOutcome::Response(
            better_auth_core::AuthResponse::new(401)
                .with_header("content-type", "application/json"),
        ));
    }

    ctx.database.delete_passkey(&body.id).await?;
    Ok(PasskeyHandlerOutcome::Success(StatusResponse {
        status: true,
    }))
}

pub(super) async fn update_passkey_core(
    body: &UpdatePasskeyRequest,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> PasskeyHandlerResult<PasskeyResponse> {
    let passkey = ctx
        .database
        .get_passkey_by_id(&body.id)
        .await?
        .ok_or_else(|| AuthError::not_found("Passkey not found"))?;

    if passkey.user_id() != user.id() {
        return Ok(PasskeyHandlerOutcome::Response(
            better_auth_core::AuthResponse::json(
                401,
                &json!({ "code": "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", "message": "You are not allowed to register this passkey" }),
            )?,
        ));
    }

    let updated = ctx
        .database
        .update_passkey_name(&body.id, &body.name)
        .await?;

    Ok(PasskeyHandlerOutcome::Success(PasskeyResponse {
        passkey: PasskeyView::from(&updated),
    }))
}
