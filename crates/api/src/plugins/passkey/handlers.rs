use base64::Engine;
use better_auth_core::entity::{AuthPasskey, AuthSession, AuthUser, AuthVerification};
use better_auth_core::types::UpdatePasskeyAuthentication;
use better_auth_core::wire::PasskeyView;
use better_auth_core::{AuthContext, AuthError, AuthResult, CreatePasskey, CreateVerification};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{
    DiscoverableKey, Passkey as WebauthnPasskey, PublicKeyCredential, RegisterPublicKeyCredential,
};

use crate::plugins::StatusResponse;
use crate::plugins::helpers::{SessionIssueError, issue_user_session};

use super::types::{
    DeletePasskeyRequest, PasskeyResponse, SessionResponse, UpdatePasskeyRequest,
    VerifyAuthenticationRequest, VerifyRegistrationRequest,
};
use super::webauthn::{
    StoredAuthenticationState, StoredRegistrationState, authentication_options_json,
    build_webauthn, challenge_cookie_name, create_challenge_cookie,
    credential_id_from_authentication, decode_challenge_cookie, decode_credential_id,
    extract_registration_metadata, generate_ts_user_handle, get_cookie_value, parse_stored_passkey,
    parse_transports_csv, registration_options_json, resolve_origin, snapshot_passkey,
    transports_to_csv,
};
use super::{PasskeyConfig, PasskeyRegistrationUser};

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

pub(super) type PasskeyHandlerResult<T> = AuthResult<PasskeyHandlerOutcome<T>>;

pub(super) enum PasskeyHandlerOutcome<T> {
    Success(T),
    Response(better_auth_core::AuthResponse),
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
    let webauthn = build_webauthn(config, &ctx.config, &generation_origin(config, ctx))?;
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
            if let Some(transports) = parse_transports_csv(passkey.transports())
                && let Some(object) = descriptor.as_object_mut()
            {
                let _ = object.insert("transports".to_string(), json!(transports));
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
    let (options, state) = webauthn
        .start_passkey_registration(
            Uuid::new_v4(),
            &user_name,
            &user_display_name,
            Some(exclude_credentials),
        )
        .map_err(|error| {
            AuthError::internal(format!("Failed to generate register options: {error}"))
        })?;

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let serialized_state = serde_json::to_string(&StoredRegistrationState {
        user_id: user.id.clone(),
        user: Some(user.clone()),
        context: requested_context.map(str::to_owned),
        state,
    })?;
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: token.clone(),
            value: serialized_state,
            expires_at,
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = registration_options_json(
        options,
        &generate_ts_user_handle(),
        authenticator_attachment,
    )?;
    if let Some(object) = response.as_object_mut() {
        let _ = object.insert(
            "excludeCredentials".to_string(),
            Value::Array(exclude_credentials_json),
        );
    }
    Ok((response, cookie))
}

pub(super) async fn generate_authenticate_options_core<U: AuthUser>(
    maybe_user: Option<&U>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<(Value, String)> {
    let webauthn = build_webauthn(config, &ctx.config, &generation_origin(config, ctx))?;

    let stored_passkeys = if let Some(user) = maybe_user {
        ctx.database.list_passkeys_by_user(&user.id()).await?
    } else {
        Vec::new()
    };
    let parsed_passkeys = stored_passkeys
        .iter()
        .filter_map(|passkey| parse_stored_passkey(passkey.credential()).ok())
        .collect::<Vec<WebauthnPasskey>>();
    let allow_credentials_json = stored_passkeys
        .iter()
        .map(|passkey| {
            let mut descriptor = json!({
                "id": passkey.credential_id(),
                "type": "public-key",
            });
            if let Some(transports) = parse_transports_csv(passkey.transports())
                && let Some(object) = descriptor.as_object_mut()
            {
                let _ = object.insert("transports".to_string(), json!(transports));
            }
            descriptor
        })
        .collect::<Vec<_>>();

    let (options, state) = if parsed_passkeys.is_empty() {
        let (options, state) = webauthn
            .start_discoverable_authentication()
            .map_err(|error| {
                AuthError::internal(format!("Failed to generate authenticate options: {error}"))
            })?;
        (options, StoredAuthenticationState::Discoverable { state })
    } else {
        let (options, state) = webauthn
            .start_passkey_authentication(&parsed_passkeys)
            .map_err(|error| {
                AuthError::internal(format!("Failed to generate authenticate options: {error}"))
            })?;
        (options, StoredAuthenticationState::Passkey { state })
    };

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    let _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: token.clone(),
            value: serde_json::to_string(&state)?,
            expires_at,
        })
        .await?;

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token)?;
    let mut response = authentication_options_json(options)?;
    if let Some(object) = response.as_object_mut() {
        if allow_credentials_json.is_empty() {
            let _ = object.remove("allowCredentials");
        } else {
            let _ = object.insert(
                "allowCredentials".to_string(),
                Value::Array(allow_credentials_json),
            );
        }
    }
    Ok((response, cookie))
}

pub(super) async fn verify_registration_core<S: better_auth_core::AuthSchema>(
    body: &VerifyRegistrationRequest,
    req: &better_auth_core::AuthRequest,
    authenticated_owner: Option<&str>,
    config: &PasskeyConfig,
    ctx: &AuthContext<S>,
) -> PasskeyHandlerResult<Value> {
    let Some(origin) = resolve_origin(config, req) else {
        return response_null(400);
    };

    let Some(cookie_value) = get_cookie_value(req, &challenge_cookie_name(&ctx.config)) else {
        return challenge_not_found();
    };
    let token = match decode_challenge_cookie(&ctx.config, &cookie_value) {
        Ok(token) => token,
        Err(_) => return challenge_not_found(),
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

    let webauthn = match build_webauthn(config, &ctx.config, &origin) {
        Ok(webauthn) => webauthn,
        Err(_) => return passkey_registration_failure(),
    };
    let verified_passkey =
        match webauthn.finish_passkey_registration(&registration, &stored_state.state) {
            Ok(passkey) => passkey,
            Err(_) => return passkey_registration_failure(),
        };
    let snapshot = match snapshot_passkey(&verified_passkey) {
        Ok(snapshot) => snapshot,
        Err(_) => return passkey_registration_failure(),
    };
    let metadata = match extract_registration_metadata(&registration) {
        Ok(metadata) => metadata,
        Err(_) => return passkey_registration_failure(),
    };

    let transports = registration.response.transports.as_ref().map(|transports| {
        transports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    });

    use super::registration::{PasskeyRegistrationContext, VerifiedPasskeyRegistration, trim_name};
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(verified_passkey.cred_id().as_ref());
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
        transports: transports_to_csv(&transports),
        credential: snapshot.serialized,
        aaguid: metadata.aaguid,
    };
    let callback = config.registration.after_verification.clone();
    let client_data = body.response.clone();
    let stored_context = stored_state.context;
    let authenticated_owner = authenticated_owner.map(str::to_owned);
    let request = req.clone();
    let auth_config = ctx.config.clone();
    let extensions = ctx.extensions.clone();
    let apply_policy = move |mut input: CreatePasskey| async move {
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
                    input.user_id = user_id;
                }
                if input.name.is_none() {
                    input.name = result
                        .name
                        .as_deref()
                        .map(trim_name)
                        .filter(|name| !name.is_empty())
                        .map(str::to_owned);
                }
            }
        }
        if input.user_id.is_empty() {
            return Err(AuthError::Upstream {
                status: 400,
                code: "RESOLVED_USER_INVALID",
                message: "Resolved user is invalid",
            });
        }
        Ok(input)
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
                            additional_fields: Default::default(),
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
                            AuthError::Forbidden(message)
                                if message == "session creation cancelled by database hook" =>
                            {
                                AuthError::Upstream {
                                    status: 500,
                                    code: "UNABLE_TO_CREATE_SESSION",
                                    message: "Unable to create session",
                                }
                            }
                            other => other,
                        })?;
                    Ok(Box::new((passkey, user, session))
                        as better_auth_core::store::BoxedTransactionValue)
                })
            }))
            .await;
        match committed {
            Ok(value) => {
                let (passkey, user, session) = *value
                    .downcast::<(better_auth_core::Passkey, S::User, S::Session)>()
                    .map_err(|_| {
                        AuthError::internal("invalid passkey registration transaction result")
                    })?;
                let mut result = serde_json::to_value(PasskeyView::from(&passkey))?;
                if let Some(object) = result.as_object_mut() {
                    let _ =
                        object.insert("user".into(), serde_json::to_value(ctx.user_view(&user))?);
                    let _ = object.insert(
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
                .and_then(|passkey| {
                    serde_json::to_value(PasskeyView::from(&passkey)).map_err(AuthError::from)
                }),
            Err(error) => Err(error),
        }
    };
    match outcome {
        Ok(value) => Ok(PasskeyHandlerOutcome::Success(value)),
        Err(error @ AuthError::Upstream { .. }) => Err(error),
        Err(_) => passkey_registration_failure(),
    }
}

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
    let token = match decode_challenge_cookie(&ctx.config, &cookie_value) {
        Ok(token) => token,
        Err(_) => return challenge_not_found(),
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
    let authentication: PublicKeyCredential = match serde_json::from_value(body.response.clone()) {
        Ok(authentication) => authentication,
        Err(_) => return passkey_authentication_failure(),
    };
    let credential_id = match credential_id_from_authentication(&authentication) {
        Ok(credential_id) => credential_id,
        Err(_) => return passkey_authentication_failure(),
    };

    let Some(passkey) = ctx
        .database
        .get_passkey_by_credential_id(&credential_id)
        .await?
    else {
        return passkey_not_found();
    };

    let mut stored_passkey = match parse_stored_passkey(passkey.credential()) {
        Ok(passkey) => passkey,
        Err(_) => return passkey_authentication_failure(),
    };
    let webauthn = match build_webauthn(config, &ctx.config, &origin) {
        Ok(webauthn) => webauthn,
        Err(_) => return passkey_authentication_failure(),
    };

    let authentication_result = match stored_state {
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
        Err(webauthn_rs::prelude::WebauthnError::AuthenticationFailure) => {
            return response_code(401, "AUTHENTICATION_FAILED", "Authentication failed");
        }
        Err(_) => return passkey_authentication_failure(),
    };

    if stored_passkey
        .update_credential(&authentication_result)
        .is_none()
    {
        return passkey_authentication_failure();
    }

    let snapshot = match snapshot_passkey(&stored_passkey) {
        Ok(snapshot) => snapshot,
        Err(_) => return passkey_authentication_failure(),
    };
    let device_type = snapshot.device_type().to_string();
    let updated_passkey = match ctx
        .database
        .update_passkey_authentication(
            passkey.id().as_ref(),
            UpdatePasskeyAuthentication {
                credential: snapshot.serialized,
                counter: snapshot.counter,
                backed_up: snapshot.backed_up,
                device_type,
            },
        )
        .await
    {
        Ok(passkey) => passkey,
        Err(_) => return passkey_authentication_failure(),
    };

    let Some(user) = ctx
        .database
        .get_user_by_id(updated_passkey.user_id().as_ref())
        .await?
    else {
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
        session.token().to_string(),
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
