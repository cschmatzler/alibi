use super::{
    AuthContext, AuthError, AuthResult, AuthUser, CreateVerification, DiscoverableKey, Duration,
    PasskeyConfig, PasskeyHandlerOutcome, PasskeyHandlerResult, PublicKeyCredential,
    SessionIssueError, SessionResponse, StoredAuthenticationState, StoredRegistrationState,
    UpdatePasskeyAuthentication, UserVerificationPolicy, Utc, Uuid, Value,
    VerifyAuthenticationRequest, WebauthnError, authentication_options_json,
    build_verification_core, build_webauthn, challenge_cookie_name, challenge_not_found,
    create_challenge_cookie, credential_id_from_authentication, decode_challenge_cookie,
    decode_credential_id, finish_core_authentication, generation_origin, get_cookie_value,
    issue_user_session_record, json, parse_transports_csv, passkey_authentication_failure,
    passkey_not_found, response_code, response_message, snapshot_passkey,
};
use alibi_core::AuthPasskey;
use alibi_core::AuthSession;
use base64::Engine;
pub(in crate::passkey) async fn generate_authenticate_options_core<U: AuthUser>(
    maybe_user: Option<&U>,
    extensions: Option<Value>,
    config: &PasskeyConfig,
    ctx: &AuthContext<impl alibi_core::AuthSchema>,
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
    let state = StoredAuthenticationState::CoreRaw {
        challenge: base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(options.public_key.challenge.as_ref()),
        state,
    };

    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::seconds(config.challenge_ttl_secs);
    drop(
        ctx.verifications()
            .create(CreateVerification {
                identifier: token.clone(),
                value: serde_json::to_string(&state)?,
                expires_at,
            })
            .await?,
    );

    let cookie = create_challenge_cookie(&ctx.config, config.challenge_ttl_secs, &token, config)?;
    let mut response = authentication_options_json(options)?;
    if let Some(extensions) = extensions {
        if !extensions.is_object() {
            return Err(AuthError::bad_request(
                "Passkey extensions must be an object",
            ));
        }
        if let Some(object) = response.as_object_mut() {
            let _ = object.insert("extensions".into(), extensions);
        }
    }
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
    reason = "Keep credential verification, counter updates, and session callbacks in protocol order"
)]
pub(in crate::passkey) async fn verify_authentication_core<S: alibi_core::AuthSchema>(
    body: &VerifyAuthenticationRequest,
    req: &alibi_core::AuthRequest,
    config: &PasskeyConfig,
    ip_address: Option<String>,
    user_agent: Option<String>,
    ctx: &AuthContext<S>,
) -> PasskeyHandlerResult<(Value, String)> {
    let Some(origin) = super::super::webauthn::ceremony_origin(config, req, body.response.as_ref())
    else {
        return response_message(400, "origin missing");
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

    let stored_state: StoredAuthenticationState = match serde_json::from_str(verification.value()?)
    {
        Ok(state) => state,
        Err(_)
            if serde_json::from_str::<StoredRegistrationState>(verification.value()?).is_ok() =>
        {
            return challenge_not_found();
        }
        Err(_) => return passkey_authentication_failure(),
    };
    let Some(response) = body.response.as_ref() else {
        return passkey_authentication_failure();
    };
    let authentication: PublicKeyCredential =
        match serde_json::from_value(response.to_json_value()?) {
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

    let Ok(mut stored) =
        serde_json::from_str::<super::super::raw_none::StoredCredential>(passkey.credential())
    else {
        return passkey_authentication_failure();
    };
    let Ok(counter) = u32::try_from(passkey.counter()) else {
        return passkey_authentication_failure();
    };
    if matches!(
        &stored_state,
        StoredAuthenticationState::Core { .. } | StoredAuthenticationState::CoreRaw { .. }
    ) {
        let Ok(public_key) = base64::engine::general_purpose::STANDARD.decode(passkey.public_key())
        else {
            return passkey_authentication_failure();
        };
        match &mut stored {
            super::super::raw_none::StoredCredential::Raw(raw) => {
                raw.replace_public_key(public_key);
            }
            super::super::raw_none::StoredCredential::Core(saved) => {
                let Ok((key, _)) = super::super::raw_none::decode_first(&public_key) else {
                    return passkey_authentication_failure();
                };
                let Ok(key) = super::super::source::crypto::COSEKey::try_from(&key) else {
                    return passkey_authentication_failure();
                };
                let mut current = saved.cred.clone();
                current.cred = key;
                current.cred_id = decode_credential_id(passkey.credential_id())?;
                saved.cred = current;
            }
        }
    }

    let authentication_result = match (&mut stored, stored_state) {
        (
            super::super::raw_none::StoredCredential::Raw(raw),
            StoredAuthenticationState::CoreRaw { challenge, .. },
        ) => super::super::raw_none::authenticate_raw(
            raw,
            &authentication,
            response,
            &challenge,
            &super::super::webauthn::resolve_rp_id(config, &ctx.config)?,
            &origin,
            counter,
        ),
        (super::super::raw_none::StoredCredential::Raw(_), _) => {
            return passkey_authentication_failure();
        }
        (super::super::raw_none::StoredCredential::Core(stored_passkey), state) => {
            let Ok(webauthn) = build_webauthn(config, &ctx.config, &origin) else {
                return passkey_authentication_failure();
            };
            let result = match state {
                StoredAuthenticationState::Core { state }
                | StoredAuthenticationState::CoreRaw { state, .. } => {
                    let mut current = stored_passkey.cred.clone();
                    current.counter = counter;
                    stored_passkey.cred = current;
                    let Ok(core) = build_verification_core(config, &ctx.config, &origin) else {
                        return passkey_authentication_failure();
                    };
                    finish_core_authentication(
                        &core,
                        &authentication,
                        state,
                        stored_passkey,
                        counter,
                        &origin,
                    )
                }
                StoredAuthenticationState::Passkey { state } => {
                    webauthn.finish_passkey_authentication(&authentication, &state)
                }
                StoredAuthenticationState::Discoverable { state } => {
                    let Ok(legacy) = stored_passkey.to_registry() else {
                        return passkey_authentication_failure();
                    };
                    let discoverable_key = DiscoverableKey::from(legacy);
                    webauthn.finish_discoverable_authentication(
                        &authentication,
                        state,
                        &[discoverable_key],
                    )
                }
            };
            result.map(super::super::authentication::AuthenticationResult::Core)
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
        let context = super::super::PasskeyAuthenticationContext {
            request: req,
            auth_config: &ctx.config,
            extensions: &ctx.extensions,
        };
        let verified = super::super::VerifiedPasskeyAuthentication {
            result: authentication_result.clone(),
            origin: origin.clone(),
            rp_id: super::super::webauthn::resolve_rp_id(config, &ctx.config)?,
        };
        match callback
            .after_verification(&context, &verified, response)
            .await
        {
            Ok(()) => {}
            Err(error) if super::super::registration::is_application_error(&error) => {
                return Err(error);
            }
            Err(_) => return passkey_authentication_failure(),
        }
        // Source's counter-only update preserves application writes made by the
        // callback. Refresh the public metadata the store update must carry.
        // A callback may remove the row; a successful no-row counter update
        // still completes authentication for the original verified owner.
        match ctx.database.get_passkey_by_id(passkey.id().as_ref()).await {
            Ok(Some(current)) => {
                public_backed_up = current.backed_up();
                current.device_type().clone_into(&mut public_device_type);
            }
            Ok(None) => {}
            Err(_) => return passkey_authentication_failure(),
        }
    }

    let snapshot = match (&mut stored, &authentication_result) {
        (
            super::super::raw_none::StoredCredential::Core(passkey),
            super::super::authentication::AuthenticationResult::Core(result),
        ) => {
            if passkey.update_credential(result).is_none() {
                return passkey_authentication_failure();
            }
            snapshot_passkey(passkey)
        }
        (
            super::super::raw_none::StoredCredential::Raw(raw),
            super::super::authentication::AuthenticationResult::Raw(result),
        ) => {
            raw.apply_authentication(result);
            raw.snapshot()
        }
        _ => return passkey_authentication_failure(),
    };
    let Ok(snapshot) = snapshot else {
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

    let Some(user) = ctx.database.get_user_by_id_record(&verified_owner).await? else {
        return response_message(500, "User not found");
    };

    let session = match issue_user_session_record(ctx, &user.id(), ip_address, user_agent)
        .await
        .map_err(SessionIssueError::into_auth_error)
    {
        Ok(issued) => issued.session,
        Err(error) => return Err(error),
    };

    let Some(user) = ctx.database.get_user_by_id_record(&verified_owner).await? else {
        return response_message(500, "User not found");
    };
    super::super::super::helpers::record_completed_session_user_view::<S>(
        &user,
        &session,
        ctx.trusted_user_view(&user),
    );

    Ok(PasskeyHandlerOutcome::Success((
        serde_json::to_value(SessionResponse {
            session: ctx.session_view(&session),
            // The pinned verification endpoint returns the adapter user directly.
            user: ctx.trusted_user_view(&user),
        })?,
        session.token().to_owned(),
    )))
}
