mod authentication;
mod endpoint;
pub use endpoint::{
    PasskeyAuthenticated, PasskeyDeleted, PasskeyRegistrationInput, PasskeyUpdated,
};
mod options;
pub use options::{
    PasskeyAuthenticatorSelection, PasskeyExtensions, PasskeyExtensionsResolver,
    PasskeyOptionsContext,
};

pub(super) mod handlers;

mod raw_none;
mod source;

mod registration;

pub(super) mod types;

pub(super) mod webauthn;

use alibi_core::error::codes;
use alibi_core::utils::cookie_utils::create_session_cookie;
use alibi_core::{AuthContext, AuthError, AuthResult};
use alibi_core::{AuthRequest, AuthResponse};
pub use authentication::{
    AuthenticationResult, PasskeyAuthenticationAfterVerification, PasskeyAuthenticationConfig,
    PasskeyAuthenticationContext, VerifiedPasskeyAuthentication,
};
use handlers::{
    PasskeyHandlerOutcome, delete_passkey_core, generate_authenticate_options_core,
    generate_register_options_core, list_user_passkeys_core, update_passkey_core,
    verify_authentication_core, verify_registration_core,
};
pub use registration::{
    PasskeyRegistrationAfterVerification, PasskeyRegistrationConfig, PasskeyRegistrationContext,
    PasskeyRegistrationOverride, PasskeyRegistrationUser, PasskeyUserResolver,
    VerifiedPasskeyRegistration,
};
use types::{
    DeletePasskeyRequest, UpdatePasskeyRequest, VerifyAuthenticationRequest,
    VerifyRegistrationRequest,
};

/// Passkey / `WebAuthn` authentication plugin.
///
/// Generates WebAuthn-compatible registration and authentication options,
/// stores challenge state via the auth store, and manages passkey CRUD.
pub struct PasskeyPlugin {
    config: PasskeyConfig,
}

#[derive(Debug, Clone, alibi_core::PluginConfig)]
#[plugin(name = "PasskeyPlugin")]
pub struct PasskeyConfig {
    #[config(default = String::new())]
    pub rp_id: String,
    #[config(default = "Better Auth".to_owned())]
    pub rp_name: String,
    #[config(default = String::new())]
    pub origin: String,
    /// Additional explicit origins accepted by signed ceremonies.
    #[config(default = Vec::new())]
    pub origins: Vec<String>,
    #[config(default = PasskeyAuthenticatorSelection::default())]
    pub authenticator_selection: PasskeyAuthenticatorSelection,
    #[config(default = 300)]
    pub challenge_ttl_secs: i64,
    #[config(default = "better-auth-passkey".to_owned())]
    pub web_authn_challenge_cookie: String,
    /// Per-format PEM roots, matching the verifier `SettingsService`.
    /// Unspecified formats retain published defaults.
    #[config(default = None)]
    pub attestation_root_certificates: Option<std::collections::BTreeMap<String, Vec<String>>>,
    #[config(default = PasskeyRegistrationConfig::default())]
    pub registration: PasskeyRegistrationConfig,
    #[config(default = PasskeyAuthenticationConfig::default())]
    pub authentication: PasskeyAuthenticationConfig,
}

impl PasskeyPlugin {
    /// GET /passkey/generate-register-options
    async fn handle_generate_register_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let query = req
            .query
            .iter()
            .map(|(name, value)| {
                (
                    name.clone().into(),
                    alibi_core::utils::json::JsValue::String(value.clone().into()),
                )
            })
            .collect();
        self.generate_register_options(req, &query, ctx).await
    }

    async fn generate_register_options<S: alibi_core::AuthSchema>(
        &self,
        req: &impl alibi_core::session::SessionRequest,
        query: &alibi_core::utils::json::JsObject,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        use alibi_core::AuthUser;
        let session = self.registration_session(req, ctx).await?;
        let projected_user = session
            .as_ref()
            .map(|(user, _)| ctx.user_view(user))
            .transpose()?;
        let source =
            if !self.config.registration.require_session
                && ctx.config.session.has_server_session_store()
            {
                Some(session.as_ref().map_or(
                    webauthn::RegistrationSource::Resolver,
                    |(_, session)| webauthn::RegistrationSource::Session {
                        token_hash: webauthn::session_token_hash(&session.token),
                    },
                ))
            } else {
                None
            };
        let user = if let Some((user, _)) = session {
            let id = user.id().into_owned();
            let name = user
                .email()
                .filter(|email| !email.is_empty())
                .unwrap_or(&id)
                .to_owned();
            PasskeyRegistrationUser {
                id,
                name: name.clone().into(),
                display_name: Some(name.into()),
            }
        } else {
            let Some(resolver) = &self.config.registration.resolve_user else {
                return Ok(AuthResponse::json(
                    400,
                    &serde_json::json!({"code":codes::RESOLVE_USER_REQUIRED,"message":"Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false"}),
                )?);
            };
            let context = PasskeyRegistrationContext {
                request: req.physical_request(),
                endpoint: req.endpoint_call(),
                auth_config: &ctx.config,
                extensions: &ctx.extensions,
            };
            match resolver
                .resolve_user(
                    &context,
                    query
                        .get("context")
                        .and_then(alibi_core::utils::json::JsValue::as_js_string),
                )
                .await
            {
                Ok(Some(user)) if !user.id.is_empty() && !user.name.is_empty() => user,
                Ok(_) => {
                    return Ok(AuthResponse::json(
                        400,
                        &serde_json::json!({"code":codes::RESOLVED_USER_INVALID,"message":"Resolved user is invalid"}),
                    )?);
                }
                Err(error) if registration::is_application_error(&error) => return Err(error),
                Err(_) => return Ok(AuthResponse::new(500)),
            }
        };
        let extensions = if let Some(input) = &self.config.registration.extensions {
            Some(
                input
                    .resolve(&PasskeyOptionsContext {
                        request: req.physical_request(),
                        endpoint: req.endpoint_call(),
                        auth_config: &ctx.config,
                        extensions: &ctx.extensions,
                        user: projected_user.as_ref(),
                    })
                    .await?,
            )
        } else {
            None
        };
        let passkey_name = query
            .get("name")
            .and_then(alibi_core::utils::json::JsValue::as_js_string);
        let authenticator_attachment = query
            .get("authenticatorAttachment")
            .and_then(alibi_core::utils::json::JsValue::as_str);
        let (result, cookie_header) = generate_register_options_core(
            &user,
            query
                .get("context")
                .and_then(alibi_core::utils::json::JsValue::as_js_string),
            passkey_name,
            authenticator_attachment,
            extensions,
            source,
            &self.config,
            ctx,
        )
        .await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-registration
    async fn handle_verify_registration(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyRegistrationRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        self.verify_registration(&body, req, ctx).await
    }

    async fn verify_registration<S: alibi_core::AuthSchema>(
        &self,
        body: &VerifyRegistrationRequest,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let session = if self.config.registration.require_session {
            self.registration_session(req, ctx).await?
        } else {
            None
        };
        let owner_id = session
            .as_ref()
            .map(|(user, _)| alibi_core::AuthUser::id(user).into_owned());
        match verify_registration_core(body, req, owner_id.as_deref(), &self.config, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                let token = result
                    .get("session")
                    .and_then(|session_2| session_2.get("token"))
                    .and_then(alibi_core::utils::json::JsValue::as_str);
                let response = AuthResponse::json(200, &result)?;
                if let Some(token) = token {
                    use alibi_core::utils::cookie_utils::{
                        create_session_cookie_with_max_age, create_session_like_cookie,
                        related_cookie_name, sign_cookie_value, verify_cookie_value,
                    };
                    let preference = related_cookie_name(&ctx.config, "dont_remember");
                    let dont_remember = crate::helpers::get_cookie(req, &preference)
                        .and_then(|value| verify_cookie_value(&value, ctx.config.current_secret()))
                        .is_some_and(|value| !value.is_empty());
                    let mut response = response.with_appended_header(
                        "Set-Cookie",
                        create_session_cookie_with_max_age(
                            Some(token),
                            if dont_remember {
                                None
                            } else {
                                Some(ctx.config.session.expires_in.num_seconds())
                            },
                            &ctx.config,
                        )?,
                    );
                    if dont_remember {
                        response.headers.append(
                            "Set-Cookie",
                            create_session_like_cookie(
                                &preference,
                                &sign_cookie_value("true", ctx.config.current_secret()),
                                None,
                                &ctx.config,
                            )?,
                        );
                    }
                    Ok(response)
                } else {
                    Ok(response)
                }
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    async fn registration_session<S: alibi_core::AuthSchema>(
        &self,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<
        Option<(
            alibi_core::AuthenticatedUser<S>,
            alibi_core::wire::SessionView,
        )>,
    > {
        let session = match Box::pin(webauthn::registration_session(req, ctx)).await {
            Ok(session) => Some(session),
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound)
                if !self.config.registration.require_session =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        if self.config.registration.require_session
            && let Some((_, session)) = &session
            && !ctx.session_manager().is_session_fresh(session)
        {
            return Err(AuthError::Upstream {
                status: 403,
                code: codes::SESSION_NOT_FRESH,
                message: "Session is not fresh",
            });
        }
        Ok(session)
    }

    /// GET /passkey/generate-authenticate-options
    async fn handle_generate_authenticate_options(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.generate_authentication_options(req, ctx).await
    }

    async fn generate_authentication_options<S: alibi_core::AuthSchema>(
        &self,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let maybe_user = ctx.require_cached_session(req).await.ok().map(|(u, _)| u);
        let projected_user = maybe_user
            .as_ref()
            .map(|user| ctx.user_view(user))
            .transpose()?;
        let extensions = if let Some(input) = &self.config.authentication.extensions {
            Some(
                input
                    .resolve(&PasskeyOptionsContext {
                        request: req.physical_request(),
                        endpoint: req.endpoint_call(),
                        auth_config: &ctx.config,
                        extensions: &ctx.extensions,
                        user: projected_user.as_ref(),
                    })
                    .await?,
            )
        } else {
            None
        };
        let (result, cookie_header) =
            generate_authenticate_options_core(maybe_user.as_ref(), extensions, &self.config, ctx)
                .await?;
        Ok(AuthResponse::json(200, &result)?.with_header("Set-Cookie", cookie_header))
    }

    /// POST /passkey/verify-authentication
    async fn handle_verify_authentication(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: VerifyAuthenticationRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        self.verify_authentication(&body, req, ctx).await
    }

    async fn verify_authentication<S: alibi_core::AuthSchema>(
        &self,
        body: &VerifyAuthenticationRequest,
        req: &impl alibi_core::session::SessionRequest,
        ctx: &AuthContext<S>,
    ) -> AuthResult<AuthResponse> {
        let metadata = if req.endpoint_call().is_some() {
            alibi_core::RequestMeta {
                ip_address: Some(
                    ctx.config
                        .advanced
                        .ip_address
                        .resolve_ip(req.session_headers())
                        .unwrap_or_default(),
                ),
                user_agent: Some(
                    req.session_headers()
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default(),
                ),
            }
        } else {
            req.physical_request()
                .map(alibi_core::RequestMeta::from_request)
                .unwrap_or_default()
        };
        match verify_authentication_core(
            body,
            req,
            &self.config,
            metadata.ip_address,
            metadata.user_agent,
            ctx,
        )
        .await?
        {
            PasskeyHandlerOutcome::Success((response, token)) => {
                let cookie_header = create_session_cookie(&token, &ctx.config)?;
                Ok(AuthResponse::json(200, &response)?.with_header("Set-Cookie", cookie_header))
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// GET /passkey/list-user-passkeys
    async fn handle_list_user_passkeys(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let result = list_user_passkeys_core(&user, ctx).await?;
        AuthResponse::json(200, &result).map_err(AuthError::from)
    }

    /// POST /passkey/delete-passkey
    async fn handle_delete_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let body: DeletePasskeyRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        match delete_passkey_core(&body, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                AuthResponse::json(200, &result).map_err(AuthError::from)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }

    /// POST /passkey/update-passkey
    async fn handle_update_passkey(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let (user, _session) = super::helpers::ordinary_session(req, ctx).await?;
        let body: UpdatePasskeyRequest = match alibi_core::validate_request_body(req) {
            Ok(v) => v,
            Err(resp) => return Ok(resp),
        };
        match update_passkey_core(&body, &user, ctx).await? {
            PasskeyHandlerOutcome::Success(result) => {
                AuthResponse::json(200, &result).map_err(AuthError::from)
            }
            PasskeyHandlerOutcome::Response(response) => Ok(response),
        }
    }
}

alibi_core::impl_auth_plugin! {
    PasskeyPlugin, "passkey";
    routes {
        get  "/passkey/generate-register-options"      => handle_generate_register_options,      "passkey_generate_register_options";
        post "/passkey/verify-registration"            => handle_verify_registration,            "passkey_verify_registration";
        get  "/passkey/generate-authenticate-options"  => handle_generate_authenticate_options,  "passkey_generate_authenticate_options";
        post "/passkey/verify-authentication"          => handle_verify_authentication,          "passkey_verify_authentication";
        get  "/passkey/list-user-passkeys"             => handle_list_user_passkeys,             "passkey_list_user_passkeys";
        post "/passkey/delete-passkey"                 => handle_delete_passkey,                 "passkey_delete_passkey";
        post "/passkey/update-passkey"                 => handle_update_passkey,                 "passkey_update_passkey";
    }

 extra {
    async fn on_init(&self, ctx: &mut alibi_core::AuthInitContext<S>) -> AuthResult<()> {
        if self.config.origin.is_empty() && self.config.origins.is_empty() && !self.config.rp_id.is_empty()
            && let Some(dynamic) = &ctx.config.dynamic_base_url
            && dynamic.allowed_hosts.iter().any(|pattern| {
                let host = pattern.split_once("://").map_or(pattern.as_str(), |(_, host)| host).split([':', '/']).next().unwrap_or_default();
                let Some(wildcard) = host.rfind(['*', '?']) else { return false; };
                let suffix = host.get(wildcard + 1..).unwrap_or_default().trim_start_matches('.');
                suffix.is_empty() || suffix == self.config.rp_id || suffix.ends_with(&format!(".{}", self.config.rp_id)) || self.config.rp_id.ends_with(&format!(".{suffix}"))
            })
        {
            return Err(AuthError::config(format!("Passkey `origin` must be set when a wildcard in `baseURL.allowedHosts` covers the passkey `rpID` \"{}\".", self.config.rp_id)));
        }
        Ok(())
    }
    fn server_endpoints(&self) -> Vec<alibi_core::endpoint::EndpointDefinition> {
        endpoint::definitions()
    }
    fn validate_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, _ctx: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointInput> {
        endpoint::validate(call)
    }
    async fn on_endpoint(&self, call: &alibi_core::endpoint::EndpointCall, ctx: &AuthContext<S>) -> AuthResult<alibi_core::endpoint::EndpointResponse> {
        if call.operation_id() == "passkeyVerifyAuthentication" { self.verify_authentication_endpoint(call, ctx).await } else if call.operation_id() == "passkeyVerifyRegistration" { self.verify_registration_endpoint(call, ctx).await } else if call.operation_id() == "passkeyGenerateAuthenticateOptions" { self.authentication_options_endpoint(call, ctx).await } else if call.operation_id() == "generatePasskeyRegistrationOptions" { self.registration_options_endpoint(call, ctx).await } else if call.operation_id() == "deletePasskey" { self.delete_endpoint(call, ctx).await } else if call.operation_id() == "updatePasskey" { self.update_endpoint(call, ctx).await } else { self.list_endpoint(call, ctx).await }
    }
    route_openapi_metadata!(S);
 }
}

impl std::fmt::Debug for PasskeyPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyPlugin").finish_non_exhaustive()
    }
}

// LCOV_EXCL_START
#[cfg(test)]
mod canonical_input_tests {
    use super::endpoint::{definitions, validate};
    use alibi_core::endpoint::{EndpointCall, EndpointOptions};
    use alibi_core::utils::json::{self, JsValue};
    use validator::Validate;

    fn assert_source_inputs(operation: &str, expected_cases: usize) {
        let fixture = json::parse_value(include_str!("canonical_input_cases.json")).unwrap();
        assert_eq!(fixture["better_auth"], "1.7.18");
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 36);
        let operation_id = if operation == "registration" {
            "passkeyVerifyRegistration"
        } else {
            "updatePasskey"
        };
        let definition = definitions()
            .into_iter()
            .find(|definition| definition.operation_id == operation_id)
            .unwrap();
        let mut matched = 0;
        for case in cases
            .iter()
            .filter(|case| case["operation"].as_str() == Some(operation))
        {
            matched += 1;
            let mode = case["mode"].as_str().unwrap();
            let mut input = case["input"].as_object().unwrap().clone();
            for key in case["input_undefined"].as_array().unwrap() {
                _ = input.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
            }
            let call = EndpointCall::new(
                &definition,
                Some(JsValue::Object(input)),
                None,
                EndpointOptions::default(),
            );
            let result = validate(&call);
            if !case["success"].as_bool().unwrap() {
                let alibi_core::AuthError::Api {
                    status, message, ..
                } = result.unwrap_err()
                else {
                    panic!("{operation}/{mode}: expected a validation error");
                };
                assert_eq!(status, 400);
                assert_eq!(
                    message,
                    case["error"].as_str().unwrap(),
                    "{operation}/{mode}"
                );
                continue;
            }
            let body = result
                .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"))
                .body
                .unwrap();
            let mut expected = case["expected"].as_object().unwrap().clone();
            for key in case["undefined"].as_array().unwrap() {
                _ = expected.insert(key.as_js_string().unwrap().clone(), JsValue::Undefined);
            }
            assert_eq!(body, JsValue::Object(expected), "{operation}/{mode}");
            let keys = JsValue::Array(
                body.as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .map(JsValue::String)
                    .collect(),
            );
            assert_eq!(keys, case["keys"], "{operation}/{mode}");
            assert_eq!(
                json::to_string(&body).unwrap(),
                case["wire"].as_str().unwrap(),
                "{operation}/{mode}"
            );
            if operation == "registration" {
                let request: super::types::VerifyRegistrationRequest =
                    json::from_value(body).unwrap();
                request
                    .validate()
                    .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"));
            } else {
                let request: super::types::UpdatePasskeyRequest = json::from_value(body)
                    .unwrap_or_else(|error| panic!("{operation}/{mode}: {error}"));
                request.validate().unwrap();
            }
        }
        assert_eq!(matched, expected_cases);
    }

    #[test]
    fn canonical_registration_input_matches_actual_source_schema() {
        assert_source_inputs("registration", 25);
    }

    #[test]
    fn canonical_update_input_matches_actual_source_schema() {
        assert_source_inputs("update", 11);
    }

    #[test]
    fn canonical_public_rename_output_keeps_utf16() {
        let value = json::parse_value(r#"{"passkey":{"name":"\ud800"}}"#).unwrap();
        let output: super::endpoint::PasskeyUpdated = json::from_value(value.clone()).unwrap();
        assert_eq!(
            json::to_js_value(&output.passkey).unwrap(),
            value["passkey"]
        );
    }

    #[tokio::test]
    async fn canonical_passkey_names_survive_memory_rename_and_list() {
        use super::handlers::{
            PasskeyHandlerOutcome, list_user_passkeys_core, registration_value, update_passkey_core,
        };
        let fixture = json::parse_value(include_str!(
            "../../../core/src/store/passkey_name_cases.json"
        ))
        .unwrap();
        let ctx = alibi_core::AuthContext::<alibi_core::store::stateless::StatelessSchema>::new(
            std::sync::Arc::new(crate::test_helpers::create_test_config()),
            std::sync::Arc::new(alibi_core::store::stateless::StatelessStore::default()),
        );
        let user = ctx
            .database
            .create_user(alibi_core::CreateUser::new().with_email("passkey-names@test"))
            .await
            .unwrap();
        let mut count = 0;
        for case in fixture["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|case| case["backend"] == "memory")
        {
            count += 1;
            let created = ctx
                .database
                .create_passkey(alibi_core::CreatePasskey {
                    user_id: user.id.clone(),
                    name: Some(case["registration"].as_js_string().unwrap().clone()),
                    credential_id: case["mode"].as_str().unwrap().into(),
                    public_key: "public".into(),
                    counter: 0,
                    device_type: "singleDevice".into(),
                    backed_up: false,
                    transports: None,
                    aaguid: None,
                })
                .await
                .unwrap();
            assert_eq!(
                registration_value(&created).unwrap()["name"],
                case["create"]
            );
            let request: super::types::UpdatePasskeyRequest = json::from_value(JsValue::Object(
                [
                    ("id".into(), JsValue::String(created.id.clone().into())),
                    ("name".into(), case["update_input"].clone()),
                ]
                .into(),
            ))
            .unwrap();
            let PasskeyHandlerOutcome::Success(renamed) =
                update_passkey_core(&request, &user, &ctx).await.unwrap()
            else {
                panic!("rename rejected")
            };
            assert_eq!(
                json::to_js_value(&renamed).unwrap()["passkey"]["name"],
                case["rename"]
            );
            let listed = list_user_passkeys_core(&user, &ctx).await.unwrap();
            assert_eq!(
                listed
                    .iter()
                    .find(|row| row["id"] == created.id.as_str())
                    .unwrap()["name"],
                case["list"]
            );
            let wire = json::to_string(&listed).unwrap();
            assert_eq!(json::parse_value(&wire).unwrap(), JsValue::Array(listed));
            let stored = ctx
                .database
                .get_passkey_by_id(&created.id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(stored.name.as_ref(), case["list"].as_js_string());
        }
        assert_eq!(count, 6);
    }
}

#[cfg(test)]
mod tests {
    mod revocation {
        //! Real CRL delivery must affect enrollment before any credential is committed.
        #![allow(
            clippy::indexing_slicing,
            reason = "Independent ceremony fixtures have asserted JSON and byte shapes"
        )]
        use super::*;
        use openssl::{
            asn1::Asn1Time,
            bn::BigNum,
            ec::{EcGroup, EcKey},
            hash::MessageDigest,
            nid::Nid,
            pkey::PKey,
            sign::Signer,
            x509::{X509, X509Extension, X509NameBuilder, extension::BasicConstraints},
        };
        use serde_cbor_2::Value as Cbor;
        use sha2::{Digest, Sha256};
        use std::{
            collections::BTreeMap,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[tokio::test]
        #[expect(
            clippy::panic_in_result_fn,
            reason = "Assert ceremony and persistence contracts while propagating fixture setup errors"
        )]
        async fn delivered_crl_rejects_revoked_attestation_without_persisting_credentials()
        -> Result<(), Box<dyn std::error::Error>> {
            let root_pem =
                include_str!("../../../../tests/compat/fixtures/passkey-attestation/ca.pem");
            let root = X509::from_pem(root_pem.as_bytes())?;
            let root_key = PKey::private_key_from_pem(include_bytes!(
                "../../../../tests/compat/fixtures/passkey-attestation/ca-key.pem"
            ))?;
            let crl =
                include_bytes!("../../../../tests/compat/fixtures/passkey-attestation/revoked.der");
            for (mode, serial, expected) in [
                ("revoked", 42, 400),
                ("allowed", 43, 200),
                ("malformed", 42, 200),
                ("http-error-valid-crl", 42, 400),
                ("unavailable", 42, 200),
            ] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let uri = format!("http://{}/revocation.der", listener.local_addr()?);
                let delivered = Arc::new(AtomicUsize::new(0));
                let count = delivered.clone();
                let server = tokio::spawn(async move {
                    loop {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let mut request = [0_u8; 4096];
                        let size = socket.read(&mut request).await.unwrap();
                        assert!(request[..size].starts_with(b"GET /revocation.der HTTP/1.1"));
                        count.fetch_add(1, Ordering::SeqCst);
                        if mode == "unavailable" {
                            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\nConnection: close\r\n\r\ntruncated").await.unwrap();
                            continue;
                        }
                        let bytes = if mode == "malformed" {
                            b"not a DER CRL".as_slice()
                        } else {
                            crl.as_slice()
                        };
                        let status = if mode == "http-error-valid-crl" {
                            "503 Unavailable"
                        } else {
                            "200 OK"
                        };
                        let header = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            bytes.len()
                        );
                        socket.write_all(header.as_bytes()).await.unwrap();
                        socket.write_all(bytes).await.unwrap();
                    }
                });
                let key = PKey::from_ec_key(EcKey::generate(
                    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?.as_ref(),
                )?)?;
                let mut name = X509NameBuilder::new()?;
                for (field, value) in [
                    ("C", "US"),
                    ("O", "Native test authenticator"),
                    ("OU", "Authenticator Attestation"),
                    ("CN", "Native CRL leaf"),
                ] {
                    name.append_entry_by_text(field, value)?;
                }
                let name = name.build();
                let mut leaf = X509::builder()?;
                leaf.set_version(2)?;
                leaf.set_serial_number(BigNum::from_u32(serial)?.to_asn1_integer()?.as_ref())?;
                leaf.set_subject_name(&name)?;
                leaf.set_issuer_name(root.subject_name())?;
                leaf.set_pubkey(&key)?;
                leaf.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
                leaf.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
                leaf.append_extension(BasicConstraints::new().critical().build()?)?;
                // No AKI/SKI: each ceremony must actually fetch its own local CRL, and
                // cannot inherit a process-global cached verdict from another case.
                #[expect(
                    deprecated,
                    reason = "OpenSSL exposes distribution-point configuration through this extension builder"
                )]
                let distribution = X509Extension::new_nid(
                    None,
                    None,
                    Nid::CRL_DISTRIBUTION_POINTS,
                    &format!("URI:{uri}"),
                )?;
                leaf.append_extension(distribution)?;
                leaf.sign(&root_key, MessageDigest::sha256())?;
                let leaf = leaf.build();
                let plugin = passkey_plugin().attestation_root_certificates(BTreeMap::from([(
                    "packed".into(),
                    vec![root_pem.into()],
                )]));
                let (ctx, user, session) = test_helpers::create_test_context_with_user(
                    CreateUser::new()
                        .with_email("revocation@fixture.test")
                        .with_name("CRL owner"),
                    Duration::hours(1),
                )
                .await;
                let options = plugin
                    .handle_generate_register_options(
                        &test_helpers::create_auth_request(
                            HttpMethod::Get,
                            "/passkey/generate-register-options",
                            Some(&session.token),
                            None,
                            HashMap::new(),
                        ),
                        &ctx,
                    )
                    .await?;
                let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
                let client = serde_json::to_vec(
                    &serde_json::json!({"type":"webauthn.create","challenge":issued["challenge"],"origin":"http://localhost:3000"}),
                )?;
                let credential_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
                let cose = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                    (Cbor::Integer(1), Cbor::Integer(1)),
                    (Cbor::Integer(3), Cbor::Integer(-8)),
                    (Cbor::Integer(-1), Cbor::Integer(6)),
                    (
                        Cbor::Integer(-2),
                        Cbor::Bytes(credential_key.verifying_key().as_bytes().to_vec()),
                    ),
                ])))?;
                let id = b"crl-enrollment";
                let mut data = Sha256::digest(b"localhost").to_vec();
                data.push(0x45);
                data.extend_from_slice(&1_u32.to_be_bytes());
                data.extend_from_slice(&[0; 16]);
                data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
                data.extend_from_slice(id);
                data.extend_from_slice(&cose);
                let mut signed = data.clone();
                signed.extend_from_slice(&Sha256::digest(&client));
                let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
                signer.update(&signed)?;
                let statement = Cbor::Map(BTreeMap::from([
                    (Cbor::Text("alg".into()), Cbor::Integer(-7)),
                    (
                        Cbor::Text("x5c".into()),
                        Cbor::Array(vec![Cbor::Bytes(leaf.to_der()?)]),
                    ),
                    (Cbor::Text("sig".into()), Cbor::Bytes(signer.sign_to_vec()?)),
                ]));
                let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                    (Cbor::Text("fmt".into()), Cbor::Text("packed".into())),
                    (Cbor::Text("authData".into()), Cbor::Bytes(data)),
                    (Cbor::Text("attStmt".into()), statement),
                ])))?;
                let response = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"attestationObject":URL_SAFE_NO_PAD.encode(attestation),"transports":["internal"]}});
                let mut request = test_helpers::create_auth_request(
                    HttpMethod::Post,
                    "/passkey/verify-registration",
                    Some(&session.token),
                    Some(serde_json::to_vec(
                        &serde_json::json!({"response":response}),
                    )?),
                    HashMap::new(),
                );
                write!(
                    request.headers.get_mut("cookie").unwrap(),
                    "; {}",
                    cookie_header(&options).split(';').next().unwrap()
                )?;
                let result = plugin.handle_verify_registration(&request, &ctx).await?;
                server.abort();
                assert_eq!(delivered.load(Ordering::SeqCst), 1, "{mode}");
                assert_eq!(
                    result.status,
                    expected,
                    "{mode}: {}",
                    String::from_utf8_lossy(&result.body)
                );
                let stored = ctx
                    .database
                    .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
                    .await?;
                if expected == 200 {
                    assert_eq!(stored.unwrap().user_id, user.id);
                } else {
                    assert!(stored.is_none());
                    assert!(
                        result
                            .headers
                            .get_all("set-cookie")
                            .all(|cookie| !cookie.contains("session_token="))
                    );
                }
                assert_eq!(ctx.database.get_user_sessions(&user.id).await?.len(), 1);
            }
            Ok(())
        }
    }
    use super::*;
    use crate::test_helpers;
    use alibi_core::{CreatePasskey, CreateUser, HttpMethod};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::Duration;
    use std::collections::HashMap;
    use std::fmt::Write;

    fn passkey_plugin() -> PasskeyPlugin {
        PasskeyPlugin::new()
            .rp_id("localhost")
            .rp_name("Better Auth Test")
            .origin("http://localhost:3000")
    }

    fn cookie_header(response: &AuthResponse) -> &str {
        response
            .headers
            .get("Set-Cookie")
            .expect("response should include a Set-Cookie header")
    }

    fn credential_id(label: &str) -> String {
        URL_SAFE_NO_PAD.encode(label.as_bytes())
    }

    #[test]
    fn test_extract_passkey_snapshot_fields_requires_all_expected_fields() {
        let value = serde_json::json!({
            "cred": {
                "counter": 7,
                "backup_state": true
            }
        });

        let err = webauthn::extract_passkey_snapshot_fields(&value).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Internal server error: Stored passkey JSON missing backup_eligible"
        );
    }

    #[test]
    fn test_extract_passkey_snapshot_fields_reads_expected_values() {
        let value = serde_json::json!({
            "cred": {
                "counter": 11,
                "backup_state": true,
                "backup_eligible": false
            }
        });

        let (counter, backed_up, backup_eligible) =
            webauthn::extract_passkey_snapshot_fields(&value).unwrap();
        assert_eq!(counter, 11);
        assert!(backed_up);
        assert!(!backup_eligible);
    }

    #[tokio::test]
    async fn test_generate_register_options_sets_cookie_and_uses_query_name() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: Some("Existing Key".into()),
                credential_id: credential_id("cred-existing"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: Some("usb,nfc".to_owned()),

                aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request(
            HttpMethod::Get,
            "/passkey/generate-register-options",
            Some(&session.token),
            None,
            HashMap::from([
                ("name".to_owned(), "Custom Account Label".to_owned()),
                (
                    "authenticatorAttachment".to_owned(),
                    "cross-platform".to_owned(),
                ),
            ]),
        );

        let response = plugin
            .handle_generate_register_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(cookie_header(&response).contains("better-auth-passkey="));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
        assert_eq!(
            (*(*(body).get("user").unwrap_or(&serde_json::Value::Null))
                .get("name")
                .unwrap_or(&serde_json::Value::Null)),
            "Custom Account Label"
        );
        assert_eq!(
            (*(*(body)
                .get("authenticatorSelection")
                .unwrap_or(&serde_json::Value::Null))
            .get("authenticatorAttachment")
            .unwrap_or(&serde_json::Value::Null)),
            "cross-platform"
        );
        assert_eq!(
            (*(*(*(body)
                .get("excludeCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null)),
            credential_id("cred-existing")
        );
        assert_eq!(
            (*(*(*(*(body)
                .get("excludeCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("transports")
            .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null)),
            "usb"
        );
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_is_get_and_sets_cookie_without_auth() {
        let plugin = passkey_plugin();
        let ctx = test_helpers::create_test_context().await;
        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/generate-authenticate-options",
            None,
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(cookie_header(&response).contains("better-auth-passkey="));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!((*(body).get("challenge").unwrap_or(&serde_json::Value::Null)).is_string());
        assert!(body.get("allowCredentials").is_none());
    }

    #[tokio::test]
    async fn test_generate_authenticate_options_with_auth_lists_allow_credentials() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: Some("Authenticator".into()),
                credential_id: credential_id("cred-auth"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: Some("internal".to_owned()),

                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/generate-authenticate-options",
            Some(&session.token),
            None,
        );

        let response = plugin
            .handle_generate_authenticate_options(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(*(*(body)
                .get("allowCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("id")
            .unwrap_or(&serde_json::Value::Null)),
            credential_id("cred-auth")
        );
        assert_eq!(
            (*(*(*(*(body)
                .get("allowCredentials")
                .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null))
            .get("transports")
            .unwrap_or(&serde_json::Value::Null))
            .get(0)
            .unwrap_or(&serde_json::Value::Null)),
            "internal"
        );
    }

    #[tokio::test]
    async fn test_verify_registration_without_challenge_cookie_returns_challenge_not_found() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        let body = serde_json::json!({
            "response": {
                "id": "fake-credential-id",
                "rawId": "ZmFrZS1yYXctaWQ",
                "response": {
                    "attestationObject": "ZmFrZS1hdHRlc3RhdGlvbg",
                    "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ"
                },
                "type": "public-key"
            }
        });
        let mut req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/verify-registration",
            Some(&session.token),
            Some(body),
        );
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let response = plugin.handle_verify_registration(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 400);

        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Challenge not found"
        );
    }

    #[tokio::test]
    async fn test_verify_authentication_without_challenge_cookie_returns_challenge_not_found() {
        let plugin = passkey_plugin();
        let ctx = test_helpers::create_test_context().await;

        let body = serde_json::json!({
            "response": {
                "id": credential_id("cred-auth"),
                "rawId": credential_id("cred-auth"),
                "response": {
                    "authenticatorData": "ZmFrZS1hdXRoLWRhdGE",
                    "clientDataJSON": "ZmFrZS1jbGllbnQtZGF0YQ",
                    "signature": "ZmFrZS1zaWduYXR1cmU"
                },
                "type": "public-key"
            }
        });
        let mut req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/verify-authentication",
            None,
            Some(body),
        );
        req.headers
            .insert("origin".to_owned(), "http://localhost:3000".to_owned());

        let response = plugin
            .handle_verify_authentication(&req, &ctx)
            .await
            .unwrap();
        assert_eq!(response.status, 400);

        let body_2: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body_2).get("message").unwrap_or(&serde_json::Value::Null)),
            "Challenge not found"
        );
    }

    #[tokio::test]
    async fn test_list_user_passkeys_omits_updated_at_and_retains_sql_null_fields() {
        let plugin = passkey_plugin();
        let (ctx, user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("passkey-test@example.com")
                .with_name("Passkey Tester"),
            Duration::hours(1),
        )
        .await;

        ctx.database
            .create_passkey(CreatePasskey {
                user_id: user.id.clone(),
                name: None,
                credential_id: credential_id("cred-list"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,

                aaguid: Some("00000000-0000-0000-0000-000000000000".to_owned()),
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_request_no_query(
            HttpMethod::Get,
            "/passkey/list-user-passkeys",
            Some(&session.token),
            None,
        );
        let response = plugin.handle_list_user_passkeys(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(
            (*(body).get(0).unwrap_or(&serde_json::Value::Null))
                .get("updatedAt")
                .is_none()
        );
        assert_eq!(
            (*(*(body).get(0).unwrap_or(&serde_json::Value::Null))
                .get("aaguid")
                .unwrap_or(&serde_json::Value::Null)),
            "00000000-0000-0000-0000-000000000000"
        );
        let passkey = body.get(0).unwrap();
        // The published SQL adapter returns nullable columns as own properties.
        assert_eq!(passkey.get("name"), Some(&serde_json::Value::Null));
        assert_eq!(passkey.get("transports"), Some(&serde_json::Value::Null));
    }

    #[tokio::test]
    async fn test_delete_passkey_non_owner_is_unauthorized() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("owner@example.com")
                .with_name("Owner"),
            Duration::hours(1),
        )
        .await;
        let other = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("other@example.com")
                .with_name("Other"),
        )
        .await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other.id.clone(),
                name: Some("Other Key".into()),
                credential_id: credential_id("cred-other-delete"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,

                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/delete-passkey",
            Some(&session.token),
            Some(serde_json::json!({ "id": passkey.id })),
        );

        let response = plugin.handle_delete_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        assert_eq!(response.body.len(), 0);
        let preserved = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preserved.name.as_ref().and_then(|name| name.as_str()),
            Some("Other Key")
        );
    }

    #[tokio::test]
    async fn test_update_passkey_non_owner_is_unauthorized() {
        let plugin = passkey_plugin();
        let (ctx, _user, session) = test_helpers::create_test_context_with_user(
            CreateUser::new()
                .with_email("owner@example.com")
                .with_name("Owner"),
            Duration::hours(1),
        )
        .await;
        let other = test_helpers::create_user(
            &ctx,
            CreateUser::new()
                .with_email("other@example.com")
                .with_name("Other"),
        )
        .await;

        let passkey = ctx
            .database
            .create_passkey(CreatePasskey {
                user_id: other.id.clone(),
                name: Some("Other Key".into()),
                credential_id: credential_id("cred-other-update"),
                public_key: "public-key".to_owned(),
                counter: 0,
                device_type: "singleDevice".to_owned(),
                backed_up: false,
                transports: None,

                aaguid: None,
            })
            .await
            .unwrap();

        let req = test_helpers::create_auth_json_request_no_query(
            HttpMethod::Post,
            "/passkey/update-passkey",
            Some(&session.token),
            Some(serde_json::json!({
                "id": passkey.id,
                "name": "Hijacked",
            })),
        );

        let response = plugin.handle_update_passkey(&req, &ctx).await.unwrap();
        assert_eq!(response.status, 401);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            (*(body).get("code").unwrap_or(&serde_json::Value::Null)),
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
        );
        let preserved = ctx
            .database
            .get_passkey_by_id(&passkey.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            preserved.name.as_ref().and_then(|name| name.as_str()),
            Some("Other Key")
        );
    }

    /// Previously persisted ceremonies keep both their codec and original Required policy.
    #[tokio::test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn raw_none_credential_sql_readback_keeps_original_key_and_hidden_codec()
    -> Result<(), Box<dyn std::error::Error>> {
        use serde_cbor_2::Value as Cbor;
        use sha2::{Digest, Sha256};
        use std::collections::BTreeMap;
        // The raw storage owner also protects the usable mismatched-key codec.
        // SDK observations cannot read the Native-only hidden credential column.
        for (algorithm, curve) in [(-8, 8), (-7, 6)] {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
            let plugin = passkey_plugin();
            let (ctx, user, session) = test_helpers::create_test_context_with_user(
                CreateUser::new()
                    .with_email("raw-codec-owner@fixture.test")
                    .with_name("Raw codec owner"),
                Duration::hours(1),
            )
            .await;
            let request = test_helpers::create_auth_request(
                HttpMethod::Get,
                "/passkey/generate-register-options",
                Some(&session.token),
                None,
                HashMap::new(),
            );
            let options = plugin
                .handle_generate_register_options(&request, &ctx)
                .await?;
            let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
            let key = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                (Cbor::Integer(1), Cbor::Integer(1)),
                (Cbor::Integer(3), Cbor::Integer(algorithm)),
                (Cbor::Integer(-1), Cbor::Integer(curve)),
                (
                    Cbor::Integer(-2),
                    Cbor::Bytes(signing.verifying_key().as_bytes().to_vec()),
                ),
            ])))?;
            let id = b"raw-none-actual-persisted-credential";
            let mut data = Sha256::digest(b"localhost").to_vec();
            data.push(0x41);
            data.extend_from_slice(&25_u32.to_be_bytes());
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(&u16::try_from(id.len())?.to_be_bytes());
            data.extend_from_slice(id);
            data.extend_from_slice(&key);
            let attestation = serde_cbor_2::to_vec(&Cbor::Map(BTreeMap::from([
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
                (Cbor::Text("authData".into()), Cbor::Bytes(data)),
            ])))?;
            let proof = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{
                "clientDataJSON":URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"type":"webauthn.create","challenge":(*(issued).get("challenge").expect("fixture contains the requested index")),"origin":"http://localhost:3000"}))?),
                "attestationObject":URL_SAFE_NO_PAD.encode(attestation),"transports":["internal"],
            }});
            let mut request_2 = test_helpers::create_auth_request(
                HttpMethod::Post,
                "/passkey/verify-registration",
                Some(&session.token),
                Some(serde_json::to_vec(&serde_json::json!({"response":proof}))?),
                HashMap::new(),
            );
            let issued_cookie = cookie_header(&options)
                .split(';')
                .next()
                .ok_or("issued challenge cookie required")?;
            _ = write!(
                request_2
                    .headers
                    .get_mut("cookie")
                    .ok_or("signed owner cookie required")?,
                "; {issued_cookie}"
            );
            let result = plugin.handle_verify_registration(&request_2, &ctx).await?;
            assert_eq!(result.status, 200);
            let wire: serde_json::Value = serde_json::from_slice(&result.body)?;
            assert!(wire.get("credential").is_none());
            let row = ctx
                .database
                .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
                .await?
                .ok_or("actual credential row required")?;
            assert_eq!(row.user_id, user.id);
            assert_eq!(row.counter, 25);
            assert_eq!(
                row.public_key,
                base64::engine::general_purpose::STANDARD.encode(&key)
            );
            if curve == 6 {
                use ed25519_dalek::Signer;
                let mut persisted = serde_json::to_value(&row)?;
                for control in [
                    "first",
                    "signature",
                    "counter",
                    "origin",
                    "challenge",
                    "rp",
                    "presence",
                    "backup",
                    "last",
                ] {
                    let successful = matches!(control, "first" | "last");
                    let counter = if matches!(control, "first" | "counter") {
                        26_u32
                    } else {
                        27_u32
                    };
                    let request = test_helpers::create_auth_request(
                        HttpMethod::Get,
                        "/passkey/generate-authenticate-options",
                        None,
                        None,
                        HashMap::new(),
                    );
                    let options = plugin
                        .handle_generate_authenticate_options(&request, &ctx)
                        .await?;
                    let issued: serde_json::Value = serde_json::from_slice(&options.body)?;
                    let challenge = issued
                        .get("challenge")
                        .expect("issued authentication challenge");
                    let client = serde_json::to_vec(
                        &serde_json::json!({"type":"webauthn.get", "challenge":if control == "challenge" { serde_json::Value::String("Zm9yZWlnbg".into()) } else { challenge.clone() },"origin":if control == "origin" { "http://foreign.test" } else { "http://localhost:3000" }}),
                    )?;
                    let mut data = Sha256::digest(if control == "rp" {
                        b"foreign.test".as_slice()
                    } else {
                        b"localhost".as_slice()
                    })
                    .to_vec();
                    data.push(match control {
                        "presence" => 0,
                        "backup" => 0x11,
                        _ => 1,
                    });
                    data.extend_from_slice(&counter.to_be_bytes());
                    let mut signed = data.clone();
                    signed.extend_from_slice(&Sha256::digest(&client));
                    let mut signature = signing.sign(&signed).to_bytes();
                    if control == "signature" {
                        signature[0] ^= 1;
                    }
                    let response = serde_json::json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":{},"response":{
                        "clientDataJSON":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(data),"signature":URL_SAFE_NO_PAD.encode(signature)
                    }});
                    let mut request = test_helpers::create_auth_request(
                        HttpMethod::Post,
                        "/passkey/verify-authentication",
                        None,
                        Some(serde_json::to_vec(
                            &serde_json::json!({"response":response}),
                        )?),
                        HashMap::new(),
                    );
                    request.headers.insert(
                        "cookie".into(),
                        cookie_header(&options)
                            .split(';')
                            .next()
                            .ok_or("issued authentication cookie required")?
                            .into(),
                    );
                    let result = plugin.handle_verify_authentication(&request, &ctx).await?;
                    assert_eq!(
                        result.status,
                        if successful {
                            200
                        } else if control == "signature" {
                            401
                        } else {
                            400
                        },
                        "{control}"
                    );
                    let updated = ctx
                        .database
                        .get_passkey_by_credential_id(&URL_SAFE_NO_PAD.encode(id))
                        .await?
                        .ok_or("updated raw row required")?;
                    if !successful {
                        let wire: serde_json::Value = serde_json::from_slice(&result.body)?;
                        assert_eq!(
                            wire.get("code"),
                            Some(&serde_json::json!("AUTHENTICATION_FAILED")),
                            "{control}"
                        );
                        assert!(
                            result
                                .headers
                                .get_all("set-cookie")
                                .all(|cookie| !cookie.contains("session_token="))
                        );
                        assert_eq!(serde_json::to_value(&updated)?, persisted, "{control}");
                        assert_eq!(ctx.database.get_user_sessions(&user.id).await?.len(), 2);
                        continue;
                    }
                    persisted = serde_json::to_value(&updated)?;
                    assert_eq!(updated.public_key, row.public_key);
                    assert_eq!(updated.credential_id, row.credential_id);
                    assert_eq!(updated.user_id, row.user_id);
                    assert_eq!(updated.counter, u64::from(counter));
                }
            }
            assert_eq!(
                ctx.database.get_user_sessions(&user.id).await?.len(),
                if curve == 6 { 3 } else { 1 }
            );
        }
        Ok(())
    }
}
// LCOV_EXCL_STOP
