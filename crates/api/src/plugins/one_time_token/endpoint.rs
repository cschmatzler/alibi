use super::{OneTimeTokenPlugin, OneTimeTokenSession};
use crate::plugins::authentication_helpers::JsonField;
use crate::plugins::endpoint::{definition, validate_fields};
use better_auth_core::HttpMethod;
use better_auth_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use better_auth_core::session::SessionRequest;
use better_auth_core::utils::cookie_utils::{
    create_session_cookie_with_max_age, create_session_like_cookie, related_cookie_name,
    sign_cookie_value, verify_cookie_value,
};
use better_auth_core::utils::json::JsValue;
use better_auth_core::{AuthContext, AuthError, AuthResult, AuthSchema};
use chrono::Utc;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct OneTimeTokenOutput {
    pub token: String,
}

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition(
            "generateOneTimeToken",
            "generateOneTimeToken",
            Some("/one-time-token/generate"),
            HttpMethod::Get,
        ),
        definition(
            "verifyOneTimeToken",
            "verifyOneTimeToken",
            Some("/one-time-token/verify"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    Ok(EndpointInput {
        body: if call.operation_id() == "verifyOneTimeToken" {
            Some(validate_fields(
                call.body(),
                "body",
                &[JsonField::string("token", true)],
            )?)
        } else {
            call.body().cloned()
        },
        query: call.query().cloned(),
    })
}

impl OneTimeTokenPlugin {
    /// Generate from genuine credentials through installed middleware and hooks.
    #[must_use]
    pub const fn generate_endpoint() -> ServerEndpoint<OneTimeTokenOutput> {
        ServerEndpoint::new("one-time-token", "generateOneTimeToken")
    }

    /// Consume a token through the registered endpoint, including cookie publication.
    #[must_use]
    pub fn verify_endpoint(token: impl Into<String>) -> ServerEndpoint<OneTimeTokenSession> {
        ServerEndpoint::new("one-time-token", "verifyOneTimeToken").with_body_value(
            JsValue::Object(
                [("token".into(), JsValue::String(token.into()))]
                    .into_iter()
                    .collect(),
            ),
        )
    }

    pub(super) async fn call_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        if call.operation_id() == "generateOneTimeToken" {
            let (user, session) = ctx.require_cached_session(call).await.map_err(|error| {
                if matches!(error, AuthError::Unauthenticated) {
                    super::unauthorized()
                } else {
                    error
                }
            })?;
            let user = match &user {
                better_auth_core::AuthenticatedUser::Stored(user) => ctx.user_view(user),
                better_auth_core::AuthenticatedUser::Cached(user) => (**user).clone(),
            };
            let session = OneTimeTokenSession {
                user,
                session: call.virtual_session().unwrap_or(session),
            };
            call.record_authenticated_session(session.user.clone(), session.session.clone());
            if self.config.disable_client_request && call.request().is_some() {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "Client requests are disabled".into(),
                });
            }
            EndpointResponse::json(
                &serde_json::json!({"token": self.generate_for_session(&session, call.request(), ctx).await?}),
            )
        } else {
            #[derive(Deserialize)]
            struct Body {
                token: String,
            }
            let body: Body = call.body_as()?;
            let (user, stored_session) = self.consume_stored_session(&body.token, ctx).await?;
            let session = OneTimeTokenSession {
                user: ctx.user_view(&user),
                session: ctx.session_view(&stored_session),
            };
            if !self.config.disable_set_session_cookie {
                let dont_remember = call
                    .session_headers()
                    .get("cookie")
                    .and_then(|headers| {
                        cookie::Cookie::split_parse(headers)
                            .flatten()
                            .find(|cookie| {
                                cookie.name() == related_cookie_name(&ctx.config, "dont_remember")
                            })
                            .map(|cookie| cookie.value().to_owned())
                    })
                    .and_then(|value| verify_cookie_value(&value, &ctx.config.secret))
                    .is_some_and(|value| !value.is_empty());
                call.queue_response_header(
                    "set-cookie",
                    create_session_cookie_with_max_age(
                        Some(&session.session.token),
                        (!dont_remember).then_some(ctx.config.session.expires_in.num_seconds()),
                        &ctx.config,
                    ),
                );
                if dont_remember {
                    call.queue_response_header(
                        "set-cookie",
                        create_session_like_cookie(
                            &related_cookie_name(&ctx.config, "dont_remember"),
                            &sign_cookie_value("true", &ctx.config.secret),
                            None,
                            &ctx.config,
                        ),
                    );
                }
                better_auth_core::cache::runtime::emit_issuance(ctx, &user, &stored_session)
                    .await?;
            }
            if session.session.expires_at < Utc::now() {
                return Err(AuthError::Api {
                    status: 400,
                    code: None,
                    message: "Session expired".into(),
                });
            }
            EndpointResponse::json(&session)
        }
    }
}
