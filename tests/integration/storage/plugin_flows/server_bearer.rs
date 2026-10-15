//! Bearer middleware must authenticate genuine direct server calls and publish real signed cookies.
use super::*;
use alibi::endpoint::{EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::{BearerConfig, BearerPlugin};
backend_tests!(server_bearer_authenticates_headers_and_publishes_signed_session_tokens);
postgres_tests!(server_bearer_authenticates_headers_and_publishes_signed_session_tokens);
struct Exposure;
#[async_trait::async_trait]
impl<S: AuthSchema> alibi::AuthPlugin<S> for Exposure {
    fn name(&self) -> &'static str {
        "exposure"
    }
    fn routes(&self) -> Vec<alibi::AuthRoute> {
        vec![]
    }
    fn endpoint_hooks(&self) -> Vec<&dyn EndpointHook<S>> {
        vec![self]
    }
    async fn on_request(
        &self,
        _req: &AuthRequest,
        _ctx: &alibi::AuthContext<S>,
    ) -> alibi::AuthResult<Option<AuthResponse>> {
        Ok(None)
    }
}
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for Exposure {
    async fn after(
        &self,
        _call: &alibi::endpoint::EndpointCall,
        _ctx: &alibi::AuthContext<S>,
        response: EndpointResponse,
    ) -> alibi::AuthResult<EndpointResponse> {
        Ok(response.with_header(
            "access-control-expose-headers",
            "X-First, X-First, X-Second",
        ))
    }
}
async fn get<S: AuthSchema>(
    auth: &Alibi<S>,
    headers: Option<std::collections::HashMap<String, String>>,
    request: Option<AuthRequest>,
) -> alibi::AuthResult<AuthResponse> {
    let output = Box::pin(auth.dispatch_endpoint(
        ServerEndpoint::<Value>::new("session-management", "getSession"),
        EndpointOptions {
            headers,
            request,
            ..Default::default()
        },
    ))
    .await
    .map_err(|error| error.error)?;
    output.into_response()
}
async fn server_bearer_authenticates_headers_and_publishes_signed_session_tokens<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for signed_only in [false, true] {
        let builder = builder::<B>(&connection);
        let builder = if signed_only {
            builder.plugin(Exposure)
        } else {
            builder
        };
        let auth = builder
            .plugin(BearerPlugin::with_config(BearerConfig {
                require_signature: signed_only,
            }))
            .build()
            .await?;
        let mut owners = Vec::new();
        for suffix in ["owner", "other"] {
            let output=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":format!("sdk-bearer-{signed_only}-{suffix}@example.com"),"password":"a-native-password-123","name":suffix}))?,EndpointOptions::default())).await.map_err(|error|error.error)?.into_response()?;
            assert_eq!(output.status, 200);
            let value = body(&output);
            let signed = output
                .headers
                .get("set-auth-token")
                .expect("logical issuance must expose the actual signed cookie")
                .to_owned();
            assert!(
                output
                    .headers
                    .get("access-control-expose-headers")
                    .is_some_and(|value| value.split(", ").any(|name| name == "set-auth-token"))
            );
            if signed_only {
                assert_eq!(
                    output
                        .headers
                        .get("access-control-expose-headers")
                        .map(String::as_str),
                    Some("X-First, X-Second, set-auth-token")
                );
            }
            owners.push((
                value["token"].as_str().unwrap().to_owned(),
                signed,
                value["user"]["email"].as_str().unwrap().to_owned(),
            ));
        }
        let (token, signed, email) = owners.first().unwrap();
        let other = owners.get(1).unwrap();
        let unsigned = get(
            &auth,
            Some(
                [("authorization".into(), format!("Bearer {token}"))]
                    .into_iter()
                    .collect(),
            ),
            None,
        )
        .await?;
        if signed_only {
            assert_eq!(body(&unsigned), Value::Null);
        } else {
            assert_eq!(body(&unsigned)["user"]["email"], *email);
        }
        let verified = get(
            &auth,
            Some(
                [("authorization".into(), format!("Bearer {signed}"))]
                    .into_iter()
                    .collect(),
            ),
            None,
        )
        .await?;
        assert_eq!(body(&verified)["user"]["email"], *email);
        let cookie = format!("better-auth.session_token={signed}");
        let forged = get(
            &auth,
            Some(
                [
                    ("authorization".into(), "Bearer forged.signature".into()),
                    ("cookie".into(), cookie.clone()),
                ]
                .into_iter()
                .collect(),
            ),
            None,
        )
        .await?;
        assert_eq!(body(&forged)["user"]["email"], *email);
        let replaced = get(
            &auth,
            Some(
                [
                    ("authorization".into(), format!("Bearer {}", other.1)),
                    ("cookie".into(), cookie),
                ]
                .into_iter()
                .collect(),
            ),
            None,
        )
        .await?;
        assert_eq!(body(&replaced)["user"]["email"], other.2);
        let mut original = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        _ = original
            .headers
            .insert("authorization".into(), format!("Bearer {}", other.1));
        let preferred = get(
            &auth,
            Some(
                [("authorization".into(), format!("Bearer {signed}"))]
                    .into_iter()
                    .collect(),
            ),
            Some(original),
        )
        .await?;
        assert_eq!(body(&preferred)["user"]["email"], other.2);
        let mut original = AuthRequest::new(HttpMethod::Get, "/api/auth/get-session");
        _ = original
            .headers
            .insert("authorization".into(), format!("Bearer {signed}"));
        let request_only = get(&auth, None, Some(original)).await?;
        assert_eq!(body(&request_only)["user"]["email"], *email);
    }
    Ok(())
}
