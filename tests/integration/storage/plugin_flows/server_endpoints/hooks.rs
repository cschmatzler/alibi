//! Installed application hooks around a real OTP issuance, including failures
//! before and after persistence. No mock endpoint manufactures the saved proof.
use super::*;
use async_trait::async_trait;
use better_auth_core::endpoint::{
    BeforeEndpointAction, EndpointCall, EndpointContextPatch, EndpointHook, EndpointResponse,
};
use better_auth_core::{AuthContext, AuthError, AuthResult};

backend_tests!(
    logical_endpoint_hooks_preserve_order_failure_and_persistence_contracts,
    concurrent_nested_typed_calls_isolate_principals_frames_and_headers
);
postgres_tests!(
    logical_endpoint_hooks_preserve_order_failure_and_persistence_contracts,
    concurrent_nested_typed_calls_isolate_principals_frames_and_headers
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Patch,
    Respond,
    Reject,
    BeforeApi,
    BeforeOrdinary,
    Matcher,
    AfterApi,
    AfterOrdinary,
    InvalidPatch,
    DecodeAfter,
}

struct Hook {
    number: u8,
    mode: Mode,
    events: Arc<Mutex<Vec<String>>>,
}
impl Hook {
    fn event(&self, name: &str) {
        self.events
            .lock()
            .unwrap()
            .push(format!("{name}{}", self.number));
    }
    fn cookie(&self, phase: &str) -> String {
        format!("hook{}={phase}; Path=/; HttpOnly", self.number)
    }
}
fn veto() -> AuthError {
    AuthError::Api {
        status: 403,
        code: Some("APPLICATION_VETO".into()),
        message: "Application veto".into(),
    }
}

#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for Hook {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        if call.operation_id() != "createEmailVerificationOTP" {
            return Ok(false);
        }
        self.event("match");
        // Later matchers still see the caller's original logical frame. Patches
        // accumulate until validation; a middleware default is not a caller input.
        assert!(call.method().is_none());
        assert!(call.headers().is_none());
        assert_eq!(
            call.body().unwrap().get("email").unwrap().as_str(),
            Some("original@example.test")
        );
        if self.number == 2 && self.mode == Mode::Matcher {
            return Err(AuthError::internal("private matcher failure"));
        }
        Ok(true)
    }
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        self.event("before");
        assert!(call.method().is_none());
        assert_eq!(call.path(), Some("/"));
        call.queue_response_header("set-cookie", self.cookie("before"));
        if self.number == 2 {
            match self.mode {
                Mode::Respond => {
                    return Ok(Some(BeforeEndpointAction::Respond(
                        EndpointResponse::json(&"intercepted")?.with_status(202),
                    )));
                }
                Mode::Reject => {
                    return Ok(Some(BeforeEndpointAction::Reject(EndpointResponse::error(
                        veto(),
                    ))));
                }
                Mode::BeforeApi => return Err(veto()),
                Mode::BeforeOrdinary => {
                    return Err(AuthError::internal("private callback failure"));
                }
                _ => {}
            }
        }
        let patch = if self.number == 1 {
            json!({"type":"sign-in"})
        } else if self.mode == Mode::InvalidPatch {
            json!({"email":"patched@example.test", "type":"unsupported"})
        } else {
            json!({"email":"patched@example.test"})
        };
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                body: Some(parse_value(&patch.to_string())?),
                ..Default::default()
            },
        ))))
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "createEmailVerificationOTP")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        self.event("after");
        assert_eq!(
            call.body().unwrap().get("email").unwrap().as_str(),
            Some("patched@example.test")
        );
        call.queue_response_header("set-cookie", self.cookie("after"));
        if self.number == 1 {
            match self.mode {
                Mode::AfterApi => return Err(veto()),
                Mode::AfterOrdinary => return Err(AuthError::internal("private after failure")),
                _ => {}
            }
        }
        if self.number == 2 && self.mode == Mode::DecodeAfter {
            return Ok(
                EndpointResponse::json(&json!({"application":"changed response type"}))?
                    .with_status(202),
            );
        }
        Ok(response.with_status(202))
    }
}

async fn logical_endpoint_hooks_preserve_order_failure_and_persistence_contracts<B: Backend>(
    db: Db,
) -> TestResult {
    for mode in [
        Mode::Patch,
        Mode::Respond,
        Mode::Reject,
        Mode::BeforeApi,
        Mode::BeforeOrdinary,
        Mode::Matcher,
        Mode::AfterApi,
        Mode::AfterOrdinary,
        Mode::InvalidPatch,
        Mode::DecodeAfter,
    ] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let events = Arc::new(Mutex::new(Vec::new()));
        let auth = builder::<B>(&connection)
            .endpoint_hook(Hook {
                number: 1,
                mode,
                events: events.clone(),
            })
            .endpoint_hook(Hook {
                number: 2,
                mode,
                events: events.clone(),
            })
            .plugin(EmailOtpPlugin::new(EmailOtpConfig::default()))
            .build()
            .await?;
        if mode == Mode::Patch {
            let missing = auth
                .dispatch_endpoint(JwtPlugin::token_endpoint(), EndpointOptions::default())
                .await
                .unwrap_err();
            assert_eq!(missing.error.status_code(), 404);
            assert!(missing.to_string().contains("not installed"));
            let unknown = auth
                .dispatch_endpoint(
                    better_auth_core::endpoint::ServerEndpoint::<String>::new(
                        "email-otp",
                        "unregistered-operation",
                    ),
                    EndpointOptions::default(),
                )
                .await
                .unwrap_err();
            assert_eq!(unknown.error.status_code(), 404);
            assert!(unknown.to_string().contains("not registered"));
            assert!(events.lock().unwrap().is_empty());
            assert_eq!(db.count("verifications").await?, 0);
        }
        let endpoint = EmailOtpPlugin::create_verification_otp_endpoint(
            "original@example.test",
            EmailOtpType::SignIn,
        )
        .with_body_value(parse_value(
            r#"{"email":"original@example.test","type":"invalid-until-hooks-patch-it"}"#,
        )?);
        let result = auth
            .dispatch_endpoint(endpoint, EndpointOptions::default())
            .await;
        let mut expected = vec!["match1", "before1", "match2"];
        if mode != Mode::Matcher {
            expected.push("before2");
        }
        let persisted = matches!(
            mode,
            Mode::Patch | Mode::AfterApi | Mode::AfterOrdinary | Mode::DecodeAfter
        );
        if persisted || mode == Mode::InvalidPatch {
            expected.push("after1");
        }
        if matches!(
            mode,
            Mode::Patch | Mode::AfterApi | Mode::DecodeAfter | Mode::InvalidPatch
        ) {
            expected.push("after2");
        }
        assert_eq!(*events.lock().unwrap(), expected, "{mode:?}");
        assert_eq!(
            db.count("verifications").await?,
            i64::from(persisted),
            "{mode:?}"
        );
        let read = auth
            .dispatch_endpoint(
                EmailOtpPlugin::get_verification_otp_endpoint(
                    "patched@example.test",
                    EmailOtpType::SignIn,
                ),
                EndpointOptions::default(),
            )
            .await?
            .decode()?
            .otp;
        assert_eq!(read.is_some(), persisted, "{mode:?}");
        assert!(
            auth.dispatch_endpoint(
                EmailOtpPlugin::get_verification_otp_endpoint(
                    "original@example.test",
                    EmailOtpType::SignIn
                ),
                EndpointOptions::default()
            )
            .await?
            .decode()?
            .otp
            .is_none()
        );
        match mode {
            Mode::InvalidPatch => {
                let error = result.unwrap_err();
                assert_eq!(error.error.status_code(), 400);
                assert!(error.to_string().contains("type"));
            }
            Mode::DecodeAfter => {
                let output = result?;
                assert_eq!(output.status(), Some(202));
                assert_eq!(
                    output.value().get("application").unwrap().as_str(),
                    Some("changed response type")
                );
                assert!(output.decode().is_err());
                // A decode error is a caller-side projection failure; the OTP
                // already created by the real handler remains usable.
                let accepted = call(
                    &auth,
                    request(
                        "/sign-in/email-otp",
                        Some(json!({"email":"patched@example.test","otp":read.unwrap()})),
                        "",
                    ),
                    200,
                )
                .await;
                authenticated(&auth, &cookies(&accepted), "patched@example.test").await;
            }
            Mode::Patch | Mode::Respond => {
                let output = result?;
                assert_eq!(output.status(), Some(202));
                assert_eq!(
                    output.headers().get_all("set-cookie").collect::<Vec<_>>(),
                    if mode == Mode::Patch {
                        [
                            "hook1=after; Path=/; HttpOnly",
                            "hook2=after; Path=/; HttpOnly",
                        ]
                    } else {
                        [
                            "hook1=before; Path=/; HttpOnly",
                            "hook2=before; Path=/; HttpOnly",
                        ]
                    }
                );
                if mode == Mode::Respond {
                    assert_eq!(output.decode()?, "intercepted");
                } else {
                    let code = output.decode()?;
                    assert_eq!(Some(&code), read.as_ref());
                    let accepted = call(
                        &auth,
                        request(
                            "/sign-in/email-otp",
                            Some(json!({"email":"patched@example.test","otp":code})),
                            "",
                        ),
                        200,
                    )
                    .await;
                    authenticated(&auth, &cookies(&accepted), "patched@example.test").await;
                }
            }
            Mode::Reject | Mode::BeforeApi | Mode::AfterApi => {
                let error = result.unwrap_err();
                assert_eq!(error.error.status_code(), 403);
                let cookies = error
                    .headers
                    .unwrap()
                    .get_all("set-cookie")
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("|");
                if mode == Mode::AfterApi {
                    assert_eq!(
                        cookies,
                        "hook1=after; Path=/; HttpOnly|hook2=after; Path=/; HttpOnly"
                    );
                } else {
                    assert_eq!(cookies, "hook2=before; Path=/; HttpOnly");
                }
            }
            Mode::BeforeOrdinary | Mode::AfterOrdinary | Mode::Matcher => {
                let error = result.unwrap_err();
                assert_eq!(error.error.status_code(), 500);
                assert!(error.headers.is_none());
                if mode == Mode::Matcher {
                    assert!(!error.to_string().contains("private matcher failure"));
                }
            }
        }
        B::close(connection).await?;
    }
    Ok(())
}

struct IsolationHook<S: AuthSchema> {
    auth: Arc<std::sync::OnceLock<std::sync::Weak<BetterAuth<S>>>>,
}
#[async_trait]
impl<S: AuthSchema> EndpointHook<S> for IsolationHook<S> {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call
            .headers()
            .is_some_and(|headers| headers.contains_key("x-call")))
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call
            .headers()
            .is_some_and(|headers| headers.contains_key("x-call")))
    }
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<BeforeEndpointAction>> {
        let tag = call.headers().unwrap()["x-call"].clone();
        tokio::task::yield_now().await;
        let frame = better_auth_core::endpoint::current_endpoint_call_context().unwrap();
        assert_eq!(frame.headers().unwrap()["x-call"], tag);
        assert_eq!(
            frame.headers().unwrap()["cookie"],
            call.headers().unwrap()["cookie"]
        );
        if let Some(cookie) = call.headers().unwrap().get("x-nested-cookie") {
            let auth = self.auth.get().unwrap().upgrade().unwrap();
            let nested = auth
                .dispatch_endpoint(
                    JwtPlugin::token_endpoint(),
                    EndpointOptions {
                        headers: Some(
                            [
                                ("cookie".into(), cookie.clone()),
                                ("x-call".into(), format!("nested-{tag}")),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| error.error)?;
            assert_eq!(
                nested.headers().get("x-result").map(String::as_str),
                Some(format!("nested-{tag}").as_str())
            );
            use base64::Engine as _;
            let jwt = nested
                .decode()
                .map_err(|error| AuthError::internal(error.to_string()))?
                .token;
            let claims: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(jwt.split('.').nth(1).unwrap())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(claims["sub"], call.headers().unwrap()["x-nested-owner"]);
            let restored = better_auth_core::endpoint::current_endpoint_call_context().unwrap();
            assert_eq!(
                restored.headers().unwrap()["x-call"],
                tag,
                "nested calls restore the enclosing frame"
            );
            assert_eq!(
                restored.headers().unwrap()["cookie"],
                call.headers().unwrap()["cookie"]
            );
        }
        Ok(Some(BeforeEndpointAction::Patch(Box::new(
            EndpointContextPatch {
                headers: Some([("x-patched".into(), "yes".into())].into_iter().collect()),
                ..Default::default()
            },
        ))))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        tokio::task::yield_now().await;
        let frame = better_auth_core::endpoint::current_endpoint_call_context().unwrap();
        let tag = &call.headers().unwrap()["x-call"];
        assert_eq!(call.headers().unwrap()["x-patched"], "yes");
        assert_eq!(frame.headers().unwrap()["x-patched"], "yes");
        assert_eq!(frame.headers().unwrap()["x-call"], *tag);
        call.queue_response_header("x-result", tag);
        Ok(response)
    }
}

async fn concurrent_nested_typed_calls_isolate_principals_frames_and_headers<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let slot = Arc::new(std::sync::OnceLock::new());
    let auth = Arc::new(
        builder::<B>(&connection)
            .endpoint_hook(IsolationHook { auth: slot.clone() })
            .plugin(JwtPlugin::new())
            .build()
            .await?,
    );
    assert!(slot.set(Arc::downgrade(&auth)).is_ok());
    let left = signup(&auth, "typed-left@example.test").await;
    let right = signup(&auth, "typed-right@example.test").await;
    let sessions = db.table("sessions").await?;
    let options = |tag: &str, owner: &AuthResponse, nested: &AuthResponse| EndpointOptions {
        headers: Some(
            [
                ("cookie".into(), cookies(owner)),
                ("x-call".into(), tag.into()),
                ("x-nested-cookie".into(), cookies(nested)),
                (
                    "x-nested-owner".into(),
                    body(nested)["user"]["id"].as_str().unwrap().into(),
                ),
            ]
            .into_iter()
            .collect(),
        ),
        ..Default::default()
    };
    let (first, second) = tokio::join!(
        auth.dispatch_endpoint(JwtPlugin::token_endpoint(), options("left", &left, &right)),
        auth.dispatch_endpoint(JwtPlugin::token_endpoint(), options("right", &right, &left))
    );
    let published = auth
        .dispatch_endpoint(JwtPlugin::jwks_endpoint(), EndpointOptions::default())
        .await?
        .decode()?;
    let keys: jsonwebtoken::jwk::JwkSet = serde_json::from_value(published)?;
    for (response, tag, owner) in [(first?, "left", &left), (second?, "right", &right)] {
        assert_eq!(
            response.headers().get_all("x-result").collect::<Vec<_>>(),
            vec![tag]
        );
        let token = response.decode()?.token;
        let header = jsonwebtoken::decode_header(&token)?;
        let key = keys.find(header.kid.as_deref().unwrap()).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_issuer(&[ORIGIN]);
        validation.set_audience(&[ORIGIN]);
        let claims = jsonwebtoken::decode::<Value>(
            &token,
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?
        .claims;
        assert_eq!(claims["sub"], body(owner)["user"]["id"]);
    }
    assert_eq!(db.table("sessions").await?, sessions);
    assert!(better_auth_core::endpoint::current_endpoint_call_context().is_none());
    assert!(better_auth_core::hooks::current_request_hook_context().is_none());
    B::close(connection).await
}
