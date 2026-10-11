//! Logical path params and redirect errors preserve the issued reset proof.
use super::auth_probe::fast_builder;
use super::*;
use alibi::endpoint::{
    EndpointCall, EndpointHook, EndpointOptions, EndpointResponse, ServerEndpoint,
};
use alibi::plugins::password_management::{
    PasswordManagementPlugin, ResetPasswordCallbackQuery, SendResetPassword,
};
use alibi::{AuthContext, AuthResult};

#[derive(Default)]
struct Delivery(Mutex<Vec<String>>);
#[async_trait::async_trait]
impl SendResetPassword for Delivery {
    async fn send(&self, _: &Value, _: &str, token: &str) -> AuthResult<()> {
        self.0.lock().unwrap().push(token.into());
        Ok(())
    }
}
#[derive(Clone, Default)]
struct Observer(Arc<Mutex<Vec<Value>>>);
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for Observer {
    fn matches_before(&self, call: &EndpointCall, _: &AuthContext<S>) -> AuthResult<bool> {
        Ok(call.operation_id() == "resetPasswordCallback"
            && call.body().and_then(|body| body.get("token")).is_some())
    }
    async fn before(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
    ) -> AuthResult<Option<alibi::endpoint::BeforeEndpointAction>> {
        let token = call.body().and_then(|body| body.get("token")).unwrap();
        Ok(Some(alibi::endpoint::BeforeEndpointAction::Patch(
            Box::new(alibi::endpoint::EndpointContextPatch {
                params: Some(alibi::utils::json::parse_value(
                    &json!({"token":token}).to_string(),
                )?),
                ..Default::default()
            }),
        )))
    }
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(call.operation_id() == "resetPasswordCallback")
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert!(call.session().is_none());
        assert_eq!(call.path(), Some("/reset-password/:token"));
        if call.body().and_then(|body| body.get("token")).is_some() {
            let current = alibi::endpoint::current_endpoint_call_context().unwrap();
            assert_eq!(
                current
                    .params()
                    .unwrap()
                    .get("token")
                    .and_then(alibi::utils::json::JsValue::as_str),
                Some("missing-proof")
            );
        }
        self.0
            .lock()
            .unwrap()
            .push(serde_json::to_value(call.params().unwrap())?);
        if response.status() == Some(302) {
            assert!(response.error_body_is_absent());
        }
        Ok(response.with_header("x-callback", "logical"))
    }
}
fn endpoint(token: &str, query: &Value) -> AuthResult<ServerEndpoint<()>> {
    ServerEndpoint::new("password-management", "requestPasswordResetCallback")
        .with_params(&json!({"token":token}))?
        .with_query(query)
}
backend_tests!(server_reset_callback_preserves_proof_and_original_logical_params);
async fn server_reset_callback_preserves_proof_and_original_logical_params<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let delivery = Arc::new(Delivery::default());
    let observer = Observer::default();
    let auth = fast_builder::<B>(&connection)
        .plugin(PasswordManagementPlugin::new().send_reset_password(delivery.clone()))
        .endpoint_hook(observer.clone())
        .build()
        .await?;
    let owner = signup(&auth, "callback-owner@example.test").await;
    let _ = signup(&auth, "callback-foreign@example.test").await;
    let _ = call(
        &auth,
        request(
            "/request-password-reset",
            Some(json!({"email":"callback-owner@example.test"})),
            "",
        ),
        200,
    )
    .await;
    let token = delivery.0.lock().unwrap()[0].clone();
    let before = db
        .tables(&["users", "accounts", "sessions", "verifications"])
        .await?;
    for query in [
        json!({}),
        json!(null),
        json!({"callbackURL":null}),
        json!({"callbackURL":7}),
    ] {
        let denied = auth
            .dispatch_endpoint(endpoint(&token, &query)?, EndpointOptions::default())
            .await
            .unwrap_err();
        assert_eq!(denied.error.status_code(), 400, "{denied}");
        assert!(denied.error.to_string().contains("[query"));
    }
    for (proof, callback, key, value) in [
        (
            "missing-proof",
            "/reset?application=retained#step",
            "error",
            "INVALID_TOKEN",
        ),
        (
            token.as_str(),
            "/reset?application=retained#step",
            "token",
            token.as_str(),
        ),
        (
            token.as_str(),
            "https://external.example/reset?application=retained#step",
            "token",
            token.as_str(),
        ),
        (token.as_str(), "", "error", "INVALID_TOKEN"),
    ] {
        let redirect = auth
            .dispatch_endpoint(
                PasswordManagementPlugin::request_password_reset_callback_endpoint(
                    proof,
                    &ResetPasswordCallbackQuery {
                        callback_url: callback.into(),
                    },
                )?,
                EndpointOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(redirect.error.status_code(), 302, "{redirect}");
        assert!(redirect.body_absent);
        assert!(redirect.body.is_none());
        let headers = redirect.headers.unwrap();
        assert_eq!(
            headers.get("x-callback").map(String::as_str),
            Some("logical")
        );
        let location = url::Url::parse(headers.get("location").unwrap())?;
        let mut expected = url::Url::parse(ORIGIN)?.join(if callback.is_empty() {
            "/api/auth/error"
        } else {
            callback
        })?;
        let _ = expected.query_pairs_mut().append_pair(key, value);
        assert_eq!(location, expected);
        assert_eq!(
            db.tables(&["users", "accounts", "sessions", "verifications"])
                .await?,
            before
        );
    }
    let patched = auth
        .dispatch_endpoint(
            endpoint("missing-proof", &json!({"callbackURL":"/patched"}))?
                .with_body(&json!({"token":token}))?,
            EndpointOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(patched.error.status_code(), 302);
    let location = url::Url::parse(patched.headers.as_ref().unwrap().get("location").unwrap())?;
    assert_eq!(
        location
            .query_pairs()
            .find(|(name, _)| name == "token")
            .unwrap()
            .1,
        token
    );
    assert_eq!(observer.0.lock().unwrap().last().unwrap()["token"], token);
    assert_eq!(
        db.tables(&["users", "accounts", "sessions", "verifications"])
            .await?,
        before
    );
    assert!(
        observer
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|params| params["token"] == token)
    );
    let reset = auth
        .dispatch_endpoint(
            ServerEndpoint::<Value>::new("password-management", "resetPassword")
                .with_body(&json!({"token":token,"newPassword":"callback-replacement-205"}))?,
            EndpointOptions::default(),
        )
        .await?;
    assert_eq!(
        reset
            .value()
            .get("status")
            .and_then(alibi::utils::json::JsValue::as_bool),
        Some(true)
    );
    assert_eq!(db.count("verifications").await?, 0);
    let login=call(&auth,request("/sign-in/email",Some(json!({"email":"callback-owner@example.test","password":"callback-replacement-205"})),""),200).await;
    assert_eq!(body(&login)["user"]["id"], body(&owner)["user"]["id"]);
    B::close(connection).await
}
