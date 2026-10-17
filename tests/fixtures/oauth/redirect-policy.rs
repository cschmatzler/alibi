//! Actual application policy shared by the native and SDK fixture hosts.
#[derive(Debug, Default)]
pub(super) struct RedirectPolicy {
    pub calls: std::sync::Mutex<Vec<serde_json::Value>>,
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthRedirectUriValidator for RedirectPolicy {
    async fn validate(
        &self,
        uri: &str,
        registered: &[String],
        default_result: bool,
    ) -> alibi::AuthResult<bool> {
        self.calls.lock().unwrap().push(serde_json::json!({
            "uri": uri, "registered": registered, "defaultResult": default_result
        }));
        if uri.contains("throw.fixture.test") {
            return Err(alibi::AuthError::internal(
                "application redirect policy failed",
            ));
        }
        Ok(uri != "https://app.fixture.test/callback"
            && (uri.contains("preview.fixture.test") || default_result))
    }
}
