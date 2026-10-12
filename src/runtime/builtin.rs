use super::{
    Alibi, AuthContext, AuthRequest, AuthResponse, AuthResult, AuthSchema, HttpMethod, OkResponse,
    core_paths,
};
impl<S: AuthSchema> Alibi<S> {
    /// Handle core authentication requests.
    pub(in crate::runtime) async fn handle_core_request(
        &self,
        req: &AuthRequest,
        context: &AuthContext<S>,
    ) -> AuthResult<Option<AuthResponse>> {
        match (req.method(), req.path()) {
            (HttpMethod::Get, core_paths::OK) => {
                Ok(Some(AuthResponse::json(200, &OkResponse { ok: true })?))
            }
            (HttpMethod::Get, core_paths::ERROR) => Ok(Some(self.error_response(req)?)),
            (HttpMethod::Post, core_paths::UPDATE_USER) => Ok(Some(
                alibi_plugins::user_management::handle_update_user(req, context).await?,
            )),
            _ => Ok(None),
        }
    }

    fn error_response(&self, req: &AuthRequest) -> AuthResult<AuthResponse> {
        let (error_code, error_description) = if let Some(url) = req.url() {
            let parameter = |name: &str| {
                url.query_pairs()
                    .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
            };
            (
                parameter("error").unwrap_or_else(|| "UNKNOWN".into()),
                parameter("error_description"),
            )
        } else {
            // Native HTTP embedding also accepts a parsed request without a URL.
            (
                req.query
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".into()),
                req.query.get("error_description").cloned(),
            )
        };
        let response = alibi_core::error::page::error_page_response(
            &self.config,
            &error_code,
            error_description
                .as_deref()
                .filter(|value| !value.is_empty()),
        )?;
        if let Some(frame) = req
            .extensions()
            .get::<super::http_hooks::HttpEndpointFrame>()
        {
            // The handler constructs a fresh Response; Source's new endpoint
            // header accumulator replaces headers emitted by before hooks.
            _ = req.take_response_headers();
            *frame
                .returned_response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(response.clone());
        }
        Ok(response)
    }
}
