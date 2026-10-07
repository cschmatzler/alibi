use super::*;
impl<S: AuthSchema> BetterAuth<S> {
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
            (HttpMethod::Get, core_paths::ERROR) => {
                let error_code = req
                    .query
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_owned());
                let error_description = req
                    .query
                    .get("error_description")
                    .map(String::as_str)
                    .filter(|description| !description.is_empty());
                if !self.config.render_error_page {
                    return Ok(Some(AuthResponse::new(302).with_header(
                        "location",
                        alibi_core::error::page::error_page_redirect_location(
                            &error_code,
                            error_description,
                        ),
                    )));
                }
                let html = alibi_core::error::page::error_page_html_with_description(
                    &error_code,
                    error_description,
                );
                Ok(Some(
                    AuthResponse::html(200, html).with_header("content-type", "text/html"),
                ))
            }
            (HttpMethod::Post, core_paths::UPDATE_USER) => Ok(Some(
                crate::plugins::user_management::handle_update_user(req, context).await?,
            )),
            _ => Ok(None),
        }
    }
}
