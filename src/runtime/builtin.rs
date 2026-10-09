use super::{
    AuthContext, AuthError, AuthRequest, AuthResponse, AuthResult, AuthSchema, BetterAuth,
    HttpMethod, OkResponse, core_paths,
};
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
                if let Some(target) = self
                    .config
                    .api_error_url
                    .as_deref()
                    .filter(|target| !target.is_empty())
                {
                    let relative = target.starts_with('/');
                    let origin = url::Url::parse("https://better-auth.invalid")
                        .map_err(|error| AuthError::internal(error.to_string()))?;
                    let mut location = if relative {
                        origin.join(target)
                    } else {
                        url::Url::parse(target)
                    }
                    .map_err(|error| {
                        AuthError::CallbackFailure(Box::new(AuthError::internal(error.to_string())))
                    })?;
                    if target.starts_with("//")
                        || target.starts_with("/\\")
                        || (relative && location.origin() != origin.origin())
                    {
                        return Err(AuthError::CallbackFailure(Box::new(AuthError::internal(
                            "Invalid error URL",
                        ))));
                    }
                    let generated = alibi_core::error::page::error_page_redirect_location(
                        &error_code,
                        error_description,
                    );
                    let query = generated.strip_prefix("/?").unwrap_or_default();
                    let existing = location.query().unwrap_or_default();
                    let separator = if existing.is_empty() || existing.ends_with('&') {
                        ""
                    } else {
                        "&"
                    };
                    let combined = format!("{existing}{separator}{query}");
                    location.set_query(Some(&combined));
                    let location = if relative {
                        location[url::Position::BeforePath..].to_owned()
                    } else {
                        location.to_string()
                    };
                    return Ok(Some(
                        AuthResponse::new(302).with_header("location", location),
                    ));
                }
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
                alibi_plugins::user_management::handle_update_user(req, context).await?,
            )),
            _ => Ok(None),
        }
    }
}
