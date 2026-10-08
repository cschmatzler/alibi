use super::*;
impl DeviceAuthorizationPlugin {
    pub(in crate::plugins::device_authorization) async fn issue_device_code(
        &self,
        body: DeviceCodeRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.issue_device_code_with_fields(body, serde_json::Map::new(), ctx).await
    }
    pub(super) async fn issue_device_code_with_fields(&self, mut body:DeviceCodeRequest, fields:serde_json::Map<String,serde_json::Value>, ctx:&AuthContext<impl alibi_core::AuthSchema>)->AuthResult<AuthResponse> {
        if body.client_id.is_empty() {
            return device_error_response(400, "invalid_request", "client_id is required");
        }
        body.user_id = body.user_id.filter(|value| !value.is_empty());
        body.scope = body.scope.filter(|value| !value.is_empty());

        if !self.validate_client_id(&body.client_id).await? {
            return device_error_response(400, "invalid_client", INVALID_CLIENT_ID);
        }

        if let Some(callback) = &self.config.on_device_auth_request {
            callback(body.client_id.clone(), body.scope.clone())
                .await
                .map_err(device_callback_error)?;
        }

        let expires_at = Utc::now() + self.config.expires_in;
        let polling_interval = self.config.interval.num_milliseconds();
        for _ in 0..3 {
            let device_code = self.generate_device_code().await?;
            if device_code.chars().count() > 191 {
                return device_error_response(
                    400,
                    "invalid_request",
                    "Generated device code must be at most 191 characters",
                );
            }
            let user_code = self.generate_user_code().await?;
            if user_code.chars().count() > 191 {
                return device_error_response(
                    400,
                    "invalid_request",
                    "Generated user code must be at most 191 characters",
                );
            }
            match ctx
                .database
                .create_device_code_with_fields(CreateDeviceCode {
                    device_code: device_code.clone(),
                    user_code: user_code.clone(),
                    user_id: body.user_id.clone(),
                    expires_at,
                    status: DEVICE_STATUS_PENDING.to_owned(),
                    last_polled_at: None,
                    polling_interval: Some(polling_interval),
                    client_id: Some(body.client_id.clone()),
                    scope: body.scope.clone(),
                }, fields.clone())
                .await
            {
                Ok(_) => {}
                Err(error) if is_unique_constraint_error(&error) => continue,
                Err(error) => return Err(error),
            }

            let (verification_uri, verification_uri_complete) = build_verification_uris(
                self.config.verification_uri.as_deref(),
                &ctx.config.base_url,
                &user_code,
            )?;

            return Ok(AuthResponse::json(
                200,
                &DeviceCodeResponse {
                    device_code,
                    user_code,
                    verification_uri,
                    verification_uri_complete,
                    expires_in: duration_seconds_floor(self.config.expires_in),
                    interval: duration_seconds_floor(self.config.interval),
                },
            )?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"));
        }
        device_error_response(
            500,
            "server_error",
            "Failed to generate a unique device code",
        )
    }
}
