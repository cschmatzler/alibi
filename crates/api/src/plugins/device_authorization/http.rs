use super::*;
impl DeviceAuthorizationPlugin {
    pub(in crate::plugins::device_authorization) async fn handle_device_code(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if let Some(grant) = &self.config.grant {
            return self
                .handle_application_issuance(req, ctx, grant.as_ref())
                .await;
        }
        let body: DeviceCodeRequest = match parse_device_body(req, DeviceRequestKind::Issuance)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };

        self.issue_device_code(body, ctx)
            .await
            .inspect_err(|error| {
                if alibi_core::endpoint::is_endpoint_api_error(error) {
                    set_device_no_store_headers(req);
                }
            })
            .map(|response| {
                response
                    .with_header("Cache-Control", "no-store")
                    .with_header("Pragma", "no-cache")
            })
    }

    pub(in crate::plugins::device_authorization) async fn handle_device_token(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let body: DeviceTokenRequest = match parse_device_body(req, DeviceRequestKind::Token)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };

        self.redeem_device_token(body, req, ctx)
            .await
            .inspect_err(|error| {
                if alibi_core::endpoint::is_endpoint_api_error(error) {
                    set_device_no_store_headers(req);
                }
            })
            .map(|response| {
                response
                    .with_header("Cache-Control", "no-store")
                    .with_header("Pragma", "no-cache")
            })
    }

    pub(in crate::plugins::device_authorization) async fn handle_device_verify(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        let Some(user_code) = req.query.get("user_code").cloned() else {
            return device_error_response(400, "invalid_request", INVALID_REQUEST);
        };

        let Some(mut device_code) = find_device_code_by_user_code(ctx, &user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        // A signed-in caller claims the code here; `/device/approve` and
        // `/device/deny` refuse to act on a code nobody has claimed. The
        // session is optional — anyone may look up the status.
        let user_id = match ctx.require_cached_session(req).await {
            Ok((user, _)) => Some(user.id().into_owned()),
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => None,
            Err(err) => return Err(err),
        };
        if device_code.user_id.is_none()
            && device_code.status == DEVICE_STATUS_PENDING
            && let Some(user_id) = user_id.as_deref()
            && ctx
                .database
                .claim_device_code(&device_code.id, user_id)
                .await?
        {
            device_code.user_id = Some(user_id.to_owned());
        }
        let can_review_request = user_id.is_some() && device_code.user_id == user_id;

        let mut response = serde_json::to_value(DeviceVerifyResponse {
            user_code,
            status: device_code.status.clone(),
            client_id: can_review_request.then_some(device_code.client_id.clone()),
            scope: can_review_request.then_some(device_code.scope.clone()),
        })?;
        if can_review_request && let Some(grant) = &self.config.grant {
            let fields = ctx.database.device_code_fields(&device_code.id).await?;
            let record = DeviceGrantRecord {
                device_code,
                fields,
            };
            if let Some(object) = response.as_object_mut() {
                object.extend(grant.verification_context(&record).await?);
            }
        }
        AuthResponse::json(200, &response).map_err(AuthError::from)
    }

    pub(in crate::plugins::device_authorization) async fn handle_device_approve(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Approve)
            .await
    }

    pub(in crate::plugins::device_authorization) async fn handle_device_deny(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        self.handle_device_decision(req, ctx, DeviceDecision::Deny)
            .await
    }

    pub(in crate::plugins::device_authorization) async fn handle_device_decision(
        &self,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
        decision: DeviceDecision,
    ) -> AuthResult<AuthResponse> {
        if let Err(response) = validate_device_media(req, false) {
            return Ok(response);
        }
        let body: DeviceActionRequest = match parse_device_body(req, DeviceRequestKind::Decision)
            .and_then(deserialize_device_body)
        {
            Ok(value) => value,
            Err(response) => return Ok(response),
        };
        let user = match ctx.require_cached_session(req).await {
            Ok((user, _session)) => user,
            Err(AuthError::Unauthenticated | AuthError::SessionNotFound) => {
                return device_error_response(401, "unauthorized", AUTHENTICATION_REQUIRED);
            }
            Err(error) => return Err(error),
        };

        let current_user_id = user.id().into_owned();

        let Some(device_code) = find_device_code_by_user_code(ctx, &body.user_code).await? else {
            return device_error_response(400, "invalid_request", INVALID_USER_CODE);
        };

        if device_code.expires_at < Utc::now() {
            return device_error_response(400, "expired_token", EXPIRED_USER_CODE);
        }

        if device_code.status != DEVICE_STATUS_PENDING {
            return device_error_response(400, "invalid_request", DEVICE_CODE_ALREADY_PROCESSED);
        }

        // The code must already be bound to a user by `GET /device`. Without
        // this, any signed-in caller who knows a user_code could approve a
        // device they never claimed.
        let Some(claimed_user_id) = device_code.user_id.as_deref() else {
            return device_error_response(400, "invalid_request", DEVICE_CODE_NOT_CLAIMED);
        };

        if claimed_user_id != current_user_id {
            return device_error_response(403, "access_denied", decision.forbidden_message());
        }

        let updated_user_id = claimed_user_id.to_owned();

        // Pinned Source validates the fetched pending snapshot, then updates by ID.
        // An overlapping owner decision may also pass validation; the last
        // completed adapter write determines the state used by redemption.
        let _updated = ctx
            .database
            .update_device_code(
                &device_code.id,
                UpdateDeviceCode {
                    status: Some(decision.status().to_owned()),
                    user_id: Some(Some(updated_user_id)),
                    ..Default::default()
                },
            )
            .await?;

        AuthResponse::json(200, &DeviceActionResponse { success: true }).map_err(AuthError::from)
    }
}
