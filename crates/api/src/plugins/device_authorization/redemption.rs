use super::*;
impl DeviceAuthorizationPlugin {
    pub(in crate::plugins::device_authorization) async fn redeem_device_token(
        &self,
        body: DeviceTokenRequest,
        req: &AuthRequest,
        ctx: &AuthContext<impl alibi_core::AuthSchema>,
    ) -> AuthResult<AuthResponse> {
        if !self.validate_client_id(&body.client_id).await? {
            return device_error_response(400, "invalid_grant", INVALID_CLIENT_ID);
        }

        let Some(device_code) = ctx
            .database
            .get_device_code_by_device_code(&body.device_code)
            .await?
        else {
            return device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE);
        };

        if let Some(grant) = &self.config.grant {
            let record = DeviceGrantRecord {
                fields: ctx.database.device_code_fields(&device_code.id).await?,
                device_code: device_code.clone(),
            };
            if let Err(error) = grant.assert_session_redemption(&record).await {
                return error.into_response();
            }
        }

        if let Some(client_id) = device_code.client_id.as_deref()
            && client_id != body.client_id
        {
            return device_error_response(400, "invalid_grant", CLIENT_ID_MISMATCH);
        }

        let now = Utc::now();
        if let (Some(last_polled_at), Some(polling_interval)) =
            (device_code.last_polled_at, device_code.polling_interval)
        {
            let elapsed = now.signed_duration_since(last_polled_at).num_milliseconds();
            if elapsed < polling_interval {
                return device_error_response(400, "slow_down", POLLING_TOO_FREQUENTLY);
            }
        }

        if let Err(error) = ctx
            .database
            .update_device_code(
                &device_code.id,
                UpdateDeviceCode {
                    last_polled_at: Some(Some(now)),
                    ..Default::default()
                },
            )
            .await
        {
            // Another redemption can consume the code between lookup and this
            // polling update. Preserve the OAuth error contract for that loser,
            // while retaining real storage failures when the code still exists.
            if matches!(
                ctx.database
                    .get_device_code_by_device_code(&body.device_code)
                    .await,
                Ok(None)
            ) {
                return device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE);
            }
            return Err(error);
        }

        if device_code.expires_at < now {
            ctx.database.delete_device_code(&device_code.id).await?;
            return device_error_response(400, "expired_token", EXPIRED_DEVICE_CODE);
        }

        if device_code.status == DEVICE_STATUS_PENDING {
            return device_error_response(400, "authorization_pending", AUTHORIZATION_PENDING);
        }

        if device_code.status == DEVICE_STATUS_DENIED {
            ctx.database.delete_device_code(&device_code.id).await?;
            return device_error_response(400, "access_denied", ACCESS_DENIED);
        }

        if device_code.status == DEVICE_STATUS_APPROVED {
            let Some(user_id) = device_code.user_id.as_deref() else {
                return device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS);
            };

            let Some(user) = ctx.database.get_user_by_id(user_id).await? else {
                return device_error_response(500, "server_error", USER_NOT_FOUND);
            };

            if !ctx
                .database
                .delete_device_code_if_status(&device_code.id, DEVICE_STATUS_APPROVED)
                .await?
            {
                return device_error_response(400, "invalid_grant", INVALID_DEVICE_CODE);
            }

            let meta = RequestMeta::from_request(req);
            let session =
                match create_user_session_record(ctx, &user.id(), meta.ip_address, meta.user_agent)
                    .await
                    .map_err(SessionIssueError::into_auth_error)
                {
                    Ok(issued) => issued.session,
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            device_code_id = %device_code.id,
                            user_id,
                            "failed to create session after device code redemption"
                        );
                        return device_error_response(
                            500,
                            "server_error",
                            FAILED_TO_CREATE_SESSION,
                        );
                    }
                };

            return Ok(AuthResponse::json(
                200,
                &DeviceTokenResponse {
                    access_token: session.token().to_owned(),
                    token_type: "Bearer",
                    expires_in: (session.expires_at().timestamp_millis()
                        - Utc::now().timestamp_millis())
                    .div_euclid(1000)
                    .max(0),
                    scope: device_code.scope.unwrap_or_default(),
                },
            )?
            .with_header("Cache-Control", "no-store")
            .with_header("Pragma", "no-cache"));
        }

        device_error_response(500, "server_error", INVALID_DEVICE_CODE_STATUS)
    }
}
