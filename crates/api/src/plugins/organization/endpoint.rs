use super::{OrganizationPlugin, handlers, hooks, types};
use crate::plugins::authentication_helpers::JsonField;
use crate::plugins::endpoint::{definition, error_response, validate_fields, validation};
use better_auth_core::endpoint::{
    EndpointCall, EndpointDefinition, EndpointInput, EndpointResponse, ServerEndpoint,
};
use better_auth_core::session::SessionRequest;
use better_auth_core::utils::json::JsValue;
use better_auth_core::{AuthContext, AuthError, AuthResult, AuthSchema, HttpMethod};

pub(super) fn definitions() -> Vec<EndpointDefinition> {
    vec![
        definition("addMember", "addMember", None, HttpMethod::Post),
        definition(
            "removeMember",
            "removeMember",
            Some("/organization/remove-member"),
            HttpMethod::Post,
        ),
        definition(
            "createOrganization",
            "createOrganization",
            Some("/organization/create"),
            HttpMethod::Post,
        ),
        definition(
            "deleteOrganization",
            "deleteOrganization",
            Some("/organization/delete"),
            HttpMethod::Post,
        ),
    ]
}

pub(super) fn validate(call: &EndpointCall) -> AuthResult<EndpointInput> {
    let mut body = call.body().cloned();
    match call.operation_id() {
        "createOrganization" => {
            let _validated =
                handlers::org_input::create_value(body.clone()).map_err(error_response)?;
            if let Some(JsValue::Object(body)) = &mut body {
                body.retain(|key, _| {
                    [
                        "name",
                        "slug",
                        "userId",
                        "logo",
                        "metadata",
                        "keepCurrentActiveOrganization",
                    ]
                    .contains(&key.as_str())
                });
                if let Some(value) = body.get("userId") {
                    let value = value.coerce_string().map_err(validation)?;
                    drop(body.insert("userId".into(), JsValue::String(value)));
                }
            }
        }
        "addMember" => {
            let Some(JsValue::Object(input)) = &mut body else {
                return Err(validation(format!(
                    "[body] Invalid input: expected object, received {}",
                    crate::plugins::authentication_helpers::json_type(body.as_ref())
                )));
            };
            let user_id = input
                .get("userId")
                .map_or_else(|| Ok("undefined".into()), JsValue::coerce_string)
                .map_err(validation)?;
            drop(input.insert("userId".into(), JsValue::String(user_id)));
            let _strings = validate_fields(
                body.as_ref(),
                "body",
                &[
                    JsonField::string("userId", true),
                    JsonField::string("organizationId", false),
                    JsonField::string("teamId", false),
                ],
            )?;
            let role = body.as_ref().and_then(|body| body.get("role"));
            if !role.is_some_and(|role| {
                role.is_string()
                    || role
                        .as_array()
                        .is_some_and(|values| values.iter().all(JsValue::is_string))
            }) {
                return Err(validation("[body.role] Invalid input"));
            }
            if let Some(JsValue::Object(body)) = &mut body {
                body.retain(|key, _| {
                    ["userId", "role", "organizationId", "teamId"].contains(&key.as_str())
                });
            }
        }
        "removeMember" => {
            body = Some(validate_fields(
                body.as_ref(),
                "body",
                &[
                    JsonField::string("memberIdOrEmail", true),
                    JsonField::string("organizationId", false),
                ],
            )?);
        }
        "deleteOrganization" => {
            body = Some(validate_fields(
                body.as_ref(),
                "body",
                &[JsonField::string("organizationId", true)],
            )?);
        }
        _ => {}
    }
    Ok(EndpointInput {
        body,
        query: call.query().cloned(),
    })
}

impl OrganizationPlugin {
    /// Privileged server-only admission through actual installed hooks.
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn add_member_endpoint(
        body: &types::AddOrganizationMemberRequest,
    ) -> AuthResult<ServerEndpoint<types::BasicMemberResponse>> {
        ServerEndpoint::new("organization", "addMember").with_body(body)
    }

    /// Remove a member using genuine verified credentials and installed hooks.
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn remove_member_endpoint(
        body: &types::RemoveMemberRequest,
    ) -> AuthResult<
        ServerEndpoint<types::RemovedMemberResponse<types::OrganizationMemberRemovalSnapshot>>,
    > {
        ServerEndpoint::new("organization", "removeMember").with_body(body)
    }

    /// Create through logical dispatch; an explicit user ID is a trusted server option.
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn create_endpoint(
        body: &types::CreateOrganizationRequest,
        user_id: Option<&str>,
    ) -> AuthResult<
        ServerEndpoint<
            types::CreateOrganizationResponse<
                types::CreatedOrganizationResponse,
                types::BasicMemberResponse,
            >,
        >,
    > {
        let mut value = better_auth_core::utils::json::parse_value(
            &better_auth_core::utils::json::to_string(body)?,
        )?;
        if let Some(user_id) = user_id
            && let JsValue::Object(body) = &mut value
        {
            drop(body.insert("userId".into(), JsValue::String(user_id.into())));
        }
        Ok(ServerEndpoint::new("organization", "createOrganization").with_body_value(value))
    }

    /// Delete through installed hooks and scoped organization authority.
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn delete_endpoint(
        body: &types::DeleteOrganizationRequest,
    ) -> AuthResult<ServerEndpoint<Option<types::OrganizationResponse>>> {
        ServerEndpoint::new("organization", "deleteOrganization").with_body(body)
    }

    pub(super) async fn call_endpoint<S: AuthSchema>(
        &self,
        call: &EndpointCall,
        ctx: &AuthContext<S>,
    ) -> AuthResult<EndpointResponse> {
        match call.operation_id() {
            "addMember" => {
                let body: types::AddOrganizationMemberRequest = call.body_as()?;
                let session = if body.user_id.is_empty() {
                    None
                } else {
                    ctx.require_cached_session(call).await.ok()
                };
                EndpointResponse::json(
                    &handlers::member_addition::add_member_with_session(
                        &body,
                        session,
                        call.request(),
                        &self.config,
                        ctx,
                    )
                    .await?,
                )
            }
            "removeMember" => {
                let body: types::RemoveMemberRequest = call.body_as()?;
                let (user, session) = ctx.require_cached_session(call).await.map_err(|error| {
                    if matches!(error, AuthError::Unauthenticated) {
                        handlers::extension_common::org_error(401, "UNAUTHORIZED")
                    } else {
                        error
                    }
                })?;
                EndpointResponse::json(
                    &handlers::member::remove_member_core(
                        &body,
                        &user,
                        &session,
                        &self.config,
                        ctx,
                    )
                    .await?,
                )
            }
            "deleteOrganization" => {
                let body: types::DeleteOrganizationRequest = call.body_as()?;
                if self.config.disable_organization_deletion {
                    return Err(handlers::extension_common::org_error(
                        404,
                        "ORGANIZATION_DELETION_DISABLED",
                    ));
                }
                let (user, session) = ctx.require_cached_session(call).await.map_err(|error| {
                    if matches!(error, AuthError::Unauthenticated) {
                        handlers::extension_common::org_error(401, "UNAUTHORIZED")
                    } else {
                        error
                    }
                })?;
                EndpointResponse::json(
                    &handlers::org::delete_organization_core(
                        &body,
                        &user,
                        &session,
                        hooks::organization::DeleteInvocation {
                            headers: call.session_headers(),
                            request: call.request(),
                        },
                        &self.config,
                        ctx,
                    )
                    .await?,
                )
            }
            "createOrganization" => {
                let body: types::CreateOrganizationRequest = call.body_as()?;
                let session = ctx.require_cached_session(call).await.ok();
                if session.is_none() && (call.request().is_some() || call.headers().is_some()) {
                    return Err(AuthError::Api {
                        status: 401,
                        code: None,
                        message: String::new(),
                    });
                }
                if let Some((user, session)) = session {
                    let response = handlers::org::create_organization_core(
                        &body,
                        &user,
                        call.request(),
                        Some(&session),
                        &self.config,
                        ctx,
                    )
                    .await?;
                    if !body.keep_current_active_organization.unwrap_or(false) {
                        drop(
                            ctx.database
                                .update_session_active_organization_record(
                                    &session.token,
                                    Some(response.organization.id.as_str()),
                                )
                                .await?,
                        );
                        if let Some(team_id) = &response.default_team_id {
                            drop(
                                ctx.database
                                    .update_session_active_team_record(
                                        &session.token,
                                        Some(team_id),
                                    )
                                    .await?,
                            );
                        }
                    }
                    EndpointResponse::json(&response)
                } else {
                    let user_id = call
                        .body()
                        .and_then(|body| body.get("userId"))
                        .and_then(JsValue::as_str)
                        .filter(|id| !id.is_empty())
                        .ok_or(AuthError::Api {
                            status: 401,
                            code: None,
                            message: String::new(),
                        })?;
                    let user =
                        ctx.database
                            .get_user_by_id(user_id)
                            .await?
                            .ok_or(AuthError::Api {
                                status: 401,
                                code: None,
                                message: String::new(),
                            })?;
                    EndpointResponse::json(
                        &handlers::org::create_organization_core(
                            &body,
                            &user,
                            None,
                            None,
                            &self.config,
                            ctx,
                        )
                        .await?,
                    )
                }
            }
            _ => Err(AuthError::not_found("Unregistered organization operation")),
        }
    }
}
