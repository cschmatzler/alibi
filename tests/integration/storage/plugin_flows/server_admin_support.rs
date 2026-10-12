//! Shared application hook observing genuine logical admin principals.
use super::*;
use alibi::endpoint::{EndpointCall, EndpointHook, EndpointResponse};
use alibi::{AuthContext, AuthResult};

pub(super) struct AdminObserver;
#[async_trait::async_trait]
impl<S: AuthSchema> EndpointHook<S> for AdminObserver {
    fn matches_after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        _: &EndpointResponse,
    ) -> AuthResult<bool> {
        Ok(matches!(
            call.operation_id(),
            "getUser"
                | "setUserRole"
                | "createUser"
                | "userHasPermission"
                | "adminUpdateUser"
                | "listUsers"
                | "adminListUserSessions"
                | "unbanUser"
                | "banUser"
                | "revokeUserSession"
                | "revokeUserSessions"
                | "removeUser"
                | "setUserPassword"
                | "impersonateUser"
                | "stopImpersonating"
        ))
    }
    async fn after(
        &self,
        call: &EndpointCall,
        _: &AuthContext<S>,
        mut response: EndpointResponse,
    ) -> AuthResult<EndpointResponse> {
        assert!(call.request().is_none());
        assert_eq!(
            call.path(),
            Some(if call.operation_id() == "getUser" {
                "/admin/get-user"
            } else if call.operation_id() == "stopImpersonating" {
                "/admin/stop-impersonating"
            } else if call.operation_id() == "impersonateUser" {
                "/admin/impersonate-user"
            } else if call.operation_id() == "setUserPassword" {
                "/admin/set-user-password"
            } else if call.operation_id() == "removeUser" {
                "/admin/remove-user"
            } else if call.operation_id() == "revokeUserSessions" {
                "/admin/revoke-user-sessions"
            } else if call.operation_id() == "revokeUserSession" {
                "/admin/revoke-user-session"
            } else if call.operation_id() == "banUser" {
                "/admin/ban-user"
            } else if call.operation_id() == "unbanUser" {
                "/admin/unban-user"
            } else if call.operation_id() == "adminListUserSessions" {
                "/admin/list-user-sessions"
            } else if call.operation_id() == "listUsers" {
                "/admin/list-users"
            } else if call.operation_id() == "adminUpdateUser" {
                "/admin/update-user"
            } else if call.operation_id() == "userHasPermission" {
                "/admin/has-permission"
            } else if call.operation_id() == "createUser" {
                "/admin/create-user"
            } else {
                "/admin/set-role"
            })
        );
        if let Some((user, _)) = call.session() {
            response = response.with_header("x-admin-principal", user.id);
        }
        Ok(response
            .with_header("set-cookie", "application_a=first; Path=/; HttpOnly")
            .with_header("set-cookie", "application_b=second; Path=/; HttpOnly"))
    }
}
