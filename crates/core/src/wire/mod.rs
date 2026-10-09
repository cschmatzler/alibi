//! Concrete auth types for API responses and framework callbacks.
//!
//! These types decouple JSON response shapes from app-owned `SeaORM` entities.
//! Each view implements its corresponding `Auth*` entity trait, allowing it
//! to be used in trait-generic framework code (hooks, helpers).
mod account;
mod plugins;
mod session;
mod user;
mod verification;

pub use account::AccountView;
pub use plugins::ApiKeyView;
pub use plugins::InvitationView;
pub use plugins::OrganizationView;
pub use plugins::PasskeyView;
pub use session::SessionView;
pub use user::UserView;
pub use verification::VerificationView;

// LCOV_EXCL_START
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn user_view_serializes_camel_case() {
        let user = UserView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "user-1".to_owned(),
            name: Some("Ada".to_owned()),
            email: Some("ada@example.com".to_owned()),
            email_verified: true,
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            username: Some("ada".to_owned()),
            display_username: Some("Ada".to_owned()),
            two_factor_enabled: Some(true),
            role: Some("admin".to_owned()),
            banned: Some(false),
            ban_reason: None,
            ban_expires: None,
            is_anonymous: None,
            phone_number: None,
            phone_number_verified: None,
            last_login_method: None,
            extension_fields: std::collections::BTreeMap::default(),
            metadata: serde_json::json!({}),
        };

        let json = serde_json::to_value(UserView::from(&user)).expect("serialize user view");
        assert_eq!(
            (*(json)
                .get("emailVerified")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
        assert_eq!(
            (*(json)
                .get("displayUsername")
                .unwrap_or(&serde_json::Value::Null)),
            "Ada"
        );
        assert_eq!(
            (*(json)
                .get("twoFactorEnabled")
                .unwrap_or(&serde_json::Value::Null)),
            true
        );
    }

    #[test]
    fn session_view_serializes_camel_case() {
        let session = SessionView {
            omitted_fields: std::collections::BTreeSet::default(),
            id: "session-1".to_owned(),
            expires_at: Utc::now(),
            token: "token".to_owned(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: Some("agent".to_owned()),
            user_id: "user-1".to_owned(),
            impersonated_by: Some("admin-1".to_owned()),
            active_organization_id: Some("org-1".to_owned()),
            active_team_id: None,
            active: true,
            extension_fields: std::collections::BTreeMap::default(),
        };

        let json =
            serde_json::to_value(SessionView::from(&session)).expect("serialize session view");
        assert!((*(json).get("expiresAt").unwrap_or(&serde_json::Value::Null)).is_string());
        assert_eq!(
            (*(json).get("ipAddress").unwrap_or(&serde_json::Value::Null)),
            "127.0.0.1"
        );
        assert_eq!(
            (*(json)
                .get("activeOrganizationId")
                .unwrap_or(&serde_json::Value::Null)),
            "org-1"
        );
    }

    #[test]
    fn account_view_omits_password_on_serialize() {
        let account = AccountView {
            id: "acc-1".to_owned(),
            account_id: "account-id".to_owned(),
            provider_id: "credential".to_owned(),
            user_id: "user-1".to_owned(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some("$2a$hash".to_owned()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_value(&account).expect("serialize account view");
        assert!(
            json.get("password").is_none(),
            "password field must not appear in serialized output"
        );
    }
}
// LCOV_EXCL_STOP
