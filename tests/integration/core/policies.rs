//! Public policy engines exercised directly: user-list queries, validation, usernames and field input.
#![allow(
    clippy::indexing_slicing,
    clippy::panic_in_result_fn,
    reason = "tests assert independently specified wire fields and fixtures"
)]
use alibi::AuthConfig;
use alibi_core::field_policy::{FieldConfig, FieldInputError, FieldValues, SessionFields};
use alibi_core::hooks::{RequestHookContext, with_request_hook_context};
use alibi_core::types::{ListUsersParams, UserFilterValue};
use alibi_core::user_query::{apply_list_users, apply_list_users_presorted};
use alibi_core::user_validation::{
    UserInfoValidator, UserValidationData, UserValidationRejection, UserValidationSource,
    validate_user_info,
};
use alibi_core::utils::json::JsValue;
use alibi_core::utils::username::{UsernameConfig, UsernameNormalization, UsernameValidationOrder};
use alibi_core::wire::{UserView, VerificationView};
use alibi_core::{AuthError, AuthRequest, AuthResult, CreateUser, HttpMethod};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

fn user(id: &str, name: &str, banned: bool, created: &str) -> UserView {
    serde_json::from_value(json!({
        "id": id,
        "name": name,
        "email": format!("{id}@example.test"),
        "emailVerified": false,
        "image": null,
        "createdAt": created,
        "updatedAt": created,
        "role": if banned { "admin" } else { "user" },
        "banned": banned,
        "banExpires": if banned { json!("2099-01-01T00:00:00.000Z") } else { json!(null) },
    }))
    .unwrap()
}

fn roster() -> Vec<UserView> {
    vec![
        user("b", "Bob", false, "2024-02-01T00:00:00.000Z"),
        user("a", "Alice", true, "2024-03-01T00:00:00.000Z"),
        user("c", "Carol", false, "2024-01-01T00:00:00.000Z"),
    ]
}

fn ids(users: &[UserView]) -> String {
    users.iter().map(|user| user.id.as_str()).collect()
}

fn filter(field: &str, operator: &str, value: &str) -> ListUsersParams {
    ListUsersParams {
        filter_field: Some(field.into()),
        filter_operator: Some(operator.into()),
        filter_value: Some(UserFilterValue::Scalar(value.into())),
        sort_by: Some("id".into()),
        ..Default::default()
    }
}

#[test]
fn user_filters_cover_every_operator_and_field_kind() {
    let cases = [
        ("name", "eq", "Bob", "b"),
        ("name", "ne", "Bob", "ac"),
        ("name", "lt", "Bob", "a"),
        ("name", "lte", "Bob", "ab"),
        ("name", "gt", "Bob", "c"),
        ("name", "gte", "Bob", "bc"),
        ("name", "contains", "ar", "c"),
        ("name", "starts_with", "Al", "a"),
        ("name", "ends_with", "ob", "b"),
        ("name", "not_in", "Bob", "ac"),
        ("name", "bogus", "Bob", ""),
        ("role", "eq", "admin", "a"),
        ("banned", "eq", "true", "a"),
        ("banned", "ne", "true", "bc"),
        ("banned", "gt", "true", ""),
        ("banned", "eq", "maybe", ""),
        ("createdAt", "gt", "2024-01-15T00:00:00.000Z", "ab"),
        ("createdAt", "lte", "2024-02-01T00:00:00.000Z", "bc"),
        ("createdAt", "eq", "2024-03-01T00:00:00.000Z", "a"),
        ("createdAt", "ne", "2024-03-01T00:00:00.000Z", "bc"),
        ("createdAt", "lt", "2024-02-01T00:00:00.000Z", "c"),
        ("createdAt", "gte", "2024-02-01T00:00:00.000Z", "ab"),
        ("createdAt", "gt", "not a date", ""),
        ("createdAt", "contains", "2024-03-01T00:00:00.000Z", ""),
        ("unknown", "eq", "x", ""),
    ];
    for (field, operator, value, expected) in cases {
        let (users, total) = apply_list_users(roster(), &filter(field, operator, value));
        assert_eq!(ids(&users), expected, "{field} {operator} {value}");
        assert_eq!(total, users.len());
    }
}

#[test]
fn multiple_value_filters_search_sort_and_paging() {
    let multiple = |operator: &str, values: &[&str]| ListUsersParams {
        filter_field: Some("name".into()),
        filter_operator: Some(operator.into()),
        filter_value: Some(UserFilterValue::Multiple(
            values.iter().map(|value| (*value).to_owned()).collect(),
        )),
        sort_by: Some("id".into()),
        ..Default::default()
    };
    for (operator, values, expected) in [
        ("in", &["Bob", "Carol"][..], "bc"),
        ("not_in", &["Bob", "Carol"][..], "a"),
        ("contains", &["ar"][..], "c"),
        ("starts_with", &["Al"][..], "a"),
        ("ends_with", &["ol"][..], "c"),
        ("eq", &["Bob"][..], ""),
    ] {
        let (users, _) = apply_list_users(roster(), &multiple(operator, values));
        assert_eq!(ids(&users), expected, "{operator}");
    }
    let unknown_field = ListUsersParams {
        filter_field: Some("nope".into()),
        filter_value: Some(UserFilterValue::Multiple(vec!["x".into()])),
        ..Default::default()
    };
    assert!(apply_list_users(roster(), &unknown_field).0.is_empty());

    let search = |field: &str, operator: &str, value: &str| ListUsersParams {
        search_field: Some(field.into()),
        search_operator: Some(operator.into()),
        search_value: Some(value.into()),
        sort_by: Some("id".into()),
        ..Default::default()
    };
    assert_eq!(
        ids(&apply_list_users(roster(), &search("name", "ends_with", "l")).0),
        "c"
    );
    assert_eq!(
        ids(&apply_list_users(roster(), &search("name", "starts_with", "B")).0),
        "b"
    );
    assert_eq!(
        ids(&apply_list_users(roster(), &search("name", "eq", "Bob")).0),
        ""
    );
    assert_eq!(
        ids(&apply_list_users(roster(), &search("banned", "contains", "t")).0),
        ""
    );

    for (sort_by, direction, expected) in [
        (None, None, "abc"),
        (Some("createdAt"), Some("asc"), "cba"),
        (Some("name"), Some("desc"), "cba"),
        (Some("email"), None, "abc"),
        (Some("role"), Some("asc"), "abc"),
        (Some("banned"), Some("asc"), "bca"),
        (Some("banned"), Some("desc"), "abc"),
        (Some("banExpires"), Some("asc"), "bca"),
        (Some("updatedAt"), Some("desc"), "abc"),
        (Some("unknown"), Some("asc"), "cba"),
    ] {
        let params = ListUsersParams {
            sort_by: sort_by.map(str::to_owned),
            sort_direction: direction.map(str::to_owned),
            ..Default::default()
        };
        assert_eq!(
            ids(&apply_list_users(roster(), &params).0),
            expected,
            "{sort_by:?}"
        );
    }

    let paged = ListUsersParams {
        offset: Some(1),
        limit: Some(1),
        sort_by: Some("id".into()),
        ..Default::default()
    };
    let (users, total) = apply_list_users_presorted(roster(), &paged);
    assert_eq!((ids(&users).as_str(), total), ("a", 3));
}

struct Policy(fn(&mut UserValidationData) -> AuthResult<Option<UserValidationRejection>>);

#[async_trait]
impl UserInfoValidator for Policy {
    async fn validate(
        &self,
        data: &mut UserValidationData,
        _: &RequestHookContext,
    ) -> AuthResult<Option<UserValidationRejection>> {
        (self.0)(data)
    }
}

fn config_with(
    policy: fn(&mut UserValidationData) -> AuthResult<Option<UserValidationRejection>>,
) -> AuthConfig {
    let mut config = AuthConfig::new("policies-secret-at-least-32-characters-long");
    config.user_validation = Some(Arc::new(Policy(policy)));
    config
}

async fn validate(
    config: &AuthConfig,
    source: UserValidationSource,
    scoped: bool,
) -> AuthResult<()> {
    let mut data = UserValidationData {
        user: CreateUser::default(),
        source,
    };
    if scoped {
        let request = AuthRequest::new(HttpMethod::Post, "/sign-up/email");
        with_request_hook_context(&request, validate_user_info(config, &mut data)).await
    } else {
        validate_user_info(config, &mut data).await
    }
}

fn code(result: AuthResult<()>) -> (u16, String, String) {
    match result.unwrap_err() {
        AuthError::Api {
            status,
            code,
            message,
        } => (status, code.unwrap_or_default(), message),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn user_validation_requires_a_complete_source_and_an_endpoint_context() {
    let config = config_with(|_| Ok(None));
    assert_eq!(
        code(validate(&config, UserValidationSource::creation(""), true).await),
        (
            403,
            "validation_source_missing".into(),
            "User validation source is required".into()
        )
    );
    let mut oauth = UserValidationSource::creation("oauth");
    assert_eq!(
        code(validate(&config, oauth.clone(), true).await).2,
        "OAuth user validation source requires oauth.providerId"
    );
    oauth.oauth = Some(alibi_core::user_validation::UserValidationProvider {
        provider_id: String::new(),
        profile: None,
    });
    assert_eq!(
        code(validate(&config, oauth, true).await).2,
        "OAuth user validation source requires oauth.providerId"
    );
    for method in ["sso-oidc", "sso-saml"] {
        assert_eq!(
            code(validate(&config, UserValidationSource::creation(method), true).await).2,
            "SSO user validation source requires sso.providerId"
        );
    }
    assert_eq!(
        code(validate(&config, UserValidationSource::creation("email"), false).await),
        (
            403,
            "validation_context_missing".into(),
            "User validation requires an endpoint context".into()
        )
    );
    validate(&config, UserValidationSource::creation("email"), true)
        .await
        .unwrap();
}

#[tokio::test]
async fn user_validation_maps_policy_outcomes_to_denials() {
    let source = || UserValidationSource::creation("email");
    let described = config_with(|_| {
        Ok(Some(UserValidationRejection {
            error: "blocked".into(),
            error_description: Some("domain not allowed".into()),
        }))
    });
    assert_eq!(
        code(validate(&described, source(), true).await),
        (403, "blocked".into(), "domain not allowed".into())
    );
    let bare = config_with(|_| {
        Ok(Some(UserValidationRejection {
            error: "blocked".into(),
            error_description: Some(String::new()),
        }))
    });
    assert_eq!(code(validate(&bare, source(), true).await).2, "blocked");
    let admitted = config_with(|_| {
        Ok(Some(UserValidationRejection {
            error: String::new(),
            error_description: None,
        }))
    });
    validate(&admitted, source(), true).await.unwrap();
    let failing = config_with(|_| Err(AuthError::internal("private")));
    assert_eq!(
        code(validate(&failing, source(), true).await),
        (
            403,
            "validation_failed".into(),
            "User validation failed".into()
        )
    );
}

#[tokio::test]
async fn username_policy_stages_follow_configured_order_and_length() {
    let config = UsernameConfig::default();
    assert!(config.value_error(&"x".repeat(31)).await.unwrap().is_some());
    assert_eq!(
        config
            .validate_value(&"x".repeat(31), 422)
            .await
            .unwrap_err()
            .to_string(),
        AuthError::Upstream {
            status: 422,
            code: "USERNAME_TOO_LONG",
            message: "Username is too long"
        }
        .to_string()
    );
    let preserve = UsernameConfig {
        normalization: UsernameNormalization::Preserve,
        validation_order: Some(UsernameValidationOrder::PostNormalization),
        ..UsernameConfig::default()
    };
    assert_eq!(preserve.normalize("MiXed").unwrap(), "MiXed");
    preserve.validate_hook_value("valid_name").await.unwrap();
    assert!(preserve.validate_hook_value("bad name").await.is_err());
    preserve.validate_display("anything").await.unwrap();

    let hidden = UsernameConfig {
        include_display_username: false,
        ..UsernameConfig::default()
    };
    hidden.validate_display("ignored").await.unwrap();
    let fields = hidden.fields();
    assert!(!fields["displayUsername"].input && !fields["displayUsername"].returned);
    let mut username = Some("UserName".to_owned());
    let mut display = Some("Shown".to_owned());
    let mut values = FieldValues::new();
    hidden
        .normalize_fields(&mut username, &mut display, &mut values, true)
        .unwrap();
    assert_eq!((username.as_deref(), display), (Some("username"), None));
    assert!(values.get("displayUsername").is_none());

    let shown = UsernameConfig::default();
    let mut username = Some("UserName".to_owned());
    let mut display = None;
    let mut values = FieldValues::new();
    shown
        .normalize_fields(&mut username, &mut display, &mut values, true)
        .unwrap();
    assert_eq!(display.as_deref(), Some("UserName"));
    assert_eq!(
        values["displayUsername"],
        JsValue::String("UserName".into())
    );
    let mut display = Some("Fancy".to_owned());
    shown
        .normalize_fields(&mut username, &mut display, &mut values, false)
        .unwrap();
    assert_eq!(display.as_deref(), Some("Fancy"));
}

fn text() -> serde_json::Value {
    json!({"type":"string"})
}

fn session_fields(fields: Vec<(&str, FieldConfig)>) -> SessionFields {
    SessionFields(
        fields
            .into_iter()
            .map(|(name, field)| (name.to_owned(), field))
            .collect(),
    )
}

fn parse(
    fields: &SessionFields,
    creation: bool,
    value: serde_json::Value,
) -> Result<FieldValues, FieldInputError> {
    let JsValue::Object(input) = alibi_core::utils::json::parse_value(&value.to_string()).unwrap()
    else {
        panic!("object input expected");
    };
    if creation {
        fields.parse_create(&input)
    } else {
        fields.parse_update(&input)
    }
}

fn denial(error: FieldInputError) -> String {
    match error {
        FieldInputError::Validation { code, .. } => code.to_owned(),
        FieldInputError::Transform(error) => error.to_string(),
    }
}

#[test]
fn field_input_rules_for_server_owned_defaults_and_undefined_transforms() {
    let fields = session_fields(vec![
        (
            "owned",
            FieldConfig::new(text())
                .read_only()
                .default_value(json!("server")),
        ),
        ("plain", FieldConfig::new(text()).field_name("plain_col")),
        ("dropped", FieldConfig::new(text()).transform(|_| Ok(None))),
    ]);
    let created = parse(
        &fields,
        true,
        json!({"owned":"client","plain":"p","dropped":"x"}),
    )
    .unwrap();
    assert_eq!(created["owned"], JsValue::String("server".into()));
    assert_eq!(created["plain"], JsValue::String("p".into()));
    assert!(created.get("dropped").is_none());
    assert!(created.has_input_fields());
    assert_eq!(
        serde_json::to_value(&created).unwrap(),
        json!({"owned":"server","plain":"p"})
    );

    for (value, rejected) in [
        (json!(true), true),
        (json!(1), true),
        (json!("x"), true),
        (json!([]), true),
        (json!({}), true),
        (json!(false), false),
        (json!(0), false),
        (json!(""), false),
        (json!(null), false),
    ] {
        let fields = session_fields(vec![("owned", FieldConfig::new(text()).read_only())]);
        let result = parse(&fields, false, json!({"owned": value}));
        match (rejected, result) {
            (true, Err(error)) => assert_eq!(denial(error), "FIELD_NOT_ALLOWED"),
            (false, Ok(parsed)) => assert!(parsed.is_empty()),
            (expected, other) => panic!("{value}: {expected} {other:?}"),
        }
    }
}

#[test]
fn wire_views_round_trip_through_their_entity_traits() {
    use alibi_core::AuthUser;

    let created = chrono::DateTime::from_timestamp_millis(1_709_251_200_000).unwrap();
    let view = VerificationView {
        id: "v1".into(),
        identifier: "email".into(),
        value: "code".into(),
        expires_at: created,
        created_at: created,
        updated_at: created,
    };
    let copy = VerificationView::from(&view);
    assert_eq!(copy, view);
    assert_eq!(
        serde_json::to_value(&copy).unwrap()["expiresAt"],
        "2024-03-01T00:00:00.000Z"
    );

    let mut user = user("u", "Una", false, "2024-03-01T00:00:00.000Z");
    assert!(!AuthUser::two_factor_enabled(&user));
    user.two_factor_enabled = Some(true);
    assert!(AuthUser::two_factor_enabled(&user));
    let _ = user
        .extension_fields
        .insert("emailVerified".into(), json!("yes"));
    assert_eq!(serde_json::to_value(&user).unwrap()["emailVerified"], "yes");
}

fn session_view(id: &str) -> alibi_core::wire::SessionView {
    serde_json::from_value(json!({
        "id": id,
        "expiresAt": "2099-01-01T00:00:00.000Z",
        "token": "token-1",
        "createdAt": "2024-03-01T00:00:00.000Z",
        "updatedAt": "2024-03-01T00:00:00.000Z",
        "ipAddress": null,
        "userAgent": null,
        "userId": "u",
    }))
    .unwrap()
}

#[test]
fn compact_cache_envelopes_reject_unsound_payloads_and_non_finite_expiry() {
    use alibi_core::session::cookie_cache::{decode_compact, encode_compact};
    use base64::Engine as _;

    const SECRET: &str = "compact-cache-secret-at-least-32-characters";
    let account = user("u", "Una", false, "2024-03-01T00:00:00.000Z");
    let encode = |session_id: &str, version: &str, max_age: f64| {
        encode_compact(
            &account,
            &session_view(session_id),
            version,
            1_709_251_200_000,
            max_age,
            false,
            SECRET,
        )
        .unwrap()
    };

    let valid = decode_compact(&encode("session-1", "v1", 300.0), SECRET).unwrap();
    assert_eq!(
        (valid.version.as_deref(), valid.session.id.as_str()),
        (Some("v1"), "session-1")
    );
    assert!(
        decode_compact(
            &encode("session-1", "v1", 300.0),
            "another-secret-at-least-32-characters"
        )
        .is_none()
    );

    assert!(decode_compact(&encode("2024-03-01T00:00:00.000Z", "v1", 300.0), SECRET).is_none());
    assert!(
        decode_compact(
            &encode("session-1", "2024-03-01T00:00:00.000Z", 300.0),
            SECRET
        )
        .is_none()
    );
    assert!(decode_compact(&encode("session-1", "v1", f64::INFINITY), SECRET).is_none());

    let envelope = |value: serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
    };
    for malformed in [
        envelope(json!({})),
        envelope(json!({"session":"x","expiresAt":1,"signature":"s"})),
        envelope(json!({"session":{},"expiresAt":"soon","signature":"s"})),
        "not json".to_owned(),
    ] {
        assert!(decode_compact(&malformed, SECRET).is_none(), "{malformed}");
    }
}
