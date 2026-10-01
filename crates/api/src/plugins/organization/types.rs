use better_auth_core::entity::MemberUserView;
use better_auth_core::entity::{AuthMember, AuthOrganization};
use better_auth_core::utils::json::JsValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use validator::Validate;

pub(super) fn undefined_string() -> String {
    "undefined".to_owned()
}

/// The pinned membership endpoints use JavaScript's `String` coercion for IDs.
pub(super) fn deserialize_coercible_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    fn string(value: &JsValue) -> Result<String, &'static str> {
        match value {
            JsValue::Null => Ok("null".to_owned()),
            JsValue::Bool(value) => Ok(value.to_string()),
            JsValue::String(value) => Ok(value.clone()),
            JsValue::Number(value) => Ok(ryu_js::Buffer::new().format(*value).to_owned()),
            JsValue::Array(values) => values
                .iter()
                .map(|value| match value {
                    JsValue::Null => Ok(String::new()),
                    value => string(value),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|values| values.join(",")),
            JsValue::Object(value) if value.contains_key("toString") => {
                Err("Cannot convert object to primitive value")
            }
            JsValue::Object(_) => Ok("[object Object]".to_owned()),
        }
    }
    let value = JsValue::deserialize(deserializer)?;
    string(&value).map_err(serde::de::Error::custom)
}

// These routes intentionally use different published query conversions:
// list-members Number(string), get-full-organization parseInt(string).
fn query_whitespace(c: char) -> bool {
    matches!(c, '\u{0009}'..='\u{000D}' | '\u{0020}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
}
fn number_query(value: &str) -> f64 {
    let value = value.trim_matches(query_whitespace);
    if value.is_empty() {
        return 0.0;
    }
    for (prefixes, radix, bits) in [
        (["0x", "0X"], 16, 4),
        (["0o", "0O"], 8, 3),
        (["0b", "0B"], 2, 1),
    ] {
        if let Some(digits) = prefixes
            .iter()
            .find_map(|prefix| value.strip_prefix(prefix))
        {
            return radix_number(digits, radix, bits).unwrap_or(f64::NAN);
        }
    }
    match value {
        "Infinity" | "+Infinity" => f64::INFINITY,
        "-Infinity" => f64::NEG_INFINITY,
        _ if value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"+-.eE".contains(&byte)) =>
        {
            value.parse().unwrap_or(f64::NAN)
        }
        _ => f64::NAN,
    }
}
fn integer_query(value: &str) -> f64 {
    let value = value.trim_start_matches(query_whitespace);
    let (value, sign) = if let Some(value) = value.strip_prefix('-') {
        (value, -1.0)
    } else {
        (value.strip_prefix('+').unwrap_or(value), 1.0)
    };
    if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        let length = value.bytes().take_while(u8::is_ascii_hexdigit).count();
        return sign
            * radix_number(value.get(..length).unwrap_or_default(), 16, 4).unwrap_or(f64::NAN);
    }
    let length = value.bytes().take_while(u8::is_ascii_digit).count();
    sign * value
        .get(..length)
        .unwrap_or_default()
        .parse::<f64>()
        .unwrap_or(f64::NAN)
}
fn deserialize_query_number<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    integer_string: bool,
) -> Result<Option<f64>, D::Error> {
    match Option::<JsValue>::deserialize(deserializer)? {
        None => Ok(None),
        Some(JsValue::Number(number)) => Ok(Some(number)),
        Some(JsValue::String(value)) => Ok(Some(if integer_string {
            integer_query(&value)
        } else {
            number_query(&value)
        })),
        _ => Err(serde::de::Error::custom(
            "Page limits must be a string or number",
        )),
    }
}
fn deserialize_optional_number<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<f64>, D::Error> {
    deserialize_query_number(deserializer, false)
}
fn deserialize_optional_integer_query<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<f64>, D::Error> {
    deserialize_query_number(deserializer, true)
}
// Retain one-rounded radix conversion already used for JS Number SIWE inputs.
fn radix_number(digits: &str, radix: u32, bits_per_digit: usize) -> Option<f64> {
    if digits.is_empty() {
        return None;
    }
    let digits = digits
        .chars()
        .map(|character| character.to_digit(radix))
        .collect::<Option<Vec<_>>>()?;
    let Some(first_nonzero) = digits.iter().position(|digit| *digit != 0) else {
        return Some(0.0);
    };
    let significant = digits.get(first_nonzero..)?;
    let first = *significant.first()?;
    let first_bits = (u32::BITS - first.leading_zeros()) as usize;
    let bit_length = first_bits + (significant.len() - 1) * bits_per_digit;
    if bit_length > 1024 {
        return Some(f64::INFINITY);
    }
    let mut mantissa = 0u64;
    let mut position = 0;
    let mut guard = false;
    let mut sticky = false;
    for (index, digit) in significant.iter().enumerate() {
        let width = if index == 0 {
            first_bits
        } else {
            bits_per_digit
        };
        for bit in (0..width).rev() {
            let set = (*digit >> bit) & 1 != 0;
            if position < 53 {
                mantissa = (mantissa << 1) | u64::from(set);
            } else if position == 53 {
                guard = set;
            } else {
                sticky |= set;
            }
            position += 1;
        }
    }
    if bit_length <= 53 {
        return Some(mantissa as f64);
    }
    if guard && (sticky || mantissa & 1 != 0) {
        mantissa += 1;
    }
    Some(mantissa as f64 * 2.0f64.powi((bit_length - 53) as i32))
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NullableStringField {
    #[default]
    Missing,
    Null,
    Value(String),
}

pub(super) fn deserialize_nullable_string_field<'de, D>(
    deserializer: D,
) -> Result<NullableStringField, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(match value {
        Some(value) => NullableStringField::Value(value),
        None => NullableStringField::Null,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub fn joined(&self) -> String {
        match self {
            Self::One(role) => role.clone(),
            Self::Many(roles) => roles.join(","),
        }
    }

    pub fn roles(&self) -> Vec<&str> {
        match self {
            Self::One(role) => role
                .split(',')
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
            Self::Many(roles) => roles
                .iter()
                .flat_map(|role| role.split(','))
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .collect(),
        }
    }
}

/// Input to the privileged server-only member-admission operation.
/// Roles are joined verbatim, including whitespace, duplicates and empty roles.
#[derive(Debug, Clone, Deserialize)]
pub struct AddOrganizationMemberRequest {
    #[serde(
        rename = "userId",
        default = "undefined_string",
        deserialize_with = "deserialize_coercible_string"
    )]
    pub user_id: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "teamId")]
    pub team_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateOrganizationRequest {
    #[validate(length(min = 1, message = "Name is required"))]
    pub name: String,
    #[validate(length(min = 1, message = "Slug is required"))]
    pub slug: String,
    pub logo: Option<String>,
    #[serde(
        default,
        deserialize_with = "better_auth_core::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "keepCurrentActiveOrganization")]
    pub keep_current_active_organization: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationData {
    pub name: Option<String>,
    pub slug: Option<String>,
    #[serde(default, with = "serde_with::rust::double_option")]
    pub logo: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "better_auth_core::utils::json::deserialize_optional_value"
    )]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub data: UpdateOrganizationData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct DeleteOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CheckSlugRequest {
    pub slug: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SetActiveOrganizationRequest {
    #[serde(
        default,
        rename = "organizationId",
        deserialize_with = "deserialize_nullable_string_field"
    )]
    pub organization_id: NullableStringField,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LeaveOrganizationRequest {
    #[serde(rename = "organizationId")]
    pub organization_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetFullOrganizationQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
    #[serde(
        default,
        rename = "membersLimit",
        deserialize_with = "deserialize_optional_integer_query"
    )]
    pub members_limit: Option<f64>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct InviteMemberRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub role: RoleInput,
    #[serde(rename = "teamId")]
    pub team_id: Option<TeamInput>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TeamInput {
    One(String),
    Many(Vec<String>),
}
impl TeamInput {
    pub fn ids(&self) -> Vec<&str> {
        match self {
            Self::One(id) => vec![id],
            Self::Many(ids) => ids.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct RemoveMemberRequest {
    #[serde(rename = "memberIdOrEmail")]
    pub member_id_or_email: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateMemberRoleRequest {
    #[serde(rename = "memberId")]
    pub member_id: String,
    pub role: RoleInput,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListMembersQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    pub limit: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
    pub offset: Option<f64>,
    #[serde(rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(rename = "sortDirection")]
    pub sort_direction: Option<String>,
    #[serde(rename = "filterField")]
    pub filter_field: Option<String>,
    #[serde(rename = "filterValue")]
    pub filter_value: Option<String>,
    #[serde(rename = "filterOperator")]
    pub filter_operator: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RejectInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CancelInvitationRequest {
    #[serde(rename = "invitationId")]
    pub invitation_id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetInvitationQuery {
    pub id: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct GetActiveMemberRoleQuery {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListInvitationsQuery {
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct HasPermissionRequest {
    pub permissions: HashMap<String, Vec<String>>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckSlugResponse {
    pub status: bool,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
}

#[derive(Debug, Serialize)]
pub struct HasPermissionResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateOrganizationResponse<O: Serialize, M: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<M>,
    #[serde(skip)]
    pub default_team_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FullOrganizationResponse<O: Serialize, I: Serialize> {
    #[serde(flatten)]
    pub organization: O,
    pub members: Vec<MemberResponse>,
    pub invitations: Vec<I>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<FullOrganizationTeamResponse>>,
}

/// Upstream's full-organization join exposes the stored counter even though
/// standalone team endpoints filter it from their response.
#[derive(Debug, Serialize)]
pub struct FullOrganizationTeamResponse {
    #[serde(flatten)]
    pub team: better_auth_core::types::Team,
    #[serde(rename = "memberCount")]
    pub member_count: i64,
}

impl From<better_auth_core::types::Team> for FullOrganizationTeamResponse {
    fn from(team: better_auth_core::types::Team) -> Self {
        Self {
            member_count: team.member_count,
            team,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct InvitationResponse<I: Serialize> {
    pub invitation: I,
}

#[derive(Debug, Serialize)]
pub struct RemovedMemberResponse<M = MemberResponse> {
    pub member: M,
}

/// The original removed member. Email selection retains the joined minimal
/// user; ID selection omits that join, matching the source adapter projection.
#[derive(Debug, Clone, Serialize)]
pub struct OrganizationMemberRemovalSnapshot {
    #[serde(flatten)]
    pub member: better_auth_core::Member,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<MemberUserView>,
}

#[derive(Debug, Serialize)]
pub struct BasicMemberResponse {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::datetime::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct AcceptInvitationResponse<I: Serialize, M: Serialize> {
    pub invitation: I,
    pub member: M,
}

#[derive(Debug, Serialize)]
pub struct ListMembersResponse {
    pub members: Vec<MemberResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct GetActiveMemberRoleResponse {
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct GetInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName")]
    pub organization_name: String,
    #[serde(rename = "organizationSlug")]
    pub organization_slug: String,
    #[serde(rename = "inviterEmail")]
    pub inviter_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserInvitationResponse<I: Serialize> {
    #[serde(flatten)]
    pub invitation: I,
    #[serde(rename = "organizationName", skip_serializing_if = "Option::is_none")]
    pub organization_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreatedOrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::datetime::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::datetime::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: Option<serde_json::Value>,
}

impl CreatedOrganizationResponse {
    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: organization.metadata().cloned(),
        }
    }
}

impl OrganizationResponse {
    pub(crate) fn from_stored_organization(
        organization: &impl AuthOrganization,
    ) -> Result<Self, serde_json::Error> {
        let mut response = Self::from_organization(organization);
        response.metadata = response
            .metadata
            .map(|value| match value {
                serde_json::Value::String(value) => Ok(serde_json::Value::String(value)),
                value => {
                    better_auth_core::utils::json::to_string(&value).map(serde_json::Value::String)
                }
            })
            .transpose()?;
        Ok(response)
    }

    pub fn from_organization(organization: &impl AuthOrganization) -> Self {
        Self {
            id: organization.id().to_string(),
            name: organization.name().to_string(),
            slug: organization.slug().to_string(),
            logo: organization.logo().map(str::to_owned),
            created_at: organization.created_at(),
            metadata: organization.metadata().cloned(),
        }
    }
}

/// Member with user details (for API responses).
///
/// Uses [`MemberUserView`] from `better_auth_core::entity` for user info,
/// keeping it compatible with the built-in auth store.
#[derive(Debug, Clone, Serialize)]
pub struct MemberResponse {
    pub id: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub role: String,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "better_auth_core::utils::datetime::serialize")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub user: MemberUserView,
}

impl MemberResponse {
    /// Construct from any type implementing [`AuthMember`] and [`AuthUser`](better_auth_core::entity::AuthUser).
    pub fn from_member_and_user(
        member: &impl better_auth_core::entity::AuthMember,
        user: &impl better_auth_core::entity::AuthUser,
    ) -> Self {
        Self {
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
            user: MemberUserView::from_user(user),
        }
    }
}

impl BasicMemberResponse {
    pub fn from_member(member: &impl AuthMember) -> Self {
        Self {
            id: member.id().to_string(),
            organization_id: member.organization_id().to_string(),
            user_id: member.user_id().to_string(),
            role: member.role().to_string(),
            created_at: member.created_at(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CreateOrganizationRequest, GetFullOrganizationQuery, NullableStringField,
        SetActiveOrganizationRequest,
    };

    #[test]
    fn set_active_request_distinguishes_missing_from_null() {
        let missing: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({}))
            .expect("missing field should deserialize");
        let null: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": null
        }))
        .expect("null field should deserialize");
        let value: SetActiveOrganizationRequest = serde_json::from_value(serde_json::json!({
            "organizationId": "org-123"
        }))
        .expect("string field should deserialize");

        assert!(matches!(
            missing.organization_id,
            NullableStringField::Missing
        ));
        assert!(matches!(null.organization_id, NullableStringField::Null));
        assert!(matches!(
            value.organization_id,
            NullableStringField::Value(ref organization_id) if organization_id == "org-123"
        ));
    }

    #[test]
    fn create_organization_request_deserializes_keep_current_active_organization() {
        let request: CreateOrganizationRequest = serde_json::from_value(serde_json::json!({
            "name": "Acme",
            "slug": "acme",
            "keepCurrentActiveOrganization": true
        }))
        .expect("request should deserialize");

        assert_eq!(request.keep_current_active_organization, Some(true));
    }

    #[test]
    fn get_full_organization_query_deserializes_members_limit_from_string_or_number() {
        let string_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": "1"
        }))
        .expect("string limit should deserialize");
        let number_limit: GetFullOrganizationQuery = serde_json::from_value(serde_json::json!({
            "membersLimit": 2
        }))
        .expect("number limit should deserialize");

        assert_eq!(string_limit.members_limit, Some(1.0));
        assert_eq!(number_limit.members_limit, Some(2.0));
    }
}
