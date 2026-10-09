//! Profile transports and projections shared by the remaining dedicated factories.
//! Public JSON and typed persistence are kept separate; account identity always
//! comes from the original provider profile, before application mapping.
use super::{OAuthUserInfo, OAuthUserInfoHandler, OAuthUserInfoRequest, OAuthUserInfoResponse};
use base64::Engine;
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
pub(super) enum ProfileKind {
    Roblox,
    Salesforce,
    Slack,
    Spotify,
    Twitch,
    Twitter,
    Vercel,
    Vk,
    Zoom,
}

#[derive(Clone)]
pub(super) struct PublishedProfile {
    pub kind: ProfileKind,
    pub endpoint: Option<String>,
    pub email_endpoint: Option<String>,
    pub client_id: String,
    pub mapper: Option<fn(Value) -> Result<OAuthUserInfo, String>>,
    pub application_mapper: Option<std::sync::Arc<dyn super::OAuthProfileMapper>>,
}

pub(in crate::oauth) const PROFILE_EXCEPTION_PREFIX: &str = "oauth-profile-exception:";
pub(super) fn profile_exception(error: impl std::fmt::Display) -> String {
    format!("{PROFILE_EXCEPTION_PREFIX}{error}")
}

pub(in crate::oauth) fn truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        _ => true,
    }
}

pub(super) fn scalar(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Number(value)) => alibi_core::utils::json::number_to_string(value)
            .map(Some)
            .map_err(|error| error.to_string()),
        Some(Value::Bool(value)) => Ok(Some(value.to_string())),
        _ => Ok(None),
    }
}

pub(super) fn js_string(value: &Value) -> Result<String, String> {
    alibi_core::utils::json::JsValue::from(value.clone())
        .coerce_string()
        .map_err(str::to_owned)
}

pub(in crate::oauth) fn js_whitespace(value: char) -> bool {
    matches!(
        value,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// Number coercion used by the published grant helpers' multiplication.
pub(in crate::oauth) fn js_number(value: &Value) -> Option<f64> {
    match value {
        Value::Null => Some(0.0),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        Value::Number(value) => value.as_f64(),
        Value::Object(_) => None,
        Value::Array(_) => js_number(&Value::String(js_string(value).ok()?)),
        Value::String(value) => {
            let value = value.trim_matches(js_whitespace);
            if value.is_empty() {
                return Some(0.0);
            }
            for (prefix, radix) in [
                ("0x", 16),
                ("0X", 16),
                ("0b", 2),
                ("0B", 2),
                ("0o", 8),
                ("0O", 8),
            ] {
                if let Some(digits) = value.strip_prefix(prefix) {
                    if digits.is_empty() {
                        return None;
                    }
                    let mut result = 0.0;
                    for digit in digits.chars() {
                        result = result * f64::from(radix) + f64::from(digit.to_digit(radix)?);
                    }
                    return Some(result);
                }
            }
            if matches!(value, "Infinity" | "+Infinity") {
                return Some(f64::INFINITY);
            }
            if value == "-Infinity" {
                return Some(f64::NEG_INFINITY);
            }
            // Rust accepts inf spellings that ECMAScript Number does not.
            if value
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                return None;
            }
            value.parse().ok()
        }
    }
}

pub(in crate::oauth) fn grant_expiry(
    value: &Value,
    require_truthy: bool,
) -> Option<chrono::DateTime<chrono::Utc>> {
    if require_truthy && !truthy(value) {
        return None;
    }
    let timestamp = chrono::Utc::now().timestamp_millis() as f64 + js_number(value)? * 1000.0;
    if !timestamp.is_finite() || timestamp.abs() > 8_640_000_000_000_000.0 {
        return None;
    }
    chrono::DateTime::from_timestamp_millis(timestamp.trunc() as i64)
}

pub(super) fn has_access_token(request: &OAuthUserInfoRequest) -> bool {
    match &request.raw {
        Some(raw) => raw.get("access_token").is_some_and(truthy),
        None => request
            .access_token
            .as_ref()
            .is_some_and(|value| !value.is_empty()),
    }
}

pub(super) fn bearer_access_token(request: &OAuthUserInfoRequest) -> Result<String, String> {
    match &request.raw {
        Some(raw) => raw
            .get("access_token")
            .map(js_string)
            .transpose()
            .map(|value| value.unwrap_or_else(|| "undefined".into())),
        None => Ok(request
            .access_token
            .clone()
            .unwrap_or_else(|| "undefined".into())),
    }
}

pub(super) fn decode_grant_jwt(token: &str) -> Result<Value, String> {
    let parts: Vec<_> = token.split('.').collect();
    let [_, payload, _] = parts.as_slice() else {
        return Err("Invalid grant ID token".into());
    };
    if payload.is_empty() {
        return Err("Invalid grant ID-token payload".into());
    }
    let decoder = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let bytes = decoder
        .decode(payload.replace('-', "+").replace('_', "/"))
        .map_err(|error| error.to_string())?;
    let profile: Value =
        alibi_core::utils::json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if !profile.is_object() {
        return Err("Invalid grant ID-token claims".into());
    }
    Ok(profile)
}

pub(super) fn strict_primitive_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        _ => false,
    }
}

pub(super) fn grant_id_token(request: &OAuthUserInfoRequest) -> Result<Option<String>, String> {
    match &request.raw {
        Some(raw) => match raw.get("id_token").filter(|value| truthy(value)) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            _ => Err("Non-string grant ID token".into()),
        },
        None => Ok(request.id_token.clone().filter(|value| !value.is_empty())),
    }
}

pub(in crate::oauth) fn raw_subject(value: Option<&Value>) -> Result<String, String> {
    let subject = js_string(value.ok_or("Missing provider subject")?)?;
    if subject.trim_matches(js_whitespace).is_empty()
        || matches!(subject.as_str(), "null" | "undefined")
    {
        return Err("Invalid provider subject".into());
    }
    Ok(subject)
}

pub(super) fn subject(kind: ProfileKind, profile: &Value) -> Result<String, String> {
    let value = match kind {
        ProfileKind::Roblox | ProfileKind::Twitch | ProfileKind::Vercel => profile.get("sub"),
        ProfileKind::Salesforce => profile.get("user_id"),
        ProfileKind::Slack => profile.get("https://slack.com/user_id"),
        ProfileKind::Spotify | ProfileKind::Zoom => profile.get("id"),
        ProfileKind::Twitter => profile.pointer("/data/id"),
        ProfileKind::Vk => profile.pointer("/user/user_id"),
    };
    raw_subject(value)
}

fn copy(output: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        drop(output.insert(key.into(), value.clone()));
    }
}
fn or_empty<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Value {
    values
        .into_iter()
        .flatten()
        .find(|value| truthy(value))
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()))
}
fn nullish_empty<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Value {
    values
        .into_iter()
        .flatten()
        .find(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()))
}
fn placeholder(identifier: Option<&Value>, namespace: &str) -> Result<Value, String> {
    let identifier = identifier
        .map(js_string)
        .transpose()
        .map_err(profile_exception)?
        .unwrap_or_else(|| "undefined".into());
    let email = format!("{identifier}@{namespace}.placeholder.invalid");
    // The published helper validates the generated address rather than accepting
    // routing characters supplied by a malformed profile identifier.
    if !crate::authentication_helpers::is_valid_email(&email) {
        return Err(profile_exception("Invalid placeholder email"));
    }
    Ok(Value::String(email))
}

#[async_trait::async_trait]
impl OAuthUserInfoHandler for PublishedProfile {
    fn configured_client_ids(
        &self,
        ids: &[String],
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        if !matches!(self.kind, ProfileKind::Vk) {
            return None;
        }
        let mut handler = self.clone();
        handler.client_id = ids.join(",");
        Some(std::sync::Arc::new(handler))
    }
    fn errors_are_exceptions(&self) -> bool {
        false
    }

    fn mapped_handler(
        &self,
        mapper: std::sync::Arc<dyn super::OAuthProfileMapper>,
    ) -> Option<std::sync::Arc<dyn OAuthUserInfoHandler>> {
        let mut handler = self.clone();
        handler.mapper = None;
        handler.application_mapper = Some(mapper);
        Some(std::sync::Arc::new(handler))
    }

    async fn get_user_info(
        &self,
        request: OAuthUserInfoRequest,
    ) -> Result<OAuthUserInfoResponse, String> {
        let client = reqwest::Client::new();
        let mut profile: Value = if matches!(self.kind, ProfileKind::Twitch) {
            let token = grant_id_token(&request)?.ok_or("Missing Twitch ID token")?;
            decode_grant_jwt(&token)?
        } else {
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or("Missing provider userinfo endpoint")?;
            let access = bearer_access_token(&request)?;
            let transport = if matches!(self.kind, ProfileKind::Vk) {
                if !has_access_token(&request) {
                    return Err("Missing VK access token".into());
                }
                client.post(endpoint).form(&[
                    ("access_token", access.as_str()),
                    ("client_id", self.client_id.as_str()),
                ])
            } else {
                client.get(endpoint).bearer_auth(&access)
            };
            transport
                .send()
                .await
                .map_err(|error| error.to_string())?
                .error_for_status()
                .map_err(|error| error.to_string())?
                .json()
                .await
                .map_err(|error| error.to_string())?
        };
        if matches!(self.kind, ProfileKind::Salesforce | ProfileKind::Vercel) && !truthy(&profile) {
            return Err("Missing provider profile".into());
        }
        let mut twitter_verified = false;
        if matches!(self.kind, ProfileKind::Twitter) {
            let endpoint = self
                .email_endpoint
                .as_deref()
                .unwrap_or("https://api.x.com/2/users/me?user.fields=confirmed_email");
            if let Ok(response) = client
                .get(endpoint)
                .bearer_auth(bearer_access_token(&request)?)
                .send()
                .await
                && response.status().is_success()
                && let Ok(email_profile) = response.json::<Value>().await
                && let Some(email) = email_profile
                    .pointer("/data/confirmed_email")
                    .filter(|value| truthy(value))
            {
                let email = email.clone();
                let data = profile
                    .get_mut("data")
                    .and_then(Value::as_object_mut)
                    .ok_or_else(|| profile_exception("Invalid Twitter email receiver"))?;
                drop(data.insert("email".into(), email));
                twitter_verified = true;
            }
        }
        let application_output = if let Some(mapper) = &self.application_mapper {
            Some(mapper.map_profile(profile.clone()).await.map_err(|error| {
                if matches!(self.kind, ProfileKind::Salesforce) {
                    error
                } else {
                    profile_exception(error)
                }
            })?)
        } else {
            None
        };
        let mapped = self
            .mapper
            .map(|mapper| mapper(profile.clone()))
            .transpose()
            .map_err(|error| {
                if matches!(self.kind, ProfileKind::Salesforce) {
                    error
                } else {
                    profile_exception(error)
                }
            })?;
        // Unlike the caught Salesforce transport, these factory projections
        // access fields directly after invoking the application mapper.
        if profile.is_null() {
            return Err(profile_exception("Null provider profile"));
        }
        let mut output = Map::new();
        match self.kind {
            ProfileKind::Roblox => {
                drop(output.insert(
                    "name".into(),
                    or_empty([profile.get("nickname"), profile.get("preferred_username")]),
                ));
                copy(&mut output, "image", profile.get("picture"));
                drop(output.insert("email".into(), placeholder(profile.get("sub"), "roblox")?));
                drop(output.insert("emailVerified".into(), Value::Bool(false)));
            }
            ProfileKind::Salesforce => {
                copy(&mut output, "name", profile.get("name"));
                copy(&mut output, "email", profile.get("email"));
                copy(
                    &mut output,
                    "image",
                    profile
                        .pointer("/photos/picture")
                        .filter(|value| truthy(value))
                        .or_else(|| profile.pointer("/photos/thumbnail")),
                );
                drop(
                    output.insert(
                        "emailVerified".into(),
                        profile
                            .get("email_verified")
                            .filter(|value| !value.is_null())
                            .cloned()
                            .unwrap_or(Value::Bool(false)),
                    ),
                );
            }
            ProfileKind::Slack => {
                drop(output.insert("name".into(), or_empty([profile.get("name")])));
                copy(&mut output, "email", profile.get("email"));
                copy(&mut output, "emailVerified", profile.get("email_verified"));
                copy(
                    &mut output,
                    "image",
                    profile
                        .get("picture")
                        .filter(|value| truthy(value))
                        .or_else(|| profile.get("https://slack.com/user_image_512")),
                );
            }
            ProfileKind::Spotify => {
                copy(&mut output, "name", profile.get("display_name"));
                copy(&mut output, "email", profile.get("email"));
                let images = profile
                    .get("images")
                    .ok_or_else(|| profile_exception("Missing Spotify images"))?;
                if images.is_null() {
                    return Err(profile_exception("Null Spotify images"));
                }
                copy(
                    &mut output,
                    "image",
                    images
                        .as_array()
                        .and_then(|images| images.first())
                        .or_else(|| images.get("0"))
                        .and_then(|image| image.get("url")),
                );
                drop(output.insert("emailVerified".into(), Value::Bool(false)));
            }
            ProfileKind::Twitch => {
                for (key, field) in [
                    ("name", "preferred_username"),
                    ("email", "email"),
                    ("image", "picture"),
                    ("emailVerified", "email_verified"),
                ] {
                    copy(&mut output, key, profile.get(field));
                }
            }
            ProfileKind::Twitter => {
                let data = profile
                    .get("data")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| profile_exception("Missing Twitter data"))?;
                copy(&mut output, "name", data.get("name"));
                copy(&mut output, "image", data.get("profile_image_url"));
                drop(output.insert(
                    "email".into(),
                    match data.get("email").filter(|value| truthy(value)) {
                        Some(email) => email.clone(),
                        None => placeholder(data.get("id"), "twitter")?,
                    },
                ));
                drop(output.insert("emailVerified".into(), Value::Bool(twitter_verified)));
            }
            ProfileKind::Vercel => {
                drop(output.insert(
                    "name".into(),
                    nullish_empty([profile.get("name"), profile.get("preferred_username")]),
                ));
                copy(&mut output, "email", profile.get("email"));
                copy(&mut output, "image", profile.get("picture"));
                drop(
                    output.insert(
                        "emailVerified".into(),
                        profile
                            .get("email_verified")
                            .filter(|value| !value.is_null())
                            .cloned()
                            .unwrap_or(Value::Bool(false)),
                    ),
                );
            }
            ProfileKind::Vk => {
                let user = profile
                    .get("user")
                    .filter(|value| !value.is_null())
                    .ok_or_else(|| profile_exception("Missing VK user"))?;
                if !user.get("email").is_some_and(truthy)
                    && mapped.as_ref().is_none_or(|user| user.email.is_empty())
                    && !application_output
                        .as_ref()
                        .and_then(|output| output.get("email"))
                        .is_some_and(truthy)
                {
                    return Err("Missing VK email".into());
                }
                for field in ["first_name", "last_name", "birthday", "sex"] {
                    copy(&mut output, field, user.get(field));
                }
                let template = |value: Option<&Value>| -> Result<String, String> {
                    match value {
                        None => Ok("undefined".into()),
                        Some(Value::Null) => Ok("null".into()),
                        Some(value) => js_string(value),
                    }
                };
                drop(output.insert(
                    "name".into(),
                    Value::String(format!(
                        "{} {}",
                        template(user.get("first_name"))?,
                        template(user.get("last_name"))?
                    )),
                ));
                copy(&mut output, "email", user.get("email"));
                copy(&mut output, "image", user.get("avatar"));
                drop(output.insert("emailVerified".into(), Value::Bool(false)));
            }
            ProfileKind::Zoom => {
                copy(&mut output, "name", profile.get("display_name"));
                copy(&mut output, "email", profile.get("email"));
                copy(&mut output, "image", profile.get("pic_url"));
                drop(output.insert(
                    "emailVerified".into(),
                    Value::Bool(profile.get("verified").is_some_and(truthy)),
                ));
            }
        }
        if let Some(mapped) = &mapped {
            output.extend(mapped.public_profile(true));
        }
        if let Some(mapped) = application_output {
            output.extend(mapped);
        }
        let user = match mapped {
            Some(user) => user,
            None => OAuthUserInfo {
                additional_fields: output
                    .iter()
                    .filter(|(key, _)| {
                        !matches!(
                            key.as_str(),
                            "id" | "name" | "email" | "image" | "emailVerified"
                        )
                    })
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
                id: subject(self.kind, &profile).unwrap_or_default(),
                name: scalar(output.get("name").filter(|value| truthy(value)))?,
                email: output
                    .get("email")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                image: scalar(output.get("image"))?,
                email_verified: output.get("emailVerified").is_some_and(truthy),
            },
        };
        Ok(OAuthUserInfoResponse {
            user_output: Some(output),
            user,
            data: profile,
        })
    }
}
