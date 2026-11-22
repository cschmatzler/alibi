//! Stable storage keys shared by SCIM mutations, queries, and adapters.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub(super) fn tuple(parts: &[&str]) -> Result<String, serde_json::Error> {
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(serde_json::to_vec(parts)?)))
}

pub fn connection(id: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-connection", id])
}

pub fn connection_user(connection: &str, user: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-user", connection, user])
}

pub fn group_display_name(connection: &str, name: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-group-display-name", connection, &name.to_lowercase()])
}

pub fn group_external_id(connection: &str, id: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-group-external-id", connection, id])
}

pub fn user_name(connection: &str, name: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-user-name", connection, &name.to_lowercase()])
}

pub fn user_external_id(connection: &str, id: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-user-external-id", connection, id])
}

pub fn email_value(normalized: &str) -> Result<String, serde_json::Error> {
    tuple(&["scim-email-value", normalized])
}
