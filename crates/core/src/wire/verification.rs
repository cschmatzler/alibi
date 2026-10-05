use super::*;
/// Public verification response shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationView {
    pub id: String,
    pub identifier: String,
    pub value: String,
    #[serde(rename = "expiresAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "createdAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    #[serde(serialize_with = "crate::utils::datetime::serialize")]
    pub updated_at: DateTime<Utc>,
}

impl<T: AuthVerification> From<&T> for VerificationView {
    fn from(verification: &T) -> Self {
        Self {
            id: verification.id().into_owned(),
            identifier: verification.identifier().to_owned(),
            value: verification.value().to_owned(),
            expires_at: verification.expires_at(),
            created_at: verification.created_at(),
            updated_at: verification.updated_at(),
        }
    }
}

impl AuthVerification for VerificationView {
    fn id(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.id)
    }
    fn identifier(&self) -> &str {
        &self.identifier
    }
    fn value(&self) -> &str {
        &self.value
    }
    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}
