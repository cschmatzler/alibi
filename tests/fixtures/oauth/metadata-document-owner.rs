//! An already validated first-party source admits only its durable document row.
//! Persistence is exercised separately through register_client_metadata_document.
#[derive(Debug)]
pub(super) struct MetadataDocumentOwner;
#[async_trait::async_trait]
impl alibi::plugins::oauth_provider::OAuthClientDiscovery for MetadataDocumentOwner {
    fn id(&self) -> &str {
        "trusted-document-owner"
    }
    fn matches(&self, id: &str) -> bool {
        id == "https://client.fixture.test/metadata.json"
    }
    async fn resolve(
        &self,
        _: &alibi::CallbackContext,
        _: &str,
        existing: Option<alibi::store::OAuthClient>,
    ) -> alibi::AuthResult<Option<alibi::store::OAuthClient>> {
        Ok(existing)
    }
}

/// Application claims expose only the metadata actually delivered by the provider.
#[derive(Debug)]
pub(super) struct MetadataDocumentClaims;
#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenClaimsContributor for MetadataDocumentClaims {
    async fn contribute(
        &self,
        input: alibi::plugins::OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<serde_json::Map<String, serde_json::Value>> {
        Ok(serde_json::json!({
            "document_metadata": input.metadata,
            "sub": "forged", "scope": "forged",
        })
        .as_object()
        .unwrap()
        .clone())
    }
}
