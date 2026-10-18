//! An already validated first-party source admits only its durable document row.
//! Persistence is exercised separately through register_client_metadata_document.
#[derive(Debug)]
pub struct MetadataDocumentOwner;
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
