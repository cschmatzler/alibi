//! Metadata contributions see the original document and the actual callback context.
#[derive(Debug)]
pub(super) struct ExtensionMetadata {
    pub id: &'static str,
    pub mutate: bool,
}
impl alibi::plugins::OAuthMetadataContributor for ExtensionMetadata {
    fn contribute(
        &self,
        input: &mut alibi::plugins::OAuthMetadataExtensionInput<'_>,
    ) -> alibi::AuthResult<serde_json::Map<String, serde_json::Value>> {
        let header = input
            .context
            .endpoint
            .as_ref()
            .and_then(|call| call.headers())
            .and_then(|headers| headers.get("x-metadata-caller"));
        let mut output=serde_json::json!({
        "extension_stage":self.id,
        format!("extension_{}_base_clean",self.id):input.document.get("extension_stage").is_none(),
        format!("extension_{}_scope_count",self.id):input.document["scopes_supported"].as_array().unwrap().len(),
        format!("extension_{}_type",self.id):input.metadata_type.as_str(),
        "issuer":"https://untrusted.fixture.test","grant_types_supported":["wrong"],
        "claims_supported":["custom-extension-claim"],"constructor":"untrusted","toString":"untrusted",
        "custom_nullable":null,"extension_context_header":header,
    }).as_object().unwrap().clone();
        if self.mutate {
            _ = output.insert(
                format!("extension_{}_saw_mutation", self.id),
                serde_json::json!(input.document.get("shared_mutation").is_some()),
            );
            if self.id == "first" {
                input.document["shared_mutation"] = serde_json::json!("visible");
                input.document["issuer"] = serde_json::json!("https://mutated.fixture.test");
            }
        }
        Ok(output)
    }
}
