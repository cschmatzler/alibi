use alibi::plugins::{OAuthTokenClaimsInput, OAuthUserInfoClaimsInput};
use serde_json::{Map, Value, json};

#[derive(Debug)]
pub(super) struct ExtensionClaims {
    pub id: &'static str,
    pub target: &'static str,
    pub live: Option<std::sync::Arc<LiveAccessClaims>>,
    pub user_info: Option<std::sync::Arc<LiveUserInfoClaims>>,
}

#[derive(Debug, Default)]
pub(crate) struct LiveAccessClaims {
    pub value: std::sync::Mutex<String>,
    pub calls: std::sync::Mutex<Vec<Value>>,
    pub operator: std::sync::Mutex<bool>,
    pub mutate_resource: std::sync::Mutex<Option<String>>,
    pub operator_calls: std::sync::Mutex<Vec<Value>>,
    pub operator_contexts: std::sync::Mutex<Vec<Value>>,
}

struct AccessOperator<S: alibi::AuthSchema> {
    live: std::sync::Arc<LiveAccessClaims>,
    schema: std::marker::PhantomData<fn() -> S>,
}
impl<S: alibi::AuthSchema> std::fmt::Debug for AccessOperator<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessOperator").finish_non_exhaustive()
    }
}
pub(crate) fn access_operator<S: alibi::AuthSchema>(
    live: std::sync::Arc<LiveAccessClaims>,
) -> std::sync::Arc<dyn alibi::plugins::OAuthTokenClaimsContributor> {
    std::sync::Arc::new(AccessOperator::<S> {
        live,
        schema: std::marker::PhantomData,
    })
}
#[async_trait::async_trait]
impl<S: alibi::AuthSchema> alibi::plugins::OAuthTokenClaimsContributor for AccessOperator<S> {
    async fn contribute(
        &self,
        input: OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        if !*self.live.operator.lock().unwrap() {
            return Ok(Map::new());
        }
        let value = self.live.value.lock().unwrap().clone();
        self.live.operator_calls.lock().unwrap().push(json!({
            "userId":input.params.user.as_ref().map(|user| &user.id),
            "scopes":input.params.scopes,"resources":input.params.resources,
            "referenceId":input.params.reference_id,"metadata":input.metadata,
        }));
        self.live.operator_contexts.lock().unwrap().push(json!({
            "grant":input.grant_type,"sessionId":input.params.session_id,"clientId":input.params.client.client_id,
        }));
        let resource = self.live.mutate_resource.lock().unwrap().clone();
        if let Some(resource) = resource {
            let ctx = input
                .context
                .context::<S>()
                .expect("actual callback schema");
            let mut row = ctx.database.get_oauth_resource(&resource).await?.unwrap();
            row.metadata["customClaims"]["resource_wins"] =
                json!(format!("resource-during-{value}"));
            let _ = ctx
                .database
                .update_oauth_resource(&resource, row.metadata, chrono::Utc::now())
                .await?;
        }
        Ok(json!({
            "operator_value":value,"extension_owner":format!("operator-{value}"),"per_request":format!("operator-{value}"),
            "resource_wins":format!("operator-{value}"),
            "iss":"https://forged.fixture.test","sub":"forged","aud":"forged","exp":1,"iat":1,"jti":"forged",
            "client_id":"forged","azp":"forged","scope":"forged","sid":"forged",
            "auth_time":1,"acr":"forged","amr":["forged"],"cnf":{"jkt":"forged"},
        }).as_object().unwrap().clone())
    }
}

/// Application-owned state; changing it never changes the persisted user profile.
#[derive(Debug, Default)]
pub(crate) struct LiveUserInfoClaims {
    pub value: std::sync::Mutex<Option<String>>,
    pub calls: std::sync::Mutex<Vec<Value>>,
    pub events: std::sync::Mutex<Vec<String>>,
    pub contexts: std::sync::Mutex<Vec<Value>>,
}

#[derive(Debug, Default)]
pub(crate) struct LiveIdTokenClaims {
    pub value: std::sync::Mutex<Option<String>>,
    pub error: std::sync::Mutex<String>,
    pub calls: std::sync::Mutex<Vec<Value>>,
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenClaimsContributor for LiveIdTokenClaims {
    async fn contribute(
        &self,
        input: OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        let Some(value) = self.value.lock().unwrap().clone() else {
            return Ok(Map::new());
        };
        self.calls.lock().unwrap().push(json!({
            "userId":input.params.user.as_ref().map(|user| &user.id),
            "userName":input.params.user.as_ref().and_then(|user| user.name.as_ref()),
            "userEmail":input.params.user.as_ref().and_then(|user| user.email.as_ref()),
            "scopes":input.params.scopes,"metadata":input.metadata,
        }));
        match self.error.lock().unwrap().as_str() {
            "api" => {
                return Err(alibi::AuthError::Api {
                    status: 400,
                    code: Some("ID_CLAIM_REJECTED".into()),
                    message: "ID callback rejected".into(),
                });
            }
            "ordinary" => return Err(alibi::AuthError::internal("ID callback failed")),
            _ => {}
        }
        Ok(json!({
            "name":format!("ID operator {value}"),"email":format!("id-{value}@example.test"),"email_verified":true,
            "extension_owner":format!("id-operator-{value}"),"per_request":format!("id-operator-{value}"),
            "iss":"https://forged.fixture.test","sub":"forged","aud":"forged","iat":1,"exp":2,"nbf":1,"jti":"forged",
            "nonce":"forged","azp":"forged","sid":"forged","auth_time":1,"acr":"forged","amr":["forged"],
            "at_hash":"forged","c_hash":"forged","s_hash":"forged",
            "cnf":{"operator":value},
        }).as_object().unwrap().clone())
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthUserInfoClaimsContributor for LiveUserInfoClaims {
    async fn contribute(
        &self,
        input: OAuthUserInfoClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        let Some(value) = self.value.lock().unwrap().clone() else {
            return Ok(Map::new());
        };
        self.events.lock().unwrap().push("operator".into());
        self.calls.lock().unwrap().push(json!({
            "userId": input.user.id,
            "userName": input.user.name,
            "userEmail": input.user.email,
            "scopes": input.scopes,
            "requestedClaims": input.requested_claims,
            "payloadSub": input.payload.get("sub"),
            "payloadClientId": input.payload.get("client_id").or_else(|| input.payload.get("azp")),
            "payloadScope": input.payload.get("scope"),
        }));
        self.contexts.lock().unwrap().push(json!({
            "clientId": input.client.map(|client| &client.client_id),
            "caller": input.context.endpoint.as_ref().and_then(|call|call.headers()).and_then(|headers|headers.get("x-claims-caller")),
            "configured": input.options.custom_user_info_claims.is_some(),
            "path": input.context.request.as_ref().map(|request| &request.path),
        }));
        Ok(json!({
            "name": format!("Operator {value}"),
            "email": format!("operator-{value}@example.test"),
            "extension_owner": format!("operator-{value}"),
            "toString": format!("operator-toString-{value}"),
            "__proto__": {"operatorPrototype": value},
            "sub": "operator-forged-sub",
        })
        .as_object()
        .unwrap()
        .clone())
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthTokenClaimsContributor for ExtensionClaims {
    async fn contribute(
        &self,
        input: OAuthTokenClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        if input
            .context
            .endpoint
            .as_ref()
            .and_then(|call| call.headers())
            .and_then(|headers| headers.get("x-claims-error"))
            .map(String::as_str)
            == Some(self.target)
        {
            return Err(alibi::AuthError::Api {
                status: 400,
                code: Some("CLAIM_REJECTED".into()),
                message: format!("rejected {}", self.target),
            });
        }
        let mut claims = json!({
            "extension_owner": self.id,
            format!("extension_{}", self.id): {
                "grant": input.grant_type,
                "scopes": input.params.scopes,
                "userId": input.params.user.as_ref().map(|user| &user.id),
                "clientId": input.params.client.client_id,
                "referenceId": input.params.reference_id,
                "sessionId": input.params.session_id,
                "metadata": input.metadata,
                "caller": input.context.endpoint.as_ref().and_then(|call|call.headers()).and_then(|headers|headers.get("x-claims-caller")),
            },
            "per_request": self.id,
            "resource_wins": self.id,
            "sub": "forged", "iss": "https://forged.fixture.test", "aud": "forged",
            "email": "forged@example.test", "scope": "forged", "exp": 1, "sid": "forged",
            "constructor": "forged", "nullable_claim": null,
        }).as_object().unwrap().clone();
        // JavaScript omits undefined issuance context in the recorded claim.
        if serde_json::to_value(input.grant_type)?.is_null() {
            let _ = claims[&format!("extension_{}", self.id)]
                .as_object_mut()
                .unwrap()
                .remove("grant");
        }
        if let Some(live) = &self.live {
            live.calls.lock().unwrap().push(json!({
                "extension": self.id,
                "grant": input.grant_type,
                "sessionId": input.params.session_id,
                "userId": input.params.user.as_ref().map(|user| &user.id),
                "clientId": input.params.client.client_id,
                "referenceId": input.params.reference_id,
                "scopes": input.params.scopes,
                "resources": input.params.resources,
                "metadata": input.metadata,
            }));
            claims.extend(
                json!({
                    "live_value": *live.value.lock().unwrap(),
                    "active": false, "azp": "forged", "client_id": "forged",
                    "token_type": "forged", "iat": 1, "jti": "forged",
                    "cnf": {"jkt":"forged"}, "auth_time": 1, "acr": "forged", "amr": ["forged"],
                })
                .as_object()
                .unwrap()
                .clone(),
            );
        }
        Ok(claims)
    }
}

#[async_trait::async_trait]
impl alibi::plugins::OAuthUserInfoClaimsContributor for ExtensionClaims {
    async fn contribute(
        &self,
        input: OAuthUserInfoClaimsInput<'_>,
    ) -> alibi::AuthResult<Map<String, Value>> {
        if let Some(live) = &self.user_info {
            live.events.lock().unwrap().push(self.id.into());
        }
        Ok(json!({
            "extension_owner": self.id,
            format!("extension_{}", self.id): {
                "scopes": input.scopes,
                "userId": input.user.id,
                "clientId": input.client.map(|client| &client.client_id),
                "requestedClaims": input.requested_claims,
                "payloadSub": input.payload.get("sub"),
                "caller": input.context.endpoint.as_ref().and_then(|call|call.headers()).and_then(|headers|headers.get("x-claims-caller")),
            },
            "sub": "forged", "name": "Forged name", "email_verified": true,
            "constructor": "forged", "nullable_claim": null,
        }).as_object().unwrap().clone())
    }
}
pub(crate) fn extensions_with_live(
    live: Option<std::sync::Arc<LiveAccessClaims>>,
) -> Vec<std::sync::Arc<alibi::plugins::OAuthProviderExtension>> {
    extensions_with_state(live, None)
}

pub(super) fn extensions_with_user_info(
    live: std::sync::Arc<LiveUserInfoClaims>,
) -> Vec<std::sync::Arc<alibi::plugins::OAuthProviderExtension>> {
    extensions_with_state(None, Some(live))
}

fn extensions_with_state(
    live: Option<std::sync::Arc<LiveAccessClaims>>,
    user_info: Option<std::sync::Arc<LiveUserInfoClaims>>,
) -> Vec<std::sync::Arc<alibi::plugins::OAuthProviderExtension>> {
    ["first", "second"]
        .into_iter()
        .map(|id| {
            std::sync::Arc::new(alibi::plugins::OAuthProviderExtension {
                claims: alibi::plugins::OAuthExtensionClaims {
                    access_token: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "access",
                        live: live.clone(),
                        user_info: None,
                    })),
                    id_token: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "id",
                        live: None,
                        user_info: None,
                    })),
                    user_info: Some(std::sync::Arc::new(ExtensionClaims {
                        id,
                        target: "userinfo",
                        live: None,
                        user_info: user_info.clone(),
                    })),
                },
                ..Default::default()
            })
        })
        .collect()
}
