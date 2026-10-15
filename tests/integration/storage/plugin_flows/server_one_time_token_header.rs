//! Header-delivered transfer tokens from server calls must redeem once.
use super::*;
use alibi::endpoint::{EndpointOptions, EndpointResponse, ServerEndpoint};
use alibi::plugins::one_time_token::{
    GenerateOneTimeToken, HashOneTimeToken, OneTimeTokenConfig, OneTimeTokenPlugin,
    OneTimeTokenSession, OneTimeTokenStorage,
};
backend_tests!(server_one_time_token_header_delivers_redeemable_single_use_credentials);
postgres_tests!(server_one_time_token_header_delivers_redeemable_single_use_credentials);
struct Tokens(Mutex<usize>);
#[async_trait::async_trait]
impl GenerateOneTimeToken for Tokens {
    async fn generate(
        &self,
        session: &OneTimeTokenSession,
        request: Option<&AuthRequest>,
    ) -> alibi::AuthResult<String> {
        assert!(request.is_none());
        assert_eq!(session.session.user_id, session.user.id);
        let mut serial = self.0.lock().unwrap();
        *serial += 1;
        Ok(format!("ott-header-token-{serial}"))
    }
}
struct Digest;
#[async_trait::async_trait]
impl HashOneTimeToken for Digest {
    async fn hash(&self, token: &str) -> alibi::AuthResult<String> {
        Ok(format!("digest-{token}"))
    }
}
async fn redeem<S: AuthSchema>(auth: &Alibi<S>, token: &str) -> alibi::AuthResult<AuthResponse> {
    match Box::pin(auth.dispatch_endpoint(
        OneTimeTokenPlugin::verify_endpoint(token),
        EndpointOptions::default(),
    ))
    .await
    {
        Ok(output) => output.into_response(),
        Err(error) => EndpointResponse::error(error.error).to_response(),
    }
}
async fn server_one_time_token_header_delivers_redeemable_single_use_credentials<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    for enabled in [false, true] {
        let auth = builder::<B>(&connection)
            .plugin(OneTimeTokenPlugin::with_config(OneTimeTokenConfig {
                set_ott_header_on_new_session: enabled,
                generator: Some(Arc::new(Tokens(Mutex::new(0)))),
                storage: OneTimeTokenStorage::Custom(Arc::new(Digest)),
                ..Default::default()
            }))
            .build()
            .await?;
        let response=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("email-password","signUpEmail").with_body(&json!({"email":format!("sdk-ott-{enabled}@example.com"),"name":"Owner","password":PASSWORD}))?,EndpointOptions::default())).await.map_err(|error|error.error)?.into_response()?;
        assert_eq!(response.status, 200);
        if !enabled {
            assert!(response.headers.get("set-ott").is_none());
            continue;
        }
        let token = response
            .headers
            .get("set-ott")
            .expect("SDK issuance must deliver the persisted transfer token");
        assert_eq!(token, "ott-header-token-1");
        assert_eq!(
            response
                .headers
                .get("access-control-expose-headers")
                .map(String::as_str),
            Some("set-ott")
        );
        let transferred = redeem(&auth, token).await?;
        assert_eq!(transferred.status, 200);
        assert_eq!(
            body(&transferred)["session"]["token"],
            body(&response)["token"]
        );
        assert_eq!(
            body(&transferred)["user"]["id"],
            body(&response)["user"]["id"]
        );
        let replacement = transferred
            .headers
            .get("set-ott")
            .expect("SDK transfer publication issues its own one-time credential");
        assert_eq!(replacement, "ott-header-token-2");
        let replay = redeem(&auth, token).await?;
        assert_eq!(replay.status, 400);
        assert_eq!(body(&replay)["message"], "Invalid token");
        assert!(replay.headers.get("set-ott").is_none());
        assert_eq!(redeem(&auth, replacement).await?.status, 200);
    }
    Ok(())
}
