//! Verified-domain assignment follows actual social OAuth completion and canonical identity.
use super::sso_oidc_peer as peer;
use super::*;
use alibi::endpoint::{EndpointOptions, ServerEndpoint};
use alibi::plugins::oauth::{OAuthCallbackInput, OAuthProvider};
use alibi::plugins::{OAuthPlugin, SsoConfig, SsoPlugin};
use alibi::store::{AccountStore, MemberStore};
backend_tests!(sso_verified_domain_assigns_social_users_and_rejects_ambiguous_organizations);
async fn sso_verified_domain_assigns_social_users_and_rejects_ambiguous_organizations<
    B: Backend,
>(
    db: Db,
) -> TestResult {
    let idp = peer::start().await;
    let dns = super::sso_dns::start().await;
    let (connection, store) = db.migrated::<B>(SECRET).await?;
    let config = AuthConfig::new(SECRET)
        .base_url(ORIGIN)
        .trusted_origin(&idp.base);
    for (index, case) in ["verified", "unverified", "disabled", "ambiguous"]
        .into_iter()
        .enumerate()
    {
        let auth = AuthBuilder::<B::Schema>::new(config.clone())
            .store(B::store(Arc::new(config.clone()), &connection))
            .rate_limit(alibi::middleware::RateLimitConfig::new().enabled(false))
            .plugin(super::auth_probe::fast_password())
            .plugin(SessionManagementPlugin::new())
            .plugin(alibi::plugins::OrganizationPlugin::new())
            .plugin(OAuthPlugin::new().add_provider(
                "gitlab",
                OAuthProvider::gitlab_with_issuer("enterprise-client", "stored-secret", &idp.base),
            ))
            .plugin(SsoPlugin::with_config(SsoConfig {
                domain_verification: true,
                domain_verification_dns_servers: vec![dns.address],
                organization_provisioning: alibi::plugins::SsoOrganizationProvisioning {
                    disabled: case == "disabled",
                    ..Default::default()
                },
                ..Default::default()
            }))
            .build()
            .await?;
        let owner = signup(&auth, &format!("domain-owner-{case}@example.test")).await;
        let owner_cookie = cookies(&owner);
        let domain = format!("{case}.company.test");
        let mut organizations = Vec::new();
        for target in 0..if case == "ambiguous" { 2 } else { 1 } {
            let organization = call(
                &auth,
                request(
                    "/organization/create",
                    Some(json!({"name":"Domain company","slug":format!("domain-{case}-{target}")})),
                    &owner_cookie,
                ),
                200,
            )
            .await;
            let organization_id = body(&organization)["id"].as_str().unwrap().to_owned();
            let provider = format!("domain-{case}-{target}");
            let registered=Box::pin(auth.dispatch_endpoint(SsoPlugin::register_sso_provider_endpoint(&json!({"providerId":provider,"organizationId":organization_id,"issuer":idp.base,"domain":domain,"oidcConfig":{"clientId":"enterprise-client","clientSecret":"stored-secret","skipDiscovery":true,"pkce":true}}))?,EndpointOptions {headers:Some([("cookie".into(),owner_cookie.clone())].into_iter().collect()),..Default::default()})).await?.into_response()?;
            assert_eq!(registered.status, 200);
            let token = body(&registered)["domainVerificationToken"]
                .as_str()
                .unwrap()
                .to_owned();
            *dns.records.lock().unwrap() =
                vec![vec![format!("_better-auth-token-{provider}={token}")]];
            let verified = Box::pin(
                auth.dispatch_endpoint(
                    ServerEndpoint::<Value>::new("sso", "verifyDomain")
                        .with_body(&json!({"providerId":provider}))?,
                    EndpointOptions {
                        headers: Some(
                            [("cookie".into(), owner_cookie.clone())]
                                .into_iter()
                                .collect(),
                        ),
                        ..Default::default()
                    },
                ),
            )
            .await?
            .into_response()?;
            assert_eq!(verified.status, 204);
            organizations.push(organization_id);
        }
        let email = format!("employee@{domain}");
        let subject = 710 + index;
        *idp.profile.lock().unwrap() = Some(
            json!({"id":subject,"email":email,"email_verified":case!="unverified","name":"Domain employee","state":"active","locked":false}),
        );
        let started=Box::pin(auth.dispatch_endpoint(ServerEndpoint::<Value>::new("oauth","signInSocial").with_body(&json!({"provider":"gitlab","callbackURL":format!("{ORIGIN}/complete"),"disableRedirect":true}))?,EndpointOptions::default())).await?.into_response()?;
        assert_eq!(started.status, 200);
        let grant = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?
            .get(body(&started)["url"].as_str().unwrap())
            .send()
            .await?;
        assert_eq!(grant.status(), 302);
        let url = url::Url::parse(grant.headers().get("location").unwrap().to_str()?)?;
        let query: OAuthCallbackInput = serde_json::from_value(json!(
            url.query_pairs()
                .into_owned()
                .collect::<std::collections::HashMap<_, _>>()
        ))?;
        let completed = Box::pin(auth.dispatch_endpoint(
            OAuthPlugin::callback_oauth_endpoint("gitlab", Some(&query))?,
            EndpointOptions {
                headers: Some([("cookie".into(), cookies(&started))].into_iter().collect()),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
        let mut response = AuthResponse::new(completed.error.status_code());
        response.headers = completed.headers.unwrap_or_default();
        assert_eq!(response.status, 302);
        assert_eq!(
            url::Url::parse(response.headers.get("location").unwrap())?.path(),
            "/complete"
        );
        let session = call(
            &auth,
            request("/get-session", None, &cookies(&response)),
            200,
        )
        .await;
        assert_eq!(body(&session)["user"]["email"], email);
        assert_eq!(
            body(&session)["user"]["emailVerified"],
            case != "unverified"
        );
        let user_id = body(&session)["user"]["id"].as_str().unwrap().to_owned();
        assert!(
            store
                .get_account("gitlab", &subject.to_string())
                .await?
                .is_some()
        );
        for organization in organizations {
            let member = store.get_member(&organization, &user_id).await?;
            if case == "verified" {
                assert_eq!(
                    member
                        .expect("verified social user must join the organization")
                        .role,
                    "member"
                );
            } else {
                assert!(member.is_none());
            }
        }
    }
    B::close(connection).await
}
