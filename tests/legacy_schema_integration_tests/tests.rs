use super::*;
use better_auth_core::field_policy::FieldValues;

#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report test failures; Result propagates setup and fixture errors"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn numeric_user_schema_cleans_team_memberships_without_a_bundled_user_foreign_key()
-> Result<(), Box<dyn std::error::Error>> {
    use better_auth_core::store::{
        MemberStore, OrganizationStore, TeamStore, UserStore, WalletAddressStore,
    };
    use better_auth_core::types::{
        AddTeamMemberResult, CreateMember, CreateOrganization, CreateTeam, CreateWalletAddress,
    };
    let database = test_database().await;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let store = SeaOrmStore::<LegacySchema>::new(test_config(), database.clone());
    let user = store
        .create_user(CreateUser::new().with_email("numeric-team@example.com"))
        .await?;
    assert_eq!(user.id, 1);
    let wallet_address = "0x52908400098527886E0F7030069857D2E4169EE7";
    let wallet = store
        .create_wallet_address(CreateWalletAddress::new("0001", wallet_address, 1.0))
        .await?;
    assert_eq!(wallet.user_id, "1");
    let other_user = store
        .create_user(CreateUser::new().with_email("numeric-other@example.com"))
        .await?;
    let other_wallet = store
        .create_wallet_address(CreateWalletAddress::new("2", wallet_address, 100.0))
        .await?;
    assert_eq!(other_user.id, 2);
    let first_org = store
        .create_organization(CreateOrganization::new("Numeric first", "numeric-first"))
        .await?;
    let second_org = store
        .create_organization(CreateOrganization::new("Numeric second", "numeric-second"))
        .await?;
    let first_member = store
        .create_member(CreateMember::new(&first_org.id, "1", "member"))
        .await?;
    drop(
        store
            .create_member(CreateMember::new(&second_org.id, "1", "member"))
            .await?,
    );
    let first = store
        .create_team(CreateTeam {
            name: "First".to_owned(),
            organization_id: first_org.id.clone(),
            updated_at: None,
        })
        .await?;
    let second = store
        .create_team(CreateTeam {
            name: "Second".to_owned(),
            organization_id: second_org.id.clone(),
            updated_at: None,
        })
        .await?;
    assert!(matches!(
        store.add_team_member(&first.id, "1", Some(1)).await?,
        AddTeamMemberResult::Added(_)
    ));
    assert!(matches!(
        store.add_team_member(&second.id, "1", Some(1)).await?,
        AddTeamMemberResult::Added(_)
    ));
    store.delete_member(&first_member.id).await?;
    assert!(store.get_team_member(&first.id, "1").await?.is_none());
    assert!(store.get_team_member(&second.id, "1").await?.is_some());
    assert_eq!(
        store
            .get_team(None, &first.id)
            .await?
            .map(|team| team.member_count),
        Some(0)
    );
    let _ignored_execute_unprepared = database.execute_unprepared("CREATE TRIGGER numeric_wallet_delete_abort BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'numeric wallet deletion veto'); END").await?;
    assert!(store.delete_user("0001").await.is_err());
    assert!(store.get_user_by_id("1").await?.is_some());
    assert_eq!(
        store.get_wallet_address(wallet_address, Some(1.0)).await?,
        Some(wallet)
    );
    assert!(store.get_team_member(&second.id, "1").await?.is_some());
    assert_eq!(
        store
            .get_team(None, &second.id)
            .await?
            .map(|team| team.member_count),
        Some(1)
    );
    let _ignored_execute_unprepared_2 = database
        .execute_unprepared("DROP TRIGGER numeric_wallet_delete_abort")
        .await?;
    store.delete_user("0001").await?;
    assert!(store.get_user_by_id("1").await?.is_none());
    assert!(store.list_user_teams("1").await?.is_empty());
    assert!(store.get_team_member(&second.id, "1").await?.is_none());
    assert_eq!(
        store
            .get_team(None, &second.id)
            .await?
            .map(|team| team.member_count),
        Some(0)
    );
    assert!(
        store
            .get_wallet_address(wallet_address, Some(1.0))
            .await?
            .is_none()
    );
    assert_eq!(
        store.get_wallet_address(wallet_address, None).await?,
        Some(other_wallet)
    );
    assert!(store.get_user_by_id("2").await?.is_some());
    Ok(())
}

#[tokio::test]
async fn legacy_numeric_schema_signup_flow_uses_numeric_ids_and_defaults() {
    let auth = create_auth().await;

    let signup = request(
        HttpMethod::Post,
        "/sign-up/email",
        Some(json!({
            "email": "new@example.com",
            "password": "Password123!",
            "name": "New User",
        })),
    );
    let response = auth
        .handle_request(signup)
        .await
        .expect("signup should succeed");
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
    let token = body["token"]
        .as_str()
        .expect("token should exist")
        .to_owned();

    let stored_user = auth
        .store()
        .get_user_by_email("new@example.com")
        .await
        .expect("lookup should succeed")
        .expect("user should exist");
    assert!(stored_user.id > 0);
    assert_eq!(stored_user.tenant_id, 1);
    assert_eq!(stored_user.locale, "en");
    assert_eq!(body["user"]["id"], stored_user.id.to_string());

    // Raw numeric pages must use this application's native ID parser and retain
    // its physical custom fields, rather than a bundled string-ID projection.
    let paged = auth
        .store()
        .list_users_by_ids_page(&[format!("00{}", stored_user.id)], 1.0)
        .await
        .expect("numeric alias page should use the custom ID parser");
    assert_eq!(
        serde_json::to_value(paged).expect("page JSON"),
        serde_json::to_value(vec![stored_user.clone()]).expect("stored JSON")
    );
    assert!(matches!(
        auth.store()
            .list_users_by_ids_page(&[format!("{}suffix", stored_user.id)], 1.0,)
            .await,
        Err(AuthError::BadRequest(_))
    ));

    let session_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
        .await
        .expect("get-session should succeed");
    assert_eq!(session_response.status, 200);
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_response.body).expect("valid session json");
    assert_eq!(session_body["user"]["id"], stored_user.id.to_string());

    let accounts_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/list-accounts", &token))
        .await
        .expect("list-accounts should succeed");
    assert_eq!(accounts_response.status, 200);
    let accounts_body: serde_json::Value =
        serde_json::from_slice(&accounts_response.body).expect("valid accounts json");
    assert_eq!(accounts_body.as_array().expect("array").len(), 1);
    assert_eq!(accounts_body[0]["userId"], stored_user.id.to_string());
    assert_eq!(accounts_body[0]["providerId"], "credential");
}

#[tokio::test]
async fn legacy_numeric_schema_existing_user_can_sign_in() {
    let database = test_database().await;
    let legacy_user_id = seed_legacy_user(&database).await;
    let config = test_config();
    let store = SeaOrmStore::<LegacySchema>::new(config.clone(), database);
    let auth = BetterAuth::<LegacySchema>::new(config)
        .store(store)
        .plugin(EmailPasswordPlugin::new().enable_signup(true))
        .plugin(SessionManagementPlugin::new())
        .plugin(PasswordManagementPlugin::new())
        .plugin(AccountManagementPlugin::new())
        .build()
        .await
        .expect("legacy auth should build");

    let signin = request(
        HttpMethod::Post,
        "/sign-in/email",
        Some(json!({
            "email": "legacy@example.com",
            "password": "legacy-password",
        })),
    );
    let response = auth
        .handle_request(signin)
        .await
        .expect("signin should succeed");
    assert_eq!(response.status, 200);

    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("valid json");
    let token = body["token"]
        .as_str()
        .expect("token should exist")
        .to_owned();
    assert_eq!(body["user"]["id"], legacy_user_id.to_string());

    let session_response = auth
        .handle_request(auth_request(HttpMethod::Get, "/get-session", &token))
        .await
        .expect("get-session should succeed");
    let session_body: serde_json::Value =
        serde_json::from_slice(&session_response.body).expect("valid session json");
    assert_eq!(session_body["user"]["id"], legacy_user_id.to_string());
    assert_eq!(
        session_body["session"]["userId"],
        legacy_user_id.to_string()
    );
}

#[tokio::test]
async fn legacy_numeric_schema_store_verifications_use_public_string_ids() {
    let auth = create_auth().await;

    let verification = auth
        .store()
        .create_verification(CreateVerification {
            identifier: "verify:legacy".to_owned(),
            value: "token-123".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        })
        .await
        .expect("verification should insert");

    assert!(!verification.id().is_empty());

    let loaded = auth
        .store()
        .get_verification_by_identifier("verify:legacy")
        .await
        .expect("lookup should succeed");
    assert!(loaded.is_some());

    auth.store()
        .delete_verification(&verification.id())
        .await
        .expect("delete should succeed");

    let loaded_2 = auth
        .store()
        .get_verification_by_identifier("verify:legacy")
        .await
        .expect("lookup should succeed");
    assert!(loaded_2.is_none());

    let reservation = auth
        .store()
        .reserve_verification(CreateVerification {
            identifier: "numeric-reservation".to_owned(),
            value: "claim".to_owned(),
            expires_at: Utc::now() + chrono::Duration::minutes(30),
        })
        .await;
    assert!(
        reservation.is_err(),
        "numeric schemas must fail closed without a deterministic reservation binding"
    );
    assert!(
        auth.store()
            .get_latest_verification_by_identifier("numeric-reservation")
            .await
            .expect("raw lookup should succeed")
            .is_none()
    );
}

#[tokio::test]
async fn manual_numeric_session_schema_fails_closed_for_unbound_configured_fields() {
    let mut config = test_config();
    drop(config.session.additional_fields.insert(
        "label".into(),
        better_auth::field_policy::FieldConfig::new(json!({"type":"string"})),
    ));
    let auth = BetterAuth::<LegacySchema>::new(config.clone())
        .store(SeaOrmStore::<LegacySchema>::new(
            config,
            test_database().await,
        ))
        .plugin(EmailPasswordPlugin::new())
        .plugin(SessionManagementPlugin::new())
        .build()
        .await
        .expect("manual schema still builds with default methods");
    let signup = auth.handle_request(request(HttpMethod::Post,"/sign-up/email",Some(json!({"email":"unbound-session@example.com","password":"Password123!","name":"Manual"})))).await.expect("signup succeeds without field bindings");
    assert_eq!(signup.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&signup.body).expect("signup JSON");
    let token = body["token"].as_str().expect("token");
    let before = auth
        .store()
        .get_session(token)
        .await
        .expect("lookup")
        .expect("stored session");
    let mut update = auth_request(HttpMethod::Post, "/update-session", token);
    update.body = Some(br#"{"label":"must-not-save","userId":"foreign"}"#.to_vec());
    drop(
        update
            .headers
            .insert("content-type".into(), "application/json".into()),
    );
    let rejected = auth
        .handle_request(update)
        .await
        .expect("fail-closed response");
    assert_eq!(rejected.status, 500);
    assert_eq!(rejected.body, Vec::<u8>::new());
    let after = auth
        .store()
        .get_session(token)
        .await
        .expect("lookup")
        .expect("session preserved");
    assert_eq!(after.updated_at, before.updated_at);
    assert_eq!(after.user_id, before.user_id);
    assert_eq!(after.token, before.token);
}

/// Trusted patches distinguish absent expiry from explicit SQL NULL for both
/// generated string-ID entities and application-owned numeric-ID entities.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn nullable_ban_expiry_patch_preserves_ban_and_other_principals()
-> Result<(), Box<dyn std::error::Error>> {
    #[expect(
        clippy::too_many_lines,
        reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
    )]
    async fn check<S: AuthSchema>(store: SeaOrmStore<S>) -> Result<(), Box<dyn std::error::Error>>
    where
        S::User: SeaOrmUserModel,
        S::Session: SeaOrmSessionModel,
    {
        use better_auth_core::store::{SessionStore, UserStore};
        use better_auth_core::wire::{SessionView, UserView};
        use sea_orm::Statement;
        let owner = store
            .create_user(CreateUser::new().with_email("ban-owner@patch.fixture.test"))
            .await?;
        let foreign = store
            .create_user(CreateUser::new().with_email("ban-foreign@patch.fixture.test"))
            .await?;
        let foreign_before = serde_json::to_value(UserView::from(&foreign))?;
        let mut sessions = Vec::new();
        for user in [&owner, &foreign] {
            let session = store
                .create_session(CreateSession {
                    additional_fields: FieldValues::default(),
                    token: None,
                    user_id: user.id().into_owned(),
                    expires_at: Utc::now() + chrono::Duration::days(1),
                    ip_address: None,
                    user_agent: Some("ban-patch-storage-proof".to_owned()),
                    impersonated_by: None,
                    active_organization_id: None,
                    active_team_id: None,
                })
                .await?;
            sessions.push((
                session.token().to_owned(),
                serde_json::to_value(SessionView::from(&session))?,
            ));
        }
        let expiry: DateTime<Utc> = "2030-01-02T03:04:05.125Z".parse()?;
        let set: UpdateUser = serde_json::from_value(
            json!({"banned":true,"ban_reason":"retained reason","ban_expires":expiry}),
        )?;
        let banned = store.update_user(&owner.id(), set).await?;
        assert_eq!(banned.ban_expires(), Some(expiry));
        let omitted: UpdateUser = serde_json::from_value(json!({"name":"unrelated rename"}))?;
        let encoded_omitted = serde_json::to_value(&omitted)?;
        assert!(encoded_omitted.get("ban_expires").is_none());
        let renamed = store
            .update_user(&owner.id(), serde_json::from_value(encoded_omitted)?)
            .await?;
        assert_eq!(
            renamed.ban_expires(),
            Some(expiry),
            "omitting an expiry must retain the stored date"
        );
        for clear_input in [
            json!({"banned":true,"ban_expires":null}),
            json!({"ban_expires":null}),
        ] {
            let clear: UpdateUser = serde_json::from_value(clear_input)?;
            let encoded_clear = serde_json::to_value(&clear)?;
            assert_eq!(
                encoded_clear.get("ban_expires"),
                Some(&serde_json::Value::Null)
            );
            let cleared = store
                .update_user(&owner.id(), serde_json::from_value(encoded_clear)?)
                .await?;
            assert_eq!(
                cleared.ban_expires(),
                None,
                "an explicit null expiry must clear the date without unbanning"
            );
            assert!(cleared.banned());
            assert_eq!(cleared.ban_reason(), Some("retained reason"));
            assert_eq!(cleared.name(), Some("unrelated rename"));
            assert_eq!(cleared.email(), owner.email());
            let row = store
                .connection()
                .query_one_raw(Statement::from_sql_and_values(
                    store.connection().get_database_backend(),
                    "SELECT ban_expires FROM users WHERE id = ?",
                    vec![owner.id().into_owned().into()],
                ))
                .await?
                .ok_or_else(|| std::io::Error::other("ban owner disappeared"))?;
            assert_eq!(row.try_get::<Option<String>>("", "ban_expires")?, None);
            assert_eq!(
                serde_json::to_value(UserView::from(
                    &store
                        .get_user_by_id(&foreign.id())
                        .await?
                        .ok_or_else(|| std::io::Error::other("foreign user disappeared"))?
                ))?,
                foreign_before
            );
            for (token, before) in &sessions {
                assert_eq!(
                    serde_json::to_value(SessionView::from(
                        &store
                            .get_session(token)
                            .await?
                            .ok_or_else(|| std::io::Error::other("session disappeared"))?
                    ))?,
                    *before
                );
            }
            let reset: UpdateUser = serde_json::from_value(json!({"ban_expires":expiry}))?;
            assert_eq!(
                store.update_user(&owner.id(), reset).await?.ban_expires(),
                Some(expiry)
            );
        }
        Ok(())
    }
    type Bundled = better_auth_seaorm::store::__private_test_support::bundled_schema::BundledSchema;
    let bundled = Database::connect("sqlite::memory:").await?;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&bundled).await?;
    check(SeaOrmStore::<Bundled>::new(test_config(), bundled)).await?;
    check(SeaOrmStore::<LegacySchema>::new(
        test_config(),
        test_database().await,
    ))
    .await?;
    Ok(())
}

/// Numeric application session IDs and a manual model without active-team support
/// must update their own columns, then fail closed and roll back unsupported scope.
#[tokio::test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "public custom-schema test asserts actual persisted state and propagates setup failures"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep this ordered integration scenario and its assertions together; Result propagates setup failures"
)]
async fn invitation_transaction_uses_manual_numeric_session_columns_and_rolls_back_missing_team_binding()
-> Result<(), Box<dyn std::error::Error>> {
    use better_auth_core::store::{
        MemberStore, OrganizationStore, SessionStore, TeamStore, UserStore, transaction,
    };
    use better_auth_core::{CreateMember, CreateOrganization, CreateTeam};
    let database = test_database().await;
    better_auth_seaorm::store::__private_test_support::migrator::run_migrations(&database).await?;
    let store = SeaOrmStore::<LegacySchema>::new(test_config(), database.clone());
    let owner = store
        .create_user(CreateUser::new().with_email("manual-invitation-owner@example.test"))
        .await?;
    let other = store
        .create_user(CreateUser::new().with_email("manual-invitation-peer@example.test"))
        .await?;
    let org = store
        .create_organization(CreateOrganization::new(
            "Manual scope",
            "manual-invitation-scope",
        ))
        .await?;
    let team = store
        .create_team(CreateTeam {
            name: "Manual team".into(),
            organization_id: org.id.clone(),
            updated_at: None,
        })
        .await?;
    let session = store
        .create_session(CreateSession {
            user_id: owner.id().into_owned(),
            token: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: FieldValues::default(),
        })
        .await?;
    let peer = store
        .create_session(CreateSession {
            user_id: other.id().into_owned(),
            token: None,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            ip_address: None,
            user_agent: None,
            impersonated_by: None,
            active_organization_id: None,
            active_team_id: None,
            additional_fields: FieldValues::default(),
        })
        .await?;
    let (token, organization_id, user_id) = (
        session.token.clone(),
        org.id.clone(),
        owner.id().into_owned(),
    );
    let value = organization_id.clone();
    let committed = transaction(&store, move |tx| {
        Box::pin(async move {
            let member = tx
                .create_member(CreateMember {
                    organization_id: value.clone(),
                    user_id,
                    role: "member".into(),
                })
                .await?;
            let selected = tx
                .update_session_active_organization(&token, Some(&organization_id))
                .await?;
            assert!(selected.id > 0);
            Ok(member)
        })
    })
    .await?;
    assert_eq!(committed.user_id, owner.id().as_ref());
    let before = store
        .get_session(&session.token)
        .await?
        .ok_or("missing manual session")?;
    assert_eq!(before.id, session.id);
    assert_eq!(
        before.active_organization_id.as_deref(),
        Some(org.id.as_str())
    );
    assert_eq!(
        serde_json::to_value(
            store
                .get_session(&peer.token)
                .await?
                .ok_or("missing peer")?
        )?,
        serde_json::to_value(&peer)?
    );
    let (token_2, team_id, user_id_2, organization_id_2) = (
        session.token.clone(),
        team.id.clone(),
        owner.id().into_owned(),
        org.id.clone(),
    );
    let rejected: AuthResult<()> = transaction(&store, move |tx| {
        Box::pin(async move {
            assert!(tx.get_team(&organization_id_2, &team_id).await?.is_some());
            drop(tx.add_team_member(&team_id, &user_id_2, Some(1)).await?);
            drop(
                tx.update_session_active_team(&token_2, Some(&team_id))
                    .await?,
            );
            Ok(())
        })
    })
    .await;
    assert!(
        matches!(rejected, Err(AuthError::Internal(message)) if message == "the session schema has no active-team field")
    );
    assert!(
        store
            .get_team_member(&team.id, &owner.id())
            .await?
            .is_none()
    );
    assert_eq!(store.list_organization_members(&org.id).await?.len(), 1);
    assert_eq!(
        serde_json::to_value(
            store
                .get_session(&session.token)
                .await?
                .ok_or("missing rolled-back session")?
        )?,
        serde_json::to_value(before)?
    );
    assert_eq!(
        serde_json::to_value(
            store
                .get_session(&peer.token)
                .await?
                .ok_or("missing unchanged peer")?
        )?,
        serde_json::to_value(peer)?
    );
    Ok(())
}
