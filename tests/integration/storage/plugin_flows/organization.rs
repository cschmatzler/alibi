//! Tenant discovery, invitation visibility and durable active-membership state.
use super::*;
use better_auth::plugins::organization::{
    DynamicAccessControlConfig, OrganizationConfig, OrganizationPlugin, TeamsConfig,
    default_organization_statements,
};

backend_tests!(
    organization_discovery_invitations_and_active_membership_are_owner_scoped,
    concurrent_organization_admissions_respect_capacity
);
postgres_tests!(
    organization_discovery_invitations_and_active_membership_are_owner_scoped,
    concurrent_organization_admissions_respect_capacity
);

async fn organization_discovery_invitations_and_active_membership_are_owner_scoped<B: Backend>(
    db: Db,
) -> TestResult {
    let (connection, _) = db.migrated::<B>(SECRET).await?;
    let auth = builder::<B>(&connection)
        .plugin(OrganizationPlugin::with_config(OrganizationConfig {
            access_control: Some(default_organization_statements()),
            dynamic_access_control: DynamicAccessControlConfig {
                enabled: true,
                ..Default::default()
            },
            teams: TeamsConfig {
                enabled: true,
                create_default_team: false,
                allow_removing_all_teams: true,
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
        .await?;
    let owner = signup(&auth, "org-owner@example.test").await;
    let invited = signup(&auth, "org-invited@example.test").await;
    let outsider = signup(&auth, "org-foreign@example.test").await;
    let cookie = cookies(&owner);
    let member_cookie = cookies(&invited);
    let member_id = body(&invited)["user"]["id"].as_str().unwrap().to_owned();
    let _ = call(
        &auth,
        request(
            "/organization/check-slug",
            Some(json!({"slug":"tenant"})),
            &cookie,
        ),
        200,
    )
    .await;
    let created = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Tenant","slug":"tenant"})),
            &cookie,
        ),
        200,
    )
    .await;
    let org = body(&created)["id"].as_str().unwrap().to_owned();
    let foreign = call(
        &auth,
        request(
            "/organization/create",
            Some(json!({"name":"Foreign","slug":"foreign-tenant"})),
            &cookies(&outsider),
        ),
        200,
    )
    .await;
    let foreign_id = body(&foreign)["id"].as_str().unwrap().to_owned();
    let original = db.tables(&["organization", "member"]).await?;
    let _ = call(
        &auth,
        request(
            "/organization/check-slug",
            Some(json!({"slug":"tenant"})),
            &cookie,
        ),
        400,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":foreign_id})),
            &cookie,
        ),
        403,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/organization/leave",
            Some(json!({"organizationId":org})),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(db.tables(&["organization", "member"]).await?, original);
    assert!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[body(&owner)["token"].as_str().unwrap()]
        )
        .await?
        .is_none(),
        "a rejected organization selection clears the caller's previous selection"
    );
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[body(&outsider)["token"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some(foreign_id.as_str())
    );
    let own = call(&auth, request("/organization/list", None, &cookie), 200).await;
    assert_eq!(body(&own).as_array().unwrap().len(), 1);
    assert_eq!(body(&own)[0]["id"], org);
    let absent = call(
        &auth,
        request("/organization/list", None, &member_cookie),
        200,
    )
    .await;
    assert_eq!(body(&absent), json!([]));
    let invitation = call(
        &auth,
        request(
            "/organization/invite-member",
            Some(json!({"organizationId":org,"email":"org-invited@example.test","role":"member"})),
            &cookie,
        ),
        200,
    )
    .await;
    let id = body(&invitation)["id"].as_str().unwrap().to_owned();
    let mut query = request("/organization/list-invitations", None, &cookie);
    drop(query.query.insert("organizationId".into(), org.clone()));
    let listed = call(&auth, query.clone(), 200).await;
    assert_eq!(body(&listed).as_array().unwrap().len(), 1);
    assert_eq!(body(&listed)[0]["id"], id);
    drop(query.headers.insert("cookie".into(), cookies(&outsider)));
    let _ = call(&auth, query, 403).await;
    let unavailable = call(
        &auth,
        request("/organization/list-user-invitations", None, &member_cookie),
        403,
    )
    .await;
    assert_eq!(
        body(&unavailable)["code"],
        "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"
    );
    let trusted = OrganizationPlugin::new();
    let listed = trusted
        .list_user_invitations(auth.context(), "org-invited@example.test")
        .await?;
    let listed = serde_json::to_value(listed)?;
    assert_eq!(listed[0]["id"], id);
    assert_eq!(listed[0]["organizationName"], "Tenant");
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert!(
        trusted
            .list_user_invitations(auth.context(), "org-foreign@example.test")
            .await?
            .is_empty()
    );
    assert!(
        trusted
            .list_user_invitations(auth.context(), "")
            .await
            .is_err()
    );
    let invitations_before = db.table("invitation").await?;
    // The verified-mailbox gate has just rejected the real unverified session;
    // application provisioning now admits both actual users for visibility checks.
    for user in [&member_id, body(&outsider)["user"]["id"].as_str().unwrap()] {
        drop(
            auth.store()
                .update_user(
                    user,
                    better_auth_core::UpdateUser {
                        email_verified: Some(true),
                        ..Default::default()
                    },
                )
                .await?,
        );
    }
    assert_eq!(db.table("invitation").await?, invitations_before);
    let mine = call(
        &auth,
        request("/organization/list-user-invitations", None, &member_cookie),
        200,
    )
    .await;
    assert_eq!(body(&mine).as_array().unwrap().len(), 1);
    assert_eq!(body(&mine)[0]["id"], id);
    let others = call(
        &auth,
        request(
            "/organization/list-user-invitations",
            None,
            &cookies(&outsider),
        ),
        200,
    )
    .await;
    assert_eq!(body(&others), json!([]));

    let mut detail = request("/organization/get-invitation", None, &member_cookie);
    drop(detail.query.insert("id".into(), id.clone()));
    let received = call(&auth, detail.clone(), 200).await;
    assert_eq!(body(&received)["id"], id);
    assert_eq!(body(&received)["organizationId"], org);
    assert_eq!(body(&received)["organizationName"], "Tenant");
    assert_eq!(body(&received)["organizationSlug"], "tenant");
    assert_eq!(body(&received)["inviterEmail"], "org-owner@example.test");
    drop(detail.headers.insert("cookie".into(), cookies(&outsider)));
    let _ = call(&auth, detail, 403).await;
    let invitations = db.table("invitation").await?;
    let _ = call(
        &auth,
        request(
            "/organization/cancel-invitation",
            Some(json!({"invitationId":id})),
            &cookies(&outsider),
        ),
        400,
    )
    .await;
    assert_eq!(db.table("invitation").await?, invitations);
    let _ = call(
        &auth,
        request(
            "/organization/cancel-invitation",
            Some(json!({"invitationId":id})),
            &cookie,
        ),
        200,
    )
    .await;
    assert_eq!(
        db.text("SELECT status FROM invitation WHERE id=$1", &[&id])
            .await?
            .as_deref(),
        Some("canceled")
    );
    assert!(
        trusted
            .list_user_invitations(auth.context(), "org-invited@example.test")
            .await?
            .is_empty()
    );
    let _ = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":id})),
            &member_cookie,
        ),
        400,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id=$1 AND user_id=$2",
            &[&org, &member_id]
        )
        .await?,
        0
    );
    let invitation = call(
        &auth,
        request(
            "/organization/invite-member",
            Some(json!({"organizationId":org,"email":"org-invited@example.test","role":"member"})),
            &cookie,
        ),
        200,
    )
    .await;
    let _ = call(
        &auth,
        request(
            "/organization/accept-invitation",
            Some(json!({"invitationId":body(&invitation)["id"]})),
            &member_cookie,
        ),
        200,
    )
    .await;
    // Rejection has its own recipient guard; possessing a valid foreign
    // session and invitation ID must leave both invitation and membership intact.
    let rejected = call(
        &auth,
        request(
            "/organization/invite-member",
            Some(json!({"organizationId":org,"email":"org-foreign@example.test","role":"member"})),
            &cookie,
        ),
        200,
    )
    .await;
    let rejected_id = body(&rejected)["id"].as_str().unwrap().to_owned();
    let pending = db.tables(&["invitation", "member"]).await?;
    let denied = call(
        &auth,
        request(
            "/organization/reject-invitation",
            Some(json!({"invitationId":rejected_id})),
            &member_cookie,
        ),
        403,
    )
    .await;
    assert_eq!(
        body(&denied)["message"],
        "You are not the recipient of the invitation"
    );
    assert_eq!(db.tables(&["invitation", "member"]).await?, pending);
    let members_before = db.table("member").await?;
    let _ = call(
        &auth,
        request(
            "/organization/reject-invitation",
            Some(json!({"invitationId":rejected_id})),
            &cookies(&outsider),
        ),
        200,
    )
    .await;
    assert_eq!(
        db.text("SELECT status FROM invitation WHERE id=$1", &[&rejected_id])
            .await?
            .as_deref(),
        Some("rejected")
    );
    assert_eq!(db.table("member").await?, members_before);
    let own_role = call(&auth,request("/organization/create-role",Some(json!({"organizationId":org,"role":"auditor","permission":{"organization":["update"]}})),&cookie),200).await;
    let foreign_role = call(&auth,request("/organization/create-role",Some(json!({"organizationId":foreign_id,"role":"auditor","permission":{"organization":["update"]}})),&cookies(&outsider)),200).await;
    let own_role_id = body(&own_role)["roleData"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let foreign_role_id = body(&foreign_role)["roleData"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let roles = db.table("organization_role").await?;
    for (tenant, headers, expected) in [
        (&org, cookie.clone(), &own_role_id),
        (&foreign_id, cookies(&outsider), &foreign_role_id),
    ] {
        let mut list = request("/organization/list-roles", None, &headers);
        drop(list.query.insert("organizationId".into(), tenant.clone()));
        let listed = call(&auth, list, 200).await;
        assert_eq!(body(&listed).as_array().unwrap().len(), 1);
        assert_eq!(body(&listed)[0]["id"], *expected);
        assert_eq!(body(&listed)[0]["organizationId"], *tenant);
        assert_eq!(
            body(&listed)[0]["permission"],
            json!({"organization":["update"]})
        );
    }
    let membership = db
        .text(
            "SELECT id FROM member WHERE organization_id=$1 AND user_id=$2",
            &[&org, &member_id],
        )
        .await?
        .unwrap();
    let _ = call(
        &auth,
        request(
            "/organization/update-member-role",
            Some(json!({"organizationId":org,"memberId":membership,"role":"auditor"})),
            &cookie,
        ),
        200,
    )
    .await;
    for (route, input, query, code) in [
        (
            "get-role",
            None,
            vec![("roleId", own_role_id.as_str())],
            "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
        ),
        (
            "list-roles",
            None,
            vec![],
            "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
        ),
        (
            "create-role",
            Some(json!({"organizationId":org,"role":"new-role","permission":{}})),
            vec![],
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
        ),
        (
            "update-role",
            Some(json!({"organizationId":org,"roleId":own_role_id,"data":{"permission":{}}})),
            vec![],
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
        ),
        (
            "delete-role",
            Some(json!({"organizationId":org,"roleId":own_role_id})),
            vec![],
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
        ),
    ] {
        let mut req = request(&format!("/organization/{route}"), input, &member_cookie);
        if req.method == HttpMethod::Get {
            drop(req.query.insert("organizationId".into(), org.clone()));
        }
        req.query.extend(
            query
                .into_iter()
                .map(|(key, value)| (key.into(), value.into())),
        );
        let denied = call(&auth, req, 403).await;
        assert_eq!(body(&denied)["code"], code);
    }
    let mut cross = request("/organization/list-roles", None, &cookie);
    drop(
        cross
            .query
            .insert("organizationId".into(), foreign_id.clone()),
    );
    let denied = call(&auth, cross, 403).await;
    assert_eq!(
        body(&denied)["code"],
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"
    );
    assert_eq!(db.table("organization_role").await?, roles);
    let _ = call(
        &auth,
        request(
            "/organization/update-member-role",
            Some(json!({"organizationId":org,"memberId":membership,"role":"member"})),
            &cookie,
        ),
        200,
    )
    .await;
    let protected = db
        .tables(&["organization", "member", "invitation", "sessions"])
        .await?;
    for (route, input, status, message) in [
        (
            "delete",
            json!({"organizationId":org}),
            403,
            "You are not allowed to delete this organization",
        ),
        (
            "remove-member",
            json!({"organizationId":org,"memberIdOrEmail":membership}),
            401,
            "You are not allowed to delete this member",
        ),
        (
            "update-member-role",
            json!({"organizationId":org,"memberId":membership,"role":"owner"}),
            403,
            "You are not allowed to update this member",
        ),
    ] {
        let denied = call(
            &auth,
            request(
                &format!("/organization/{route}"),
                Some(input),
                &member_cookie,
            ),
            status,
        )
        .await;
        assert_eq!(body(&denied)["message"], message);
        assert_eq!(
            db.tables(&["organization", "member", "invitation", "sessions"])
                .await?,
            protected
        );
    }
    let selected = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationSlug":"tenant"})),
            &member_cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&selected)["id"], org);
    assert_eq!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[body(&invited)["token"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some(org.as_str())
    );
    let active = call(
        &auth,
        request("/organization/get-active-member", None, &member_cookie),
        200,
    )
    .await;
    assert_eq!(body(&active)["userId"], member_id);
    assert_eq!(body(&active)["organizationId"], org);
    let role = call(
        &auth,
        request("/organization/get-active-member-role", None, &member_cookie),
        200,
    )
    .await;
    assert_eq!(body(&role)["role"], "member");
    let mut members = request("/organization/list-members", None, &cookie);
    members.query.extend([
        ("organizationId".into(), org.clone()),
        ("filterField".into(), "role".into()),
        ("filterValue".into(), "member".into()),
        ("filterOperator".into(), "eq".into()),
    ]);
    let members = call(&auth, members, 200).await;
    assert_eq!(body(&members)["total"], 1);
    assert_eq!(body(&members)["members"].as_array().unwrap().len(), 1);
    assert_eq!(body(&members)["members"][0]["userId"], member_id);
    // Team queries must enforce both organization and team membership. Merely
    // knowing a team ID is not authority to list its members or select it.
    let team = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"organizationId":org,"name":"Owner team"})),
            &cookie,
        ),
        200,
    )
    .await;
    let team_id = body(&team)["id"].as_str().unwrap().to_owned();
    let other_team = call(
        &auth,
        request(
            "/organization/create-team",
            Some(json!({"organizationId":foreign_id,"name":"Foreign team"})),
            &cookies(&outsider),
        ),
        200,
    )
    .await;
    let other_team_id = body(&other_team)["id"].as_str().unwrap().to_owned();
    let mut full = request("/organization/get-full-organization", None, &cookie);
    drop(full.query.insert("organizationId".into(), org.clone()));
    let full = body(&call(&auth, full, 200).await);
    assert_eq!(full["id"], org);
    let mut actual_members = full["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["userId"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    actual_members.sort();
    let mut expected_members = vec![
        member_id.clone(),
        body(&owner)["user"]["id"].as_str().unwrap().to_owned(),
    ];
    expected_members.sort();
    assert_eq!(actual_members, expected_members);
    assert_eq!(full["teams"].as_array().unwrap().len(), 1);
    assert_eq!(full["teams"][0]["id"], team_id);
    let projected = full["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|invitation| invitation["id"].as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        projected,
        [
            id.clone(),
            body(&invitation)["id"].as_str().unwrap().to_owned(),
            rejected_id
        ]
        .into_iter()
        .collect()
    );
    let data_before = db
        .tables(&["organization", "member", "invitation", "team"])
        .await?;
    for route in ["get-full-organization", "get-organization"] {
        let _ = call(
            &auth,
            request(
                "/organization/set-active",
                Some(json!({"organizationId":foreign_id})),
                &cookies(&outsider),
            ),
            200,
        )
        .await;
        let owner_session = db
            .text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[body(&invited)["token"].as_str().unwrap()],
            )
            .await?;
        let mut foreign_read =
            request(&format!("/organization/{route}"), None, &cookies(&outsider));
        drop(
            foreign_read
                .query
                .insert("organizationId".into(), org.clone()),
        );
        let denied = call(&auth, foreign_read, 403).await;
        assert_eq!(
            body(&denied)["message"],
            "User is not a member of the organization"
        );
        assert!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[body(&outsider)["token"].as_str().unwrap()]
            )
            .await?
            .is_none()
        );
        assert_eq!(
            db.text(
                "SELECT active_organization_id FROM sessions WHERE token=$1",
                &[body(&invited)["token"].as_str().unwrap()]
            )
            .await?,
            owner_session
        );
        assert_eq!(
            db.tables(&["organization", "member", "invitation", "team"])
                .await?,
            data_before
        );
    }
    let mut teams = request("/organization/list-teams", None, &member_cookie);
    drop(teams.query.insert("organizationId".into(), org.clone()));
    let listed = call(&auth, teams.clone(), 200).await;
    assert_eq!(body(&listed).as_array().unwrap().len(), 1);
    assert_eq!(body(&listed)[0]["id"], team_id);
    assert_eq!(body(&listed)[0]["organizationId"], org);
    drop(
        teams
            .query
            .insert("organizationId".into(), foreign_id.clone()),
    );
    let _ = call(&auth, teams, 403).await;
    let before = db.tables(&["team", "team_member", "sessions"]).await?;
    let denied = call(
        &auth,
        request(
            "/organization/set-active-team",
            Some(json!({"teamId":team_id})),
            &member_cookie,
        ),
        403,
    )
    .await;
    assert_eq!(body(&denied)["code"], "USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
    let denied = call(
        &auth,
        request(
            "/organization/set-active-team",
            Some(json!({"teamId":other_team_id})),
            &member_cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "TEAM_NOT_FOUND");
    let denied = call(
        &auth,
        request(
            "/organization/update-team",
            Some(json!({"teamId":team_id,"data":{"organizationId":org,"name":"Unauthorized"}})),
            &member_cookie,
        ),
        403,
    )
    .await;
    assert_eq!(
        body(&denied)["code"],
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"
    );
    let denied = call(
        &auth,
        request(
            "/organization/update-team",
            Some(
                json!({"teamId":other_team_id,"data":{"organizationId":org,"name":"Cross-tenant"}}),
            ),
            &cookie,
        ),
        400,
    )
    .await;
    assert_eq!(body(&denied)["code"], "TEAM_NOT_FOUND");
    assert_eq!(
        db.tables(&["team", "team_member", "sessions"]).await?,
        before
    );
    let mut roster = request("/organization/list-team-members", None, &member_cookie);
    drop(roster.query.insert("teamId".into(), team_id.clone()));
    let denied = call(&auth, roster.clone(), 400).await;
    assert_eq!(body(&denied)["code"], "USER_IS_NOT_A_MEMBER_OF_THE_TEAM");
    let added = call(
        &auth,
        request(
            "/organization/add-team-member",
            Some(json!({"teamId":team_id,"organizationId":org,"userId":member_id})),
            &cookie,
        ),
        200,
    )
    .await;
    let membership = body(&added)["id"].as_str().unwrap().to_owned();
    let selected = call(
        &auth,
        request(
            "/organization/set-active-team",
            Some(json!({"teamId":team_id})),
            &member_cookie,
        ),
        200,
    )
    .await;
    assert_eq!(body(&selected)["id"], team_id);
    assert_eq!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[body(&invited)["token"].as_str().unwrap()]
        )
        .await?
        .as_deref(),
        Some(team_id.as_str())
    );
    let rows = call(&auth, roster.clone(), 200).await;
    assert_eq!(body(&rows).as_array().unwrap().len(), 1);
    assert_eq!(body(&rows)[0]["id"], membership);
    assert_eq!(body(&rows)[0]["userId"], member_id);
    drop(roster.query.insert("teamId".into(), other_team_id));
    let _ = call(&auth, roster, 400).await;
    let own_teams = call(
        &auth,
        request("/organization/list-user-teams", None, &member_cookie),
        200,
    )
    .await;
    assert_eq!(body(&own_teams).as_array().unwrap().len(), 1);
    assert_eq!(body(&own_teams)[0]["id"], team_id);
    let mut query = request("/organization/list-user-teams", None, &cookie);
    query.query.extend([
        ("organizationId".into(), org.clone()),
        ("userId".into(), member_id.clone()),
    ]);
    let supervised = call(&auth, query.clone(), 200).await;
    assert_eq!(body(&supervised), body(&own_teams));
    drop(query.headers.insert("cookie".into(), member_cookie.clone()));
    drop(query.query.insert(
        "userId".into(),
        body(&owner)["user"]["id"].as_str().unwrap().to_owned(),
    ));
    let _ = call(&auth, query, 403).await;
    let cleared = call(
        &auth,
        request(
            "/organization/set-active-team",
            Some(json!({"teamId":null})),
            &member_cookie,
        ),
        200,
    )
    .await;
    assert!(body(&cleared).is_null());
    assert!(
        db.text(
            "SELECT active_team_id FROM sessions WHERE token=$1",
            &[body(&invited)["token"].as_str().unwrap()]
        )
        .await?
        .is_none()
    );
    let _ = call(
        &auth,
        request(
            "/organization/leave",
            Some(json!({"organizationId":org})),
            &member_cookie,
        ),
        200,
    )
    .await;
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id=$1 AND user_id=$2",
            &[&org, &member_id]
        )
        .await?,
        0
    );
    assert!(
        db.text(
            "SELECT active_organization_id FROM sessions WHERE token=$1",
            &[body(&invited)["token"].as_str().unwrap()]
        )
        .await?
        .is_none()
    );
    let original = db.tables(&["member"]).await?;
    let _ = call(
        &auth,
        request(
            "/organization/set-active",
            Some(json!({"organizationId":org})),
            &member_cookie,
        ),
        403,
    )
    .await;
    assert_eq!(db.tables(&["member"]).await?, original);
    authenticated(&auth, &member_cookie, "org-invited@example.test").await;
    // Trusted helpers resolve real signed cookies, but server-created tenants
    // have no browser session to activate and may bypass only the allow policy.
    let helper = OrganizationPlugin::with_config(OrganizationConfig {
        allow_user_to_create_organization: false,
        organization_limit: Some(2.0),
        teams: TeamsConfig {
            enabled: true,
            create_default_team: false,
            allow_removing_all_teams: true,
            ..Default::default()
        },
        ..Default::default()
    });
    let owner_id = body(&owner)["user"]["id"].as_str().unwrap().to_owned();
    let sessions = db.table("sessions").await?;
    let created = helper
        .create_organization_for_user(
            auth.context(),
            &owner_id,
            &serde_json::from_value(json!({"name":"Server tenant","slug":"server-tenant"}))?,
        )
        .await?;
    let disposable = created.organization.id;
    assert_eq!(created.members.len(), 1);
    assert_eq!(
        serde_json::to_value(&created.members)?[0]["userId"],
        owner_id
    );
    assert_eq!(serde_json::to_value(&created.members)?[0]["role"], "owner");
    assert_eq!(db.table("sessions").await?, sessions);
    let unchanged = db.tables(&["organization", "member", "sessions"]).await?;
    let denied = helper
        .create_organization_for_user(
            auth.context(),
            &owner_id,
            &serde_json::from_value(json!({"name":"Excess tenant","slug":"excess-tenant"}))?,
        )
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), 403);
    assert!(denied.to_string().contains("maximum number"));
    assert_eq!(
        db.tables(&["organization", "member", "sessions"]).await?,
        unchanged
    );
    let empty = std::collections::HashMap::new();
    let headers = [("Cookie".into(), cookie.clone())].into_iter().collect();
    let member_headers = [("Cookie".into(), member_cookie.clone())]
        .into_iter()
        .collect();
    let admitted = helper
        .add_member_with_headers(
            auth.context(),
            &empty,
            &serde_json::from_value(
                json!({"userId":member_id,"role":"member","organizationId":disposable}),
            )?,
        )
        .await?;
    let updated_at =
        chrono::DateTime::parse_from_rfc3339("2024-02-03T04:05:06Z")?.with_timezone(&chrono::Utc);
    let team_input = || better_auth_core::CreateTeam {
        name: "Server team".into(),
        organization_id: disposable.clone(),
        updated_at: Some(updated_at),
    };
    let unchanged = db.tables(&["team", "member"]).await?;
    assert_eq!(
        helper
            .create_team_with_headers(auth.context(), &empty, team_input())
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    assert_eq!(
        helper
            .create_team_with_headers(auth.context(), &member_headers, team_input())
            .await
            .unwrap_err()
            .status_code(),
        403
    );
    assert_eq!(db.tables(&["team", "member"]).await?, unchanged);
    let team = helper
        .create_team_with_headers(auth.context(), &headers, team_input())
        .await?;
    assert_eq!(team.updated_at, Some(updated_at));
    let unchanged = db.table("team").await?;
    assert_eq!(
        helper
            .remove_team_with_headers(auth.context(), &member_headers, &disposable, &team.id)
            .await
            .unwrap_err()
            .status_code(),
        403
    );
    assert_eq!(db.table("team").await?, unchanged);
    helper
        .remove_team_with_headers(auth.context(), &headers, &disposable, &team.id)
        .await?;
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM team WHERE id=$1", &[&team.id])
            .await?,
        0
    );
    let removal =
        serde_json::from_value(json!({"memberIdOrEmail":admitted.id,"organizationId":disposable}))?;
    let unchanged = db.table("member").await?;
    assert_eq!(
        helper
            .remove_member_with_headers(auth.context(), &empty, &removal)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let denied = helper
        .remove_member_with_headers(auth.context(), &member_headers, &removal)
        .await
        .unwrap_err();
    assert_eq!(denied.status_code(), 401);
    assert!(
        denied
            .to_string()
            .contains("not allowed to delete this member")
    );
    assert_eq!(db.table("member").await?, unchanged);
    let _ = helper
        .remove_member_with_headers(auth.context(), &headers, &removal)
        .await?;
    assert_eq!(
        db.count_where("SELECT COUNT(*) FROM member WHERE id=$1", &[&admitted.id])
            .await?,
        0
    );
    let deletion = serde_json::from_value(json!({"organizationId":disposable}))?;
    assert_eq!(
        helper
            .delete_organization_with_headers(auth.context(), &empty, &deletion)
            .await
            .unwrap_err()
            .status_code(),
        401
    );
    let deleted = helper
        .delete_organization_with_headers(auth.context(), &headers, &deletion)
        .await?
        .unwrap();
    assert_eq!(deleted.id, disposable);
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM organization WHERE id=$1",
            &[&disposable]
        )
        .await?,
        0
    );
    assert_eq!(
        db.count_where(
            "SELECT COUNT(*) FROM member WHERE organization_id=$1",
            &[&disposable]
        )
        .await?,
        0
    );
    assert_eq!(db.count("organization").await?, 2);
    assert_eq!(db.table("sessions").await?, sessions);
    B::close(connection).await
}

/// Pause both real requests after their baseline checks, before either can insert.
#[derive(Debug)]
struct AdmissionGate(tokio::sync::Barrier);
#[async_trait::async_trait]
impl better_auth::plugins::organization::OrganizationInvitationHooks for AdmissionGate {
    async fn before_create_invitation(
        &self,
        _: &better_auth::plugins::organization::OrganizationInvitationCreationContext,
    ) -> better_auth_core::AuthResult<
        Option<better_auth::plugins::organization::OrganizationInvitationCreatePatch>,
    > {
        let _ = self.0.wait().await;
        Ok(None)
    }
}
#[async_trait::async_trait]
impl better_auth::plugins::organization::OrganizationInvitationAcceptanceHooks for AdmissionGate {
    async fn before_accept_invitation(
        &self,
        _: &better_auth::plugins::organization::OrganizationInvitationAcceptanceContext,
    ) -> better_auth_core::AuthResult<()> {
        let _ = self.0.wait().await;
        Ok(())
    }
}
#[async_trait::async_trait]
impl better_auth::plugins::organization::OrganizationMemberAdditionHooks for AdmissionGate {
    async fn before_add_member(
        &self,
        _: &better_auth::plugins::organization::OrganizationMemberAdditionContext,
    ) -> better_auth_core::AuthResult<
        Option<better_auth::plugins::organization::OrganizationMemberCreatePatch>,
    > {
        let _ = self.0.wait().await;
        Ok(None)
    }
}

async fn concurrent_organization_admissions_respect_capacity<B: Backend>(db: Db) -> TestResult {
    use better_auth::plugins::organization::{
        InvitationLimit, MembershipLimit,
        types::{AddOrganizationMemberRequest, RoleInput},
    };
    for mode in ["invite", "accept", "add"] {
        let db = db.fresh().await?;
        let (connection, _) = db.migrated::<B>(SECRET).await?;
        let gate = Arc::new(AdmissionGate(tokio::sync::Barrier::new(2)));
        let config = OrganizationConfig {
            membership_limit: Some(MembershipLimit::Fixed(2.0)),
            invitation_limit: Some(InvitationLimit::Fixed(1.0)),
            invitation_hooks: Some(gate.clone()),
            invitation_acceptance_hooks: Some(gate.clone()),
            member_addition_hooks: Some(gate),
            ..Default::default()
        };
        let plugin = OrganizationPlugin::with_config(config.clone());
        let auth = builder::<B>(&connection)
            .plugin(OrganizationPlugin::with_config(config))
            .build()
            .await?;
        let owner = signup(&auth, "capacity-owner@example.test").await;
        let first = signup(&auth, "capacity-first@example.test").await;
        let second = signup(&auth, "capacity-second@example.test").await;
        let owner_cookie = cookies(&owner);
        let created = call(
            &auth,
            request(
                "/organization/create",
                Some(json!({"name":"Capacity","slug":"capacity"})),
                &owner_cookie,
            ),
            200,
        )
        .await;
        let org = body(&created)["id"].as_str().unwrap().to_owned();
        let (statuses, codes) = if mode == "add" {
            let make = |response: &AuthResponse| AddOrganizationMemberRequest {
                user_id: body(response)["user"]["id"].as_str().unwrap().into(),
                organization_id: Some(org.clone()),
                role: RoleInput::One("member".into()),
                team_id: None,
            };
            let first = make(&first);
            let second = make(&second);
            let headers = std::collections::HashMap::new();
            let results = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    plugin.add_member_with_headers(auth.context(), &headers, &first),
                    plugin.add_member_with_headers(auth.context(), &headers, &second)
                )
            })
            .await?;
            let mut successes = 0;
            for result in [results.0, results.1] {
                match result {
                    Ok(_) => successes += 1,
                    Err(better_auth_core::AuthError::Upstream { code, .. }) => {
                        assert_eq!(code, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED")
                    }
                    Err(error) => panic!("unexpected admission error: {error}"),
                }
            }
            assert_eq!(
                successes, 1,
                "one remaining membership seat admits exactly one user"
            );
            (Vec::new(), Vec::new())
        } else {
            let mut requests = Vec::new();
            for (response, email) in [
                (&first, "capacity-first@example.test"),
                (&second, "capacity-second@example.test"),
            ] {
                requests.push(if mode == "invite" {
                    request(
                        "/organization/invite-member",
                        Some(json!({"email":email,"role":"member","organizationId":org})),
                        &owner_cookie,
                    )
                } else {
                    // Seed invitations through the unrestricted store API, independently of the invitation quota under test.
                    let invite = auth
                        .context()
                        .database
                        .create_invitation(better_auth_core::CreateInvitation {
                            organization_id: org.clone(),
                            email: email.into(),
                            role: "member".into(),
                            team_id: None,
                            inviter_id: body(&owner)["user"]["id"].as_str().unwrap().into(),
                            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                        })
                        .await?;
                    request(
                        "/organization/accept-invitation",
                        Some(json!({"invitationId":invite.id})),
                        &cookies(response),
                    )
                });
            }
            let second_request = requests.pop().unwrap();
            let first_request = requests.pop().unwrap();
            let results = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    Box::pin(auth.handle_request(first_request)),
                    Box::pin(auth.handle_request(second_request))
                )
            })
            .await?;
            let responses = [results.0?, results.1?];
            (
                responses
                    .iter()
                    .map(|response| response.status)
                    .collect::<Vec<_>>(),
                responses
                    .iter()
                    .filter(|response| response.status != 200)
                    .map(|response| body(response)["code"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        if mode != "add" {
            assert_eq!(
                statuses.iter().filter(|status| **status == 200).count(),
                1,
                "{mode} admits exactly one competing request: {statuses:?}"
            );
            assert_eq!(
                codes,
                [if mode == "invite" {
                    "INVITATION_LIMIT_REACHED"
                } else {
                    "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"
                }]
            );
        }
        assert_eq!(
            db.count("member").await?,
            if mode == "invite" { 1 } else { 2 }
        );
        if mode == "invite" {
            assert_eq!(db.count("invitation").await?, 1);
        }
        if mode == "accept" {
            assert_eq!(
                db.text("SELECT status FROM invitation WHERE status='pending'", &[])
                    .await?
                    .as_deref(),
                Some("pending"),
                "losing acceptance releases its invitation claim"
            );
        }
        B::close(connection).await?;
    }
    Ok(())
}
