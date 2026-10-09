//! Immutable configured team branches and read-only receipts of real store transitions.
use alibi::plugins::organization::{
    OrganizationConfig, OrganizationTeamHooks,
    extensions::{DefaultTeamContext, DefaultTeamFactory, TeamHookContext},
};
use alibi::{AuthError, AuthResult};
use alibi::{
    CreateTeam, Organization, Team, TeamMember, UpdateTeam, store::TeamStore, wire::UserView,
};
use alibi::seaorm::{
    DatabaseConnection,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

pub(crate) const PROFILES: [&str; 2] = ["org-team-hooks", "org-team-factory"];
fn receipts() -> &'static Mutex<HashMap<String, Vec<Value>>> {
    static RECEIPTS: OnceLock<Mutex<HashMap<String, Vec<Value>>>> = OnceLock::new();
    RECEIPTS.get_or_init(Mutex::default)
}
fn record(id: &str, value: Value) -> AuthResult<()> {
    receipts()
        .lock()
        .map_err(|_| AuthError::internal("Team receipts unavailable"))?
        .entry(id.to_owned())
        .or_default()
        .push(value);
    Ok(())
}
async fn snapshot(database: &DatabaseConnection) -> AuthResult<Value> {
    let mut value = Map::new();
    for (name, sql, columns) in [
        (
            "organizations",
            "SELECT id,name,slug FROM organization ORDER BY slug,id",
            &["id", "name", "slug"][..],
        ),
        (
            "members",
            "SELECT m.id,m.organization_id AS organizationId,m.user_id AS userId,m.role FROM member m JOIN organization o ON o.id=m.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,u.email,m.id",
            &["id", "organizationId", "userId", "role"][..],
        ),
        (
            "teams",
            "SELECT t.id,t.organization_id AS organizationId,t.name,t.member_count AS memberCount FROM team t JOIN organization o ON o.id=t.organization_id ORDER BY o.slug,t.name,t.id",
            &["id", "organizationId", "name", "memberCount"][..],
        ),
        (
            "teamMembers",
            "SELECT m.id,m.team_id AS teamId,m.user_id AS userId FROM team_member m JOIN team t ON t.id=m.team_id JOIN organization o ON o.id=t.organization_id JOIN users u ON u.id=m.user_id ORDER BY o.slug,t.name,u.email,m.id",
            &["id", "teamId", "userId"][..],
        ),
        (
            "sessions",
            "SELECT s.id,s.user_id AS userId,s.active_organization_id AS activeOrganizationId,s.active_team_id AS activeTeamId FROM sessions s JOIN users u ON u.id=s.user_id ORDER BY u.email,s.created_at,s.id",
            &["id", "userId", "activeOrganizationId", "activeTeamId"][..],
        ),
        (
            "users",
            "SELECT id,email,name FROM users ORDER BY email,id",
            &["id", "email", "name"][..],
        ),
    ] {
        let rows = database
            .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
            .await
            .map_err(|e| AuthError::internal(e.to_string()))?;
        let mut values = Vec::new();
        for row in rows {
            let mut object = Map::new();
            for column in columns {
                let field = if *column == "memberCount" {
                    json!(
                        row.try_get::<i64>("", column)
                            .map_err(|e| AuthError::internal(e.to_string()))?
                    )
                } else {
                    json!(
                        row.try_get::<Option<String>>("", column)
                            .map_err(|e| AuthError::internal(e.to_string()))?
                    )
                };
                object.insert((*column).to_owned(), field);
            }
            values.push(Value::Object(object));
        }
        value.insert(name.to_owned(), Value::Array(values));
    }
    Ok(Value::Object(value))
}
pub(crate) async fn evidence(database: &DatabaseConnection, id: &str) -> AuthResult<Value> {
    let snapshot = snapshot(database).await?;
    let events = receipts()
        .lock()
        .map_err(|_| AuthError::internal("Team receipts unavailable"))?
        .get(id)
        .cloned()
        .unwrap_or_default();
    Ok(json!({"receipts":events,"snapshot":snapshot}))
}
#[derive(Debug)]
struct Hooks {
    database: DatabaseConnection,
}
fn user(value: Option<&UserView>) -> Value {
    value.map_or(
        Value::Null,
        |u| json!({"id":u.id,"email":u.email,"name":u.name}),
    )
}
fn team(value: &Team) -> Value {
    json!({"id":value.id,"name":value.name,"organizationId":value.organization_id})
}
fn member(value: &TeamMember) -> Value {
    json!({"id":value.id,"teamId":value.team_id,"userId":value.user_id})
}
impl Hooks {
    async fn note(
        &self,
        phase: &str,
        ctx: &TeamHookContext,
        target: Option<&UserView>,
        mut value: Value,
        marker: &str,
    ) -> AuthResult<()> {
        value["phase"] = json!(phase);
        value["organization"] = json!({"id":ctx.organization.id,"name":ctx.organization.name});
        value["user"] = user(target.or(ctx.user.as_ref()));
        value["snapshot"] = snapshot(&self.database).await?;
        let reject = marker.contains(&format!("reject-{phase}"));
        let error = marker.contains(&format!("error-{phase}"));
        if reject || error {
            let id = alibi::utils::id::generate_id(32);
            self.database.execute_raw(Statement::from_sql_and_values(DbBackend::Sqlite,"INSERT INTO team(id,organization_id,name,created_at,member_count) VALUES (?,?,?,?,0)",vec![id.into(),ctx.organization.id.clone().into(),format!("Independent:{phase}").into(),chrono::Utc::now().into()])).await.map_err(|e| AuthError::internal(e.to_string()))?;
            value["independentSnapshot"] = snapshot(&self.database).await?;
        }
        record(&ctx.organization.id, value)?;
        if error {
            return Err(AuthError::internal(format!("Callback error {phase}")));
        }
        if reject {
            return Err(AuthError::Api {
                status: 400,
                code: Some("TEAM_HOOK_REJECTED".into()),
                message: format!("Rejected {phase}"),
            });
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl OrganizationTeamHooks for Hooks {
    async fn before_create(&self, data: &mut CreateTeam, ctx: &TeamHookContext) -> AuthResult<()> {
        self.note(
            "before-create",
            ctx,
            None,
            json!({"team":{"name":data.name,"organizationId":data.organization_id}}),
            &data.name,
        )
        .await?;
        data.name = format!("Hook:{}", data.name);
        Ok(())
    }
    async fn after_create(&self, data: &Team, ctx: &TeamHookContext) -> AuthResult<()> {
        self.note(
            "after-create",
            ctx,
            None,
            json!({"team":team(data)}),
            &data.name,
        )
        .await
    }
    async fn before_update(
        &self,
        data: &Team,
        updates: &mut UpdateTeam,
        ctx: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note(
            "before-update",
            ctx,
            None,
            json!({"team":team(data),"updates":{"name":updates.name}}),
            updates.name.as_deref().unwrap_or(""),
        )
        .await?;
        updates.name = updates.name.as_ref().map(|name| format!("Hook:{name}"));
        Ok(())
    }
    async fn after_update(&self, data: &Team, ctx: &TeamHookContext) -> AuthResult<()> {
        self.note(
            "after-update",
            ctx,
            None,
            json!({"team":team(data)}),
            &data.name,
        )
        .await
    }
    async fn before_delete(&self, data: &Team, ctx: &TeamHookContext) -> AuthResult<()> {
        self.note(
            "before-delete",
            ctx,
            None,
            json!({"team":team(data)}),
            &data.name,
        )
        .await
    }
    async fn after_delete(&self, data: &Team, ctx: &TeamHookContext) -> AuthResult<()> {
        self.note(
            "after-delete",
            ctx,
            None,
            json!({"team":team(data)}),
            &data.name,
        )
        .await
    }
    async fn before_add_member(
        &self,
        data: &Team,
        target: &UserView,
        ctx: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note(
            "before-add-member",
            ctx,
            Some(target),
            json!({"team":team(data),"teamMember":{"teamId":data.id,"userId":target.id}}),
            target.name.as_deref().unwrap_or(""),
        )
        .await
    }
    async fn after_add_member(
        &self,
        link: &TeamMember,
        data: &Team,
        target: &UserView,
        ctx: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note(
            "after-add-member",
            ctx,
            Some(target),
            json!({"team":team(data),"teamMember":member(link)}),
            target.name.as_deref().unwrap_or(""),
        )
        .await
    }
    async fn before_remove_member(
        &self,
        link: &TeamMember,
        data: &Team,
        target: &UserView,
        ctx: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note(
            "before-remove-member",
            ctx,
            Some(target),
            json!({"team":team(data),"teamMember":member(link)}),
            target.name.as_deref().unwrap_or(""),
        )
        .await
    }
    async fn after_remove_member(
        &self,
        link: &TeamMember,
        data: &Team,
        target: &UserView,
        ctx: &TeamHookContext,
    ) -> AuthResult<()> {
        self.note(
            "after-remove-member",
            ctx,
            Some(target),
            json!({"team":team(data),"teamMember":member(link)}),
            target.name.as_deref().unwrap_or(""),
        )
        .await
    }
}
#[async_trait::async_trait]
impl DefaultTeamFactory for Hooks {
    async fn create(
        &self,
        organization: &Organization,
        ctx: &DefaultTeamContext,
        store: &dyn TeamStore,
    ) -> AuthResult<Option<Team>> {
        record(
            &organization.id,
            json!({"phase":"factory","organization":{"id":organization.id,"name":organization.name},"user":user(Some(&ctx.user)),"session":ctx.session.as_ref().map(|s|json!({"id":s.id,"userId":s.user_id,"activeOrganizationId":s.active_organization_id,"activeTeamId":s.active_team_id})),"request":{"method":ctx.request.as_ref().map(|r|format!("{:?}",r.method()).to_uppercase()),"header":ctx.request.as_ref().and_then(|r|r.header("x-team-factory"))},"basePath":ctx.config.base_path,"snapshot":snapshot(&self.database).await?}),
        )?;
        let team = store
            .create_team(CreateTeam {
                organization_id: organization.id.clone(),
                name: format!("Factory:{}", organization.name),
                updated_at: None,
            })
            .await?;
        if organization.name == "Factory error" {
            return Err(AuthError::internal(
                "Factory failed after independent write",
            ));
        }
        Ok(Some(team))
    }
}
pub(crate) fn configure(
    name: &str,
    database: &DatabaseConnection,
    config: &mut OrganizationConfig,
) {
    if !PROFILES.contains(&name) {
        return;
    }
    config.teams.allow_removing_all_teams = true;
    let factory = name.starts_with("org-team-factory");
    if name == "org-team-hooks" || factory {
        let hooks = Arc::new(Hooks {
            database: database.clone(),
        });
        config.teams.hooks = Some(hooks.clone());
        if factory {
            config.teams.default_team_factory = Some(hooks);
        }
    }
}
