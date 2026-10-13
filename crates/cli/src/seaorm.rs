use crate::parse_type;
use crate::selection::{CORE_ENTITIES, Selection, entity_fields, role_name};
use alibi_schema_registry::{EntityRole, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn seaorm_schema(selection: &Selection) -> TokenStream {
    let core_entities = CORE_ENTITIES.iter().map(|(module, table, role)| {
        seaorm_entity(module, table, Some(*role), &entity_fields(selection, *role))
    });
    let extra_entities = selection.extra.iter().map(|entity| {
        seaorm_entity(
            entity.mod_name,
            entity.table_name,
            entity.role,
            &entity.fields.iter().collect::<Vec<_>>(),
        )
    });
    let mut tables = CORE_ENTITIES
        .iter()
        .map(|(_, table, role)| (*table, entity_fields(selection, *role)))
        .chain(
            selection
                .extra
                .iter()
                .map(|entity| (entity.table_name, entity.fields.iter().collect())),
        )
        .collect::<Vec<_>>();
    tables.sort_by_key(|(table, _)| crate::sqlx::table_order(table));
    let sqlite = tables.iter().flat_map(|(table, fields)| {
        crate::sqlx::migration_statements(table, fields, crate::sqlx::SqlDialect::Sqlite)
    });
    let postgres = tables.iter().flat_map(|(table, fields)| {
        crate::sqlx::migration_statements(table, fields, crate::sqlx::SqlDialect::Postgres)
    });

    quote! {
        use alibi::AuthSchema;
        use alibi::seaorm::sea_orm;
        use alibi::seaorm::sea_orm::entity::prelude::*;
        use alibi::seaorm::sea_orm::ConnectionTrait;
        use alibi::seaorm::{AuthEntity, DatabaseConnection};

        #(#core_entities)*
        #(#extra_entities)*

        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }

        pub async fn run_app_migrations(
            database: &DatabaseConnection,
        ) -> Result<(), sea_orm::DbErr> {
            let statements: &[&str] = match database.get_database_backend() {
                sea_orm::DbBackend::Sqlite => &[#(#sqlite),*],
                sea_orm::DbBackend::Postgres => &[#(#postgres),*],
                _ => return Err(sea_orm::DbErr::Custom("Generated migrations support SQLite and PostgreSQL".into())),
            };
            for statement in statements {
                let _ = database.execute_unprepared(statement).await?;
            }
            Ok(())
        }
    }
}

fn seaorm_entity(
    module: &str,
    table: &str,
    role: Option<EntityRole>,
    fields: &[&FieldDef],
) -> TokenStream {
    let module = format_ident!("{}", module);
    let fields = fields.iter().map(|field| {
        let name = format_ident!("{}", field.name);
        let ty = parse_type(
            field,
            &field.ty.replace("f64", "alibi::seaorm::Number").replace(
                "i64",
                if field.name == "last_request" {
                    "i64"
                } else {
                    "alibi::seaorm::Integer"
                },
            ),
        );
        let column_attr = field
            .column_name
            .map(|column| quote! { #[sea_orm(column_name = #column)] });
        let default_attr = field
            .default_value
            .map(|value| quote! { #[sea_orm(default_value = #value)] });
        let primary_key = field
            .is_primary_key
            .then(|| quote! { #[sea_orm(primary_key, auto_increment = false)] });
        let storage = (table == "organization" && field.name == "metadata")
            .then(|| quote! { #[sea_orm(column_type = "Text", save_as = "text")] });
        quote! {
            #storage
            #column_attr
            #default_attr
            #primary_key
            pub #name: #ty,
        }
    });
    let derive = role.map_or_else(
        || quote! { #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel)] },
        |role| {
            let role = role_name(role);
            quote! {
                #[derive(Clone, Debug, serde::Serialize, DeriveEntityModel, AuthEntity)]
                #[auth(role = #role)]
            }
        },
    );
    quote! {
        mod #module {
            use super::*;

            #derive
            #[sea_orm(table_name = #table)]
            pub struct Model {
                #(#fields)*
            }

            #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
            pub enum Relation {}

            impl ActiveModelBehavior for ActiveModel {}
        }
    }
}
