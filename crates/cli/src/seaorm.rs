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
    let extra_migration_statements = selection.extra.iter().map(|entity| {
        let module = format_ident!("{}", entity.mod_name);
        quote! { schema.create_table_from_entity(#module::Entity).if_not_exists().to_owned() }
    });

    quote! {
        use alibi::AuthSchema;
        use alibi::seaorm::sea_orm;
        use alibi::seaorm::sea_orm::entity::prelude::*;
        use alibi::seaorm::sea_orm::{ConnectionTrait, Schema};
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
            let schema = Schema::new(database.get_database_backend());
            for statement in [
                schema.create_table_from_entity(user::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(session::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(account::Entity).if_not_exists().to_owned(),
                schema.create_table_from_entity(verification::Entity).if_not_exists().to_owned(),
                #(#extra_migration_statements,)*
            ] {
                let _ = database.execute(&statement).await?;
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
        let ty = parse_type(field, field.ty);
        let column_attr = field
            .column_name
            .map(|column| quote! { #[sea_orm(column_name = #column)] });
        let default_attr = field
            .default_value
            .map(|value| quote! { #[sea_orm(default_value = #value)] });
        let primary_key = field
            .is_primary_key
            .then(|| quote! { #[sea_orm(primary_key, auto_increment = false)] });
        quote! {
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
