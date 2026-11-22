use crate::parse_type;
use crate::selection::Selection;
use alibi_schema_registry::{EntityRole, FieldDef};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub(crate) fn sqlx_schema(selection: &Selection) -> TokenStream {
    let entities = selection
        .entities()
        .map(|entity| sqlx_entity(entity.module, entity.table, entity.role, &entity.fields));
    let (sqlite, postgres) = crate::migration::statements(selection);
    quote! {
        use alibi::AuthSchema;
        use alibi::sqlx::{Engine, SqlxPool};

        #(#entities)*

        pub struct AppAuthSchema;

        impl AuthSchema for AppAuthSchema {
            type User = user::Model;
            type Session = session::Model;
            type Account = account::Model;
            type Verification = verification::Model;
        }

        const SQLITE_TABLES: &[&str] = &[#(#sqlite),*];
        const POSTGRES_TABLES: &[&str] = &[#(#postgres),*];

        pub async fn run_app_migrations(
            pool: &SqlxPool,
        ) -> Result<(), alibi::sqlx::sqlx::Error> {
            let statements = match pool.engine() {
                Engine::Sqlite => SQLITE_TABLES,
                Engine::Postgres => POSTGRES_TABLES,
            };
            pool.execute_batch(statements).await
        }
    }
}

pub(crate) fn sqlx_entity(
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
            &sqlx_type(field.ty).replace(
                "i64",
                if field.name == "last_request" {
                    "i64"
                } else {
                    "alibi::sqlx::Integer"
                },
            ),
        );
        let rename = field
            .column_name
            .map(|column| quote! { #[sqlx(rename = #column)] });
        let column_kind = (table == "organization" && field.name == "metadata")
            .then(|| quote! { #[auth(column_type = "text")] });
        quote! {
            #column_kind
            #rename
            pub #name: #ty,
        }
    });
    let derive = role.map_or_else(
        || quote! { #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::SqlxModel)] #[auth(table = #table)] },
        |role| {
            let role = role.as_str();
            quote! {
                #[derive(Clone, Debug, serde::Serialize, sqlx::FromRow, alibi::sqlx::AuthEntity)]
                #[auth(role = #role, table = #table)]
            }
        },
    );
    quote! {
        pub mod #module {
            #derive
            pub struct Model {
                #(#fields)*
            }
        }
    }
}

/// The `SQLx` model type for a registry type.
pub(crate) fn sqlx_type(ty: &str) -> String {
    ty.replace("DateTimeUtc", "chrono::DateTime<chrono::Utc>")
        .replace("Json", "alibi::sqlx::JsonMetadata")
        .replace("f64", "alibi::sqlx::Number")
}
