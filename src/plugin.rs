//! Plugin authoring interfaces and shared runtime types.

pub use better_auth_core::openapi::{
    OpenApiBuilder, OpenApiEndpoint, OpenApiField, OpenApiModel, OpenApiRegistry, OpenApiSpec,
    PluginOpenApiMetadata,
};
pub use better_auth_core::plugin::{
    AuthContext, AuthInitContext, AuthPlugin, AuthRoute, BeforeRequestAction,
};
