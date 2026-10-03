//! Public access-control utilities matching Better Auth's resource and action rules.
//!
//! These operators apply to application-side authorization. Organization HTTP
//! permission requests continue to accept action arrays and use AND semantics.

use indexmap::IndexMap;

/// Literal resource names mapped to literal allowed actions.
pub type Statements = IndexMap<String, Vec<String>>;

/// How to combine resources, or the actions within one resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Connector {
    #[default]
    And,
    Or,
}

/// An action array uses AND; a resource rule can select its own connector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionRequest {
    Actions(Vec<String>),
    Rule {
        actions: Vec<String>,
        connector: Connector,
    },
}

impl From<Vec<String>> for ActionRequest {
    fn from(actions: Vec<String>) -> Self {
        Self::Actions(actions)
    }
}

/// Ordered resource requests. Order determines the first AND rejection.
pub type AuthorizeRequest = IndexMap<String, ActionRequest>;

/// A successful authorization has no error; a rejection explains the first failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeResponse {
    Success,
    Denied(String),
}

impl AuthorizeResponse {
    #[must_use]
    pub fn success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

/// A role's grants; authorization never combines different roles' statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub statements: Statements,
}

/// Construct a role directly from literal grants.
#[must_use]
pub fn role(statements: Statements) -> Role {
    Role { statements }
}

impl Role {
    /// Authorize all requested resources, with AND for plain action arrays.
    #[must_use]
    pub fn authorize(&self, request: &AuthorizeRequest) -> AuthorizeResponse {
        self.authorize_with_connector(request, Connector::And)
    }

    /// Authorize with an explicit resource connector. Empty requests and empty
    /// action lists deny. OR skips missing resources and succeeds on any grant.
    #[must_use]
    pub fn authorize_with_connector(
        &self,
        request: &AuthorizeRequest,
        connector: Connector,
    ) -> AuthorizeResponse {
        authorize(
            |resource| self.statements.get(resource).map(Vec::as_slice),
            request.iter().map(|(resource, rule)| {
                let (actions, connector) = match rule {
                    ActionRequest::Actions(actions) => (actions, Connector::And),
                    ActionRequest::Rule { actions, connector } => (actions, *connector),
                };
                (resource.as_str(), actions.as_slice(), connector)
            }),
            connector,
        )
    }
}

/// Declared access-control statements and a constructor for roles. As in the
/// Source runtime, constructing a role does not validate its grants against
/// these declarations. Rust callers supply typed string action lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessControl {
    pub statements: Statements,
}

#[must_use]
pub fn create_access_control(statements: Statements) -> AccessControl {
    AccessControl { statements }
}

impl AccessControl {
    #[must_use]
    pub fn new_role(&self, statements: Statements) -> Role {
        role(statements)
    }
}

pub(super) fn authorize<'a, 'b>(
    grants: impl Fn(&str) -> Option<&'b [String]>,
    request: impl IntoIterator<Item = (&'a str, &'a [String], Connector)>,
    connector: Connector,
) -> AuthorizeResponse {
    let mut authorized = false;
    for (resource, actions, action_connector) in request {
        let Some(allowed) = grants(resource) else {
            if connector == Connector::And {
                return AuthorizeResponse::Denied(format!(
                    "You are not allowed to access resource: {resource}"
                ));
            }
            continue;
        };
        let granted = !actions.is_empty()
            && match action_connector {
                Connector::And => actions.iter().all(|action| allowed.contains(action)),
                Connector::Or => actions.iter().any(|action| allowed.contains(action)),
            };
        if granted {
            authorized = true;
            if connector == Connector::Or {
                return AuthorizeResponse::Success;
            }
        } else if connector == Connector::And {
            return AuthorizeResponse::Denied(format!(
                "unauthorized to access resource \"{resource}\""
            ));
        }
    }
    if authorized {
        AuthorizeResponse::Success
    } else {
        AuthorizeResponse::Denied("Not authorized".into())
    }
}
