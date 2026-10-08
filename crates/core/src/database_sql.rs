//! Relation qualification shared by relational adapters.
use crate::error::{AuthError, AuthResult};
use sqlparser::{
    ast::{
        ColumnOption, Ident, ObjectName, ObjectNamePart, Query, Statement, TableConstraint,
        VisitMut, VisitorMut,
    },
    dialect::PostgreSqlDialect,
    parser::Parser,
};
use std::ops::ControlFlow;

/// Qualify physical relations without touching values, columns or bind positions.
pub fn qualify_schema(sql: &str, schema: &str) -> AuthResult<String> {
    struct Qualifier<'a> {
        schema: &'a str,
        ctes: Vec<Vec<String>>,
    }
    impl VisitorMut for Qualifier<'_> {
        type Break = ();
        fn pre_visit_query(&mut self, query: &mut Query) -> ControlFlow<()> {
            self.ctes.push(
                query
                    .with
                    .as_ref()
                    .map(|with| {
                        with.cte_tables
                            .iter()
                            .map(|cte| cte.alias.name.value.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
            );
            ControlFlow::Continue(())
        }
        fn post_visit_query(&mut self, _: &mut Query) -> ControlFlow<()> {
            let _ = self.ctes.pop();
            ControlFlow::Continue(())
        }
        fn pre_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<()> {
            if let Statement::CreateTable(table) = statement {
                // Foreign-key targets are ObjectNames but are not annotated as
                // relations by sqlparser's visitor, so visit them explicitly.
                for column in &mut table.columns {
                    for option in &mut column.options {
                        if let ColumnOption::ForeignKey(key) = &mut option.option {
                            let _ = self.pre_visit_relation(&mut key.foreign_table);
                        }
                    }
                }
                for constraint in &mut table.constraints {
                    if let TableConstraint::ForeignKey(key) = constraint {
                        let _ = self.pre_visit_relation(&mut key.foreign_table);
                    }
                }
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_relation(&mut self, relation: &mut ObjectName) -> ControlFlow<()> {
            if let [ObjectNamePart::Identifier(name)] = relation.0.as_slice() {
                if !self.ctes.iter().any(|scope| scope.contains(&name.value)) {
                    relation.0.insert(
                        0,
                        ObjectNamePart::Identifier(Ident::with_quote('"', self.schema)),
                    );
                }
            }
            ControlFlow::Continue(())
        }
    }
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|error| AuthError::internal(format!("Cannot qualify auth SQL: {error}")))?;
    let _ = statements.visit(&mut Qualifier {
        schema,
        ctes: Vec::new(),
    });
    Ok(statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; "))
}
