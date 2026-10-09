//! Relation qualification shared by relational adapters.
use crate::error::{AuthError, AuthResult};
use sqlparser::{
    ast::{
        AssignmentTarget, ColumnOption, Expr, Ident, ObjectName, ObjectNamePart, Query, Statement,
        TableConstraint, VisitMut, VisitorMut, visit_relations,
    },
    dialect::{GenericDialect, PostgreSqlDialect},
    parser::Parser,
    tokenizer::{Token, Tokenizer},
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
            _ = self.ctes.pop();
            ControlFlow::Continue(())
        }
        fn pre_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<()> {
            if let Statement::CreateTable(table) = statement {
                // Foreign-key targets are ObjectNames but are not annotated as
                // relations by sqlparser's visitor, so visit them explicitly.
                for column in &mut table.columns {
                    for option in &mut column.options {
                        if let ColumnOption::ForeignKey(key) = &mut option.option {
                            _ = self.pre_visit_relation(&mut key.foreign_table);
                        }
                    }
                }
                for constraint in &mut table.constraints {
                    if let TableConstraint::ForeignKey(key) = constraint {
                        _ = self.pre_visit_relation(&mut key.foreign_table);
                    }
                }
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_relation(&mut self, relation: &mut ObjectName) -> ControlFlow<()> {
            if let [ObjectNamePart::Identifier(name)] = relation.0.as_slice()
                && !self.ctes.iter().any(|scope| scope.contains(&name.value))
            {
                relation.0.insert(
                    0,
                    ObjectNamePart::Identifier(Ident::with_quote('"', self.schema)),
                );
            }
            ControlFlow::Continue(())
        }
    }
    let mut statements = Parser::parse_sql(&PostgreSqlDialect {}, sql)
        .map_err(|error| AuthError::internal(format!("Cannot qualify auth SQL: {error}")))?;
    _ = statements.visit(&mut Qualifier {
        schema,
        ctes: Vec::new(),
    });
    Ok(statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; "))
}

/// Apply a factor storage mapping only to statements targeting the factor table.
/// Result aliases stay canonical so typed model decoding remains unchanged.
pub fn map_two_factor(
    sql: &str,
    mapping: &crate::config::TwoFactorDatabaseConfig,
) -> AuthResult<String> {
    struct Mapper<'a>(&'a crate::config::TwoFactorDatabaseConfig);
    impl Mapper<'_> {
        fn identifier(&self, identifier: &mut Ident) {
            let physical = if identifier.value == "two_factor" {
                Some(&self.0.table_name)
            } else {
                self.0.columns.get(&identifier.value)
            };
            if let Some(physical) = physical {
                *identifier = Ident::with_quote('"', physical);
            }
        }
        fn name(&self, name: &mut ObjectName) {
            for part in &mut name.0 {
                if let ObjectNamePart::Identifier(identifier) = part {
                    self.identifier(identifier);
                }
            }
        }
    }
    impl VisitorMut for Mapper<'_> {
        type Break = ();
        fn pre_visit_relation(&mut self, name: &mut ObjectName) -> ControlFlow<()> {
            self.name(name);
            ControlFlow::Continue(())
        }
        fn pre_visit_expr(&mut self, expression: &mut Expr) -> ControlFlow<()> {
            match expression {
                Expr::Identifier(identifier) => self.identifier(identifier),
                Expr::CompoundIdentifier(identifiers) => {
                    for identifier in identifiers {
                        self.identifier(identifier);
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
        fn pre_visit_statement(&mut self, statement: &mut Statement) -> ControlFlow<()> {
            match statement {
                Statement::Insert(insert) => {
                    for column in &mut insert.columns {
                        self.name(column);
                    }
                }
                Statement::Update(update) => {
                    for assignment in &mut update.assignments {
                        match &mut assignment.target {
                            AssignmentTarget::ColumnName(name) => self.name(name),
                            AssignmentTarget::Tuple(names) => {
                                for name in names {
                                    self.name(name);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            ControlFlow::Continue(())
        }
    }
    // Migration scripts remain in the migrator's DDL path. Tokenize to skip
    // comments safely without trying to parse unrelated SQLite DDL as DML.
    const DML: [&str; 5] = ["SELECT", "INSERT", "UPDATE", "DELETE", "WITH"];
    let tokens = Tokenizer::new(&GenericDialect {}, sql)
        .tokenize()
        .map_err(|error| AuthError::internal(format!("Cannot tokenize factor SQL: {error}")))?;
    let is_dml = tokens
        .iter()
        .find(|token| !matches!(token, Token::Whitespace(_)))
        .is_some_and(|token| {
            matches!(token, Token::Word(word) if DML.contains(&word.value.to_ascii_uppercase().as_str()))
        });
    if !is_dml {
        return Ok(sql.to_owned());
    }
    let mut statements = Parser::parse_sql(&GenericDialect {}, sql)
        .map_err(|error| AuthError::internal(format!("Cannot map factor SQL: {error}")))?;
    for statement in &mut statements {
        // DDL is performed explicitly by the schema migrator; values never trigger mapping.
        if !matches!(
            statement,
            Statement::Query(_)
                | Statement::Insert(_)
                | Statement::Update(_)
                | Statement::Delete(_)
        ) {
            continue;
        }
        let mut target = false;
        _ = visit_relations(statement, |name| {
            target |= name.0.iter().any(
                |part| matches!(part, ObjectNamePart::Identifier(id) if id.value == "two_factor"),
            );
            ControlFlow::<()>::Continue(())
        });
        if target {
            _ = statement.visit(&mut Mapper(mapping));
        }
    }
    Ok(statements
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; "))
}
