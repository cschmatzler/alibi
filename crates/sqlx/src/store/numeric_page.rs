//! Preserve numeric pagination until the actual database validates its binding.
use crate::sql::Sql;

pub(super) fn bind_page(sql: &mut Sql, limit: Option<f64>, offset: Option<f64>) {
    for (clause, number) in [(" LIMIT ", limit), (" OFFSET ", offset)] {
        if let Some(number) = number {
            sql.push(clause).bind(number);
        }
    }
}
