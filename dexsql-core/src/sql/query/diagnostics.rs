//! MCP optimizer accounting after resolving query-local and session relations.
//!
//! The native relation resolver expands views before its thirty-pass pipeline.
//! Counting words in the SQL misses both eliminated membership subqueries and
//! the column demand that drives pruning of those expanded views. These rules
//! operate on parsed query structure, separately from CLI batch trace vectors.

use std::collections::{HashMap, HashSet};

use sqlparser::ast::{Expr, GroupByExpr, Query, Select, SelectItem, SetExpr, Statement};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

pub(super) fn rewrite_count(sql: &str, definitions: &HashMap<String, String>) -> usize {
    count_sql(sql, definitions, &mut HashSet::new())
}

fn count_sql(
    sql: &str,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> usize {
    let Ok(statements) = Parser::parse_sql(&SQLiteDialect {}, sql) else {
        return 0;
    };
    let [Statement::Query(query)] = statements.as_slice() else {
        return 0;
    };
    count_query(query, definitions, expanding)
        .unwrap_or_else(|| super::optimizer_rewrite_count(sql))
}

fn count_query(
    query: &Query,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> Option<usize> {
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    let mut definitions = definitions.clone();
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            definitions.insert(
                cte.alias.name.value.to_ascii_lowercase(),
                cte.query.to_string(),
            );
        }
    }
    if select.from.is_empty() {
        return Some(0);
    }
    let mut tables = Vec::new();
    super::collect_from_select(select, &mut tables);
    if tables.is_empty() {
        return None;
    }
    let wildcard = select.projection.iter().any(|item| {
        matches!(
            item,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
        )
    });
    let row_preserving_projection = select.projection.iter().all(|item| {
        super::item_expr(item)
            .is_none_or(|expr| matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_)))
    });
    let frame_limit = usize::from(
        row_preserving_projection && query.order_by.is_some() && query.limit_clause.is_some(),
    );
    let mut demand = HashSet::new();
    for item in &select.projection {
        if let Some(expr) = super::item_expr(item) {
            super::collect_expr_columns(expr, &mut demand);
        }
    }
    if let GroupByExpr::Expressions(groups, _) = &select.group_by {
        for group in groups {
            super::collect_expr_columns(group, &mut demand);
        }
    }
    // Requested sort keys remain live until the limit is pushed beneath the
    // output frame; include them when determining an expanded view's demand.
    if let Some(order) = &query.order_by {
        if let sqlparser::ast::OrderByKind::Expressions(items) = &order.kind {
            for item in items {
                super::collect_expr_columns(&item.expr, &mut demand);
            }
        }
    }
    if tables.len() == 1 {
        let table = &tables[0];
        if let Some(definition) = definitions.get(table) {
            if !expanding.insert(table.clone()) {
                return Some(0);
            }
            let inner = count_sql(definition, &definitions, expanding);
            expanding.remove(table);
            let relational_definition = Parser::parse_sql(&SQLiteDialect {}, definition)
                .ok()
                .and_then(|statements| match statements.into_iter().next()? {
                    Statement::Query(query) => Some(query.body.as_select()?.from.len() > 0),
                    _ => None,
                })
                .unwrap_or(false);
            return Some(inner + 1 + usize::from(relational_definition && !wildcard) + frame_limit);
        }
        let base = if table == "method_strings" {
            string_view_rewrites(wildcard, &demand, select)
        } else {
            let typed = usize::from(matches!(
                table.as_str(),
                "methods" | "fields" | "classes" | "types"
            ));
            // Raw relations need only a column-pruning rewrite. Resolved
            // metadata views additionally replace one typed relation leaf.
            typed + usize::from(!wildcard) + canonical_predicates(select)
        };
        let subqueries = membership_rewrites(select, &definitions, expanding);
        return Some(base + frame_limit + subqueries);
    }
    if tables.len() == 2
        && tables.iter().any(|table| table == "methods")
        && tables.iter().any(|table| table == "method_strings")
        && complete_method_identity(select)
    {
        // The built-in method_strings view already joins the unique method
        // identity (ELF view SQL at 0x1d06aa). A second complete identity join
        // is eliminated; its keys must remain live through column pruning.
        demand.insert("file_id".into());
        demand.insert("method_idx".into());
        for (method, edge) in [
            ("name", "method_name"),
            ("descriptor", "method"),
            ("class_descriptor", "method_class"),
        ] {
            if demand.remove(method) {
                demand.insert(edge.into());
            }
        }
        return Some(
            string_view_rewrites(wildcard, &demand, select)
                + if wildcard { 1 } else { 2 }
                + frame_limit,
        );
    }
    None
}

fn canonical_predicates(select: &Select) -> usize {
    let mut count = 0;
    if let Some(selection) = &select.selection {
        super::walk_expr(selection, &mut |expr| {
            if matches!(expr, Expr::Like { .. } | Expr::ILike { .. }) {
                count += 1;
            }
        });
    }
    count
}

fn membership_rewrites(
    select: &Select,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> usize {
    let Some(selection) = &select.selection else {
        return 0;
    };
    let mut rewrites = 0;
    super::walk_expr(selection, &mut |expr| {
        if let Expr::InSubquery { subquery, .. } = expr {
            let mut tables = Vec::new();
            super::sql_from_factors(subquery.body.as_ref(), &mut tables);
            // Membership by an edge identity is resolved to its native set;
            // the expanded method_strings output view is never compiled.
            if tables.as_slice() != ["method_strings"] {
                rewrites += count_query(subquery, definitions, expanding).unwrap_or(0);
            }
        }
    });
    rewrites
}

fn complete_method_identity(select: &Select) -> bool {
    let mut columns = HashSet::new();
    for table in &select.from {
        for join in &table.joins {
            if let Ok((_, sqlparser::ast::JoinConstraint::On(expr))) =
                super::relational::parts(&join.join_operator)
            {
                super::collect_expr_columns(expr, &mut columns);
            }
        }
    }
    columns.contains("file_id") && columns.contains("method_idx")
}

fn string_view_rewrites(wildcard: bool, demand: &HashSet<String>, select: &Select) -> usize {
    // Pruning the recovered four-relation view preserves different paths:
    // textual method columns keep methods; value keeps strings; the complete
    // raw method identity enables elimination of the redundant methods join.
    let method = ["method", "method_class", "method_name"]
        .iter()
        .any(|column| demand.contains(*column));
    let value = demand.contains("value");
    let identity = demand.contains("file_id") && demand.contains("method_idx");
    let mut count = if wildcard {
        12
    } else if method {
        14 - usize::from(value)
    } else if identity {
        15 - usize::from(value)
    } else if demand.contains("method_idx") || value {
        17 - usize::from(demand.contains("method_idx") && value)
    } else {
        18
    };
    if let Some(selection) = &select.selection {
        let mut columns = HashSet::new();
        super::collect_expr_columns(selection, &mut columns);
        if columns.contains("file_id") {
            count += 4;
        }
        if columns.contains("value") {
            count += if wildcard || value { 3 } else { 2 };
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_mcp_frame_and_membership_accounting() {
        let definitions = HashMap::new();
        for (sql, expected) in [
            ("SELECT 1", 0),
            ("SELECT * FROM methods", 1),
            ("SELECT method_idx FROM methods", 2),
            ("SELECT method_idx FROM methods ORDER BY method_idx LIMIT 4", 3),
            ("SELECT file_id,count(*) FROM method_strings GROUP BY file_id", 18),
            ("SELECT method_idx FROM methods WHERE method_idx IN (SELECT method_idx FROM method_strings) ORDER BY method_idx LIMIT 4", 3),
            ("SELECT m.file_id,m.method_idx,s.value FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.value LIMIT 4", 17),
        ] {
            assert_eq!(rewrite_count(sql, &definitions), expected, "{sql}");
        }
    }

    #[test]
    fn native_mcp_temporary_relation_accounting() {
        let definitions = HashMap::from([
            ("nums".into(), "SELECT 42 AS n".into()),
            (
                "chosen".into(),
                "SELECT file_id,method_idx FROM methods WHERE method_idx<2".into(),
            ),
        ]);
        assert_eq!(rewrite_count("SELECT * FROM nums", &definitions), 1);
        assert_eq!(
            rewrite_count(
                "SELECT * FROM chosen ORDER BY file_id,method_idx",
                &definitions
            ),
            3
        );
        assert_eq!(
            rewrite_count("SELECT count(*) FROM chosen", &definitions),
            4
        );
    }
}
