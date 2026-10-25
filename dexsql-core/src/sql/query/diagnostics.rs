//! MCP optimizer accounting after resolving query-local and session relations.
//!
//! The native relation resolver expands views before its thirty-pass pipeline.
//! Counting words in the SQL misses both eliminated membership subqueries and
//! the column demand that drives pruning of those expanded views. These rules
//! operate on parsed query structure, separately from CLI batch trace vectors.

use std::collections::{HashMap, HashSet};

use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, Query, Select, SelectItem, SetExpr, Statement,
};
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
    let select = match query.body.as_ref() {
        SetExpr::Select(select) => select,
        SetExpr::Query(query) => return count_query(query, definitions, expanding),
        SetExpr::Values(_) => return Some(0),
        SetExpr::SetOperation {
            left,
            right,
            set_quantifier,
            ..
        } => {
            let mut left_query = query.clone();
            left_query.body = left.clone();
            let mut right_query = query.clone();
            right_query.body = right.clone();
            return Some(
                count_query(&left_query, definitions, expanding)?
                    + count_query(&right_query, definitions, expanding)?
                    + usize::from(!matches!(
                        set_quantifier,
                        sqlparser::ast::SetQuantifier::All
                    )),
            );
        }
        _ => return None,
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
        return Some(projection_canonicalization(select));
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
        super::item_expr(item).is_none_or(|expr| {
            matches!(
                expr,
                Expr::Identifier(_) | Expr::CompoundIdentifier(_) | Expr::Value(_)
            )
        })
    }) && matches!(&select.group_by, GroupByExpr::Expressions(groups, _) if groups.is_empty());
    let constant_projection = select.projection.iter().all(|item| {
        super::item_expr(item).is_some_and(|expr| {
            let mut columns = HashSet::new();
            super::collect_expr_columns(expr, &mut columns)
                && columns.is_empty()
                && !super::item_has_aggregate(expr)
        })
    });
    let frame_limit = usize::from(
        row_preserving_projection
            && query.order_by.is_some()
            && (query.limit_clause.is_some() || constant_projection),
    );
    if select.from.len() == 1 && select.from[0].joins.is_empty() {
        if let sqlparser::ast::TableFactor::Derived { subquery, .. } = &select.from[0].relation {
            return Some(
                count_query(subquery, &definitions, expanding)?
                    + 2
                    + usize::from(!wildcard)
                    + frame_limit,
            );
        }
    }
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
            let cte = query.with.as_ref().is_some_and(|with| {
                with.cte_tables
                    .iter()
                    .any(|cte| cte.alias.name.value.eq_ignore_ascii_case(table))
            });
            return Some(
                inner
                    + 1
                    + usize::from(relational_definition && !wildcard)
                    + frame_limit
                    + usize::from(cte) * 2,
            );
        }
        let base = if table == "method_strings" {
            string_view_rewrites(wildcard, &demand, select)
        } else if let Some(count) = expanded_view_rewrites(table, wildcard, &demand, select, query)
        {
            count
        } else {
            let typed = usize::from(matches!(
                table.as_str(),
                "methods" | "fields" | "classes" | "types" | "protos"
            ));
            // Raw relations need only a column-pruning rewrite. Resolved
            // metadata views additionally replace one typed relation leaf.
            typed
                + usize::from(!wildcard)
                + canonical_predicates(select)
                + projection_canonicalization(select)
        };
        let subqueries = membership_rewrites(select, &definitions, expanding);
        if matches!(table.as_str(), "methods" | "fields" | "protos")
            && select
                .selection
                .as_ref()
                .is_some_and(|selection| is_unsigned_contradiction(table, selection))
        {
            let aggregate_only = select
                .projection
                .iter()
                .all(|item| super::item_expr(item).is_some_and(super::item_has_aggregate))
                && select
                    .projection
                    .iter()
                    .any(|item| super::item_expr(item).is_some_and(|expr| !is_count(expr)));
            return Some(
                (if aggregate_only { 3 } else { 4 }) + projection_canonicalization(select),
            );
        }
        let computed_group = matches!(&select.group_by, GroupByExpr::Expressions(groups, _) if groups.iter().any(|expr| !matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_))));
        return Some(
            base + frame_limit + subqueries
                - usize::from(computed_group && matches!(table.as_str(), "methods" | "fields")),
        );
    }
    if tables.len() == 2
        && tables.iter().any(|table| table == "methods")
        && tables.iter().any(|table| table == "method_strings")
    {
        let identity = complete_method_identity(select);
        let (method_alias, edge_alias) = join_aliases(select);
        let mut projected_methods = false;
        let mut projected_edge = false;
        for item in &select.projection {
            if let Some(expr) = super::item_expr(item) {
                super::walk_expr(expr, &mut |expr| {
                    if let Expr::CompoundIdentifier(ids) = expr {
                        projected_methods |= ids
                            .first()
                            .is_some_and(|id| id.value.eq_ignore_ascii_case(&method_alias));
                        projected_edge |= ids
                            .first()
                            .is_some_and(|id| id.value.eq_ignore_ascii_case(&edge_alias));
                    }
                });
            }
        }
        let left = select
            .from
            .iter()
            .flat_map(|from| &from.joins)
            .any(|join| relational_left(&join.join_operator));
        if left {
            return Some(
                if wildcard {
                    13
                } else if demand.contains("value") {
                    16
                } else {
                    17
                } + frame_limit,
            );
        }
        if !identity {
            let only_method_idx =
                projected_methods && demand.len() == 1 && demand.contains("method_idx");
            return Some(
                if wildcard {
                    42
                } else if only_method_idx {
                    17
                } else if projected_methods {
                    59
                } else if demand.contains("value") {
                    16
                } else {
                    17
                } + frame_limit,
            );
        }
        if !projected_methods && !wildcard {
            let count = if projected_edge
                && (demand.contains("method")
                    || demand.contains("method_name")
                    || demand.contains("method_class"))
            {
                17
            } else if demand.contains("file_id") && demand.contains("method_idx") {
                19 - usize::from(demand.contains("value"))
            } else if demand.contains("method_idx") || demand.contains("value") {
                22
            } else {
                23
            };
            return Some(count + frame_limit);
        }
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
            if wildcard {
                13
            } else if demand.contains("value") {
                16
            } else {
                17
            } + frame_limit,
        );
    }
    None
}

fn join_aliases(select: &Select) -> (String, String) {
    let mut methods = "methods".to_owned();
    let mut edges = "method_strings".to_owned();
    for factor in select.from.iter().flat_map(|from| {
        std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
    }) {
        if let sqlparser::ast::TableFactor::Table { name, alias, .. } = factor {
            let name = name.to_string().to_ascii_lowercase();
            let alias = alias
                .as_ref()
                .map(|alias| alias.name.value.clone())
                .unwrap_or_else(|| name.clone());
            if name == "methods" {
                methods = alias;
            } else if name == "method_strings" {
                edges = alias;
            }
        }
    }
    (methods, edges)
}

fn relational_left(operator: &sqlparser::ast::JoinOperator) -> bool {
    matches!(
        operator,
        sqlparser::ast::JoinOperator::Left(_) | sqlparser::ast::JoinOperator::LeftOuter(_)
    )
}

/// Native view expansion is demand driven: requesting a descriptor retains
/// the join which resolves it, while an identity-only projection permits
/// elimination of those joins. The view SQL recovered from ELF rodata forms
/// these relation families; aliases and SQL formatting do not affect them.
fn expanded_view_rewrites(
    table: &str,
    wildcard: bool,
    demand: &HashSet<String>,
    select: &Select,
    query: &Query,
) -> Option<usize> {
    let method = ["method", "method_class", "method_name"]
        .iter()
        .any(|column| demand.contains(*column));
    let identity = demand.contains("file_id") && demand.contains("method_idx");
    let mut count = match table {
        "method_calls" => {
            if wildcard {
                10
            } else if method || demand.contains("callee") {
                11
            } else {
                13 - usize::from(demand.contains("method_idx"))
            }
        }
        "method_using_numbers" => {
            if wildcard {
                4
            } else if method {
                6
            } else {
                8 - usize::from(identity)
            }
        }
        "method_field_accesses" => {
            if wildcard {
                9
            } else if method {
                11
            } else {
                14 - usize::from(demand.contains("method_idx")) - usize::from(identity)
            }
        }
        "method_used_types" => {
            if wildcard {
                16
            } else {
                19 - usize::from(demand.contains("type_descriptor") || demand.contains("type_name"))
            }
        }
        "class_methods" => 4 + usize::from(!wildcard),
        "protos" => {
            let shorty = demand.contains("shorty");
            let result = demand.contains("return_descriptor");
            let params = demand.contains("param_count") || demand.contains("param_descriptors");
            if wildcard {
                22
            } else if !(shorty || result || params) {
                2
            } else {
                let base = match (shorty, result, params) {
                    (true, true, true) => 25,
                    (true, true, false) => 32,
                    (true, false, true) => 35,
                    (false, true, true) => 34,
                    (true, false, false) => 35,
                    (false, true, false) => 39,
                    (false, false, true) => 37,
                    _ => unreachable!(),
                };
                base - usize::from(demand.contains("proto_idx"))
            }
        }
        "types" if select.selection.is_some() || query.order_by.is_some() => {
            if wildcard {
                8
            } else if demand.contains("descriptor") || demand.contains("java_name") {
                10 - usize::from(demand.contains("type_idx"))
            } else if demand.contains("type_idx") {
                13
            } else if demand.contains("file_id") {
                14
            } else if select
                .projection
                .iter()
                .any(|item| super::item_expr(item).is_some_and(super::item_has_aggregate))
            {
                12
            } else {
                13
            }
        }
        "classes"
            if select.selection.is_some()
                || query.order_by.is_some()
                || query.limit_clause.is_some() =>
        {
            if wildcard {
                29
            } else if demand.contains("descriptor") && !demand.contains("source_file")
                || demand.contains("superclass_descriptor")
                || demand.contains("interface_count")
            {
                40
            } else if demand.contains("class_idx") && !demand.contains("descriptor") {
                36
            } else {
                37
            }
        }
        _ => return None,
    };
    if table == "protos" && query.order_by.is_some() {
        if wildcard
            || [
                "shorty",
                "return_descriptor",
                "param_count",
                "param_descriptors",
            ]
            .iter()
            .any(|column| demand.contains(*column))
        {
            count += 2;
        }
        if query.limit_clause.is_none()
            && ["return_descriptor", "param_count", "param_descriptors"]
                .iter()
                .any(|column| demand.contains(*column))
        {
            count += 1;
        }
    }
    if table == "classes"
        && query.order_by.is_some()
        && query.limit_clause.is_none()
        && (wildcard
            || [
                "descriptor",
                "superclass_descriptor",
                "interface_count",
                "source_file",
            ]
            .iter()
            .any(|column| demand.contains(*column)))
    {
        count += 1;
    }
    if let Some(selection) = &select.selection {
        let mut columns = HashSet::new();
        super::collect_expr_columns(selection, &mut columns);
        // Full view predicates pass through canonicalization, join pushdown,
        // and post-prune simplification rather than the native typed leaf.
        if columns.contains("file_id") && matches!(table, "classes" | "types") {
            count += if is_null_or_unsigned_impossible(selection) {
                return Some(if table == "classes" { 6 } else { 4 });
            } else if is_unsigned_tautology(selection) {
                2 - usize::from(table == "types" && (wildcard || !demand.is_empty()))
            } else {
                4 + usize::from(table == "classes") * 2 + canonical_predicates(select)
                    - usize::from(table == "types" && (wildcard || !demand.is_empty()))
            };
        } else {
            count += canonical_predicates(select);
            if [
                "method_calls",
                "method_using_numbers",
                "method_field_accesses",
                "method_used_types",
                "class_methods",
            ]
            .contains(&table)
                && !matches!(selection, Expr::IsNotNull(_) | Expr::IsNull(_))
            {
                count += match table {
                    "class_methods" => 1,
                    "method_calls" if matches!(selection, Expr::Between { .. }) => 6,
                    "method_calls" | "method_field_accesses" => {
                        if matches!(selection, Expr::Between { .. }) {
                            5
                        } else {
                            3
                        }
                    }
                    "method_using_numbers" if matches!(selection, Expr::Between { .. }) => 5,
                    "method_used_types" if matches!(selection, Expr::Between { .. }) => 4,
                    _ => 2,
                };
            }
        }
    }
    Some(count)
}

fn is_count(expr: &Expr) -> bool {
    matches!(expr, Expr::Function(function) if function.name.to_string().eq_ignore_ascii_case("count"))
}

fn is_unsigned_contradiction(table: &str, expr: &Expr) -> bool {
    let value = match expr {
        Expr::IsNull(expr) => expr.as_ref(),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Lt,
            right,
        } if matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0") => {
            left.as_ref()
        }
        _ => return false,
    };
    let column = match value {
        Expr::Identifier(id) => &id.value,
        Expr::CompoundIdentifier(ids) => &ids.last().unwrap().value,
        _ => return false,
    };
    crate::sql::schema::TABLES
        .iter()
        .find(|meta| meta.name == table)
        .and_then(|meta| {
            meta.columns
                .iter()
                .find(|meta| meta.name.eq_ignore_ascii_case(column))
        })
        .is_some_and(|meta| meta.sql_type.starts_with("UInt") && !meta.nullable)
}

fn projection_canonicalization(select: &Select) -> usize {
    let mut count = 0;
    for item in &select.projection {
        if let Some(expr) = super::item_expr(item) {
            super::walk_expr(expr, &mut |expr| {
                if matches!(expr, Expr::Cast { data_type, .. } if data_type.to_string().eq_ignore_ascii_case("INTEGER"))
                {
                    count += 1;
                }
                if let Expr::BinaryOp {
                    op: BinaryOperator::Plus,
                    right,
                    ..
                } = expr
                {
                    if matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0")
                    {
                        count += 1;
                    }
                }
                if let Expr::Function(function) = expr {
                    if matches!(
                        function.name.to_string().to_ascii_lowercase().as_str(),
                        "coalesce" | "ifnull"
                    ) {
                        if let sqlparser::ast::FunctionArguments::List(args) = &function.args {
                            if let Some(sqlparser::ast::FunctionArg::Unnamed(
                                sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(id)),
                            )) = args.args.first()
                            {
                                let mut tables = Vec::new();
                                super::collect_from_select(select, &mut tables);
                                if tables.iter().any(|table| {
                                    crate::sql::schema::TABLES.iter().any(|meta| {
                                        meta.name == table
                                            && meta.columns.iter().any(|column| {
                                                column.name.eq_ignore_ascii_case(&id.value)
                                                    && !column.nullable
                                            })
                                    })
                                }) {
                                    count += 1;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
    count
}

fn is_null_or_unsigned_impossible(expr: &Expr) -> bool {
    matches!(expr, Expr::IsNull(_))
        || matches!(expr, Expr::BinaryOp { op: BinaryOperator::Lt, right, .. } if matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0"))
}

fn is_unsigned_tautology(expr: &Expr) -> bool {
    matches!(expr, Expr::IsNotNull(_))
        || matches!(expr, Expr::BinaryOp { op: BinaryOperator::GtEq, right, .. } if matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0"))
}

fn canonical_predicates(select: &Select) -> usize {
    let mut count = 0;
    if let Some(selection) = &select.selection {
        super::walk_expr(selection, &mut |expr| {
            if matches!(expr, Expr::Like { .. } | Expr::ILike { .. }) {
                count += 1;
            }
            if matches!(
                expr,
                Expr::Between { .. }
                    | Expr::BinaryOp {
                        op: BinaryOperator::Or,
                        ..
                    }
            ) {
                count += 1;
            }
            if matches!(expr, Expr::IsNotNull(_)) {
                count += 2;
            }
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::GtEq,
                right,
            } = expr
            {
                if matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0") {
                    let mut tables = Vec::new();
                    super::collect_from_select(select, &mut tables);
                    if tables
                        .iter()
                        .any(|table| is_unsigned_contradiction(table, &Expr::IsNull(left.clone())))
                    {
                        count += 2;
                    }
                }
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
    let mut retained = demand.clone();
    let mut predicates = Vec::new();
    if let Some(selection) = &select.selection {
        super::flatten_and(selection, &mut predicates);
        for expr in &predicates {
            if is_unsigned_contradiction("method_strings", expr) {
                return 5;
            }
            if matches!(expr, Expr::IsNotNull(_)) {
                continue;
            }
            let mut columns = HashSet::new();
            super::collect_expr_columns(expr, &mut columns);
            for column in ["method", "method_class", "method_name"] {
                if columns.contains(column) {
                    retained.insert(column.into());
                }
            }
            if let Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } = expr
            {
                if matches!(left.as_ref(), Expr::Identifier(id) if id.value.eq_ignore_ascii_case("method"))
                    && matches!(right.as_ref(), Expr::Value(value) if matches!(&value.value, sqlparser::ast::Value::SingleQuotedString(text) if !text.contains("->") || !text.contains('(')))
                {
                    return 1;
                }
            }
        }
    }
    let method = ["method", "method_class", "method_name"]
        .iter()
        .any(|column| retained.contains(*column));
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
    for selection in predicates {
        let mut columns = HashSet::new();
        super::collect_expr_columns(selection, &mut columns);
        if matches!(selection, Expr::IsNotNull(_)) {
            count += 2;
        } else if matches!(
            selection,
            Expr::BinaryOp {
                op: BinaryOperator::Or,
                ..
            }
        ) {
            count += 3 + usize::from(
                wildcard || method || demand.contains("method_idx") && !demand.contains("file_id"),
            );
        } else if columns.contains("file_id") {
            count += 4;
        } else if columns.contains("method_idx") {
            count += 3 + usize::from(
                wildcard || method || demand.contains("method_idx") && !demand.contains("file_id"),
            );
        } else if columns.contains("value") {
            count += if wildcard || value { 3 } else { 2 };
            count += usize::from(matches!(selection, Expr::Like { .. } | Expr::ILike { .. }));
        } else if ["method", "method_class", "method_name"]
            .iter()
            .any(|column| columns.contains(*column))
        {
            count += 2 + usize::from(matches!(selection, Expr::Like { .. } | Expr::ILike { .. }));
            if matches!(selection, Expr::Between { .. }) {
                count += 3;
            }
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
            ("SELECT file_id,method_idx,length(name) AS n FROM methods WHERE method_idx%3=0 ORDER BY n DESC,file_id,method_idx LIMIT 4", 2),
            ("SELECT file_id,count(*) FROM method_strings GROUP BY file_id", 18),
            ("SELECT method_idx FROM methods WHERE method_idx IN (SELECT method_idx FROM method_strings) ORDER BY method_idx LIMIT 4", 3),
            ("SELECT m.file_id,m.method_idx,s.value FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.value LIMIT 4", 17),
        ] {
            assert_eq!(rewrite_count(sql, &definitions), expected, "{sql}");
        }
    }

    #[test]
    fn view_demand_and_query_shape_are_independent_of_alias_spelling() {
        let definitions = HashMap::new();
        for (sql, expected) in [
            ("SELECT * FROM protos", 22),
            ("SELECT count(*) FROM protos", 2),
            ("SELECT a.shorty,a.proto_idx FROM protos AS a", 34),
            (
                "SELECT p.method,p.long_value FROM method_using_numbers AS p",
                6,
            ),
            (
                "SELECT p.file_id,p.method_idx FROM method_using_numbers AS p",
                7,
            ),
            ("SELECT r.method_idx FROM method_calls AS r", 12),
            ("SELECT r.method FROM method_field_accesses AS r", 11),
            ("SELECT r.type_descriptor FROM method_used_types AS r", 18),
            ("SELECT r.file_id FROM class_methods AS r", 5),
            ("SELECT r.file_id FROM classes AS r WHERE r.file_id=0", 43),
            ("SELECT r.file_id FROM types AS r WHERE r.file_id=0", 17),
            ("SELECT p.return_descriptor FROM protos p ORDER BY 1", 42),
            ("SELECT p.method_idx FROM methods p WHERE p.file_id>=0", 4),
            (
                "SELECT p.method FROM method_strings p WHERE p.method_idx=0",
                18,
            ),
            (
                "SELECT p.method_idx FROM method_strings p WHERE p.file_id=0 OR p.method_idx=0",
                21,
            ),
            (
                "SELECT method_idx FROM methods UNION SELECT method_idx FROM methods",
                5,
            ),
            (
                "WITH chosen AS (SELECT * FROM methods) SELECT method_idx FROM chosen",
                5,
            ),
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
