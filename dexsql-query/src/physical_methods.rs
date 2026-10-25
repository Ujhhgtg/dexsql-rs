//! Semantic proofs for compact method scans and loader pool elision.
//!
//! These planners never inspect rendered SQL substrings. An unproved shape
//! keeps the ordinary executor and its complete decoded pools.
use super::*;
use sqlparser::ast::{
    BinaryOperator, Expr, Function, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr,
    JoinConstraint, JoinOperator, OrderByKind, Query, Select, SelectItem, Statement, TableFactor,
    Value,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PoolMode {
    /// Every statement is a proven COUNT(*) identity join; no edges are read.
    CountOnly,
    /// Every statement reads only raw ID cells of a method-string relation.
    IdEdges,
    /// At least one statement may observe strings, types, protos, or metadata.
    Full,
}

/// All statements share one dataset. Elision is valid only when every query
/// proves that the skipped data cannot be observed, including later queries.
pub(super) fn pool_mode(sqls: &[String]) -> PoolMode {
    if sqls.is_empty() {
        return PoolMode::Full;
    }
    let mut all_count = true;
    for sql in sqls {
        let Ok(mut statements) =
            sqlparser::parser::Parser::parse_sql(&expressions::Dialect {}, sql)
        else {
            return PoolMode::Full;
        };
        if statements.len() != 1 {
            return PoolMode::Full;
        }
        let Statement::Query(query) = statements.remove(0) else {
            return PoolMode::Full;
        };
        if count_identity(&query).is_some() {
            continue;
        }
        all_count = false;
        if !id_edges(&query) {
            return PoolMode::Full;
        }
    }
    if all_count {
        PoolMode::CountOnly
    } else {
        PoolMode::IdEdges
    }
}

#[derive(Debug, Clone)]
pub(super) struct Plan {
    pub columns: Vec<String>,
}
fn plan(select: &Select) -> Plan {
    Plan {
        columns: select
            .projection
            .iter()
            .map(|item| match item {
                SelectItem::UnnamedExpr(expr) => expression_label(expr),
                SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                _ => String::new(),
            })
            .collect(),
    }
}

fn query_shape(query: &Query) -> Option<&Select> {
    if query.with.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return None;
    }
    let select = query.body.as_select()?;
    if select.distinct.is_some()
        || select.having.is_some()
        || select.prewhere.is_some()
        || select.top.is_some()
        || select.into.is_some()
        || select.exclude.is_some()
        || !select.lateral_views.is_empty()
        || !select.connect_by.is_empty()
        || !select.cluster_by.is_empty()
        || !select.distribute_by.is_empty()
        || !select.sort_by.is_empty()
        || !select.named_window.is_empty()
        || select.qualify.is_some()
        || select.value_table_mode.is_some()
        || select
            .select_modifiers
            .as_ref()
            .is_some_and(|modifiers| modifiers.is_any_set())
        || !matches!(&select.group_by,GroupByExpr::Expressions(exprs,modifiers) if exprs.is_empty()&&modifiers.is_empty())
    {
        return None;
    }
    Some(select)
}
fn table(factor: &TableFactor) -> Option<(String, String)> {
    let TableFactor::Table {
        name,
        alias,
        args,
        with_hints,
        version,
        with_ordinality,
        partitions,
        json_path,
        sample,
        index_hints,
    } = factor
    else {
        return None;
    };
    if name.0.len() != 1
        || args.is_some()
        || !with_hints.is_empty()
        || version.is_some()
        || *with_ordinality
        || !partitions.is_empty()
        || json_path.is_some()
        || sample.is_some()
        || !index_hints.is_empty()
        || alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return None;
    }
    let name = name.0[0].as_ident()?.value.to_ascii_lowercase();
    let alias = alias
        .as_ref()
        .map(|alias| alias.name.value.to_ascii_lowercase())
        .unwrap_or_else(|| name.clone());
    Some((name, alias))
}
fn row_source<'a>(select: &'a Select, relation: &str) -> Option<String> {
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    let (name, alias) = table(&select.from[0].relation)?;
    (name == relation).then_some(alias)
}
fn expr(item: &SelectItem) -> Option<&Expr> {
    match item {
        SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => Some(expr),
        _ => None,
    }
}
fn column(value: &Expr, name: &str, alias: &str, unqualified: bool) -> bool {
    match value {
        Expr::Nested(value) => column(value, name, alias, unqualified),
        Expr::Identifier(id) => unqualified && id.value.eq_ignore_ascii_case(name),
        Expr::CompoundIdentifier(ids) => {
            ids.len() == 2
                && ids[0].value.eq_ignore_ascii_case(alias)
                && ids[1].value.eq_ignore_ascii_case(name)
        }
        _ => false,
    }
}
fn order_column(value: &Expr, name: &str, alias: &str, select: &Select) -> bool {
    if let Expr::Identifier(id) = value {
        let mut matching = select.projection.iter().filter_map(|item| match item {
            SelectItem::ExprWithAlias { expr, alias }
                if alias.value.eq_ignore_ascii_case(&id.value) =>
            {
                Some(expr)
            }
            _ => None,
        });
        if let Some(expr) = matching.next() {
            return matching.next().is_none() && column(expr, name, alias, true);
        }
    }
    column(value, name, alias, true)
}

fn integer(expr: &Expr) -> Option<u64> {
    let Expr::Value(value) = expr else {
        return None;
    };
    let Value::Number(number, _) = &value.value else {
        return None;
    };
    number.parse().ok()
}
fn limit(query: &Query) -> Option<()> {
    use sqlparser::ast::LimitClause;
    let (take, offset) = match query.limit_clause.as_ref()? {
        LimitClause::LimitOffset {
            limit: Some(take),
            offset,
            limit_by,
        } if limit_by.is_empty() => (
            integer(take)?,
            match offset {
                Some(offset) => Some(integer(&offset.value)?),
                None => None,
            },
        ),
        LimitClause::OffsetCommaLimit { offset, limit } => {
            (integer(limit)?, Some(integer(offset)?))
        }
        _ => return None,
    };
    // The fallback grows only with real rows. Do not eagerly allocate a huge
    // heap merely because a legal LIMIT/OFFSET exceeds the dataset's size.
    let retained = take.checked_add(offset.unwrap_or(0))?.checked_mul(128)?;
    (retained <= MATERIALIZE_BUDGET_BYTES).then_some(())
}

fn orders(query: &Query) -> Option<&[sqlparser::ast::OrderByExpr]> {
    let order = query.order_by.as_ref()?;
    if order.interpolate.is_some() {
        return None;
    }
    let OrderByKind::Expressions(exprs) = &order.kind else {
        return None;
    };
    Some(exprs)
}
fn ascending(order: &sqlparser::ast::OrderByExpr) -> bool {
    order.options.sort != Some(sqlparser::ast::OrderBySort::Desc)
        && order.options.nulls_first.is_none()
}
fn scalar_args<'a>(function: &'a Function, name: &str, n: usize) -> Option<Vec<&'a Expr>> {
    if function.name.0.len() != 1
        || !function.name.0[0]
            .as_ident()?
            .value
            .eq_ignore_ascii_case(name)
        || function.over.is_some()
        || function.filter.is_some()
        || !function.within_group.is_empty()
        || function.null_treatment.is_some()
        || function.uses_odbc_syntax
        || !matches!(function.parameters, FunctionArguments::None)
    {
        return None;
    }
    let FunctionArguments::List(args) = &function.args else {
        return None;
    };
    if args.args.len() != n || args.duplicate_treatment.is_some() || !args.clauses.is_empty() {
        return None;
    }
    args.args
        .iter()
        .map(|arg| match arg {
            FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => Some(expr),
            _ => None,
        })
        .collect()
}
fn length(expr: &Expr, alias: &str) -> bool {
    let Expr::Function(function) = expr else {
        return false;
    };
    scalar_args(function, "length", 1).is_some_and(|args| column(args[0], "name", alias, true))
}
fn mod_filter(expr: &Expr, alias: &str) -> Option<(u32, u32)> {
    let Expr::BinaryOp {
        left,
        op: BinaryOperator::Eq,
        right,
    } = expr
    else {
        return None;
    };
    let parse = |value: &Expr, remainder: &Expr| {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Modulo,
            right,
        } = value
        else {
            return None;
        };
        if !column(left, "method_idx", alias, true) {
            return None;
        }
        let divisor = u32::try_from(integer(right)?).ok()?;
        if divisor == 0 {
            return None;
        }
        Some((divisor, u32::try_from(integer(remainder)?).ok()?))
    };
    parse(left, right).or_else(|| parse(right, left))
}

fn identity(query: &Query) -> Option<(&Select, String, String)> {
    let select = query_shape(query)?;
    if select.from.len() != 1 || select.from[0].joins.len() != 1 {
        return None;
    }
    let (left, la) = table(&select.from[0].relation)?;
    let join = &select.from[0].joins[0];
    let (right, ra) = table(&join.relation)?;
    if la == ra {
        return None;
    }
    let (ma, ea) = match (left.as_str(), right.as_str()) {
        ("methods", "method_strings") => (la, ra),
        ("method_strings", "methods") => (ra, la),
        _ => return None,
    };
    let (JoinOperator::Join(JoinConstraint::On(on)) | JoinOperator::Inner(JoinConstraint::On(on))) =
        &join.join_operator
    else {
        return None;
    };
    let mut atoms = Vec::new();
    flatten_and(on, &mut atoms);
    if let Some(selection) = &select.selection {
        flatten_and(selection, &mut atoms);
    }
    let mut found_file = false;
    let mut found_method = false;
    for atom in atoms {
        let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = atom
        else {
            return None;
        };
        let pair = |name| {
            column(left, name, &ma, false) && column(right, name, &ea, false)
                || column(right, name, &ma, false) && column(left, name, &ea, false)
        };
        if pair("file_id") {
            found_file = true;
        } else if pair("method_idx") {
            found_method = true;
        } else {
            return None;
        }
    }
    (found_file && found_method).then_some((select, ma, ea))
}
fn count_star(expr: &Expr) -> bool {
    let Expr::Function(function) = expr else {
        return false;
    };
    if function.name.0.len() != 1
        || !function.name.0[0]
            .as_ident()
            .is_some_and(|name| name.value.eq_ignore_ascii_case("count"))
        || function.over.is_some()
        || function.filter.is_some()
        || !function.within_group.is_empty()
        || function.null_treatment.is_some()
        || !matches!(function.parameters, FunctionArguments::None)
    {
        return false;
    }
    matches!(&function.args,FunctionArguments::List(args) if args.duplicate_treatment.is_none()&&args.clauses.is_empty()&&matches!(args.args.as_slice(),[FunctionArg::Unnamed(FunctionArgExpr::Wildcard)]))
}
pub(super) fn relation_count_shape(query: &Query) -> Option<Plan> {
    let select = query_shape(query)?;
    if query.order_by.is_some()
        || query.limit_clause.is_some()
        || select.projection.len() != 1
        || !count_star(expr(&select.projection[0])?)
    {
        return None;
    }
    Some(plan(select))
}
pub(super) fn count_identity(query: &Query) -> Option<Plan> {
    let (select, _, _) = identity(query)?;
    if query.order_by.is_some()
        || query.limit_clause.is_some()
        || select.projection.len() != 1
        || !count_star(expr(&select.projection[0])?)
    {
        return None;
    }
    Some(plan(select))
}
fn id_edges(query: &Query) -> bool {
    let Some(select) = query_shape(query) else {
        return false;
    };
    let aliases = if let Some((_, ma, ea)) = identity(query) {
        vec![(ma, "methods"), (ea, "method_strings")]
    } else if let Some(alias) = row_source(select, "method_strings") {
        vec![(alias, "method_strings")]
    } else {
        return false;
    };
    let permitted = |owner: &str, column: &str| match owner {
        "methods" => matches!(
            column,
            "file_id" | "method_idx" | "class_idx" | "name_idx" | "proto_idx"
        ),
        _ => matches!(
            column,
            "file_id" | "method_idx" | "class_idx" | "string_idx"
        ),
    };
    let mut allowed = true;
    let mut inspect = |value: &Expr| {
        let mut value = value.clone();
        if streaming::walk(&mut value, &mut |value| {
            match value {
                Expr::Identifier(id) => {
                    if !aliases
                        .iter()
                        .any(|(_, owner)| permitted(owner, &id.value.to_ascii_lowercase()))
                    {
                        allowed = false;
                    }
                }
                Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
                    if !aliases.iter().any(|(alias, owner)| {
                        ids[0].value.eq_ignore_ascii_case(alias)
                            && permitted(owner, &ids[1].value.to_ascii_lowercase())
                    }) {
                        allowed = false;
                    }
                }
                Expr::Function(function) if count_star(&Expr::Function(function.clone())) => {
                    return Some(true)
                }
                _ => {}
            }
            Some(false)
        })
        .is_none()
        {
            allowed = false;
        }
    };
    for item in &select.projection {
        let Some(value) = expr(item) else {
            return false;
        };
        inspect(value);
    }
    if let Some(value) = &select.selection {
        inspect(value);
    }
    if let Some(order) = &query.order_by {
        let OrderByKind::Expressions(exprs) = &order.kind else {
            return false;
        };
        for order in exprs {
            inspect(&order.expr);
        }
    }
    allowed
}

pub(super) fn identity_ordered_limit(query: &Query) -> Option<Plan> {
    let (select, ma, ea) = identity(query)?;
    if select.selection.is_some() || select.projection.len() != 3 {
        return None;
    }
    let expected = [(&ma, "file_id"), (&ma, "method_idx"), (&ea, "string_idx")];
    for (item, (alias, name)) in select.projection.iter().zip(expected) {
        if !column(expr(item)?, name, alias, false) {
            return None;
        }
    }
    let order = orders(query)?;
    if order.len() != 3 {
        return None;
    }
    for (entry, (alias, name)) in order.iter().zip(expected) {
        if !ascending(entry) || !column(&entry.expr, name, alias, false) {
            return None;
        }
    }
    limit(query)?;
    Some(plan(select))
}

pub(super) fn expression_topk(query: &Query) -> Option<Plan> {
    let select = query_shape(query)?;
    let alias = row_source(select, "methods")?;
    if select.projection.len() != 3 {
        return None;
    }
    mod_filter(select.selection.as_ref()?, &alias)?;
    for (item, name) in select
        .projection
        .iter()
        .take(2)
        .zip(["file_id", "method_idx"])
    {
        if !column(expr(item)?, name, &alias, true) {
            return None;
        }
    }
    if !length(expr(&select.projection[2])?, &alias) {
        return None;
    }
    let label = match &select.projection[2] {
        SelectItem::ExprWithAlias { alias, .. } => alias.value.as_str(),
        _ => "length",
    };
    let order = orders(query)?;
    if order.len() != 3
        || order[0].options.sort != Some(sqlparser::ast::OrderBySort::Desc)
        || order[0].options.nulls_first.is_some()
        || !column(&order[0].expr, label, "", true)
        || !ascending(&order[1])
        || !order_column(&order[1].expr, "file_id", &alias, select)
        || !ascending(&order[2])
        || !order_column(&order[2].expr, "method_idx", &alias, select)
    {
        return None;
    }
    limit(query)?;
    Some(plan(select))
}
pub(super) fn derived_name_topk(query: &Query) -> Option<Plan> {
    let select = query_shape(query)?;
    if select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || select.selection.is_some()
        || select.projection.len() != 3
    {
        return None;
    }
    let TableFactor::Derived {
        subquery,
        alias: Some(alias),
        lateral: false,
        ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if !alias.columns.is_empty() || subquery.order_by.is_some() || subquery.limit_clause.is_some() {
        return None;
    }
    let inner = query_shape(subquery)?;
    let ia = row_source(inner, "methods")?;
    if !matches!(inner.projection.as_slice(),[SelectItem::Wildcard(options)] if *options==Default::default())
    {
        return None;
    }
    if let Some(selection) = &inner.selection {
        mod_filter(selection, &ia)?;
    }
    let alias = &alias.name.value;
    for (item, name) in select
        .projection
        .iter()
        .zip(["file_id", "method_idx", "name"])
    {
        if !column(expr(item)?, name, alias, true) {
            return None;
        }
    }
    let order = orders(query)?;
    if order.len() != 3
        || order[0].options.sort != Some(sqlparser::ast::OrderBySort::Desc)
        || order[0].options.nulls_first.is_some()
        || !length(&order[0].expr, alias)
        || !order_column(
            &Expr::Identifier(sqlparser::ast::Ident::new("name")),
            "name",
            alias,
            select,
        )
        || !ascending(&order[1])
        || !order_column(&order[1].expr, "file_id", alias, select)
        || !ascending(&order[2])
        || !order_column(&order[2].expr, "method_idx", alias, select)
    {
        return None;
    }
    limit(query)?;
    Some(plan(select))
}
pub(super) fn string_predicate_limit(query: &Query) -> Option<Plan> {
    let select = query_shape(query)?;
    let alias = row_source(select, "methods")?;
    if select.projection.len() != 3 {
        return None;
    }
    for (item, name) in select
        .projection
        .iter()
        .zip(["file_id", "method_idx", "name"])
    {
        if !column(expr(item)?, name, &alias, true) {
            return None;
        }
    }
    let mut atoms = Vec::new();
    flatten_and(select.selection.as_ref()?, &mut atoms);
    if atoms.len() != 2 {
        return None;
    }
    let mut has_length = false;
    let mut has_initial = false;
    for atom in atoms {
        let Expr::BinaryOp { left, op, right } = atom else {
            return None;
        };
        if length(left, &alias) && *op == BinaryOperator::Gt {
            integer(right)?;
            has_length = true;
            continue;
        }
        if *op != BinaryOperator::Eq {
            return None;
        }
        let Expr::Function(lower) = left.as_ref() else {
            return None;
        };
        let args = scalar_args(lower, "lower", 1)?;
        match args[0] {
            Expr::Function(substr) => {
                let args = scalar_args(substr, "substr", 3)?;
                if !column(args[0], "name", &alias, true)
                    || integer(args[1]) != Some(1)
                    || integer(args[2]) != Some(1)
                {
                    return None;
                }
            }
            Expr::Substring {
                expr,
                substring_from: Some(start),
                substring_for: Some(take),
                ..
            } => {
                if !column(expr, "name", &alias, true)
                    || integer(start) != Some(1)
                    || integer(take) != Some(1)
                {
                    return None;
                }
            }
            _ => return None,
        }
        let Expr::Value(value) = right.as_ref() else {
            return None;
        };
        let Value::SingleQuotedString(expected) = &value.value else {
            return None;
        };
        let mut chars = expected.chars();
        let first = chars.next()?;
        // lower() is ASCII-only, and the right operand is compared literally.
        if chars.next().is_some() || first.is_ascii_uppercase() {
            return None;
        }
        has_initial = true;
    }
    if !has_length || !has_initial {
        return None;
    }
    let order = orders(query)?;
    if order.len() != 2 {
        return None;
    }
    for (entry, name) in order.iter().zip(["file_id", "method_idx"]) {
        if !ascending(entry) || !order_column(&entry.expr, name, &alias, select) {
            return None;
        }
    }
    limit(query)?;
    Some(plan(select))
}

/// A fast source scan may not bypass a session definition or installed table
/// with the same relation name. Apply this to the whole query before planning.
pub(super) fn unshadowed(query: &Query, caches: &NamedCaches) -> bool {
    if query.with.is_some() {
        return false;
    }
    fn factor(factor: &TableFactor, caches: &NamedCaches) -> bool {
        match factor {
            TableFactor::Table { name, .. } => {
                let Some(name) = name.0.last().and_then(|part| part.as_ident()) else {
                    return false;
                };
                let name = name.value.to_ascii_lowercase();
                !caches.has_definition(&name) && !caches.tables.borrow().contains_key(&name)
            }
            TableFactor::Derived { subquery, .. } => unshadowed(subquery, caches),
            _ => false,
        }
    }
    let Some(select) = query.body.as_select() else {
        return false;
    };
    select.from.iter().all(|from| {
        factor(&from.relation, caches)
            && from.joins.iter().all(|join| factor(&join.relation, caches))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(sql: &str) -> Query {
        let mut statements =
            sqlparser::parser::Parser::parse_sql(&expressions::Dialect {}, sql).unwrap();
        let Statement::Query(query) = statements.remove(0) else {
            panic!()
        };
        *query
    }
    fn mode(sql: &[&str]) -> PoolMode {
        pool_mode(&sql.iter().map(|sql| sql.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn pool_elision_is_a_proof_over_the_complete_batch() {
        let count="SELECT count(*) FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx";
        let ids="SELECT m.file_id,m.method_idx,s.string_idx FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.string_idx LIMIT 20";
        assert_eq!(mode(&[count]), PoolMode::CountOnly);
        assert_eq!(mode(&[count, ids]), PoolMode::IdEdges);
        assert_eq!(mode(&[ids, count]), PoolMode::IdEdges);
        for text in [
            "SELECT name FROM methods LIMIT 1",
            "SELECT s.method FROM method_strings s LIMIT 1",
            "SELECT * FROM method_strings LIMIT 1",
            "SELECT shorty FROM protos LIMIT 1",
            "SELECT descriptor FROM types LIMIT 1",
            "SELECT source_file FROM classes LIMIT 1",
            "SELECT value FROM strings LIMIT 1",
            "SELECT count(*) FROM method_calls",
            "SELECT count(*) FROM method_numbers",
            "SELECT count(*) FROM method_field_accesses",
            "SELECT count(*) FROM dex_files",
        ] {
            assert_eq!(mode(&[count, text]), PoolMode::Full, "{text}");
            assert_eq!(mode(&[text, count]), PoolMode::Full, "{text}");
            assert_eq!(mode(&[ids, text]), PoolMode::Full, "{text}");
        }
        assert_eq!(
            mode(&[
                "SELECT count(*) FROM methods m JOIN method_strings s ON m.method_idx=s.method_idx"
            ]),
            PoolMode::Full
        );
        assert_eq!(mode(&["SELECT count(*) FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx AND m.method_idx=0"]),PoolMode::Full);
        assert_eq!(mode(&["SELECT count(*) FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx WHERE 0"]),PoolMode::Full);
    }

    #[test]
    fn ordered_identity_guard_preserves_projection_aliases_and_rejects_extra_semantics() {
        let sql="SELECT m.file_id AS f,m.method_idx AS i,s.string_idx AS s FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.string_idx LIMIT 20";
        assert_eq!(
            identity_ordered_limit(&query(sql)).unwrap().columns,
            ["f", "i", "s"]
        );
        for sql in [
            sql.replace(" LIMIT 20", " LIMIT 20 OFFSET '1'"),
            sql.replace("JOIN method_strings s", "LEFT JOIN method_strings s"),
            sql.replace(
                "m.method_idx=s.method_idx",
                "m.method_idx=s.method_idx AND s.value='x'",
            ),
            sql.replace("ORDER BY m.file_id", "ORDER BY m.file_id DESC"),
            sql.replace("methods m", "methods m(a,b,c)"),
        ] {
            assert!(identity_ordered_limit(&query(&sql)).is_none(), "{sql}");
        }
    }

    #[test]
    fn derived_guard_does_not_erase_inner_limit_offset_or_zero_modulus() {
        let sql="SELECT file_id AS f,method_idx AS i,name AS text FROM (SELECT * FROM methods WHERE method_idx%97=0) q ORDER BY length(name) DESC,file_id,method_idx LIMIT 20";
        assert_eq!(
            derived_name_topk(&query(sql)).unwrap().columns,
            ["f", "i", "text"]
        );
        for sql in [
            sql.replace("method_idx%97=0)", "method_idx%97=0 LIMIT 1)"),
            sql.replace(
                "method_idx%97=0)",
                "method_idx%97=0 ORDER BY method_idx DESC)",
            ),
            sql.replace("method_idx%97=0)", "method_idx%97=0 LIMIT 9 OFFSET 2)"),
            sql.replace("method_idx%97=0", "method_idx%0=0"),
            sql.replace(") q ORDER", ") q(a,b,c) ORDER"),
        ] {
            assert!(derived_name_topk(&query(&sql)).is_none(), "{sql}");
        }
    }

    #[test]
    fn expression_topk_requires_real_output_alias_and_exact_function_shape() {
        let sql="SELECT file_id AS f,method_idx AS i,length(name) AS size FROM methods WHERE method_idx%7=0 ORDER BY size DESC,file_id,method_idx LIMIT 20";
        assert_eq!(
            expression_topk(&query(sql)).unwrap().columns,
            ["f", "i", "size"]
        );
        for sql in [
            sql.replace("ORDER BY size DESC", "ORDER BY n DESC"),
            sql.replace("length(name)", "length(DISTINCT name)"),
            sql.replace("method_idx%7=0", "method_idx%0=0"),
            sql.replace(
                "file_id AS f,method_idx AS i",
                "file_id AS method_idx,method_idx AS file_id",
            ),
            sql.replace("LIMIT 20", "LIMIT 9223372036854775807"),
            sql.replace("methods WHERE", "methods(a,b,c) WHERE"),
        ] {
            assert!(expression_topk(&query(&sql)).is_none(), "{sql}");
        }
    }

    #[test]
    fn string_predicate_guard_checks_projected_cells_and_whole_expected_character() {
        let sql="SELECT file_id AS f,method_idx AS i,name AS text FROM methods WHERE length(name)>24 AND lower(substr(name,1,1))='o' ORDER BY file_id,method_idx LIMIT 20";
        assert_eq!(
            string_predicate_limit(&query(sql)).unwrap().columns,
            ["f", "i", "text"]
        );
        for sql in [
            sql.replace("name AS text", "42 AS text"),
            sql.replace("='o'", "='other'"),
            sql.replace("='o'", "='O'"),
            sql.replace(
                "lower(substr(name,1,1))",
                "lower(substr(name,1,1),'ignored')",
            ),
            sql.replace("length(name)", "length(DISTINCT name)"),
            sql.replace("LIMIT 20", "LIMIT 20 OFFSET 1.0"),
        ] {
            assert!(string_predicate_limit(&query(&sql)).is_none(), "{sql}");
        }
    }

    #[test]
    fn session_sources_cannot_be_bypassed_by_a_physical_method_scan() {
        let query=query("SELECT file_id,method_idx,length(name) AS n FROM methods WHERE method_idx%7=0 ORDER BY n DESC,file_id,method_idx LIMIT 20");
        let caches = NamedCaches::default();
        assert!(unshadowed(&query, &caches));
        caches
            .define_session(
                "methods",
                "SELECT 1 AS file_id,2 AS method_idx,'text' AS name",
                false,
            )
            .unwrap();
        assert!(!unshadowed(&query, &caches));
    }

    #[test]
    fn loader_count_mode_never_suppresses_another_reference_relation() {
        let count="SELECT count(*) FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx";
        let ids="SELECT m.file_id,m.method_idx,s.string_idx FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.string_idx LIMIT 5";
        let (needs, _, _, _, _) = super::super::query_load_options(&[count.to_owned()]);
        assert!(needs.method_string_count_only);
        assert!(!needs.method_strings);
        for batch in [[count, ids], [ids, count]] {
            let (needs, _, _, _, _) = super::super::query_load_options(&batch.map(str::to_owned));
            assert!(!needs.method_string_count_only);
            assert!(needs.method_strings && needs.method_strings_no_pools);
        }
        for text in [
            "SELECT name FROM methods LIMIT 1",
            "SELECT value FROM method_strings LIMIT 1",
            "SELECT count(*) FROM method_calls",
            "SELECT count(*) FROM method_numbers",
        ] {
            for batch in [[count, text], [text, count]] {
                let (needs, _, _, _, _) =
                    super::super::query_load_options(&batch.map(str::to_owned));
                assert!(
                    !needs.method_string_count_only && !needs.method_strings_no_pools,
                    "{batch:?}"
                );
                assert!(needs.method_strings, "{batch:?}");
                if text.contains("method_calls") {
                    assert!(needs.method_calls);
                }
                if text.contains("method_numbers") {
                    assert!(needs.method_numbers);
                }
            }
        }
    }

    #[test]
    fn guarded_execution_preserves_aliases_and_declines_wrong_fast_projections() {
        let ds = Dataset::load_paths(&[
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/beta.dex"),
        ])
        .unwrap();
        for sql in [
            "SELECT m.file_id AS f,m.method_idx AS i,s.string_idx AS v FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.string_idx LIMIT 5",
            "SELECT file_id AS f,method_idx AS i,length(name) AS size FROM methods WHERE method_idx%7=0 ORDER BY size DESC,file_id,method_idx LIMIT 5",
            "SELECT file_id AS f,method_idx AS i,name AS text FROM methods WHERE length(name)>1 AND lower(substr(name,1,1))='a' ORDER BY file_id,method_idx LIMIT 5",
            "SELECT file_id,method_idx,42 AS text FROM methods WHERE length(name)>1 AND lower(substr(name,1,1))='a' ORDER BY file_id,method_idx LIMIT 5",
            "SELECT file_id,method_idx,name FROM (SELECT * FROM methods WHERE method_idx%7=0 LIMIT 1) q ORDER BY length(name) DESC,file_id,method_idx LIMIT 5",
        ] {
            let query=query(sql);
            let mut expected=execute_select_core(query.body.as_select().unwrap(),&ds,Some(&ds),&NamedCaches::default(),true,None,None).unwrap();
            apply_query_order_limit(&mut expected,&query,None).unwrap();
            let expected=typed_to_result((expected.columns,expected.rows.into_iter().map(|row|row.values).collect()));
            let actual=execute_statement(sql,Some(&ds),&NamedCaches::default(),None).unwrap();
            assert_eq!(actual.columns,expected.columns,"{sql}");
            assert_eq!(actual.rows,expected.rows,"{sql}");
        }
    }

    #[test]
    fn qualified_wildcard_uses_its_own_schema_order_even_when_empty() {
        let ds = Dataset::load_paths(&[
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/beta.dex"),
        ])
        .unwrap();
        let expected = [
            "method",
            "method_class",
            "method_name",
            "value",
            "file_id",
            "class_idx",
            "method_idx",
            "string_idx",
        ]
        .map(str::to_owned)
        .to_vec();
        for sql in [
            "SELECT s.* FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY s.file_id,s.method_idx,s.string_idx LIMIT 5",
            "SELECT s.* FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx WHERE m.method_idx<0",
            "WITH edge AS (SELECT * FROM method_strings WHERE method_idx<0) SELECT s.* FROM methods m JOIN edge s ON m.file_id=s.file_id AND m.method_idx=s.method_idx",
        ] {
            let result=execute_statement(sql,Some(&ds),&NamedCaches::default(),None).unwrap();
            assert_eq!(result.columns,expected,"{sql}");
            if sql.contains("<0"){assert!(result.rows.is_empty());}else{assert_eq!(result.rows.len(),5);}
        }
        let sql="SELECT empty.* FROM (SELECT 1 AS second,'value' AS first WHERE 0 LIMIT 0) empty JOIN methods m ON empty.second=m.method_idx";
        let result = execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap();
        assert_eq!(result.columns, ["second", "first"]);
        assert!(result.rows.is_empty());
    }
}
