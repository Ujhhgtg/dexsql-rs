//! Hash decorrelation for equality-correlated subqueries.
//! Inner rows stream once into compact keys, value sets, or aggregate states.
use super::{
    charge_materialized, eval_bool, eval_scalar, membership, streaming, Dataset, NamedCaches,
    RelRow, Scalar,
};
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr, Ident,
    Query, SelectItem, TableFactor,
};
use sqlparser::tokenizer::{Token, Tokenizer};
use std::collections::{HashMap, HashSet};

fn unsupported(reason: &str) -> String {
    format!("unsupported correlated EXISTS/subquery: {reason}")
}

struct Plan {
    table: String,
    alias: String,
    schema: &'static crate::sql::schema::TableMeta,
    inner_keys: Vec<String>,
    outer_keys: Vec<Expr>,
    local: Option<Expr>,
    requested: HashSet<String>,
}
impl Plan {
    fn columns(&self) -> Vec<&str> {
        self.schema
            .columns
            .iter()
            .map(|column| column.name)
            .filter(|column| self.requested.contains(*column))
            .collect()
    }
    #[inline]
    fn key(&self, row: &RelRow) -> Option<membership::KeyTuple> {
        membership::KeyTuple::from_options(
            self.inner_keys
                .iter()
                .map(|column| row.get(column).and_then(membership::key)),
        )
    }
    fn accepts(&self, row: &RelRow) -> Result<bool, String> {
        self.local
            .as_ref()
            .map_or(Ok(true), |local| eval_bool(local, row, &[]))
    }
}

/// `None` leaves uncorrelated or non-streamable queries to the ordinary
/// bounded executor; correlated unsupported shapes fail before scanning.
fn plan(
    query: &Query,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    caches: &NamedCaches,
    allow_uncorrelated: bool,
) -> Result<Option<Plan>, String> {
    let select = query.body.as_select();
    let shadowed = select
        .map(|select| {
            select
                .from
                .iter()
                .flat_map(|from| {
                    std::iter::once(&from.relation)
                        .chain(from.joins.iter().map(|join| &join.relation))
                })
                .map(|factor| super::factor_alias(factor).to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let correlated = mentions_outer(query, outer_aliases, &shadowed)?;
    if !correlated && !allow_uncorrelated {
        return Ok(None);
    }
    let unsupported_shape =
        || unsupported("requires a single ungrouped streaming table without LIMIT/OFFSET");
    let Some(select) = select else {
        return if correlated {
            Err(unsupported_shape())
        } else {
            Ok(None)
        };
    };
    let plain = query.with.is_none()
        && query.limit_clause.is_none()
        && query.fetch.is_none()
        && query.locks.is_empty()
        && query.for_clause.is_none()
        && query.settings.is_none()
        && query.format_clause.is_none()
        && query.pipe_operators.is_empty()
        && select.from.len() == 1
        && select.from[0].joins.is_empty()
        && select.prewhere.is_none()
        && select.having.is_none()
        && select.top.is_none()
        && select.into.is_none()
        && select.lateral_views.is_empty()
        && select.connect_by.is_empty()
        && select.cluster_by.is_empty()
        && select.distribute_by.is_empty()
        && select.sort_by.is_empty()
        && select.named_window.is_empty()
        && select.qualify.is_none()
        && select.value_table_mode.is_none()
        && matches!(&select.group_by, GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty());
    if !plain {
        return if correlated {
            Err(unsupported_shape())
        } else {
            Ok(None)
        };
    }
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
    } = &select.from[0].relation
    else {
        return if correlated {
            Err(unsupported_shape())
        } else {
            Ok(None)
        };
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
        return if correlated {
            Err(unsupported_shape())
        } else {
            Ok(None)
        };
    }
    let table = name.0[0]
        .as_ident()
        .ok_or_else(unsupported_shape)?
        .value
        .to_ascii_lowercase();
    if !streaming::supports_table(&table)
        || caches.has_definition(&table)
        || caches.tables.borrow().contains_key(&table)
    {
        return if correlated {
            Err(unsupported_shape())
        } else {
            Ok(None)
        };
    }
    let alias = alias
        .as_ref()
        .map(|alias| alias.name.value.to_ascii_lowercase())
        .unwrap_or_else(|| table.clone());
    let schema = crate::sql::schema::TABLES
        .iter()
        .find(|schema| schema.name == table)
        .ok_or_else(unsupported_shape)?;
    let mut plan = Plan {
        table,
        alias,
        schema,
        inner_keys: Vec::new(),
        outer_keys: Vec::new(),
        local: None,
        requested: HashSet::new(),
    };
    let mut atoms = Vec::new();
    if let Some(selection) = &select.selection {
        conjuncts(selection, &mut atoms);
    }
    let mut local = Vec::new();
    for atom in atoms {
        if let Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } = atom
        {
            let pair = inner_column(left, &plan.alias, schema)
                .zip(outer_column(right, outer_aliases, &shadowed))
                .or_else(|| {
                    inner_column(right, &plan.alias, schema).zip(outer_column(
                        left,
                        outer_aliases,
                        &shadowed,
                    ))
                });
            if let Some((column, outer)) = pair {
                plan.requested.insert(column.clone());
                plan.inner_keys.push(column);
                plan.outer_keys.push(outer.clone());
                continue;
            }
        }
        // Recursively build nested semijoins while this temporary registry
        // scope remains live for the parent inner-table scan.
        let atom = super::desugar_expr(
            atom,
            ds,
            source_dataset,
            caches,
            &HashSet::from([plan.alias.clone()]),
        )?;
        collect_local(&atom, &plan.alias, schema, &mut plan.requested)?;
        local.push(atom);
    }
    if correlated && plan.inner_keys.is_empty() {
        return Err(unsupported(
            "requires an inner-column = outer-column equality",
        ));
    }
    plan.local = local.into_iter().reduce(|left, right| Expr::BinaryOp {
        left: Box::new(left),
        op: BinaryOperator::And,
        right: Box::new(right),
    });
    if let Some(local) = &mut plan.local {
        streaming::walk(local, &mut |expr| {
            membership::Scope::compile_current(expr);
            Some(false)
        })
        .ok_or_else(|| unsupported("unsupported local predicate"))?;
    }
    Ok(Some(plan))
}

pub(super) fn exists(
    query: &Query,
    negated: bool,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    if let Some(result) = fallback_correlated_exists(query, negated, outer_aliases, ds, caches)? {
        return Ok(Some(result));
    }
    let built = {
        let _scope = membership::Scope::new();
        let Some(plan) = plan(query, outer_aliases, ds, None, caches, false)? else {
            return Ok(None);
        };
        if query
            .body
            .as_select()
            .unwrap()
            .projection
            .iter()
            .any(|item| match item {
                SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                    has_aggregate(expr)
                }
                _ => false,
            })
        {
            // An ungrouped aggregate produces one row even when the correlated
            // filter matches none. EXISTS never evaluates projection values.
            return Ok(Some(super::scalar_literal(Scalar::Int(!negated as i64))));
        }
        let keys = if let Some(keys) = direct_method_string_keys(&plan, ds)? {
            keys
        } else {
            let mut keys = HashSet::new();
            let mut bytes = 0u64;
            streaming::visit_source(ds, &plan.table, &plan.alias, &plan.columns(), None, |row| {
                if !plan.accepts(row)? {
                    return Ok(false);
                }
                if let Some(key) = plan.key(row) {
                    let added = key_tuple_size(&key);
                    if keys.insert(key) {
                        bytes += added;
                        charge_materialized(bytes)?;
                    }
                }
                Ok(false)
            })?;
            keys
        };
        (keys, plan.outer_keys)
    };
    Ok(Some(membership::register_rows(built.0, negated, built.1)))
}

/// Decorrelate a one-source CTE/derived EXISTS by replacing its ignored
/// projection with the correlation keys and executing that source once. This
/// keeps the same hash semijoin registry as native table scans while allowing
/// relational views to participate without a per-outer-row reopen.
fn fallback_correlated_exists(
    query: &Query,
    negated: bool,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    let Some(select) = query.body.as_select() else {
        return Ok(None);
    };
    if query.limit_clause.is_some()
        || query.order_by.is_some()
        || select.from.len() != 1
        || select.from[0].joins.len() != 0
        || !matches!(&select.group_by, GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty())
    {
        return Ok(None);
    }
    // Native streaming tables already have the compact one-pass plan below.
    // This fallback is only for CTE/materialized names and derived relations;
    // reopening a built-in table through execute_query_rows would retain every
    // projected row and erase the memory advantage of decorrelation.
    if let TableFactor::Table { name, .. } = &select.from[0].relation {
        if let Some(table) = name.0.last().and_then(|part| part.as_ident()) {
            let table = table.value.to_ascii_lowercase();
            if streaming::supports_table(&table)
                && !caches.has_definition(&table)
                && !caches.tables.borrow().contains_key(&table)
            {
                return Ok(None);
            }
        }
    }
    let alias_name = match &select.from[0].relation {
        TableFactor::Derived {
            alias: Some(alias), ..
        } => alias.name.value.to_ascii_lowercase(),
        TableFactor::Table { name, alias, .. } => alias
            .as_ref()
            .map(|alias| alias.name.value.to_ascii_lowercase())
            .or_else(|| {
                name.0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(|ident| ident.value.to_ascii_lowercase())
            })
            .unwrap_or_default(),
        _ => return Ok(None),
    };
    if outer_aliases.contains(&alias_name) {
        return Ok(None);
    }
    let Some(selection) = &select.selection else {
        return Ok(None);
    };
    let mut atoms = Vec::new();
    conjuncts(selection, &mut atoms);
    let mut key_columns = Vec::new();
    let mut outer_keys = Vec::new();
    let mut local = Vec::new();
    for atom in atoms {
        let pair = match atom {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => generic_inner_outer_pair(left, right, &alias_name, outer_aliases)
                .or_else(|| generic_inner_outer_pair(right, left, &alias_name, outer_aliases)),
            _ => None,
        };
        if let Some((inner, outer)) = pair {
            key_columns.push(inner);
            outer_keys.push(outer);
        } else {
            if expr_mentions_outer(atom, outer_aliases)? {
                return Err(unsupported("outer reference outside equality correlation"));
            }
            local.push(atom.clone());
        }
    }
    if key_columns.is_empty() {
        return Ok(None);
    }
    let mut rewritten = query.clone();
    let select = match rewritten.body.as_mut() {
        sqlparser::ast::SetExpr::Select(select) => select,
        _ => return Err(unsupported("derived correlation body")),
    };
    select.selection = local.into_iter().reduce(|left, right| Expr::BinaryOp {
        left: Box::new(left),
        op: BinaryOperator::And,
        right: Box::new(right),
    });
    select.projection = key_columns
        .iter()
        .enumerate()
        .map(|(index, column)| SelectItem::ExprWithAlias {
            expr: column.clone(),
            alias: Ident::new(format!("__dexsql_key{index}")),
        })
        .collect();
    let (_columns, rows) =
        super::execute_query_rows(&rewritten, ds, Some(ds), caches, None, false)?;
    let mut keys = HashSet::new();
    let mut bytes = 0u64;
    for row in rows {
        let Some(key) = membership::KeyTuple::from_options(row.iter().map(membership::key)) else {
            continue;
        };
        if keys.insert(key.clone()) {
            bytes += key_tuple_size(&key);
            charge_materialized(bytes)?;
        }
    }
    Ok(Some(membership::register_rows(keys, negated, outer_keys)))
}

fn generic_inner_outer_pair<'a>(
    inner: &'a Expr,
    outer: &'a Expr,
    alias: &str,
    outer_aliases: &HashSet<String>,
) -> Option<(Expr, Expr)> {
    let Expr::CompoundIdentifier(parts) = inner else {
        return None;
    };
    if parts.len() != 2 || !parts[0].value.eq_ignore_ascii_case(alias) {
        return None;
    }
    let Expr::CompoundIdentifier(parts) = outer else {
        return None;
    };
    if parts.len() != 2 || !outer_aliases.contains(&parts[0].value.to_ascii_lowercase()) {
        return None;
    }
    Some((inner.clone(), outer.clone()))
}

/// The method-string relation is already a compact edge array in the cache.
/// When EXISTS only asks for its two integer join columns, bypassing generic
/// RelRow/Cells construction and heap merge is both faster and lower-retained.
fn direct_method_string_keys(
    plan: &Plan,
    ds: &Dataset,
) -> Result<Option<HashSet<membership::KeyTuple>>, String> {
    if plan.table != "method_strings" || plan.local.is_some() || plan.inner_keys.is_empty() {
        return Ok(None);
    }
    if plan.inner_keys.iter().any(|column| {
        !column.eq_ignore_ascii_case("file_id") && !column.eq_ignore_ascii_case("method_idx")
    }) {
        return Ok(None);
    }
    let mut keys = HashSet::new();
    let mut bytes = 0u64;
    for file in &ds.files {
        for reference in &file.method_strings {
            let key = membership::KeyTuple::from_options(plan.inner_keys.iter().map(|column| {
                if column.eq_ignore_ascii_case("file_id") {
                    Some(membership::Key::Int(file.file_id as i64))
                } else {
                    Some(membership::Key::Int(reference.method_idx as i64))
                }
            }))
            .ok_or_else(|| unsupported("NULL method-string correlation key"))?;
            let added = key_tuple_size(&key);
            if keys.insert(key) {
                bytes += added;
                charge_materialized(bytes)?;
            }
        }
    }
    Ok(Some(keys))
}

pub(super) fn in_subquery(
    query: &Query,
    value: Expr,
    negated: bool,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    if one_projection(query).is_ok_and(has_aggregate) {
        if let Some(scalar) = scalar(query, outer_aliases, ds, source_dataset, caches)? {
            // Ungrouped aggregate subqueries have exactly one value per outer
            // key, including their empty-input default (COUNT=0, MAX=NULL).
            return Ok(Some(Expr::InList {
                expr: Box::new(value),
                list: vec![scalar],
                negated,
            }));
        }
        return Ok(None);
    }
    let built = {
        let _scope = membership::Scope::new();
        let Some(mut plan) = plan(query, outer_aliases, ds, source_dataset, caches, true)? else {
            return Ok(None);
        };
        let projection = one_projection(query)?;
        let projection = super::desugar_expr(
            projection,
            ds,
            source_dataset,
            caches,
            &HashSet::from([plan.alias.clone()]),
        )?;
        if let Err(error) =
            collect_local(&projection, &plan.alias, plan.schema, &mut plan.requested)
        {
            return if plan.outer_keys.is_empty() {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let mut groups = HashMap::<membership::KeyTuple, membership::Values>::new();
        let mut bytes = 0u64;
        streaming::visit_source(ds, &plan.table, &plan.alias, &plan.columns(), None, |row| {
            if !plan.accepts(row)? {
                return Ok(false);
            }
            if let Some(key) = plan.key(row) {
                let key_bytes = key_tuple_size(&key);
                let values = groups.entry(key).or_insert_with(|| {
                    bytes += key_bytes + 64;
                    membership::Values::default()
                });
                bytes += values.insert(eval_scalar(&projection, row, &[])?);
                charge_materialized(bytes)?;
            }
            Ok(false)
        })?;
        (groups, plan.outer_keys)
    };
    Ok(Some(membership::register_membership(
        built.0, negated, built.1, value,
    )))
}

fn has_aggregate(expr: &Expr) -> bool {
    let mut expression = expr.clone();
    let mut found = false;
    let _ = streaming::walk(&mut expression, &mut |expr| {
        if let Expr::Function(function) = expr {
            if function.over.is_none() {
                let name = function
                    .name
                    .0
                    .last()?
                    .as_ident()?
                    .value
                    .to_ascii_lowercase();
                let arity = match &function.args {
                    FunctionArguments::List(args) => args.args.len(),
                    _ => 0,
                };
                if matches!(
                    name.as_str(),
                    "count" | "sum" | "total" | "avg" | "group_concat" | "string_agg"
                ) || matches!(name.as_str(), "min" | "max") && arity == 1
                {
                    found = true;
                    return Some(true);
                }
            }
        }
        Some(false)
    });
    found
}

fn one_projection(query: &Query) -> Result<&Expr, String> {
    let projection = &query
        .body
        .as_select()
        .ok_or_else(|| unsupported("set projection"))?
        .projection;
    let [SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. }] =
        projection.as_slice()
    else {
        return Err(unsupported(
            "expression subquery must project exactly one expression",
        ));
    };
    Ok(expr)
}

fn key_tuple_size(key: &membership::KeyTuple) -> u64 {
    64 + key.retained_bytes()
}

#[derive(Clone)]
struct Aggregate {
    name: String,
    argument: Option<Expr>,
    distinct: bool,
}
struct State {
    count: u64,
    sum: f64,
    all_int: bool,
    extreme: Option<Scalar>,
    seen: Option<HashSet<membership::Key>>,
}
impl State {
    fn new(aggregate: &Aggregate) -> Self {
        Self {
            count: 0,
            sum: 0.0,
            all_int: true,
            extreme: None,
            seen: aggregate.distinct.then(HashSet::new),
        }
    }
    fn update(&mut self, aggregate: &Aggregate, row: &RelRow) -> Result<u64, String> {
        let value = aggregate
            .argument
            .as_ref()
            .map_or(Ok(Scalar::Int(1)), |expr| eval_scalar(expr, row, &[]))?;
        if matches!(value, Scalar::Null) {
            return Ok(0);
        }
        let mut bytes = 0;
        if let Some(seen) = &mut self.seen {
            let key = membership::set_key(&value);
            bytes = membership::key_bytes(&key) + 32;
            if !seen.insert(key) {
                return Ok(0);
            }
        }
        self.count += 1;
        match aggregate.name.as_str() {
            "count" => {}
            "sum" | "total" | "avg" => {
                self.sum += value.numeric().unwrap_or(0.0);
                self.all_int &= matches!(value, Scalar::Int(_));
            }
            "min" | "max" => {
                if self.extreme.as_ref().is_none_or(|old| {
                    let order = super::compare_scalar(&value, old);
                    if aggregate.name == "min" {
                        order.is_lt()
                    } else {
                        order.is_gt()
                    }
                }) {
                    self.extreme = Some(value);
                }
            }
            _ => unreachable!(),
        }
        Ok(bytes)
    }
    fn finish(&self, aggregate: &Aggregate) -> Scalar {
        match aggregate.name.as_str() {
            "count" => Scalar::Int(self.count as i64),
            "min" | "max" => self.extreme.clone().unwrap_or(Scalar::Null),
            "total" => super::scalar_functions::real_scalar(self.sum),
            _ if self.count == 0 => Scalar::Null,
            "sum" if self.all_int => Scalar::Int(self.sum as i64),
            "sum" => super::scalar_functions::real_scalar(self.sum),
            "avg" => super::aggregate_real_scalar(self.sum / self.count as f64),
            _ => unreachable!(),
        }
    }
}

pub(super) fn scalar(
    query: &Query,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    if let Some(result) = scalar_ordered_limit(query, outer_aliases, ds, source_dataset, caches)? {
        return Ok(Some(result));
    }
    let built = {
        let _scope = membership::Scope::new();
        let Some(mut plan) = plan(query, outer_aliases, ds, source_dataset, caches, false)? else {
            return Ok(None);
        };
        let mut projection = super::desugar_expr(
            one_projection(query)?,
            ds,
            source_dataset,
            caches,
            &HashSet::from([plan.alias.clone()]),
        )?;
        let mut aggregates = Vec::new();
        streaming::walk(&mut projection, &mut |expr| {
            let Expr::Function(function) = expr else {
                return Some(false);
            };
            let name = function
                .name
                .0
                .last()?
                .as_ident()?
                .value
                .to_ascii_lowercase();
            let FunctionArguments::List(args) = &function.args else {
                return None;
            };
            let aggregate = matches!(name.as_str(), "count" | "sum" | "total" | "avg")
                || matches!(name.as_str(), "min" | "max") && args.args.len() == 1;
            if !aggregate {
                return Some(false);
            }
            if args.args.len() != 1
                || !args.clauses.is_empty()
                || function.over.is_some()
                || function.filter.is_some()
                || !function.within_group.is_empty()
            {
                return None;
            }
            let argument = match &args.args[0] {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => Some(expr.clone()),
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard) if name == "count" => None,
                _ => return None,
            };
            if let Some(argument) = &argument {
                collect_local(argument, &plan.alias, plan.schema, &mut plan.requested).ok()?;
            }
            let index = aggregates.len();
            aggregates.push(Aggregate {
                name,
                argument,
                distinct: args.duplicate_treatment
                    == Some(sqlparser::ast::DuplicateTreatment::Distinct),
            });
            *expr = Expr::Identifier(Ident::new(format!("\0aggregate{index}")));
            Some(true)
        })
        .ok_or_else(|| unsupported("unsupported scalar aggregate expression"))?;
        if aggregates.is_empty() {
            if query.order_by.is_some() {
                return Err(unsupported("ordered correlated scalar projection"));
            }
            collect_local(&projection, &plan.alias, plan.schema, &mut plan.requested)?;
            let mut groups = HashMap::new();
            let mut bytes = 0;
            streaming::visit_source(ds, &plan.table, &plan.alias, &plan.columns(), None, |row| {
                if !plan.accepts(row)? {
                    return Ok(false);
                }
                if let Some(key) = plan.key(row) {
                    if let std::collections::hash_map::Entry::Vacant(entry) = groups.entry(key) {
                        bytes += key_tuple_size(entry.key()) + 64;
                        entry.insert(eval_scalar(&projection, row, &[])?);
                        charge_materialized(bytes)?;
                    }
                }
                Ok(false)
            })?;
            (groups, Scalar::Null, plan.outer_keys)
        } else {
            // Aggregates each keep one state per correlation group, even when
            // the same inner relation is probed by millions of outer rows.
            let mut groups = HashMap::<membership::KeyTuple, Vec<State>>::new();
            let mut bytes = 0;
            streaming::visit_source(ds, &plan.table, &plan.alias, &plan.columns(), None, |row| {
                if !plan.accepts(row)? {
                    return Ok(false);
                }
                if let Some(key) = plan.key(row) {
                    let key_bytes = key_tuple_size(&key);
                    let states = groups.entry(key).or_insert_with(|| {
                        bytes += key_bytes + aggregates.len() as u64 * 128;
                        aggregates.iter().map(State::new).collect()
                    });
                    for (state, aggregate) in states.iter_mut().zip(&aggregates) {
                        bytes += state.update(aggregate, row)?;
                    }
                    charge_materialized(bytes)?;
                }
                Ok(false)
            })?;
            let finish = |states: &[State]| -> Result<Scalar, String> {
                let mut row = RelRow::default();
                for (index, (state, aggregate)) in states.iter().zip(&aggregates).enumerate() {
                    row.put("", &format!("\0aggregate{index}"), state.finish(aggregate));
                }
                eval_scalar(&projection, &row, &[])
            };
            let default = finish(&aggregates.iter().map(State::new).collect::<Vec<_>>())?;
            let groups = groups
                .into_iter()
                .map(|(key, states)| Ok((key, finish(&states)?)))
                .collect::<Result<HashMap<_, _>, String>>()?;
            (groups, default, plan.outer_keys)
        }
    };
    Ok(Some(membership::register_scalars(
        built.0, built.1, built.2,
    )))
}

fn scalar_ordered_limit(
    query: &Query,
    outer_aliases: &HashSet<String>,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    caches: &NamedCaches,
) -> Result<Option<Expr>, String> {
    if super::query_limit_value(query.limit_clause.as_ref()) != Some(1) {
        return Ok(None);
    }
    let Some(order) = &query.order_by else {
        return Ok(None);
    };
    let sqlparser::ast::OrderByKind::Expressions(order_items) = &order.kind else {
        return Ok(None);
    };
    if order_items.len() != 1 || query.body.as_select().is_none() {
        return Ok(None);
    }
    let select = query.body.as_select().unwrap();
    if select.from.len() != 1 || !select.from[0].joins.is_empty() || select.projection.len() != 1 {
        return Ok(None);
    }
    let TableFactor::Table { name, alias, .. } = &select.from[0].relation else {
        return Ok(None);
    };
    let table = name
        .0
        .last()
        .and_then(|part| part.as_ident())
        .map(|id| id.value.to_ascii_lowercase())
        .unwrap_or_default();
    if !streaming::supports_table(&table) || caches.has_definition(&table) {
        return Ok(None);
    }
    let alias_name = alias
        .as_ref()
        .map(|alias| alias.name.value.to_ascii_lowercase())
        .unwrap_or_else(|| table.clone());
    let schema = crate::sql::schema::TABLES
        .iter()
        .find(|schema| schema.name == table)
        .ok_or_else(|| unsupported("missing ordered scalar schema"))?;
    let Some(selection) = &select.selection else {
        return Ok(None);
    };
    let mut atoms = Vec::new();
    conjuncts(selection, &mut atoms);
    let mut inner_keys = Vec::new();
    let mut outer_keys = Vec::new();
    let mut local = Vec::new();
    for atom in atoms {
        let pair = match atom {
            Expr::BinaryOp {
                left,
                op: BinaryOperator::Eq,
                right,
            } => inner_column(left, &alias_name, schema)
                .zip(outer_column(right, outer_aliases, &HashSet::new()))
                .map(|(column, outer)| {
                    (
                        Expr::CompoundIdentifier(vec![
                            Ident::new(alias_name.clone()),
                            Ident::new(column),
                        ]),
                        outer.clone(),
                    )
                })
                .or_else(|| {
                    inner_column(right, &alias_name, schema)
                        .zip(outer_column(left, outer_aliases, &HashSet::new()))
                        .map(|(column, outer)| {
                            (
                                Expr::CompoundIdentifier(vec![
                                    Ident::new(alias_name.clone()),
                                    Ident::new(column),
                                ]),
                                outer.clone(),
                            )
                        })
                }),
            _ => None,
        };
        if let Some((inner, outer)) = pair {
            inner_keys.push(inner);
            outer_keys.push(outer);
        } else {
            local.push(atom.clone());
        }
    }
    if inner_keys.is_empty() {
        return Ok(None);
    }
    let value_expr = super::item_expr(&select.projection[0])
        .cloned()
        .ok_or_else(|| unsupported("ordered scalar projection"))?;
    let order_expr = order_items[0].expr.clone();
    let mut rewritten = query.clone();
    let select = match rewritten.body.as_mut() {
        sqlparser::ast::SetExpr::Select(select) => select,
        _ => return Ok(None),
    };
    select.selection = local.into_iter().reduce(|left, right| Expr::BinaryOp {
        left: Box::new(left),
        op: BinaryOperator::And,
        right: Box::new(right),
    });
    let mut projection = inner_keys
        .iter()
        .enumerate()
        .map(|(i, expr)| SelectItem::ExprWithAlias {
            expr: expr.clone(),
            alias: Ident::new(format!("__key{i}")),
        })
        .collect::<Vec<_>>();
    projection.push(SelectItem::ExprWithAlias {
        expr: value_expr,
        alias: Ident::new("__value"),
    });
    projection.push(SelectItem::ExprWithAlias {
        expr: order_expr,
        alias: Ident::new("__order"),
    });
    select.projection = projection;
    rewritten.order_by = None;
    rewritten.limit_clause = None;
    let (_columns, rows) =
        super::execute_query_rows(&rewritten, ds, source_dataset, caches, None, false)?;
    let descending = order_items[0].options.sort == Some(sqlparser::ast::OrderBySort::Desc);
    let mut groups = HashMap::<membership::KeyTuple, Scalar>::new();
    let mut order_values = HashMap::<membership::KeyTuple, Scalar>::new();
    for row in rows {
        if row.len() < inner_keys.len() + 2 {
            continue;
        }
        let Some(key) =
            membership::KeyTuple::from_options(row[..inner_keys.len()].iter().map(membership::key))
        else {
            continue;
        };
        let candidate_order = row[inner_keys.len() + 1].clone();
        let replace = order_values.get(&key).is_none_or(|old| {
            let cmp = super::compare_scalar(&candidate_order, old);
            if descending {
                cmp.is_gt()
            } else {
                cmp.is_lt()
            }
        });
        if replace {
            order_values.insert(key.clone(), candidate_order);
            groups.insert(key, row[inner_keys.len()].clone());
        }
    }
    Ok(Some(membership::register_scalars(
        groups,
        Scalar::Null,
        outer_keys,
    )))
}

fn conjuncts<'a>(expr: &'a Expr, output: &mut Vec<&'a Expr>) {
    match expr {
        Expr::Nested(expr) => conjuncts(expr, output),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            conjuncts(left, output);
            conjuncts(right, output);
        }
        _ => output.push(expr),
    }
}
fn inner_column(
    expr: &Expr,
    alias: &str,
    schema: &crate::sql::schema::TableMeta,
) -> Option<String> {
    let column = match expr {
        Expr::Nested(expr) => return inner_column(expr, alias, schema),
        Expr::Identifier(column) => &column.value,
        Expr::CompoundIdentifier(parts)
            if parts.len() == 2 && parts[0].value.eq_ignore_ascii_case(alias) =>
        {
            &parts[1].value
        }
        _ => return None,
    };
    schema
        .columns
        .iter()
        .find(|candidate| candidate.name.eq_ignore_ascii_case(column))
        .map(|column| column.name.to_owned())
}
fn outer_column<'a>(
    expr: &'a Expr,
    aliases: &HashSet<String>,
    shadowed: &HashSet<String>,
) -> Option<&'a Expr> {
    match expr {
        Expr::Nested(expr) => outer_column(expr, aliases, shadowed),
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            let alias = parts[0].value.to_ascii_lowercase();
            (aliases.contains(&alias) && !shadowed.contains(&alias)).then_some(expr)
        }
        _ => None,
    }
}
fn collect_local(
    expr: &Expr,
    alias: &str,
    schema: &crate::sql::schema::TableMeta,
    requested: &mut HashSet<String>,
) -> Result<(), String> {
    let mut expr = expr.clone();
    streaming::walk(&mut expr, &mut |expr| {
        match expr {
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => {
                requested.insert(inner_column(expr, alias, schema)?);
            }
            Expr::Function(function) => {
                let name = function
                    .name
                    .0
                    .last()?
                    .as_ident()?
                    .value
                    .to_ascii_lowercase();
                let arity = match &function.args {
                    FunctionArguments::List(args) => args.args.len(),
                    _ => 0,
                };
                if matches!(
                    name.as_str(),
                    "count" | "sum" | "total" | "avg" | "group_concat" | "string_agg"
                ) || matches!(name.as_str(), "min" | "max") && arity == 1
                {
                    return None;
                }
            }
            _ => {}
        }
        Some(false)
    })
    .ok_or_else(|| {
        unsupported("correlation is only supported in AND-connected equality predicates")
    })
}
fn mentions_outer(
    query: &Query,
    aliases: &HashSet<String>,
    shadowed: &HashSet<String>,
) -> Result<bool, String> {
    if aliases.is_empty() {
        return Ok(false);
    }
    let sql = query.to_string();
    let tokens = Tokenizer::new(&sqlparser::dialect::SQLiteDialect {}, &sql)
        .tokenize()
        .map_err(|error| unsupported(&error.to_string()))?
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .collect::<Vec<_>>();
    Ok(tokens.windows(3).any(|tokens| matches!(tokens, [Token::Word(alias), Token::Period, Token::Word(_)] if aliases.contains(&alias.value.to_ascii_lowercase()) && !shadowed.contains(&alias.value.to_ascii_lowercase()))))
}

fn expr_mentions_outer(expr: &Expr, aliases: &HashSet<String>) -> Result<bool, String> {
    let sql = expr.to_string();
    let tokens = Tokenizer::new(&sqlparser::dialect::SQLiteDialect {}, &sql)
        .tokenize()
        .map_err(|error| unsupported(&error.to_string()))?;
    Ok(tokens.windows(3).any(|tokens| {
        matches!(tokens,
            [Token::Word(alias), Token::Period, Token::Word(_)]
                if aliases.contains(&alias.value.to_ascii_lowercase())
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::super::{eval_scalar, RelRow, Scalar};
    use super::*;
    use std::path::PathBuf;

    fn fixture() -> Dataset {
        Dataset::load_paths(&[
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/beta.dex"),
        ])
        .unwrap()
    }
    fn query(sql: &str) -> Query {
        let statement =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, sql)
                .unwrap()
                .remove(0);
        let sqlparser::ast::Statement::Query(query) = statement else {
            panic!()
        };
        *query
    }
    fn compiled(sql: &str, ds: &Dataset, negated: bool) -> Expr {
        exists(
            &query(sql),
            negated,
            &HashSet::from(["m".to_owned()]),
            ds,
            &NamedCaches::default(),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn multikey_exists_builds_once_and_matches_fixture_references() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let sql = "SELECT 1 FROM method_calls c WHERE c.file_id=m.file_id AND c.method_idx=m.method_idx AND c.callee_method_idx>=1";
        let exists = compiled(sql, &ds, false);
        let not_exists = compiled(sql, &ds, true);
        // Repeated probes reuse the same inner-key set, with no subquery or
        // inner-source scan in the generated expression.
        assert!(matches!(exists, Expr::Function(_)));
        for file in &ds.files {
            for method_idx in 0..file.methods.len() as u32 {
                let expected = file
                    .method_calls
                    .iter()
                    .any(|call| call.method_idx == method_idx && call.callee_method_idx >= 1);
                let mut row = RelRow::default();
                row.put("m", "file_id", Scalar::Int(file.file_id as i64));
                row.put("m", "method_idx", Scalar::Int(method_idx as i64));
                for _ in 0..4 {
                    assert_eq!(
                        eval_scalar(&exists, &row, &[]).unwrap(),
                        Scalar::Int(expected as i64)
                    );
                    assert_eq!(
                        eval_scalar(&not_exists, &row, &[]).unwrap(),
                        Scalar::Int((!expected) as i64)
                    );
                }
            }
        }
    }

    #[test]
    fn exists_keys_are_type_strict_and_null_does_not_match() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let expr = compiled("SELECT 1 FROM methods i WHERE i.method_idx=m.k", &ds, false);
        let negated = compiled("SELECT 1 FROM methods i WHERE m.k=i.method_idx", &ds, true);
        for (key, expected) in [
            (Scalar::Int(0), true),
            (Scalar::Real("-0.0".to_owned()), true),
            (Scalar::text("0"), false),
            (Scalar::Null, false),
            (Scalar::Int(i64::MAX), false),
        ] {
            let mut row = RelRow::default();
            row.put("m", "k", key);
            assert_eq!(
                eval_scalar(&expr, &row, &[]).unwrap(),
                Scalar::Int(expected as i64)
            );
            assert_eq!(
                eval_scalar(&negated, &row, &[]).unwrap(),
                Scalar::Int((!expected) as i64)
            );
        }
    }

    #[test]
    fn local_large_in_filter_and_empty_inner_set_are_bounded() {
        let ds = fixture();
        let _scope = membership::Scope::new();
        let numbers = (0..4096)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let expr = compiled(
            &format!(
                "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND i.method_idx IN ({numbers})"
            ),
            &ds,
            false,
        );
        let empty = compiled(
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND i.method_idx<0",
            &ds,
            true,
        );
        let mut row = RelRow::default();
        row.put("m", "k", Scalar::Int(0));
        assert_eq!(eval_scalar(&expr, &row, &[]).unwrap(), Scalar::Int(1));
        assert_eq!(eval_scalar(&empty, &row, &[]).unwrap(), Scalar::Int(1));
        row.values.clear();
        row.put("m", "k", Scalar::Null);
        assert_eq!(eval_scalar(&empty, &row, &[]).unwrap(), Scalar::Int(1));
    }

    #[test]
    fn unsupported_correlations_fail_before_inner_scan() {
        let ds = fixture();
        let aliases = HashSet::from(["m".to_owned()]);
        for sql in [
            "SELECT 1 FROM methods i WHERE i.method_idx>m.k",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k OR i.method_idx=0",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k LIMIT 1",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k GROUP BY i.file_id",
            "SELECT 1 FROM methods i JOIN strings s ON s.string_idx=i.name WHERE i.method_idx=m.k",
            "SELECT 1 FROM methods i WHERE i.method_idx=m.k AND m.file_id=0",
        ] {
            let result = exists(&query(sql), false, &aliases, &ds, &NamedCaches::default());
            let error = result.unwrap_err();
            assert!(
                error.contains("unsupported correlated EXISTS"),
                "{sql}: {error}"
            );
        }
    }

    #[test]
    fn inner_alias_shadowing_and_alias_text_do_not_create_correlation() {
        let ds = fixture();
        let aliases = HashSet::from(["m".to_owned()]);
        for sql in [
            "SELECT 1 FROM methods m WHERE m.method_idx=0",
            "SELECT 1 FROM methods i WHERE i.name='m.name'",
            "SELECT 1 FROM methods i WHERE i.method_idx=0 /* m.method_idx */",
        ] {
            assert!(
                exists(&query(sql), false, &aliases, &ds, &NamedCaches::default())
                    .unwrap()
                    .is_none()
            );
        }
    }

    fn rows(sql: &str, ds: &Dataset) -> Vec<Vec<Scalar>> {
        super::super::execute_query_rows(
            &query(sql),
            ds,
            None,
            &NamedCaches::default(),
            None,
            false,
        )
        .unwrap()
        .1
    }

    #[test]
    fn correlated_in_and_count_preserve_composite_correlation_keys() {
        let ds = fixture();
        let counts = rows(
            "SELECT m.file_id,m.method_idx,(SELECT count(*) FROM method_strings s WHERE s.file_id=m.file_id AND s.method_idx=m.method_idx) AS n FROM methods m ORDER BY m.file_id,m.method_idx",
            &ds,
        );
        let expected = ds
            .files
            .iter()
            .flat_map(|file| {
                (0..file.methods.len()).map(move |method_idx| {
                    vec![
                        Scalar::Int(file.file_id as i64),
                        Scalar::Int(method_idx as i64),
                        Scalar::Int(
                            file.method_strings
                                .iter()
                                .filter(|reference| reference.method_idx as usize == method_idx)
                                .count() as i64,
                        ),
                    ]
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(counts, expected);
        for negated in [false, true] {
            let actual = rows(
                &format!(
                    "SELECT m.file_id,m.method_idx FROM methods m WHERE m.method_idx {}IN (SELECT s.method_idx FROM method_strings s WHERE s.file_id=m.file_id) ORDER BY m.file_id,m.method_idx",
                    if negated { "NOT " } else { "" }
                ),
                &ds,
            );
            let expected = ds
                .files
                .iter()
                .flat_map(|file| {
                    (0..file.methods.len())
                        .filter(move |method_idx| {
                            file.method_strings
                                .iter()
                                .any(|reference| reference.method_idx as usize == *method_idx)
                                != negated
                        })
                        .map(move |method_idx| {
                            vec![
                                Scalar::Int(file.file_id as i64),
                                Scalar::Int(method_idx as i64),
                            ]
                        })
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn correlated_aggregates_default_empty_groups_and_compose_scalar_functions() {
        let ds = fixture();
        let actual = rows(
            "SELECT m.file_id,m.method_idx,(SELECT max(s.method_idx) FROM method_strings s WHERE s.file_id=m.file_id AND s.method_idx=m.method_idx) AS hi,coalesce((SELECT max(s.method_idx) FROM method_strings s WHERE s.file_id=m.file_id AND s.method_idx=m.method_idx),-1) AS fallback,(SELECT count(*)+count(DISTINCT s.method_idx) FROM method_strings s WHERE s.file_id=m.file_id AND s.method_idx=m.method_idx) AS combined FROM methods m ORDER BY m.file_id,m.method_idx",
            &ds,
        );
        let expected = ds
            .files
            .iter()
            .flat_map(|file| {
                (0..file.methods.len()).map(move |method_idx| {
                    let count = file
                        .method_strings
                        .iter()
                        .filter(|reference| reference.method_idx as usize == method_idx)
                        .count();
                    let max = if count == 0 {
                        Scalar::Null
                    } else {
                        Scalar::Int(method_idx as i64)
                    };
                    vec![
                        Scalar::Int(file.file_id as i64),
                        Scalar::Int(method_idx as i64),
                        max,
                        Scalar::Int(if count == 0 { -1 } else { method_idx as i64 }),
                        Scalar::Int((count + usize::from(count > 0)) as i64),
                    ]
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(
            rows(
                "SELECT (SELECT name FROM methods WHERE 0),coalesce((SELECT name FROM methods WHERE 0),'empty')",
                &ds
            ),
            vec![vec![Scalar::Null, Scalar::text("empty")]]
        );
        assert_eq!(
            rows(
                "SELECT m.file_id,(SELECT count(*) FROM methods x WHERE x.file_id=m.file_id AND 0),(SELECT sum(x.method_idx) FROM methods x WHERE x.file_id=m.file_id AND 0) FROM methods m LIMIT 1",
                &ds
            )[0][1..],
            [Scalar::Int(0), Scalar::Null]
        );
    }

    #[test]
    fn nested_exists_and_in_compose_without_retaining_inner_registry() {
        let ds = fixture();
        let actual = rows(
            "SELECT c.file_id,c.class_idx FROM classes c WHERE EXISTS (SELECT 1 FROM methods m WHERE m.file_id=c.file_id AND m.class_idx=c.class_idx AND EXISTS (SELECT 1 FROM method_strings s WHERE s.file_id=m.file_id AND s.method_idx=m.method_idx)) ORDER BY c.file_id,c.class_idx",
            &ds,
        );
        let mut expected = Vec::new();
        for file in &ds.files {
            let mut classes = HashSet::new();
            for reference in &file.method_strings {
                classes.insert(file.methods[reference.method_idx as usize].class_idx as u32);
            }
            for class in &file.classes {
                if classes.contains(&class.class_idx) {
                    expected.push(vec![
                        Scalar::Int(file.file_id as i64),
                        Scalar::Int(class.class_idx as i64),
                    ]);
                }
            }
        }
        expected.sort_by(|left, right| {
            super::super::compare_scalar(&left[0], &right[0])
                .then_with(|| super::super::compare_scalar(&left[1], &right[1]))
        });
        assert_eq!(actual, expected);
        let alternate = rows(
            "SELECT c.file_id,c.class_idx FROM classes c WHERE EXISTS (SELECT 1 FROM methods m WHERE m.file_id=c.file_id AND m.class_idx=c.class_idx AND m.method_idx IN (SELECT s.method_idx FROM method_strings s WHERE s.file_id=m.file_id)) ORDER BY c.file_id,c.class_idx",
            &ds,
        );
        assert_eq!(alternate, expected);
    }

    #[test]
    fn correlated_membership_nulls_and_absent_groups_follow_empty_set_rules() {
        let ds = fixture();
        let aliases = HashSet::from(["m".to_owned()]);
        let compiled;
        {
            let _scope = membership::Scope::new();
            let input = query("SELECT NULL FROM methods x WHERE x.file_id=m.file_id");
            let value = Expr::Identifier(Ident::new("probe"));
            let positive = in_subquery(
                &input,
                value.clone(),
                false,
                &aliases,
                &ds,
                None,
                &NamedCaches::default(),
            )
            .unwrap()
            .unwrap();
            let negative = in_subquery(
                &input,
                value,
                true,
                &aliases,
                &ds,
                None,
                &NamedCaches::default(),
            )
            .unwrap()
            .unwrap();
            let count = scalar(
                &query("SELECT count(*) FROM methods x WHERE x.file_id=m.file_id"),
                &aliases,
                &ds,
                None,
                &NamedCaches::default(),
            )
            .unwrap()
            .unwrap();
            for (file_id, value, expected_in, expected_not_in, expected_count) in [
                (
                    Scalar::Int(1),
                    Scalar::Int(1),
                    Scalar::Null,
                    Scalar::Null,
                    ds.files
                        .iter()
                        .find(|file| file.file_id == 1)
                        .unwrap()
                        .methods
                        .len() as i64,
                ),
                (
                    Scalar::Int(-1),
                    Scalar::Int(1),
                    Scalar::Int(0),
                    Scalar::Int(1),
                    0,
                ),
                (
                    Scalar::Int(-1),
                    Scalar::Null,
                    Scalar::Int(0),
                    Scalar::Int(1),
                    0,
                ),
                (
                    Scalar::Null,
                    Scalar::Null,
                    Scalar::Int(0),
                    Scalar::Int(1),
                    0,
                ),
                (
                    Scalar::text("1"),
                    Scalar::Int(1),
                    Scalar::Int(0),
                    Scalar::Int(1),
                    0,
                ),
            ] {
                let mut row = RelRow::default();
                row.put("m", "file_id", file_id);
                row.put("m", "probe", value);
                assert_eq!(eval_scalar(&positive, &row, &[]).unwrap(), expected_in);
                assert_eq!(eval_scalar(&negative, &row, &[]).unwrap(), expected_not_in);
                assert_eq!(
                    eval_scalar(&count, &row, &[]).unwrap(),
                    Scalar::Int(expected_count)
                );
            }
            compiled = positive;
        }
        let mut row = RelRow::default();
        row.put("m", "file_id", Scalar::Int(1));
        row.put("m", "probe", Scalar::Int(1));
        assert!(eval_scalar(&compiled, &row, &[])
            .unwrap_err()
            .contains("outside query scope"));
    }
    #[test]
    #[ignore = "reference rejects this projection as an incomplete owner"]
    fn aggregate_membership_and_exists_keep_empty_group_cardinality() {
        let ds = fixture();
        let actual = rows(
            "SELECT m.file_id,m.method_idx,m.method_idx IN (SELECT max(x.method_idx) FROM methods x WHERE x.file_id=m.file_id) AS is_max,EXISTS(SELECT count(*) FROM methods x WHERE x.file_id=m.file_id AND 0) AS exists_count,NOT EXISTS(SELECT max(x.method_idx) FROM methods x WHERE x.file_id=m.file_id AND 0) AS not_exists_max FROM methods m ORDER BY m.file_id,m.method_idx",
            &ds,
        );
        let expected = ds
            .files
            .iter()
            .flat_map(|file| {
                (0..file.methods.len()).map(move |method_idx| {
                    vec![
                        Scalar::Int(file.file_id as i64),
                        Scalar::Int(method_idx as i64),
                        Scalar::Int((method_idx + 1 == file.methods.len()) as i64),
                        Scalar::Int(1),
                        Scalar::Int(0),
                    ]
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}
