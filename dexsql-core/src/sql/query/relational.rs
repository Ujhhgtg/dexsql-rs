//! Pull-based joins retain borrowed cache record identities, decode only on
//! matches, and feed projection/grouping directly without joined row tables.
use super::*;
use sqlparser::ast::{
    BinaryOperator, Expr, JoinConstraint, JoinOperator, Query, Select, TableFactor,
};
use std::hash::{Hash, Hasher};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Inner,
    Left,
    Right,
    Full,
}
impl Kind {
    fn keeps_left(self) -> bool {
        matches!(self, Self::Left | Self::Full)
    }
    fn keeps_right(self) -> bool {
        matches!(self, Self::Right | Self::Full)
    }
}

pub(super) fn parts(operator: &JoinOperator) -> Result<(Kind, &JoinConstraint), String> {
    Ok(match operator {
        JoinOperator::Join(c) | JoinOperator::Inner(c) | JoinOperator::CrossJoin(c) => {
            (Kind::Inner, c)
        }
        JoinOperator::Left(c) | JoinOperator::LeftOuter(c) => (Kind::Left, c),
        JoinOperator::Right(c) | JoinOperator::RightOuter(c) => (Kind::Right, c),
        JoinOperator::FullOuter(c) => (Kind::Full, c),
        _ => return Err("unsupported SQL join type".into()),
    })
}

struct Source {
    table: String,
    alias: String,
    columns: Vec<String>,
}
#[derive(Clone)]
struct Pair {
    left: String,
    right: String,
    null_safe: bool,
}
struct Join {
    kind: Kind,
    constraint: Option<Expr>,
    keys: Vec<Pair>,
    // USING/NATURAL columns expose a coalesced unqualified value; qualified
    // columns retain their own side's value, including NULL extensions.
    coalesce: Vec<String>,
}

#[cfg(test)]
fn row_hash(row: &RelRow, columns: impl Iterator<Item = impl AsRef<str>>) -> Option<u64> {
    let mut hash = rustc_hash::FxHasher::default();
    for column in columns {
        membership::key(row.get(column.as_ref())?)?.hash(&mut hash);
    }
    Some(hash.finish())
}
fn join_hash(row: &RelRow, pairs: &[Pair], right: bool) -> Option<u64> {
    let mut hash = rustc_hash::FxHasher::default();
    for pair in pairs {
        let value = row.get(if right { &pair.right } else { &pair.left })?;
        if pair.null_safe {
            membership::set_key(value)
        } else {
            membership::key(value)?
        }
        .hash(&mut hash);
    }
    Some(hash.finish())
}

fn source(factor: &TableFactor, caches: &NamedCaches) -> Option<Source> {
    let TableFactor::Table {
        name, alias, args, ..
    } = factor
    else {
        return None;
    };
    if name.0.len() != 1
        || args.is_some()
        || alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return None;
    }
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    if !streaming::supports_table(&table)
        || caches.has_definition(&table)
        || caches.tables.borrow().contains_key(&table)
    {
        return None;
    }
    let schema = crate::sql::schema::TABLES
        .iter()
        .find(|schema| schema.name == table)?;
    Some(Source {
        alias: alias
            .as_ref()
            .map(|alias| alias.name.value.to_ascii_lowercase())
            .unwrap_or_else(|| table.clone()),
        table,
        columns: schema
            .columns
            .iter()
            .map(|column| column.name.to_owned())
            .collect(),
    })
}
fn column_owner(expr: &Expr, sources: &[Source]) -> Option<(usize, String)> {
    match expr {
        Expr::Nested(expr) => column_owner(expr, sources),
        Expr::Identifier(id) => {
            let column = id.value.to_ascii_lowercase();
            Some((
                sources
                    .iter()
                    .position(|source| source.columns.contains(&column))?,
                column,
            ))
        }
        Expr::CompoundIdentifier(ids) if ids.len() == 2 => {
            let alias = ids[0].value.to_ascii_lowercase();
            let column = ids[1].value.to_ascii_lowercase();
            Some((
                sources
                    .iter()
                    .position(|source| source.alias == alias && source.columns.contains(&column))?,
                column,
            ))
        }
        _ => None,
    }
}
fn equality(expr: &Expr) -> Option<(&Expr, &Expr, bool)> {
    match expr {
        Expr::Nested(expr) => equality(expr),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => Some((left, right, false)),
        Expr::IsNotDistinctFrom(left, right) => Some((left, right, true)),
        _ => None,
    }
}
fn join_keys(expr: &Expr, sources: &[Source], level: usize, keys: &mut Vec<Pair>) {
    let mut conjuncts = Vec::new();
    flatten_and(expr, &mut conjuncts);
    for expr in conjuncts {
        let Some((left, right, null_safe)) = equality(expr) else {
            continue;
        };
        let (Some((a, ac)), Some((b, bc))) =
            (column_owner(left, sources), column_owner(right, sources))
        else {
            continue;
        };
        let pair = if a < level && b == level {
            Some((
                format!("{}.{}", sources[a].alias, ac),
                format!("{}.{}", sources[b].alias, bc),
            ))
        } else if b < level && a == level {
            Some((
                format!("{}.{}", sources[b].alias, bc),
                format!("{}.{}", sources[a].alias, ac),
            ))
        } else {
            None
        };
        if let Some((left, right)) = pair {
            if !keys
                .iter()
                .any(|pair| pair.left == left && pair.right == right && pair.null_safe == null_safe)
            {
                keys.push(Pair {
                    left,
                    right,
                    null_safe,
                });
            }
        }
    }
}
fn qualified(alias: &str, column: &str) -> Expr {
    Expr::CompoundIdentifier(vec![
        sqlparser::ast::Ident::new(alias),
        sqlparser::ast::Ident::new(column),
    ])
}
fn using_constraint(columns: &[String], right_alias: &str) -> Option<Expr> {
    columns
        .iter()
        .map(|column| Expr::BinaryOp {
            left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new(column))),
            op: BinaryOperator::Eq,
            right: Box::new(qualified(right_alias, column)),
        })
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        })
}
fn using_columns(
    constraint: &JoinConstraint,
    left: &[String],
    right: &[String],
) -> Result<Vec<String>, String> {
    let columns = match constraint {
        JoinConstraint::Using(columns) => columns
            .iter()
            .map(|column| {
                column
                    .0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(|part| part.value.to_ascii_lowercase())
                    .unwrap_or_default()
            })
            .collect(),
        JoinConstraint::Natural => left
            .iter()
            .filter(|column| right.contains(column))
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    if columns
        .iter()
        .any(|column| !left.contains(column) || !right.contains(column))
    {
        return Err("unknown column in JOIN USING".into());
    }
    Ok(columns)
}
fn local_exprs<'a>(expr: Option<&'a Expr>, sources: &[Source], level: usize) -> Vec<&'a Expr> {
    let mut conjuncts = Vec::new();
    if let Some(expr) = expr {
        flatten_and(expr, &mut conjuncts);
    }
    conjuncts.into_iter().filter(|expr| {
        let mut copy = (*expr).clone(); let mut local = true;
        let supported = streaming::walk(&mut copy, &mut |expr| {
            if matches!(expr, Expr::InList { list, .. } if list.len() >= membership::HASH_THRESHOLD) { local = false; }
            if matches!(expr, Expr::Identifier(_) | Expr::CompoundIdentifier(_)) {
                local &= column_owner(expr, sources).is_some_and(|(owner, _)| owner == level);
            }
            Some(false)
        }).is_some();
        supported && local
    }).collect()
}

pub(super) fn execute(
    query: &Query,
    select: &Select,
    ds: &Dataset,
    caches: &NamedCaches,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    let mut sources = Vec::new();
    let mut joins = Vec::new();
    for table in &select.from {
        if !sources.is_empty() {
            joins.push(Join {
                kind: Kind::Inner,
                constraint: None,
                keys: Vec::new(),
                coalesce: Vec::new(),
            });
        }
        sources.push(source(&table.relation, caches)?);
        for join in &table.joins {
            let (kind, constraint) = parts(&join.join_operator).ok()?;
            let right = source(&join.relation, caches)?;
            let natural = matches!(constraint, JoinConstraint::Natural);
            let visible = |source: &Source, column: &String| {
                !natural
                    || source.table != "classes"
                    || !matches!(column.as_str(), "field_count" | "method_count")
            };
            let left_columns = sources
                .iter()
                .flat_map(|source| {
                    source
                        .columns
                        .iter()
                        .filter(|column| visible(source, column))
                        .cloned()
                })
                .collect::<Vec<_>>();
            let right_columns = right
                .columns
                .iter()
                .filter(|column| visible(&right, column))
                .cloned()
                .collect::<Vec<_>>();
            let coalesce = using_columns(constraint, &left_columns, &right_columns).ok()?;
            let expression = match constraint {
                JoinConstraint::On(expr) => Some(expr.clone()),
                _ => using_constraint(&coalesce, &right.alias),
            };
            let keys = coalesce
                .iter()
                .map(|column| Pair {
                    left: column.clone(),
                    right: format!("{}.{}", right.alias, column),
                    null_safe: false,
                })
                .collect();
            sources.push(right);
            joins.push(Join {
                kind,
                constraint: expression,
                keys,
                coalesce,
            });
        }
    }
    if sources.len() < 2 {
        return None;
    }
    let mut aliases = HashSet::new();
    if sources.iter().any(|source| !aliases.insert(&source.alias)) {
        return None;
    }
    let outer = joins.iter().any(|join| join.kind != Kind::Inner);
    for (index, join) in joins.iter_mut().enumerate() {
        if join.coalesce.is_empty() {
            if let Some(expr) = &join.constraint {
                join_keys(expr, &sources, index + 1, &mut join.keys);
            }
        }
        if !outer {
            if let Some(expr) = &select.selection {
                join_keys(expr, &sources, index + 1, &mut join.keys);
            }
        }
    }
    if let Some(output) = execute_identity(query, select, &sources, &joins, ds, cli_limit) {
        return Some(output);
    }
    if let Some(output) = execute_class_method_anti(query, select, &sources, &joins, ds, cli_limit)
    {
        return Some(output);
    }
    for join in &mut joins {
        // Hash lookup plus the exact key verification already evaluates
        // these conjuncts. Retain only residual ON expressions, avoiding a
        // second AST walk and qualified-name allocation for every match.
        if let Some(expr) = &join.constraint {
            let mut atoms = Vec::new();
            flatten_and(expr, &mut atoms);
            join.constraint = atoms
                .into_iter()
                .filter(|atom| {
                    let Some((left, right, null_safe)) = equality(atom) else {
                        return true;
                    };
                    let (Some((a, ac)), Some((b, bc))) =
                        (column_owner(left, &sources), column_owner(right, &sources))
                    else {
                        return true;
                    };
                    let left = format!("{}.{}", sources[a].alias, ac);
                    let right = format!("{}.{}", sources[b].alias, bc);
                    !join.keys.iter().any(|pair| {
                        pair.null_safe == null_safe
                            && ((pair.left == left && pair.right == right)
                                || (pair.left == right && pair.right == left))
                    })
                })
                .cloned()
                .reduce(|left, right| Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOperator::And,
                    right: Box::new(right),
                });
        }
    }
    // Every method-string edge names exactly one method by (file,id).
    // Orient this many-to-one identity join around its edge stream, matching
    // the reference's elimination of the redundant unique-method relation.
    let shared_columns = sources
        .first()
        .zip(sources.get(1))
        .map(|(left, right)| {
            left.columns
                .iter()
                .filter(|column| right.columns.contains(column))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // A swapped unqualified column must have the same value on both sides.
    // The full identity proof establishes file_id/method_idx and each
    // method's owning class_idx.
    if shared_columns
        .iter()
        .all(|column| matches!(column.as_str(), "file_id" | "method_idx" | "class_idx"))
        && sources.len() == 2
        && joins[0].kind == Kind::Inner
        && sources[0].table == "methods"
        && sources[1].table == "method_strings"
        && joins[0].coalesce.is_empty()
        && ["file_id", "method_idx"].iter().all(|column| {
            joins[0].keys.iter().any(|pair| {
                pair.left == format!("{}.{}", sources[0].alias, column)
                    && pair.right == format!("{}.{}", sources[1].alias, column)
                    && !pair.null_safe
            })
        })
    {
        sources.swap(0, 1);
        for pair in &mut joins[0].keys {
            std::mem::swap(&mut pair.left, &mut pair.right);
        }
    }
    let bounded = query.order_by.is_none()
        && (query_limit_value(query.limit_clause.as_ref()).is_some() || cli_limit.is_some())
        && select
            .projection
            .iter()
            .all(|item| item_expr(item).is_some_and(scan_projection_is_row_local))
        && select.having.is_none()
        && matches!(&select.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty());
    let mut schema = Vec::new();
    for source in &sources {
        for column in &source.columns {
            if !schema.contains(column) {
                schema.push(column.clone());
            }
            schema.push(format!("{}.{}", source.alias, column));
        }
    }
    streaming::execute_input(query, select, &schema, cli_limit, |needed, visit| {
        let mut required: HashSet<String> = needed.iter().cloned().collect();
        for join in &joins {
            if let Some(expr) = &join.constraint {
                let mut columns = HashSet::new();
                if !collect_expr_columns(expr, &mut columns) {
                    return Err("unsupported SQL expression in JOIN".into());
                }
                for column in columns {
                    for source in &sources {
                        if source.columns.contains(&column) {
                            required.insert(format!("{}.{}", source.alias, column));
                        }
                    }
                }
            }
            for pair in &join.keys {
                required.insert(pair.left.clone());
                required.insert(pair.right.clone());
            }
        }
        let columns: Vec<Vec<&str>> = sources
            .iter()
            .enumerate()
            .map(|(index, source)| {
                source
                    .columns
                    .iter()
                    .filter(|column| {
                        required.contains(&format!("{}.{}", source.alias, column))
                            || required.contains(column.as_str())
                                && sources
                                    .iter()
                                    .position(|source| source.columns.contains(column))
                                    == Some(index)
                    })
                    .map(String::as_str)
                    .collect()
            })
            .collect();
        // Outer WHERE filters must run after NULL extension. In particular a
        // nullable-side IS NULL cannot be pushed into the build scan.
        let where_locals: Vec<_> = (0..sources.len())
            .map(|index| {
                if outer {
                    Vec::new()
                } else {
                    local_exprs(select.selection.as_ref(), &sources, index)
                }
            })
            .collect();
        let mut builds = Vec::new();
        let mut retained = 0u64;
        for (index, join) in joins.iter().enumerate() {
            let source = &sources[index + 1];
            let columns = &columns[index + 1];
            let on_local = if join.kind.keeps_right() {
                Vec::new()
            } else {
                local_exprs(join.constraint.as_ref(), &sources, index + 1)
            };
            let mut scan_columns: HashSet<String> = join
                .keys
                .iter()
                .map(|pair| pair.right.rsplit('.').next().unwrap().to_owned())
                .collect();
            for expr in where_locals[index + 1].iter().chain(on_local.iter()) {
                collect_expr_columns(expr, &mut scan_columns);
            }
            let scan_columns = scan_columns.iter().map(String::as_str).collect::<Vec<_>>();
            let mut build = Build {
                rows: Vec::new(),
                index: FxHashMap::default(),
                next: Vec::new(),
                matched: RefCell::new(Vec::new()),
                table: source.table.clone(),
                alias: source.alias.clone(),
                predicates: Vec::new(),
                lazy: join.keys.is_empty() && !join.kind.keeps_right(),
                locals: where_locals[index + 1]
                    .iter()
                    .chain(on_local.iter())
                    .map(|expr| (*expr).clone())
                    .collect(),
                cells: if join.keys.is_empty() && !join.kind.keeps_right() {
                    Vec::new()
                } else {
                    ds.files
                        .iter()
                        .map(|file| {
                            RefCell::new(streaming::Cells::new(
                                file,
                                &source.table,
                                source.table == "methods"
                                    && columns.iter().any(|column| {
                                        matches!(
                                            *column,
                                            "access_flags"
                                                | "method_kind"
                                                | "opcode_count"
                                                | "opcode_hex"
                                        )
                                    }),
                                columns,
                            ))
                        })
                        .collect()
                },
                columns: columns
                    .iter()
                    .map(|column| {
                        (
                            intern_rel_component(&format!("{}.{}", source.alias, column)),
                            intern_rel_component(column),
                        )
                    })
                    .collect(),
            };
            if build.lazy {
                builds.push(build);
                continue;
            }
            streaming::visit_source_records(
                ds,
                &source.table,
                &source.alias,
                &scan_columns,
                None,
                |row, file_index, record| {
                    for expr in where_locals[index + 1].iter().chain(on_local.iter()) {
                        if !eval_bool(expr, row, &[])? {
                            return Ok(false);
                        }
                    }
                    let hash = (!join.keys.is_empty())
                        .then(|| join_hash(row, &join.keys, true))
                        .flatten();
                    if hash.is_none() && !join.keys.is_empty() && !join.kind.keeps_right() {
                        return Ok(false);
                    }
                    retained = retained.saturating_add(
                        std::mem::size_of::<(usize, streaming::Source<'_>)>() as u64 + 5,
                    );
                    if hash.is_some_and(|hash| !build.index.contains_key(&hash)) {
                        retained = retained.saturating_add(24);
                    }
                    charge_materialized(retained)?;
                    let ordinal = build.rows.len();
                    build.rows.push((file_index, record));
                    build.next.push(u32::MAX);
                    if let Some(hash) = hash {
                        let ordinal = u32::try_from(ordinal)
                            .map_err(|_| "join build exceeds row identity domain")?;
                        match build.index.entry(hash) {
                            std::collections::hash_map::Entry::Vacant(entry) => {
                                entry.insert(Bucket {
                                    first: ordinal,
                                    last: ordinal,
                                });
                            }
                            std::collections::hash_map::Entry::Occupied(mut entry) => {
                                build.next[entry.get().last as usize] = ordinal;
                                entry.get_mut().last = ordinal;
                            }
                        }
                    }
                    Ok(false)
                },
            )?;
            *build.matched.borrow_mut() = vec![false; build.rows.len()];
            builds.push(build);
        }
        let work = Cell::new(0u64);
        let mut stopped = false;
        streaming::visit_source(
            ds,
            &sources[0].table,
            &sources[0].alias,
            &columns[0],
            None,
            |row| {
                for expr in &where_locals[0] {
                    if !eval_bool(expr, row, &[])? {
                        return Ok(false);
                    }
                }
                stopped = probe(0, row, &joins, &builds, ds, bounded, &work, visit)?;
                Ok(stopped)
            },
        )?;
        if stopped {
            return Ok(());
        }
        // A right/full join emits each still-unmatched build record once,
        // then feeds it through every downstream join before flushing that
        // next join's unmatched records.
        for (level, join) in joins.iter().enumerate() {
            if !join.kind.keeps_right() {
                continue;
            }
            let mut null_left = RelRow::default();
            for (source, columns) in sources[..level + 1].iter().zip(&columns) {
                for column in columns {
                    null_left.put(&source.alias, column, Scalar::Null);
                }
            }
            for index in 0..builds[level].rows.len() {
                if builds[level].matched.borrow()[index] {
                    continue;
                }
                let mut merged = null_left.clone();
                decode(&builds[level], index, ds, &null_left, &mut merged);
                coalesce(&mut merged, &join.coalesce, &builds[level].alias);
                if probe(
                    level + 1,
                    &merged,
                    &joins,
                    &builds,
                    ds,
                    bounded,
                    &work,
                    visit,
                )? {
                    return Ok(());
                }
            }
        }
        Ok(())
    })
}

/// Foreign-class anti join: the right method identity is non-NULL for every
/// matching method. A complete (file_id,class_idx) ON plus `method_idx IS NULL`
/// therefore asks only which classes have no method IDs. A dense class bitmap
/// supplies that existence test, while the ordinary sink handles every output
/// expression, remaining predicate, grouping and ordering.
fn execute_class_method_anti(
    query: &Query,
    select: &Select,
    sources: &[Source],
    joins: &[Join],
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    if sources.len() != 2
        || joins.len() != 1
        || joins[0].kind != Kind::Left
        || sources[0].table != "classes"
        || sources[1].table != "methods"
        || !joins[0].coalesce.is_empty()
    {
        return None;
    }
    let mut atoms = Vec::new();
    flatten_and(joins[0].constraint.as_ref()?, &mut atoms);
    for name in ["file_id", "class_idx"] {
        if !atoms.iter().any(|atom| {
            equality(atom).is_some_and(|(left, right, null_safe)| {
                !null_safe
                    && ((column_owner(left, sources) == Some((0, name.to_owned()))
                        && column_owner(right, sources) == Some((1, name.to_owned())))
                        || (column_owner(left, sources) == Some((1, name.to_owned()))
                            && column_owner(right, sources) == Some((0, name.to_owned()))))
            })
        }) {
            return None;
        }
    }
    if atoms.len() != 2 {
        return None;
    }
    let mut selection = Vec::new();
    flatten_and(select.selection.as_ref()?, &mut selection);
    if !selection.iter().any(|atom| matches!(atom,Expr::IsNull(expr) if column_owner(expr,sources)==Some((1,"method_idx".to_owned())))) { return None; }
    let mut schema = Vec::new();
    for source in sources {
        for column in &source.columns {
            if !schema.contains(column) {
                schema.push(column.clone());
            }
            schema.push(format!("{}.{}", source.alias, column));
        }
    }
    streaming::execute_input(query, select, &schema, cli_limit, |needed, visit| {
        let requested = sources
            .iter()
            .enumerate()
            .map(|(owner, source)| {
                source
                    .columns
                    .iter()
                    .filter(|column| {
                        needed.contains(&format!("{}.{}", source.alias, column))
                            || needed.contains(column)
                                && sources
                                    .iter()
                                    .position(|candidate| candidate.columns.contains(column))
                                    == Some(owner)
                    })
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for file in &ds.files {
            let mut has_method = vec![false; u16::MAX as usize + 1];
            for method in &file.methods {
                has_method[method.class_idx as usize] = true;
            }
            let mut cells = streaming::Cells::new(file, "classes", false, &requested[0]);
            let mut row = RelRow::with_capacity(needed.len());
            for class in &file.classes {
                if has_method
                    .get(class.class_idx as usize)
                    .copied()
                    .unwrap_or(false)
                {
                    continue;
                }
                row.values.clear();
                row.columns.clear();
                for column in &requested[0] {
                    row.put(
                        &sources[0].alias,
                        column,
                        cells.value(streaming::Source::Class(class), column, None),
                    );
                }
                for column in &requested[1] {
                    row.put(&sources[1].alias, column, Scalar::Null);
                }
                if visit(&row)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    })
}

/// A complete foreign-method identity lets the reference relation supply each
/// joined row directly. No hash index, build rows, or merged maps are needed.
fn execute_identity(
    query: &Query,
    select: &Select,
    sources: &[Source],
    joins: &[Join],
    ds: &Dataset,
    cli_limit: Option<u64>,
) -> Option<Result<SelectOutput, String>> {
    if sources.len() != 2 || joins[0].kind != Kind::Inner {
        return None;
    }
    let method = sources
        .iter()
        .position(|source| source.table == "methods")?;
    let edge = 1 - method;
    if !matches!(
        sources[edge].table.as_str(),
        "method_strings"
            | "method_calls"
            | "method_field_accesses"
            | "method_used_types"
            | "method_numbers"
            | "method_using_numbers"
    ) {
        return None;
    }
    // Canonical cells also let scalar evaluation use an already-interned
    // identifier, avoiding a qualified-name allocation on every edge probe.
    let canonical = |owner: usize, column: &str| -> (bool, String) {
        if owner == method {
            return (true, column.to_owned());
        }
        match column {
            "file_id" | "method_idx" | "class_idx" => (true, column.to_owned()),
            "method" => (true, "descriptor".to_owned()),
            "method_name" => (true, "name".to_owned()),
            "method_class" => (true, "class_descriptor".to_owned()),
            _ => (false, column.to_owned()),
        }
    };
    let identity_pair = |expr: &Expr| -> Option<(String, String)> {
        let (a, b, _) = equality(expr)?;
        let (a, ac) = column_owner(a, sources)?;
        let (b, bc) = column_owner(b, sources)?;
        if a == method && b == edge {
            Some((ac, bc))
        } else if b == method && a == edge {
            Some((bc, ac))
        } else {
            None
        }
    };
    let mut atoms = Vec::new();
    if let Some(expr) = &joins[0].constraint {
        flatten_and(expr, &mut atoms);
    }
    if let Some(expr) = &select.selection {
        flatten_and(expr, &mut atoms);
    }
    let pairs = atoms
        .iter()
        .filter_map(|expr| identity_pair(expr))
        .collect::<Vec<_>>();
    let file_identity = pairs.iter().any(|(a, b)| a == "file_id" && b == "file_id");
    let id_identity = pairs
        .iter()
        .any(|(a, b)| a == "method_idx" && b == "method_idx");
    let descriptor_identity = pairs
        .iter()
        .any(|(a, b)| a == "descriptor" && b == "method");
    if !file_identity || !(id_identity || descriptor_identity) {
        return None;
    }
    if !id_identity && !unique_method_descriptors(ds) {
        return None;
    }
    // Strip only equalities whose two expressions now name the same cell.
    // Other ON predicates become WHERE for this inner join and remain visible
    // to the normal sink's dependency extraction and NULL-aware evaluator.
    let residual = atoms
        .into_iter()
        .filter(|expr| {
            let Some((a, b)) = identity_pair(expr) else {
                return true;
            };
            // The method and edge cells are stored under distinct canonical
            // namespaces, so equality compares cannot be removed by comparing
            // their storage keys. Remove only proven identity pairs here.
            !((a == "file_id" && b == "file_id")
                || (a == "method_idx" && b == "method_idx")
                || (a == "descriptor" && b == "method"))
        })
        .cloned()
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        });
    let mut rewritten = select.clone();
    rewritten.selection = residual;
    let mut rewritten_query = query.clone();
    let mut cells: FxHashMap<String, (bool, String)> = FxHashMap::default();
    let mut schema = Vec::new();
    for (owner, source) in sources.iter().enumerate() {
        for column in &source.columns {
            let (method, column) = canonical(owner, column);
            let key = format!(
                "\0identity:{}:{column}",
                if method { "method" } else { "edge" }
            );
            if !cells.contains_key(&key) {
                schema.push(key.clone());
                cells.insert(key, (method, column));
            }
        }
    }
    let aliases = select
        .projection
        .iter()
        .filter_map(|item| match item {
            sqlparser::ast::SelectItem::ExprWithAlias { alias, .. } => {
                Some(alias.value.to_ascii_lowercase())
            }
            _ => None,
        })
        .collect::<HashSet<_>>();
    let rewrite_expr = |expr: &mut Expr, output_aliases: bool| {
        streaming::walk(expr, &mut |expr| {
            if let Expr::Identifier(id) = expr {
                if output_aliases && aliases.contains(&id.value.to_ascii_lowercase()) {
                    return Some(true);
                }
            }
            if let Some((owner, column)) = column_owner(expr, sources) {
                let (method, column) = canonical(owner, &column);
                *expr = Expr::Identifier(sqlparser::ast::Ident::new(format!(
                    "\0identity:{}:{column}",
                    if method { "method" } else { "edge" }
                )));
                return Some(true);
            }
            if let Expr::Function(function) = expr {
                if let sqlparser::ast::FunctionArguments::List(args) = &function.args {
                    if args.args.iter().any(|arg| {
                        matches!(
                            arg,
                            sqlparser::ast::FunctionArg::Unnamed(
                                sqlparser::ast::FunctionArgExpr::Wildcard
                            )
                        )
                    }) {
                        return Some(true);
                    }
                }
            }
            Some(false)
        })
    };
    for item in &mut rewritten.projection {
        match item {
            sqlparser::ast::SelectItem::UnnamedExpr(expr) => {
                let label = expression_label(expr);
                rewrite_expr(expr, false)?;
                *item = sqlparser::ast::SelectItem::ExprWithAlias {
                    expr: expr.clone(),
                    alias: sqlparser::ast::Ident::new(label),
                };
            }
            sqlparser::ast::SelectItem::ExprWithAlias { expr, .. } => {
                rewrite_expr(expr, false)?;
            }
            _ => return None,
        }
    }
    if let Some(expr) = &mut rewritten.selection {
        rewrite_expr(expr, false)?;
    }
    if let sqlparser::ast::GroupByExpr::Expressions(exprs, _) = &mut rewritten.group_by {
        for expr in exprs {
            rewrite_expr(expr, true)?;
        }
    }
    if let Some(expr) = &mut rewritten.having {
        rewrite_expr(expr, true)?;
    }
    if let Some(order) = &mut rewritten_query.order_by {
        if let sqlparser::ast::OrderByKind::Expressions(exprs) = &mut order.kind {
            for order in exprs {
                rewrite_expr(&mut order.expr, true)?;
            }
        }
    }
    streaming::execute_input(
        &rewritten_query,
        &rewritten,
        &schema,
        cli_limit,
        |needed, visit| {
            let mut method_columns = Vec::new();
            let mut edge_columns = Vec::new();
            for name in needed {
                let (method, column) = &cells[name];
                let key = intern_rel_component(name);
                if *method {
                    method_columns.push((key, column.as_str()));
                } else {
                    edge_columns.push((key, column.as_str()));
                }
            }
            let names = method_columns
                .iter()
                .map(|(_, column)| *column)
                .collect::<Vec<_>>();
            let needs_opcode = names
                .iter()
                .any(|column| matches!(*column, "opcode_count" | "opcode_hex"));
            let needs_definitions = needs_opcode
                || names
                    .iter()
                    .any(|column| matches!(*column, "access_flags" | "method_kind"));
            let mut method_cells = ds
                .files
                .iter()
                .map(|file| streaming::Cells::uncached(file, needs_definitions, &names))
                .collect::<Vec<_>>();
            let mut edge_cells = ds
                .files
                .iter()
                .map(|file| streaming::Cells::uncached(file, false, &[]))
                .collect::<Vec<_>>();
            let mut last_method = vec![None; ds.files.len()];
            let mut method_values = vec![Vec::new(); ds.files.len()];
            let mut row = RelRow::with_capacity(needed.len());
            streaming::visit_source_records(
                ds,
                &sources[edge].table,
                &sources[edge].alias,
                &[],
                None,
                |_, file_index, record| {
                    let Some(method_idx) = record.method_index() else {
                        return Ok(false);
                    };
                    let file = &ds.files[file_index];
                    if method_idx as usize >= file.methods.len() {
                        return Ok(false);
                    }
                    if last_method[file_index] != Some(method_idx) {
                        let opcode = if names.contains(&"opcode_hex") {
                            file.method_opcode_summary(method_idx)
                        } else if needs_opcode {
                            file.method_opcode_count(method_idx)
                                .map(|count| (count, String::new()))
                        } else {
                            None
                        };
                        let values = &mut method_values[file_index];
                        values.clear();
                        for (_, column) in &method_columns {
                            values.push(method_cells[file_index].value(
                                streaming::Source::Method(method_idx),
                                column,
                                opcode.as_ref(),
                            ));
                        }
                        last_method[file_index] = Some(method_idx);
                    }
                    row.values.clear();
                    for ((key, _), value) in method_columns.iter().zip(&method_values[file_index]) {
                        row.values.insert(key.clone(), value.clone());
                    }
                    for (key, column) in &edge_columns {
                        row.values.insert(
                            key.clone(),
                            edge_cells[file_index].value(record, column, None),
                        );
                    }
                    visit(&row)
                },
            )
        },
    )
}

/// Validate descriptor uniqueness using borrowed ID/signature keys, without
/// allocating a formatted descriptor for every method. Duplicate malformed
/// pools fall back to the ordinary hash join, preserving relation duplicates.
pub(super) fn unique_method_descriptors(ds: &Dataset) -> bool {
    ds.files.iter().all(|file| {
        let mut types = std::collections::HashSet::with_capacity_and_hasher(
            file.types.len(),
            rustc_hash::FxBuildHasher,
        );
        if !file
            .types
            .iter()
            .all(|typ| types.insert(file.string(typ.descriptor_idx)))
        {
            return false;
        }
        let mut protos = std::collections::HashSet::with_capacity_and_hasher(
            file.protos.len(),
            rustc_hash::FxBuildHasher,
        );
        if !file
            .protos
            .iter()
            .all(|proto| protos.insert((proto.return_type_idx, proto.parameters.as_slice())))
        {
            return false;
        }
        let mut methods = std::collections::HashSet::with_capacity_and_hasher(
            file.methods.len(),
            rustc_hash::FxBuildHasher,
        );
        file.methods.iter().all(|method| {
            methods.insert((
                method.class_idx,
                method.proto_idx,
                file.string(method.name_idx),
            ))
        })
    })
}

struct Build<'a> {
    rows: Vec<(usize, streaming::Source<'a>)>,
    index: FxHashMap<u64, Bucket>,
    next: Vec<u32>,
    matched: RefCell<Vec<bool>>,
    cells: Vec<RefCell<streaming::Cells<'a>>>,
    table: String,
    alias: String,
    predicates: Vec<PushPredicate>,
    lazy: bool,
    locals: Vec<Expr>,
    columns: Vec<(Arc<str>, Arc<str>)>,
}
#[derive(Clone, Copy)]
struct Bucket {
    first: u32,
    last: u32,
}
fn decode(build: &Build<'_>, index: usize, ds: &Dataset, left: &RelRow, merged: &mut RelRow) {
    let (file_index, record) = build.rows[index];
    let file = &ds.files[file_index];
    let opcode = if let streaming::Source::Method(index) = record {
        if build
            .columns
            .iter()
            .any(|(_, column)| column.as_ref() == "opcode_hex")
        {
            file.method_opcode_summary(index)
        } else if build
            .columns
            .iter()
            .any(|(_, column)| column.as_ref() == "opcode_count")
        {
            file.method_opcode_count(index)
                .map(|count| (count, String::new()))
        } else {
            None
        }
    } else {
        None
    };
    let mut cells = build.cells[file_index].borrow_mut();
    for (qualified, column) in &build.columns {
        let value = cells.value(record, column, opcode.as_ref());
        merged.values.insert(qualified.clone(), value.clone());
        if !left.values.contains_key(column) {
            merged.values.insert(column.clone(), value);
        }
        if !merged.columns.contains(column) {
            merged.columns.push(column.clone());
        }
    }
}
fn null_right(build: &Build<'_>, left: &RelRow) -> RelRow {
    let mut merged = left.clone();
    for (qualified, column) in &build.columns {
        merged.values.insert(qualified.clone(), Scalar::Null);
        if !left.values.contains_key(column) {
            merged.values.insert(column.clone(), Scalar::Null);
        }
        if !merged.columns.contains(column) {
            merged.columns.push(column.clone());
        }
    }
    merged
}
fn coalesce(row: &mut RelRow, columns: &[String], right_alias: &str) {
    for column in columns {
        if row
            .get(column)
            .is_none_or(|value| matches!(value, Scalar::Null))
        {
            if let Some(value) = row.get(&format!("{right_alias}.{column}")).cloned() {
                row.values.insert(intern_rel_component(column), value);
            }
        }
    }
}
fn probe(
    level: usize,
    left: &RelRow,
    joins: &[Join],
    builds: &[Build<'_>],
    ds: &Dataset,
    bounded: bool,
    work: &Cell<u64>,
    visit: &mut dyn FnMut(&RelRow) -> Result<bool, String>,
) -> Result<bool, String> {
    if level == builds.len() {
        return visit(left);
    }
    let join = &joins[level];
    let build = &builds[level];
    if build.lazy {
        let columns = build
            .columns
            .iter()
            .map(|(_, column)| column.as_ref())
            .collect::<Vec<_>>();
        let mut found = false;
        let mut stopped = false;
        streaming::visit_source(
            ds,
            &build.table,
            &build.alias,
            &columns,
            Some(&build.predicates),
            |right| {
                work.set(work.get().saturating_add(1));
                if !bounded && work.get() > 5_000_000 {
                    return Err(
                        "unsupported SQL: large cross join without an equality condition".into(),
                    );
                }
                for local in &build.locals {
                    if !eval_bool(local, right, &[])? {
                        return Ok(false);
                    }
                }
                let mut merged = left.merge(right);
                if let Some(expr) = &join.constraint {
                    if !eval_bool(expr, &merged, &[])? {
                        return Ok(false);
                    }
                }
                found = true;
                coalesce(&mut merged, &join.coalesce, &build.alias);
                stopped = probe(level + 1, &merged, joins, builds, ds, bounded, work, visit)?;
                Ok(stopped)
            },
        )?;
        if stopped {
            return Ok(true);
        }
        if !found && join.kind.keeps_left() {
            return probe(
                level + 1,
                &null_right(build, left),
                joins,
                builds,
                ds,
                bounded,
                work,
                visit,
            );
        }
        return Ok(false);
    }
    let candidates = if join.keys.is_empty() {
        None
    } else {
        join_hash(left, &join.keys, false).and_then(|hash| build.index.get(&hash))
    };
    let mut found = false;
    let mut merged = null_right(build, left);
    let mut consume = |index: usize| -> Result<bool, String> {
        if join.keys.is_empty() {
            work.set(work.get().saturating_add(1));
            if !bounded && work.get() > 5_000_000 {
                return Err(
                    "unsupported SQL: large cross join without an equality condition".into(),
                );
            }
        }
        decode(build, index, ds, left, &mut merged);
        if join.keys.iter().any(|pair| {
            !left
                .get(&pair.left)
                .zip(merged.get(&pair.right))
                .is_some_and(|(a, b)| {
                    if pair.null_safe {
                        membership::set_key(a) == membership::set_key(b)
                    } else {
                        !matches!(a, Scalar::Null) && !matches!(b, Scalar::Null) && a.sql_eq(b)
                    }
                })
        }) {
            return Ok(false);
        }
        if let Some(expr) = &join.constraint {
            if !eval_bool(expr, &merged, &[])? {
                return Ok(false);
            }
        }
        found = true;
        if join.kind.keeps_right() {
            build.matched.borrow_mut()[index] = true;
        }
        coalesce(&mut merged, &join.coalesce, &build.alias);
        probe(level + 1, &merged, joins, builds, ds, bounded, work, visit)
    };
    if join.keys.is_empty() {
        for index in 0..build.rows.len() {
            if consume(index)? {
                return Ok(true);
            }
        }
    } else if let Some(candidates) = candidates {
        let mut index = candidates.first;
        while index != u32::MAX {
            if consume(index as usize)? {
                return Ok(true);
            }
            index = build.next[index as usize];
        }
    }
    if !found && join.kind.keeps_left() {
        let mut row = null_right(build, left);
        coalesce(&mut row, &join.coalesce, &build.alias);
        return probe(level + 1, &row, joins, builds, ds, bounded, work, visit);
    }
    Ok(false)
}

/// The generic fallback uses this schema row even when a relation is empty,
/// so outer NULL extensions retain resolvable qualified columns.
pub(super) fn template(factor: &TableFactor, rows: &[RelRow], caches: &NamedCaches) -> RelRow {
    if let Some(row) = rows.first() {
        let mut row = row.clone();
        for value in row.values.values_mut() {
            *value = Scalar::Null;
        }
        return row;
    }
    let (alias, columns) = match factor {
        TableFactor::Table { name, alias, .. } => {
            let name = name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .map(|part| part.value.to_ascii_lowercase())
                .unwrap_or_default();
            let columns = caches
                .tables
                .borrow()
                .get(&name)
                .map(|table| table.columns.clone())
                .or_else(|| {
                    crate::sql::schema::TABLES
                        .iter()
                        .find(|table| table.name == name)
                        .map(|table| {
                            table
                                .columns
                                .iter()
                                .map(|column| column.name.to_owned())
                                .collect()
                        })
                })
                .unwrap_or_default();
            (
                alias
                    .as_ref()
                    .map(|alias| alias.name.value.clone())
                    .unwrap_or(name),
                columns,
            )
        }
        TableFactor::Derived {
            alias, subquery, ..
        } => {
            let mut columns = projection_columns(&subquery.body, caches);
            if let Some(alias) = alias {
                for (column, replacement) in columns.iter_mut().zip(&alias.columns) {
                    *column = replacement.name.value.clone();
                }
            }
            (
                alias
                    .as_ref()
                    .map(|alias| alias.name.value.clone())
                    .unwrap_or_default(),
                columns,
            )
        }
        _ => (String::new(), Vec::new()),
    };
    let mut row = RelRow::default();
    for column in columns {
        row.put(&alias, &column, Scalar::Null);
    }
    row
}
fn wildcard_factor_columns(factor: &TableFactor, caches: &NamedCaches) -> Vec<String> {
    let mut columns = template(factor, &[], caches)
        .columns
        .into_iter()
        .map(|column| column.to_string())
        .collect::<Vec<_>>();
    if let TableFactor::Table { name, .. } = factor {
        if let Some(name) = name.0.last().and_then(|part| part.as_ident()) {
            let name = name.value.to_ascii_lowercase();
            if name == "classes"
                && !caches.has_definition(&name)
                && !caches.tables.borrow().contains_key(&name)
            {
                columns.retain(|column| !matches!(column.as_str(), "field_count" | "method_count"));
            }
        }
    }
    columns
}

/// Query-level schema metadata, independent of which side's rows happen to
/// appear first in a join or whether a relation has any rows at all.
pub(super) fn wildcard_sources(
    select: &Select,
    caches: &NamedCaches,
) -> FxHashMap<String, Vec<String>> {
    let mut sources = FxHashMap::default();
    for from in &select.from {
        for factor in
            std::iter::once(&from.relation).chain(from.joins.iter().map(|join| &join.relation))
        {
            sources.insert(
                relation_alias(factor).to_ascii_lowercase(),
                wildcard_factor_columns(factor, caches),
            );
        }
    }
    sources
}

fn projection_columns(body: &sqlparser::ast::SetExpr, caches: &NamedCaches) -> Vec<String> {
    use sqlparser::ast::{SelectItem, SetExpr};
    match body {
        SetExpr::Select(select) => select
            .projection
            .iter()
            .flat_map(|item| match item {
                SelectItem::ExprWithAlias { alias, .. } => vec![alias.value.clone()],
                SelectItem::UnnamedExpr(expr) => vec![expression_label(expr)],
                SelectItem::Wildcard(_) => select
                    .from
                    .iter()
                    .flat_map(|source| {
                        std::iter::once(&source.relation)
                            .chain(source.joins.iter().map(|join| &join.relation))
                    })
                    .flat_map(|factor| wildcard_factor_columns(factor, caches))
                    .collect(),
                SelectItem::QualifiedWildcard(
                    sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                    _,
                ) => {
                    let alias = name
                        .0
                        .last()
                        .and_then(|part| part.as_ident())
                        .map(|name| name.value.to_ascii_lowercase())
                        .unwrap_or_default();
                    wildcard_sources(select, caches)
                        .remove(&alias)
                        .unwrap_or_default()
                }
                _ => Vec::new(),
            })
            .collect(),
        SetExpr::Query(query) => projection_columns(&query.body, caches),
        SetExpr::SetOperation { left, .. } => projection_columns(left, caches),
        SetExpr::Values(values) => (1..=values.rows.first().map_or(0, |row| row.len()))
            .map(|index| format!("column{index}"))
            .collect(),
        _ => Vec::new(),
    }
}
fn relation_alias(factor: &TableFactor) -> &str {
    match factor {
        TableFactor::Derived { alias, .. } => alias
            .as_ref()
            .map(|alias| alias.name.value.as_str())
            .unwrap_or(""),
        _ => factor_alias(factor),
    }
}
pub(super) fn materialized_join(
    left: &[RelRow],
    right: &[RelRow],
    left_schema: &RelRow,
    right_schema: &RelRow,
    operator: &JoinOperator,
    right_factor: &TableFactor,
) -> Result<Vec<RelRow>, String> {
    let (kind, constraint) = parts(operator)?;
    let left_columns = left_schema
        .columns
        .iter()
        .map(|column| column.to_string())
        .collect::<Vec<_>>();
    let right_columns = right_schema
        .columns
        .iter()
        .map(|column| column.to_string())
        .collect::<Vec<_>>();
    let using = using_columns(constraint, &left_columns, &right_columns)?;
    let expression = match constraint {
        JoinConstraint::On(expr) => Some(expr.clone()),
        _ => using_constraint(&using, relation_alias(right_factor)),
    };
    materialized_rows(
        left,
        right,
        left_schema,
        right_schema,
        kind,
        expression.as_ref(),
        &using,
        relation_alias(right_factor),
    )
}
pub(super) fn materialized_rows(
    left: &[RelRow],
    right: &[RelRow],
    left_schema: &RelRow,
    right_schema: &RelRow,
    kind: Kind,
    constraint: Option<&Expr>,
    using: &[String],
    right_alias: &str,
) -> Result<Vec<RelRow>, String> {
    let mut keys = Vec::new();
    let mut conjuncts = Vec::new();
    if let Some(expr) = constraint {
        flatten_and(expr, &mut conjuncts);
    }
    for expr in conjuncts {
        let Some((a, b, null_safe)) = equality(expr) else {
            continue;
        };
        if eval_scalar(a, left_schema, &[]).is_ok() && eval_scalar(b, right_schema, &[]).is_ok() {
            keys.push((a, b, null_safe));
        } else if eval_scalar(b, left_schema, &[]).is_ok()
            && eval_scalar(a, right_schema, &[]).is_ok()
        {
            keys.push((b, a, null_safe));
        }
    }
    if keys.is_empty() && left.len().saturating_mul(right.len()) > 5_000_000 {
        return Err("unsupported SQL: large cross join without an equality condition".into());
    }
    let make_key = |row: &RelRow, right: bool| -> Result<Option<Vec<membership::Key>>, String> {
        keys.iter()
            .map(|(a, b, null_safe)| {
                eval_scalar(if right { b } else { a }, row, &[]).map(|value| {
                    if *null_safe {
                        Some(membership::set_key(&value))
                    } else {
                        membership::key(&value)
                    }
                })
            })
            .collect()
    };
    let mut index: FxHashMap<Vec<membership::Key>, Vec<usize>> = FxHashMap::default();
    if !keys.is_empty() {
        for (ordinal, row) in right.iter().enumerate() {
            if let Some(key) = make_key(row, true)? {
                index.entry(key).or_default().push(ordinal);
            }
        }
    }
    let mut matched = vec![false; right.len()];
    let mut output = Vec::new();
    let mut retained = 0;
    for row in left {
        let matches = if keys.is_empty() {
            None
        } else {
            make_key(row, false)?.and_then(|key| index.get(&key))
        };
        let mut found = false;
        let mut emit = |ordinal: usize| -> Result<(), String> {
            let mut merged = row.merge(&right[ordinal]);
            if let Some(constraint) = constraint {
                if !eval_bool(constraint, &merged, &[])? {
                    return Ok(());
                }
            }
            found = true;
            matched[ordinal] = true;
            coalesce(&mut merged, using, right_alias);
            push_reference_row(&mut output, merged, &mut retained)
        };
        if keys.is_empty() {
            for ordinal in 0..right.len() {
                emit(ordinal)?;
            }
        } else if let Some(matches) = matches {
            for ordinal in matches {
                emit(*ordinal)?;
            }
        }
        if !found && kind.keeps_left() {
            let mut merged = row.merge(right_schema);
            coalesce(&mut merged, using, right_alias);
            push_reference_row(&mut output, merged, &mut retained)?;
        }
    }
    if kind.keeps_right() {
        for (ordinal, row) in right.iter().enumerate() {
            if !matched[ordinal] {
                let mut merged = left_schema.merge(row);
                coalesce(&mut merged, using, right_alias);
                push_reference_row(&mut output, merged, &mut retained)?;
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Dataset {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex");
        Dataset::load_paths(&[root.join("alpha.dex"), root.join("beta.dex")]).unwrap()
    }

    fn parse(sql: &str) -> Query {
        let mut statements =
            sqlparser::parser::Parser::parse_sql(&super::super::expressions::Dialect {}, sql)
                .unwrap();
        let sqlparser::ast::Statement::Query(query) = statements.remove(0) else {
            panic!()
        };
        *query
    }

    fn run(sql: &str, ds: &Dataset, limit: Option<u64>) -> QueryResult {
        let query = parse(sql);
        let mut output = execute(
            &query,
            query.body.as_select().unwrap(),
            ds,
            &NamedCaches::default(),
            limit,
        )
        .expect("pipelined join")
        .unwrap();
        apply_query_order_limit(&mut output, &query, limit).unwrap();
        typed_to_result((
            output.columns,
            output.rows.into_iter().map(|row| row.values).collect(),
        ))
    }

    #[test]
    fn composite_keys_preserve_duplicates_and_dex_identity() {
        let ds = fixture();
        let all = run("SELECT a.file_id,a.method_idx,b.method_idx FROM methods a JOIN methods b ON a.method_idx=b.method_idx ORDER BY a.file_id,a.method_idx,b.file_id", &ds, None);
        let expected = ds
            .files
            .iter()
            .map(|file| file.methods.len())
            .sum::<usize>();
        assert!(
            all.rows.len() > expected,
            "fixture must exercise duplicate dex-local keys"
        );
        let exact = run("SELECT a.file_id,a.method_idx FROM methods a JOIN methods b ON a.file_id=b.file_id AND a.method_idx=b.method_idx ORDER BY a.file_id,a.method_idx", &ds, None);
        assert_eq!(exact.rows.len(), expected);
        let count = run("SELECT count(*) FROM methods a JOIN methods b ON a.method_idx=b.method_idx AND a.file_id=b.file_id", &ds, None);
        assert_eq!(count.rows, vec![vec![expected.to_string()]]);
    }

    #[test]
    fn joins_feed_aggregates_distinct_order_and_limits() {
        let ds = fixture();
        for sql in [
            "SELECT DISTINCT a.file_id,a.method_idx FROM methods a JOIN methods b ON a.method_idx=b.method_idx WHERE b.method_idx<>1 ORDER BY a.file_id,a.method_idx DESC LIMIT 4 OFFSET 1",
            "SELECT a.method_idx,b.name FROM methods a JOIN methods b ON b.method_idx=a.method_idx WHERE a.method_idx IN (0,2) ORDER BY a.method_idx,b.name LIMIT 3",
        ] {
            let query = parse(sql);
            // The old hash join loses self-join matches, so use its small
            // Cartesian evaluator as an independent nested-loop oracle.
            let oracle = parse(&sql
                .replace("JOIN methods b ON a.method_idx=b.method_idx WHERE", ", methods b WHERE a.method_idx=b.method_idx AND")
                .replace("JOIN methods b ON b.method_idx=a.method_idx WHERE", ", methods b WHERE b.method_idx=a.method_idx AND"));
            let select = oracle.body.as_select().unwrap();
            let mut materialized = execute_select_core(select, &ds, Some(&ds),
                &NamedCaches::default(), false, None, None).unwrap();
            apply_query_order_limit(&mut materialized, &query, None).unwrap();
            let expected = typed_to_result((materialized.columns,
                materialized.rows.into_iter().map(|row| row.values).collect()));
            let actual = run(sql, &ds, None);
            assert_eq!(actual.columns, expected.columns, "{sql}");
            assert_eq!(actual.rows, expected.rows, "{sql}");
        }
        let grouped = run("SELECT a.file_id,count(*),sum(a.method_idx),count(DISTINCT a.method_idx) FROM methods a JOIN methods b ON a.method_idx=b.method_idx GROUP BY a.file_id HAVING count(*)>0 ORDER BY a.file_id", &ds, None);
        let expected = ds
            .files
            .iter()
            .map(|file| {
                let mut count = 0usize;
                let mut sum = 0usize;
                for index in 0..file.methods.len() {
                    let matches = ds
                        .files
                        .iter()
                        .filter(|other| index < other.methods.len())
                        .count();
                    count += matches;
                    sum += matches * index;
                }
                vec![
                    file.file_id.to_string(),
                    count.to_string(),
                    sum.to_string(),
                    file.methods.len().to_string(),
                ]
            })
            .collect::<Vec<_>>();
        assert_eq!(grouped.rows, expected);
        let sql = "SELECT a.method_idx,b.file_id FROM methods a JOIN methods b ON a.method_idx=b.method_idx LIMIT 5 OFFSET 2";
        assert_eq!(run(sql, &ds, Some(1)).rows, run(sql, &ds, None).rows[..1]);
        assert!(run(sql, &ds, Some(0)).rows.is_empty());
    }

    #[test]
    fn multiway_and_comma_joins_keep_residuals_and_column_ownership() {
        let ds = fixture();
        let exact = run("SELECT a.file_id,a.method_idx FROM methods a JOIN method_ids b ON a.method_idx=b.method_idx AND a.file_id=b.file_id JOIN proto_ids p ON b.proto_idx=p.proto_idx AND b.file_id=p.file_id WHERE a.method_idx<3 ORDER BY a.file_id,a.method_idx", &ds, None);
        let expected = ds
            .files
            .iter()
            .enumerate()
            .flat_map(|(file_id, file)| {
                (0..file.methods.len().min(3))
                    .map(move |index| vec![file_id.to_string(), index.to_string()])
            })
            .collect::<Vec<_>>();
        assert_eq!(exact.rows, expected);
        let comma = run("SELECT a.file_id,a.method_idx FROM methods a,method_ids b WHERE a.file_id=b.file_id AND a.method_idx=b.method_idx AND method_idx<3 ORDER BY a.file_id,a.method_idx", &ds, None);
        assert_eq!(comma.rows, expected);
        let residual = run("SELECT a.method_idx FROM methods a JOIN method_ids b ON a.method_idx=b.method_idx AND a.file_id=b.file_id AND b.proto_idx>=0 ORDER BY a.method_idx", &ds, None);
        assert_eq!(
            residual.rows.len(),
            ds.files
                .iter()
                .map(|file| file.methods.len())
                .sum::<usize>()
        );
    }

    #[test]
    fn null_keys_do_not_join_and_empty_build_preserves_count() {
        let ds = fixture();
        let result = run(
            "SELECT count(*) FROM methods a JOIN methods b ON a.access_flags=b.access_flags",
            &ds,
            None,
        );
        let mut expected = 0;
        let mut values = Vec::new();
        streaming::visit_source(&ds, "methods", "a", &["access_flags"], None, |row| {
            values.push(row.get("access_flags").unwrap().clone());
            Ok(false)
        })
        .unwrap();
        for left in &values {
            for right in &values {
                if !matches!(left, Scalar::Null)
                    && !matches!(right, Scalar::Null)
                    && left.sql_eq(right)
                {
                    expected += 1;
                }
            }
        }
        assert_eq!(result.rows, vec![vec![expected.to_string()]]);
        assert_eq!(run("SELECT count(*) FROM methods a JOIN methods b ON a.method_idx=b.method_idx WHERE b.method_idx=-1", &ds, None).rows, vec![vec!["0".to_owned()]]);
    }

    #[test]
    fn compound_output_labels_use_one_based_ordering() {
        let ds = fixture();
        for sql in [
            "SELECT 1 AS n UNION ALL SELECT 3 ORDER BY n DESC",
            "SELECT 1 AS n UNION SELECT 3 ORDER BY n DESC",
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None)
                    .unwrap()
                    .rows,
                vec![vec!["3".to_owned()], vec!["1".to_owned()]]
            );
        }
    }

    #[test]
    fn bounded_cross_and_non_equality_joins_pull_until_satisfied() {
        let ds = fixture();
        for sql in [
            "SELECT a.file_id,a.method_idx,b.file_id,b.method_idx FROM methods a CROSS JOIN methods b LIMIT 3 OFFSET 2",
            "SELECT a.method_idx,b.method_idx FROM methods a JOIN methods b ON a.method_idx<b.method_idx LIMIT 3 OFFSET 1",
            "SELECT a.method_idx,b.method_idx FROM methods a,methods b WHERE b.method_idx>2 AND a.method_idx=1 LIMIT 4",
        ] {
            let query = parse(sql);
            let select = query.body.as_select().unwrap();
            let mut oracle = select.clone();
            // Move a non-equality ON to WHERE for the old nested-loop oracle.
            for table in &mut oracle.from {
                if let Some(join) = table.joins.first_mut() {
                    if let Some(expr) = join_constraint(&join.join_operator).unwrap() {
                        oracle.selection = Some(expr.clone());
                        join.join_operator = sqlparser::ast::JoinOperator::CrossJoin(sqlparser::ast::JoinConstraint::None);
                    }
                }
            }
            let mut expected = execute_select_core(&oracle, &ds, Some(&ds), &NamedCaches::default(), false, None, None).unwrap();
            apply_query_order_limit(&mut expected, &query, None).unwrap();
            assert_eq!(run(sql, &ds, None).rows, typed_to_result((expected.columns, expected.rows.into_iter().map(|row| row.values).collect())).rows, "{sql}");
        }
    }

    #[test]
    fn fingerprint_collisions_are_verified_against_borrowed_records() {
        let ds = fixture();
        let mut left = RelRow::default();
        left.put("a", "method_idx", Scalar::Int(0));
        let hash = row_hash(&left, ["a.method_idx"].into_iter()).unwrap();
        // Deliberately index a different source record under this fingerprint.
        let build = Build {
            rows: vec![(0, streaming::Source::Method(1))],
            matched: RefCell::new(vec![false]),
            index: FxHashMap::from_iter([(hash, Bucket { first: 0, last: 0 })]),
            next: vec![u32::MAX],
            cells: ds
                .files
                .iter()
                .map(|file| {
                    RefCell::new(streaming::Cells::new(
                        file,
                        "methods",
                        false,
                        &["method_idx"],
                    ))
                })
                .collect(),
            table: "methods".to_owned(),
            alias: "b".to_owned(),
            predicates: Vec::new(),
            lazy: false,
            locals: Vec::new(),
            columns: vec![(
                intern_rel_component("b.method_idx"),
                intern_rel_component("method_idx"),
            )],
        };
        let joins = [Join {
            kind: Kind::Inner,
            constraint: None,
            coalesce: Vec::new(),
            keys: vec![Pair {
                left: "a.method_idx".to_owned(),
                right: "b.method_idx".to_owned(),
                null_safe: false,
            }],
        }];
        let mut visited = 0;
        assert!(!probe(
            0,
            &left,
            &joins,
            &[build],
            &ds,
            false,
            &Cell::new(0),
            &mut |_| {
                visited += 1;
                Ok(false)
            }
        )
        .unwrap());
        assert_eq!(visited, 0);
    }

    #[test]
    fn fallback_derived_joins_keep_scalar_types_and_composite_keys() {
        let ds = fixture();
        for (sql, count) in [
            ("SELECT count(*) FROM (SELECT '1' AS k) a JOIN (SELECT 1 AS k) b ON a.k=b.k", "0"),
            ("SELECT count(*) FROM (SELECT 1 AS k) a JOIN (SELECT 1.0 AS k) b ON a.k=b.k", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k) a JOIN (SELECT NULL AS k) b ON a.k=b.k", "0"),
            ("WITH x AS (SELECT file_id,method_idx FROM methods) SELECT count(*) FROM x a JOIN x b ON a.file_id=b.file_id AND a.method_idx=b.method_idx", "28"),
        ] {
            assert_eq!(execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows, vec![vec![count.to_owned()]], "{sql}");
        }
    }

    #[test]
    fn fallback_comma_products_preserve_empty_inputs_at_each_position() {
        let ds = fixture();
        // Every expected result was checked against the original executable;
        // see artifacts/general/final-regression-oracle.json. Derived sources
        // force this through the generic product path rather than the pipeline.
        for (sql, expected) in [
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx<0) a, (SELECT 2 AS k) b", "0"),
            ("SELECT count(*) FROM (SELECT 1 AS k) a, (SELECT method_idx FROM methods WHERE method_idx<0) b, (SELECT 2 AS k) c", "0"),
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx=0) a, (SELECT method_idx FROM methods WHERE method_idx<0) b", "0"),
            ("SELECT count(*) FROM (SELECT method_idx FROM methods WHERE method_idx=0) a, (SELECT 2 AS k) b, (SELECT 3 AS k) c", "2"),
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows,
                vec![vec![expected.to_owned()]],
                "{sql}",
            );
        }
    }

    #[test]
    fn set_membership_preserves_numeric_equality_and_null_type_identity() {
        let ds = fixture();
        // Include source-backed operands so reduced streaming set operands and
        // typed derived results use the same numeric/NULL equality contract.
        for (sql, expected) in [
            ("SELECT count(*) FROM (SELECT 1 AS k INTERSECT SELECT 1.0) t", "1"),
            ("SELECT count(*) FROM (SELECT 1 AS k EXCEPT SELECT 1.0) t", "0"),
            ("SELECT count(*) FROM (SELECT 0 AS k INTERSECT SELECT -0.0) t", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k INTERSECT SELECT 'NULL') t", "0"),
            ("SELECT count(*) FROM (SELECT NULL AS k EXCEPT SELECT 'NULL') t", "1"),
            ("SELECT count(*) FROM (SELECT NULL AS k INTERSECT SELECT NULL) t", "1"),
            ("SELECT count(*) FROM (SELECT method_idx AS k FROM methods WHERE method_idx=0 INTERSECT SELECT 0.0) t", "1"),
            ("SELECT count(*) FROM (SELECT method_idx AS k FROM methods WHERE method_idx=0 EXCEPT SELECT 0.0) t", "0"),
            ("SELECT count(*) FROM (SELECT 9007199254740993 AS k INTERSECT SELECT 9007199254740992.0) t", "0"),
        ] {
            assert_eq!(
                execute_statement(sql, Some(&ds), &NamedCaches::default(), None).unwrap().rows,
                vec![vec![expected.to_owned()]],
                "{sql}",
            );
        }
    }

    #[test]
    fn source_outer_joins_null_extend_after_on_and_before_where() {
        let ds = fixture();
        let classes = ds
            .files
            .iter()
            .map(|file| file.classes.len())
            .sum::<usize>();
        let methods = ds
            .files
            .iter()
            .map(|file| file.methods.len())
            .sum::<usize>();
        for (sql, expected) in [
            ("SELECT count(*) FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx AND m.name='absent'", classes),
            ("SELECT count(*) FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx AND m.name='absent' WHERE m.method_idx IS NULL", classes),
            ("SELECT count(*) FROM classes c RIGHT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx AND m.name='absent'", methods),
            ("SELECT count(*) FROM classes c FULL OUTER JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx AND m.name='absent'", classes + methods),
            ("SELECT count(m.method_idx) FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx AND m.name='absent'", 0),
        ] {
            assert_eq!(run(sql, &ds, None).rows, vec![vec![expected.to_string()]], "{sql}");
        }
        let sql = "SELECT c.file_id,c.class_idx,m.method_idx FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx WHERE m.method_idx IS NULL ORDER BY c.file_id,c.class_idx";
        let expected = ds
            .files
            .iter()
            .flat_map(|file| {
                file.classes
                    .iter()
                    .filter(|class| {
                        !file
                            .methods
                            .iter()
                            .any(|method| method.class_idx as u32 == class.class_idx)
                    })
                    .map(move |class| {
                        vec![
                            file.file_id.to_string(),
                            class.class_idx.to_string(),
                            "NULL".to_owned(),
                        ]
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(run(sql, &ds, None).rows, expected);
    }

    #[test]
    fn source_using_natural_non_equality_and_null_safe_keys_are_complete() {
        let ds = fixture();
        let methods = ds
            .files
            .iter()
            .map(|file| file.methods.len())
            .sum::<usize>();
        let classes = ds
            .files
            .iter()
            .map(|file| file.classes.len())
            .sum::<usize>();
        assert_eq!(
            run(
                "SELECT count(*) FROM methods a JOIN methods b USING(file_id,method_idx)",
                &ds,
                None
            )
            .rows,
            vec![vec![methods.to_string()]]
        );
        assert_eq!(
            run(
                "SELECT count(*) FROM classes a NATURAL JOIN classes b",
                &ds,
                None
            )
            .rows,
            vec![vec![classes.to_string()]]
        );
        let mut class_rows = Vec::new();
        for file in &ds.files {
            for class in &file.classes {
                class_rows.push((file.file_id, class.class_idx));
            }
        }
        let less = class_rows
            .iter()
            .map(|(_, a)| class_rows.iter().filter(|(_, b)| a < b).count())
            .sum::<usize>();
        let either = class_rows
            .iter()
            .map(|(af, a)| {
                class_rows
                    .iter()
                    .filter(|(bf, b)| a == b || af == bf)
                    .count()
            })
            .sum::<usize>();
        assert_eq!(
            run(
                "SELECT count(*) FROM classes a JOIN classes b ON a.class_idx<b.class_idx",
                &ds,
                None
            )
            .rows,
            vec![vec![less.to_string()]]
        );
        assert_eq!(run("SELECT count(*) FROM classes a JOIN classes b ON a.class_idx=b.class_idx OR a.file_id=b.file_id",&ds,None).rows,vec![vec![either.to_string()]]);
        let mut flags = Vec::new();
        streaming::visit_source(&ds, "methods", "a", &["access_flags"], None, |row| {
            flags.push(row.get("access_flags").unwrap().clone());
            Ok(false)
        })
        .unwrap();
        let expected = flags
            .iter()
            .map(|a| {
                flags
                    .iter()
                    .filter(|b| membership::set_key(a) == membership::set_key(b))
                    .count()
            })
            .sum::<usize>();
        assert_eq!(
            run(
                "SELECT count(*) FROM methods a JOIN methods b ON a.access_flags IS b.access_flags",
                &ds,
                None
            )
            .rows,
            vec![vec![expected.to_string()]]
        );
    }

    #[test]
    fn fallback_outer_joins_keep_empty_schema_and_using_coalesced_values() {
        let ds = fixture();
        for (sql, expected) in [
            ("SELECT a.k,b.k FROM (SELECT 1 AS k WHERE 0) a FULL OUTER JOIN (SELECT 2 AS k) b ON a.k=b.k", vec![vec!["NULL","2"]]),
            ("SELECT a.k,b.k FROM (SELECT 1 AS k) a LEFT JOIN (SELECT 2 AS k WHERE 0) b ON a.k=b.k", vec![vec!["1","NULL"]]),
            ("SELECT k,a.k,b.k FROM (SELECT 1 AS k) a FULL OUTER JOIN (SELECT 2 AS k) b USING(k) ORDER BY k", vec![vec!["1","1","NULL"],vec!["2","NULL","2"]]),
            ("SELECT a.k,b.k FROM (SELECT NULL AS k UNION ALL SELECT 1) a JOIN (SELECT NULL AS k UNION ALL SELECT 1) b ON a.k IS b.k ORDER BY a.k", vec![vec!["NULL","NULL"],vec!["1","1"]]),
            ("SELECT a.k,b.k FROM (SELECT 1 AS k UNION ALL SELECT 2) a JOIN (SELECT 2 AS k UNION ALL SELECT 3) b ON a.k<b.k ORDER BY a.k,b.k", vec![vec!["1","2"],vec!["1","3"],vec!["2","3"]]),
        ] {
            let expected = expected.into_iter().map(|row| row.into_iter().map(str::to_owned).collect::<Vec<_>>()).collect::<Vec<_>>();
            assert_eq!(execute_statement(sql,Some(&ds),&NamedCaches::default(),None).unwrap().rows,expected,"{sql}");
        }
    }

    #[test]
    fn full_join_unmatched_rows_feed_subsequent_outer_join_levels_once() {
        let ds = fixture();
        let sql = "SELECT a.file_id,b.file_id,c.file_id FROM dex_files a FULL OUTER JOIN dex_files b ON a.file_id=b.file_id+10 FULL OUTER JOIN dex_files c ON b.file_id=c.file_id ORDER BY a.file_id,b.file_id,c.file_id";
        assert_eq!(
            run(sql, &ds, None).rows,
            vec![
                vec!["NULL".to_owned(), "0".to_owned(), "0".to_owned()],
                vec!["NULL".to_owned(), "1".to_owned(), "1".to_owned()],
                vec!["0".to_owned(), "NULL".to_owned(), "NULL".to_owned()],
                vec!["1".to_owned(), "NULL".to_owned(), "NULL".to_owned()],
            ]
        );
    }

    #[test]
    fn method_identity_join_preserves_edge_scan_order_from_either_sql_side() {
        let ds = fixture();
        let mut expected = ds
            .files
            .iter()
            .flat_map(|file| {
                file.method_strings
                    .iter()
                    .enumerate()
                    .map(move |(ordinal, edge)| {
                        (edge.method_idx, file.file_id, ordinal, edge.string_idx)
                    })
            })
            .collect::<Vec<_>>();
        expected.sort_by_key(|(method, file, ordinal, _)| (*method, *file, *ordinal));
        let expected = expected
            .into_iter()
            .take(7)
            .map(|(method, file, _, string)| {
                vec![file.to_string(), method.to_string(), string.to_string()]
            })
            .collect::<Vec<_>>();
        for sql in [
            "SELECT m.file_id,m.method_idx,s.string_idx FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx LIMIT 7",
            "SELECT m.file_id,m.method_idx,s.string_idx FROM method_strings s JOIN methods m ON s.method_idx=m.method_idx AND s.file_id=m.file_id LIMIT 7",
        ] {
            assert_eq!(run(sql,&ds,None).rows,expected,"{sql}");
        }
        let mut source = Vec::new();
        streaming::visit_source(
            &ds,
            "method_strings",
            "s",
            &["file_id", "method_idx", "string_idx"],
            None,
            |row| {
                source.push(
                    ["file_id", "method_idx", "string_idx"]
                        .iter()
                        .map(|column| row.get(column).unwrap().display())
                        .collect::<Vec<_>>(),
                );
                Ok(source.len() == 7)
            },
        )
        .unwrap();
        assert_eq!(source, expected);
    }

    fn run_fused(sql: &str, ds: &Dataset) -> Option<QueryResult> {
        let query = parse(sql);
        let select = query.body.as_select().unwrap();
        let caches = NamedCaches::default();
        let table = &select.from[0];
        let sources = [
            source(&table.relation, &caches)?,
            source(&table.joins[0].relation, &caches)?,
        ];
        let (kind, constraint) = parts(&table.joins[0].join_operator).unwrap();
        let expression = match constraint {
            JoinConstraint::On(expr) => Some(expr.clone()),
            _ => None,
        };
        let join = Join {
            kind,
            constraint: expression,
            keys: Vec::new(),
            coalesce: Vec::new(),
        };
        let mut output = execute_identity(&query, select, &sources, &[join], ds, None)?.unwrap();
        apply_query_order_limit(&mut output, &query, None).unwrap();
        Some(typed_to_result((
            output.columns,
            output.rows.into_iter().map(|row| row.values).collect(),
        )))
    }

    #[test]
    fn fused_method_identity_join_matches_independent_materialized_execution() {
        let ds = fixture();
        for table in [
            "method_strings",
            "method_calls",
            "method_field_accesses",
            "method_used_types",
            "method_numbers",
            "method_using_numbers",
        ] {
            let edge_column = if table == "method_numbers" {
                "opcode"
            } else {
                "method_name"
            };
            for sql in [
                format!("SELECT m.file_id,m.method_idx,m.name,e.{edge_column} FROM methods m JOIN {table} e ON m.file_id=e.file_id AND m.method_idx=e.method_idx ORDER BY m.file_id,m.method_idx,e.{edge_column}"),
                format!("SELECT m.file_id,m.method_idx,count(*) AS n FROM methods m JOIN {table} e ON m.file_id=e.file_id AND m.method_idx=e.method_idx GROUP BY m.file_id,m.method_idx ORDER BY n DESC,m.file_id,m.method_idx LIMIT 3"),
                format!("SELECT e.file_id,m.method_idx,m.name FROM {table} e JOIN methods m ON e.file_id=m.file_id AND e.method_idx=m.method_idx AND m.method_idx<8 WHERE m.name<>'absent' ORDER BY e.file_id,m.method_idx,m.name LIMIT 4 OFFSET 1"),
                format!("SELECT e.file_id,m.method_idx,m.name FROM {table} e JOIN methods m ON e.method=m.descriptor WHERE e.file_id=m.file_id AND m.method_idx<8 ORDER BY e.file_id,m.method_idx,m.name LIMIT 4 OFFSET 1"),
            ] {
                if table == "method_numbers" && sql.contains("e.method=m.descriptor") { continue; }
                let query = parse(&sql);
                let mut expected = execute_select_core(query.body.as_select().unwrap(),&ds,Some(&ds),&NamedCaches::default(),false,None,None).unwrap_or_else(|error| panic!("{sql}: {error}"));
                apply_query_order_limit(&mut expected,&query,None).unwrap();
                let expected = typed_to_result((expected.columns,expected.rows.into_iter().map(|row|row.values).collect()));
                let actual = run_fused(&sql,&ds).expect("identity proof must select the fused execution");
                assert_eq!(actual.columns,expected.columns,"{sql}");
                assert_eq!(actual.rows,expected.rows,"{sql}");
            }
        }
        for sql in [
            "SELECT m.file_id,m.method_idx,e.string_idx FROM methods m JOIN method_strings e ON m.file_id=e.file_id AND m.method_idx=e.method_idx LIMIT 7",
            "SELECT m.file_id,m.method_idx,e.string_idx FROM method_strings e JOIN methods m ON e.method=m.descriptor AND e.file_id=m.file_id LIMIT 7",
        ] {
            let actual = run_fused(sql,&ds).unwrap();
            let mut expected = Vec::new();
            streaming::visit_source(&ds,"method_strings","e",&["file_id","method_idx","string_idx"],None,|row| {
                expected.push(["file_id","method_idx","string_idx"].iter().map(|column|row.get(column).unwrap().display()).collect::<Vec<_>>());
                Ok(expected.len()==7)
            }).unwrap();
            assert_eq!(actual.rows,expected,"{sql}");
        }
    }

    #[test]
    fn identity_fusion_rejects_incomplete_and_nonunique_descriptor_proofs() {
        let mut ds = fixture();
        for sql in [
            "SELECT count(*) FROM methods m JOIN method_strings e ON m.method_idx=e.method_idx",
            "SELECT count(*) FROM methods m JOIN method_strings e ON m.descriptor=e.method",
            "SELECT count(*) FROM methods m LEFT JOIN method_strings e ON m.file_id=e.file_id AND m.method_idx=e.method_idx",
        ] { assert!(run_fused(sql,&ds).is_none(),"{sql}"); }
        let sql = "SELECT count(*) FROM methods m JOIN method_strings e ON m.file_id=e.file_id AND m.descriptor=e.method";
        assert!(run_fused(sql, &ds).is_some());
        let duplicate = ds.files[0].methods[0];
        ds.files[0].methods.push(duplicate);
        assert!(
            run_fused(sql, &ds).is_none(),
            "descriptor duplicates must retain ordinary join multiplicity"
        );
    }
}
