//! Fuse a row-local derived projection with its consumer before scanning.
//! This propagates column demand through views such as SELECT * without ever
//! decoding their unused descriptors, opcode streams or result rows.
use super::*;
use sqlparser::ast::{Expr, GroupByExpr, Query, Select, SelectItem, TableFactor};

fn mapped(expr: &Expr, alias: &str, columns: &HashMap<String, Expr>) -> Option<Expr> {
    let mut expr = expr.clone();
    streaming::walk(&mut expr, &mut |expr| {
        let name = match expr {
            Expr::Identifier(name) => Some(name.value.to_ascii_lowercase()),
            Expr::CompoundIdentifier(parts)
                if parts.len() == 2 && parts[0].value.eq_ignore_ascii_case(alias) =>
            {
                Some(parts[1].value.to_ascii_lowercase())
            }
            Expr::CompoundIdentifier(_) => return None,
            _ => None,
        };
        if let Some(name) = name {
            if let Some(value) = columns.get(&name) {
                *expr = value.clone();
            }
            // HAVING/ORDER BY aliases are resolved by the projection sink.
            return Some(true);
        }
        Some(false)
    })?;
    Some(expr)
}

pub(super) fn inline(select: &Select) -> Option<Select> {
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    let TableFactor::Derived {
        subquery,
        alias,
        lateral,
        ..
    } = &select.from[0].relation
    else {
        return None;
    };
    if *lateral
        || subquery.with.is_some()
        || subquery.order_by.is_some()
        || subquery.limit_clause.is_some()
        || subquery.fetch.is_some()
        || !subquery.locks.is_empty()
        || !subquery.pipe_operators.is_empty()
    {
        return None;
    }
    let inner = subquery.body.as_select()?;
    if inner.from.len() != 1
        || !inner.from[0].joins.is_empty()
        || inner.distinct.is_some()
        || inner.having.is_some()
        || inner
            .projection
            .iter()
            .any(|item| item_expr(item).is_some_and(item_has_aggregate))
        || !matches!(&inner.group_by, GroupByExpr::Expressions(exprs, modifiers) if exprs.is_empty() && modifiers.is_empty())
        || inner.prewhere.is_some()
        || !inner.lateral_views.is_empty()
        || !inner.named_window.is_empty()
        || inner.qualify.is_some()
        || inner.top.is_some()
        || inner.into.is_some()
        || !inner.connect_by.is_empty()
        || !inner.cluster_by.is_empty()
        || !inner.distribute_by.is_empty()
        || !inner.sort_by.is_empty()
    {
        return None;
    }
    let TableFactor::Table {
        name,
        alias: source_alias,
        args,
        ..
    } = &inner.from[0].relation
    else {
        return None;
    };
    if args.is_some()
        || name.0.len() != 1
        || source_alias
            .as_ref()
            .is_some_and(|alias| !alias.columns.is_empty())
    {
        return None;
    }
    let table = name.0.last()?.as_ident()?.value.to_ascii_lowercase();
    if !streaming::supports_table(&table) {
        return None;
    }
    let schema = dexsql_schema::TABLES
        .iter()
        .find(|schema| schema.name == table)?;
    let source_alias = source_alias
        .as_ref()
        .map(|alias| alias.name.value.as_str())
        .unwrap_or(&table);
    let derived_alias = alias
        .as_ref()
        .map(|alias| alias.name.value.as_str())
        .unwrap_or("");
    let mut output = Vec::<(String, Expr)>::new();
    for item in &inner.projection {
        match item {
            SelectItem::UnnamedExpr(expr) => output.push((expression_label(expr), expr.clone())),
            SelectItem::ExprWithAlias { expr, alias } => {
                output.push((alias.value.clone(), expr.clone()))
            }
            SelectItem::Wildcard(options) if *options == Default::default() => {
                for column in schema.columns {
                    if table == "classes" && matches!(column.name, "field_count" | "method_count") {
                        continue;
                    }
                    output.push((
                        column.name.to_owned(),
                        Expr::CompoundIdentifier(vec![
                            sqlparser::ast::Ident::new(source_alias),
                            sqlparser::ast::Ident::new(column.name),
                        ]),
                    ));
                }
            }
            SelectItem::QualifiedWildcard(
                sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                options,
            ) if *options == Default::default()
                && name.to_string().eq_ignore_ascii_case(source_alias) =>
            {
                for column in schema.columns {
                    if table == "classes" && matches!(column.name, "field_count" | "method_count") {
                        continue;
                    }
                    output.push((
                        column.name.to_owned(),
                        Expr::CompoundIdentifier(vec![
                            sqlparser::ast::Ident::new(source_alias),
                            sqlparser::ast::Ident::new(column.name),
                        ]),
                    ));
                }
            }
            _ => return None,
        }
    }
    if let Some(alias) = alias {
        for ((name, _), column) in output.iter_mut().zip(&alias.columns) {
            *name = column.name.value.clone();
        }
    }
    let mut columns = HashMap::new();
    for (name, expr) in &output {
        if columns
            .insert(name.to_ascii_lowercase(), expr.clone())
            .is_some()
        {
            return None;
        }
    }
    let mut fused = select.clone();
    fused.projection = select
        .projection
        .iter()
        .map(|item| {
            Some(match item {
                SelectItem::UnnamedExpr(expr) => SelectItem::ExprWithAlias {
                    expr: mapped(expr, derived_alias, &columns)?,
                    alias: sqlparser::ast::Ident::new(expression_label(expr)),
                },
                SelectItem::ExprWithAlias { expr, alias } => SelectItem::ExprWithAlias {
                    expr: mapped(expr, derived_alias, &columns)?,
                    alias: alias.clone(),
                },
                _ => return None,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    if let Some(expr) = &select.selection {
        fused.selection = Some(mapped(expr, derived_alias, &columns)?);
    }
    if let Some(expr) = &select.having {
        fused.having = Some(mapped(expr, derived_alias, &columns)?);
    }
    if let GroupByExpr::Expressions(exprs, _) = &mut fused.group_by {
        for expr in exprs {
            *expr = mapped(expr, derived_alias, &columns)?;
        }
    }
    fused.selection = match (inner.selection.clone(), fused.selection) {
        (Some(left), Some(right)) => Some(Expr::BinaryOp {
            left: Box::new(left),
            op: sqlparser::ast::BinaryOperator::And,
            right: Box::new(right),
        }),
        (Some(expr), None) | (None, Some(expr)) => Some(expr),
        _ => None,
    };
    fused.from = inner.from.clone();
    Some(fused)
}

/// Apply the same rewrite before determining loader data/column requirements.
pub(super) fn query(query: &Query) -> Option<Query> {
    let select = query.body.as_select()?;
    let fused = inline(select)?;
    // ORDER BY may reference unprojected derived output columns. Use a
    // temporary SELECT projection to route them through the same mapping.
    let mut query = query.clone();
    if let Some(order) = &mut query.order_by {
        let sqlparser::ast::OrderByKind::Expressions(items) = &mut order.kind else {
            return None;
        };
        for item in items {
            let mut probe = select.clone();
            probe.projection = vec![SelectItem::UnnamedExpr(item.expr.clone())];
            let mapped = inline(&probe)?;
            item.expr = item_expr(&mapped.projection[0])?.clone();
        }
    }
    query.body = Box::new(sqlparser::ast::SetExpr::Select(Box::new(fused)));
    Some(query)
}
