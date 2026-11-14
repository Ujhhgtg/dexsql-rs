use super::*;
use sqlparser::ast::{BinaryOperator, Expr, GroupByExpr, Select, SetExpr};

fn contains_subquery(expr: &Expr) -> bool {
    let mut found = false;
    let supported = streaming::walk(&mut expr.clone(), &mut |expr| {
        if matches!(
            expr,
            Expr::InSubquery { .. } | Expr::Exists { .. } | Expr::Subquery(_)
        ) {
            found = true;
            Some(true)
        } else {
            Some(false)
        }
    });
    found || supported.is_none()
}

fn conjunction(expressions: impl IntoIterator<Item = Expr>) -> Option<Expr> {
    expressions
        .into_iter()
        .reduce(|left, right| Expr::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::And,
            right: Box::new(right),
        })
}

fn unnest(expr: &Expr) -> &Expr {
    match expr {
        Expr::Nested(expr) => unnest(expr),
        expr => expr,
    }
}

fn narrow(
    atom: &Expr,
    select: &Select,
    predicates: &[Expr],
    ds: &Dataset,
    caches: &NamedCaches,
) -> Option<Expr> {
    let Expr::InSubquery {
        expr: value,
        subquery,
        negated,
    } = unnest(atom)
    else {
        return None;
    };
    if *negated
        || predicates.is_empty()
        || !matches!(
            unnest(value),
            Expr::Identifier(_) | Expr::CompoundIdentifier(_)
        )
        || select.from.len() != 1
        || !select.from[0].joins.is_empty()
        || subquery.with.is_some()
        || subquery.limit_clause.is_some()
        || subquery.fetch.is_some()
    {
        return None;
    }
    let inner = subquery.body.as_select()?;
    if inner.from.len() != 1
        || !inner.from[0].joins.is_empty()
        || inner.projection.len() != 1
        || inner.top.is_some()
        || inner.qualify.is_some()
        || !inner.named_window.is_empty()
        || matches!(inner.distinct, Some(sqlparser::ast::Distinct::On(_)))
    {
        return None;
    }
    let projected = item_expr(&inner.projection[0])?;
    if !matches!(
        unnest(projected),
        Expr::Identifier(_) | Expr::CompoundIdentifier(_)
    ) {
        return None;
    }
    let GroupByExpr::Expressions(groups, modifiers) = &inner.group_by else {
        return None;
    };
    if !modifiers.is_empty()
        || (groups.is_empty() && inner.having.is_some())
        || (!groups.is_empty()
            && !groups
                .iter()
                .any(|group| group.to_string() == projected.to_string()))
    {
        return None;
    }
    let probe_sql = format!("SELECT DISTINCT {value} FROM {}", select.from[0].relation);
    let mut statements =
        sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::SQLiteDialect {}, &probe_sql)
            .ok()?;
    let sqlparser::ast::Statement::Query(mut probe) = statements.pop()? else {
        return None;
    };
    let SetExpr::Select(probe_select) = probe.body.as_mut() else {
        return None;
    };
    probe_select.selection = conjunction(predicates.iter().cloned());
    let output =
        streaming::execute(&probe, probe.body.as_select()?, ds, caches, Some(4097))?.ok()?;
    if output.rows.len() > 4096 {
        return None;
    }
    let domain = output
        .rows
        .into_iter()
        .map(|row| scalar_literal(row.values.into_iter().next().unwrap_or(Scalar::Null)))
        .collect();
    let restriction = Expr::InList {
        expr: Box::new(projected.clone()),
        list: domain,
        negated: false,
    };
    let mut subquery = subquery.clone();
    let SetExpr::Select(inner) = subquery.body.as_mut() else {
        return None;
    };
    inner.selection = conjunction(std::iter::once(restriction).chain(inner.selection.take()));
    Some(Expr::InSubquery {
        expr: value.clone(),
        subquery,
        negated: *negated,
    })
}

pub(super) fn selection(
    select: &Select,
    ds: &Dataset,
    source_dataset: Option<&Dataset>,
    caches: &NamedCaches,
    aliases: &HashSet<String>,
) -> Result<Option<Expr>, String> {
    let Some(selection) = &select.selection else {
        return Ok(None);
    };
    let mut atoms = Vec::new();
    flatten_and(selection, &mut atoms);
    let (plain, mut nested): (Vec<_>, Vec<_>) =
        atoms.into_iter().partition(|atom| !contains_subquery(atom));
    nested.sort_by_key(|atom| atom.to_string().contains("opcode_hex"));
    let mut predicates = plain.into_iter().cloned().collect::<Vec<_>>();
    for atom in nested {
        let narrowed = narrow(atom, select, &predicates, ds, caches);
        predicates.push(desugar_expr(
            narrowed.as_ref().unwrap_or(atom),
            ds,
            source_dataset,
            caches,
            aliases,
        )?);
    }
    Ok(conjunction(predicates))
}
