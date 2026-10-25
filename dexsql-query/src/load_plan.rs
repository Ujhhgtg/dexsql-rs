//! Batch-wide proofs for dropping unobserved metadata during loading.
use super::*;
use sqlparser::ast::{
    Expr, GroupByExpr, JoinConstraint, JoinOperator, Query, SelectItem, Statement, TableFactor,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LoadPlan {
    pub omit_class_members: bool,
    pub omit_pools: bool,
}
impl LoadPlan {
    const FULL: Self = Self {
        omit_class_members: false,
        omit_pools: false,
    };
}

fn query_plan(query: &Query) -> Option<LoadPlan> {
    if query.with.is_some() {
        return None;
    }
    if let sqlparser::ast::SetExpr::SetOperation { left, right, .. } = query.body.as_ref() {
        // Set-level ORDER BY consumes output cells; all native dependencies
        // belong to the operand projections/filters. Demand is the union of
        // both operands, including UNION ALL's independently loaded inputs.
        let mut operand = query.clone();
        operand.order_by = None;
        operand.body = left.clone();
        let left = query_plan(&operand)?;
        operand.body = right.clone();
        let right = query_plan(&operand)?;
        return Some(LoadPlan {
            omit_class_members: left.omit_class_members && right.omit_class_members,
            omit_pools: left.omit_pools && right.omit_pools,
        });
    }
    if let sqlparser::ast::SetExpr::Query(inner) = query.body.as_ref() {
        return query_plan(inner);
    }
    let select = query.body.as_select()?;
    let mut sources = Vec::<(String, String)>::new();
    for source in &select.from {
        for factor in
            std::iter::once(&source.relation).chain(source.joins.iter().map(|join| &join.relation))
        {
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
            let name = name.0[0].as_ident()?.value.to_ascii_lowercase();
            if !matches!(
                name.as_str(),
                "methods"
                    | "method_ids"
                    | "classes"
                    | "class_defs"
                    | "fields"
                    | "field_ids"
                    | "method_strings"
                    | "method_calls"
                    | "method_numbers"
                    | "method_using_numbers"
                    | "method_used_types"
                    | "method_field_accesses"
                    | "strings"
                    | "type_ids"
                    | "types"
                    | "proto_ids"
                    | "protos"
            ) {
                return None;
            }
            let alias = alias
                .as_ref()
                .map(|alias| alias.name.value.to_ascii_lowercase())
                .unwrap_or_else(|| name.clone());
            if sources.iter().any(|(_, owner)| *owner == alias) {
                return None;
            }
            sources.push((name, alias));
        }
    }
    if sources.is_empty() {
        return None;
    }
    let aliases = select
        .projection
        .iter()
        .filter_map(|item| match item {
            SelectItem::ExprWithAlias { expr, alias } => {
                Some((alias.value.to_ascii_lowercase(), expr))
            }
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let mut columns = Vec::<(String, String)>::new();
    let mut collect = |expr: &Expr, resolve: bool| -> Option<()> {
        let mut expr = expr.clone();
        if resolve {
            if let Expr::Identifier(name) = &expr {
                if let Some(alias) = aliases.get(&name.value.to_ascii_lowercase()) {
                    expr = (*alias).clone();
                }
            }
        }
        streaming::walk(&mut expr, &mut |node| {
            let (owner, column) = match node {
                Expr::Identifier(name) => (None, name.value.to_ascii_lowercase()),
                Expr::CompoundIdentifier(parts) if parts.len() == 2 => (
                    Some(parts[0].value.to_ascii_lowercase()),
                    parts[1].value.to_ascii_lowercase(),
                ),
                Expr::CompoundIdentifier(_) | Expr::Wildcard(_) | Expr::QualifiedWildcard(_, _) => {
                    return None
                }
                _ => return Some(false),
            };
            let table = sources
                .iter()
                .find(|(table, alias)| {
                    owner.as_ref().is_none_or(|owner| owner == alias)
                        && dexsql_schema::TABLES
                            .iter()
                            .find(|schema| schema.name == *table)
                            .is_some_and(|schema| {
                                schema.columns.iter().any(|meta| meta.name == column)
                            })
                })?
                .0
                .clone();
            columns.push((table, column));
            Some(true)
        })
    };
    for item in &select.projection {
        let expr = item_expr(item)?;
        collect(expr, false)?;
    }
    for expr in select.selection.iter() {
        collect(expr, false)?;
    }
    for expr in select.having.iter() {
        collect(expr, true)?;
    }
    let GroupByExpr::Expressions(group, modifiers) = &select.group_by else {
        return None;
    };
    if !modifiers.is_empty() {
        return None;
    }
    for expr in group {
        collect(expr, true)?;
    }
    if let Some(order) = &query.order_by {
        let sqlparser::ast::OrderByKind::Expressions(order) = &order.kind else {
            return None;
        };
        for entry in order {
            collect(&entry.expr, true)?;
        }
    }
    for source in &select.from {
        for join in &source.joins {
            let constraint = match &join.join_operator {
                JoinOperator::Join(c)
                | JoinOperator::Inner(c)
                | JoinOperator::Left(c)
                | JoinOperator::LeftOuter(c)
                | JoinOperator::Right(c)
                | JoinOperator::RightOuter(c)
                | JoinOperator::FullOuter(c)
                | JoinOperator::CrossJoin(c) => c,
                _ => return None,
            };
            match constraint {
                JoinConstraint::On(expr) => collect(expr, false)?,
                JoinConstraint::None => {}
                _ => return None,
            }
        }
    }
    let omit_class_members = !columns.iter().any(|(table, column)| match table.as_str() {
        "classes" => matches!(column.as_str(), "field_count" | "method_count"),
        "methods" => matches!(
            column.as_str(),
            "access_flags" | "method_kind" | "opcode_count" | "opcode_hex"
        ),
        _ => false,
    });
    // Only these ID relations can be served without the type/proto/string
    // pools. Restrict every column too: param_count and method text may be
    // referenced solely in WHERE, JOIN, GROUP BY, HAVING or ORDER BY.
    let omit_pools = sources.iter().all(|(table, _)| {
        matches!(
            table.as_str(),
            "methods"
                | "method_ids"
                | "classes"
                | "class_defs"
                | "fields"
                | "field_ids"
                | "method_strings"
                | "method_calls"
                | "method_numbers"
                | "method_using_numbers"
                | "method_used_types"
                | "method_field_accesses"
        )
    }) && columns.iter().all(|(table, column)| match table.as_str() {
        "methods" | "method_ids" => matches!(
            column.as_str(),
            "file_id"
                | "method_idx"
                | "class_idx"
                | "proto_idx"
                | "name_idx"
                | "access_flags"
                | "method_kind"
                | "opcode_count"
                | "opcode_hex"
        ),
        "classes" | "class_defs" => matches!(
            column.as_str(),
            "file_id"
                | "class_idx"
                | "class_def_idx"
                | "access_flags"
                | "superclass_idx"
                | "source_file_idx"
                | "class_data_off"
                | "annotations_off"
                | "interfaces_off"
                | "static_values_off"
                | "field_count"
                | "method_count"
        ),
        "fields" | "field_ids" => matches!(
            column.as_str(),
            "file_id" | "field_idx" | "class_idx" | "type_idx" | "name_idx"
        ),
        _ => matches!(
            column.as_str(),
            "file_id"
                | "method_idx"
                | "class_idx"
                | "string_idx"
                | "callee_method_idx"
                | "field_idx"
                | "type_idx"
                | "opcode"
                | "number_type"
                | "long_value"
                | "double_value"
        ),
    });
    Some(LoadPlan {
        omit_class_members,
        omit_pools,
    })
}

pub(super) fn plan_batch(sqls: &[String]) -> LoadPlan {
    if sqls.is_empty() {
        return LoadPlan::FULL;
    }
    let mut plan = LoadPlan {
        omit_class_members: true,
        omit_pools: true,
    };
    for sql in sqls {
        let Ok(mut statements) =
            sqlparser::parser::Parser::parse_sql(&expressions::Dialect {}, sql)
        else {
            return LoadPlan::FULL;
        };
        if statements.len() != 1 {
            return LoadPlan::FULL;
        }
        let Statement::Query(query) = statements.remove(0) else {
            return LoadPlan::FULL;
        };
        let Some(next) = query_plan(&query) else {
            return LoadPlan::FULL;
        };
        plan.omit_class_members &= next.omit_class_members;
        plan.omit_pools &= next.omit_pools;
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(sqls: &[&str]) -> LoadPlan {
        plan_batch(&sqls.iter().map(|sql| sql.to_string()).collect::<Vec<_>>())
    }
    #[test]
    fn every_dependency_and_batch_statement_controls_omission() {
        let raw = "SELECT c.file_id,c.class_idx FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx WHERE m.method_idx IS NULL ORDER BY c.file_id,c.class_idx LIMIT 20";
        assert_eq!(
            plan(&[raw]),
            LoadPlan {
                omit_class_members: true,
                omit_pools: true
            }
        );
        for sql in [
            "SELECT m.name FROM methods m",
            "SELECT method_idx FROM methods ORDER BY length(name)",
            "SELECT method_idx FROM methods WHERE name='x'",
            "SELECT class_idx,count(*) FROM methods GROUP BY class_idx HAVING max(length(name))>0",
        ] {
            assert!(!plan(&[raw, sql]).omit_pools, "{sql}");
            assert!(!plan(&[sql, raw]).omit_pools, "{sql}");
        }
        assert!(!plan(&["SELECT method_count FROM classes"]).omit_class_members);
        assert!(!plan(&["SELECT opcode_count FROM methods"]).omit_class_members);
        assert!(!plan(&["SELECT method_idx FROM methods WHERE access_flags=1"]).omit_class_members);
        assert_eq!(plan(&["SELECT * FROM methods"]), LoadPlan::FULL);
        assert_eq!(
            plan(&["SELECT x.method_idx FROM unknown x"]),
            LoadPlan::FULL
        );
        assert_eq!(
            plan(&["WITH q AS (SELECT name FROM methods) SELECT * FROM q"]),
            LoadPlan::FULL
        );
        assert!(
            plan(&["SELECT file_id,count(*) AS n FROM methods GROUP BY file_id ORDER BY n"])
                .omit_pools
        );
        for op in ["UNION", "UNION ALL", "EXCEPT", "INTERSECT"] {
            let raw = format!("SELECT file_id,method_idx FROM methods WHERE method_idx%7=0 {op} SELECT file_id,method_idx FROM method_strings WHERE method_idx%3=0 ORDER BY file_id,method_idx LIMIT 3");
            assert!(plan_batch(&[raw]).omit_pools);
            let text = format!("SELECT file_id,name FROM methods {op} SELECT file_id,value FROM method_strings ORDER BY file_id");
            assert!(!plan_batch(&[text]).omit_pools);
        }
    }

    #[test]
    fn reduced_metadata_loads_preserve_queries_and_batch_unions() {
        let paths = ["alpha", "beta", "annotated"].map(|name| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../fixtures/dex/{name}.dex"))
        });
        let full = Dataset::load_paths(&paths).unwrap();
        let raw = "SELECT c.file_id,c.class_idx FROM classes c LEFT JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx WHERE m.method_idx IS NULL ORDER BY c.file_id,c.class_idx LIMIT 20";
        for sqls in [
            vec![raw],
            vec!["SELECT a.file_id,a.class_idx,b.file_id,b.class_idx FROM classes a CROSS JOIN classes b LIMIT 1"],
            vec!["SELECT count(*) FROM classes c JOIN methods m ON c.file_id=m.file_id AND c.class_idx=m.class_idx"],
            vec!["SELECT file_id,class_idx,count(*) AS n FROM methods GROUP BY file_id,class_idx ORDER BY n DESC,file_id,class_idx"],
            vec!["SELECT file_id,opcode_count FROM methods ORDER BY file_id,method_idx"],
            vec!["SELECT file_id,access_flags,method_kind FROM methods ORDER BY file_id,method_idx"],
            vec!["SELECT count(*) FROM method_strings"],
            vec!["SELECT c.class_idx,c.method_count FROM classes c ORDER BY c.class_idx"],
            vec![raw,"SELECT file_id,name FROM methods ORDER BY file_id,method_idx LIMIT 2"],
            vec!["SELECT file_id,name FROM methods ORDER BY file_id,method_idx LIMIT 2",raw],
            vec!["SELECT file_id,count(*) AS n FROM methods GROUP BY file_id ORDER BY n,file_id"],
        ] {
            let batch = sqls.iter().map(|sql| sql.to_string()).collect::<Vec<_>>();
            let (needs,eager,code,classes,raw_bytes) = query_load_options(&batch);
            let reduced = Dataset::load_paths_with_retention(&paths,needs,eager,code,classes,raw_bytes).unwrap();
            for sql in sqls {
                let a = execute_statement(sql,Some(&full),&NamedCaches::default(),None).unwrap();
                let b = execute_statement(sql,Some(&reduced),&NamedCaches::default(),None).unwrap();
                assert_eq!((a.columns,a.rows),(b.columns,b.rows),"{sql}");
            }
        }
    }
}
