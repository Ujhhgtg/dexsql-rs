//! Typed output boundary for clients which cannot round-trip cells through
//! the CLI's display representation. In particular, text `"NULL"`, text
//! `"12"`, SQL NULL, integers and blobs must remain distinct in MCP results.

use super::*;
use crate::sql::ast::query as native;
use sqlparser::ast::{
    BinaryOperator, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, JoinConstraint, Query,
    Select, SelectItem, SetExpr, TableFactor, UnaryOperator, Value,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputColumn {
    pub name: String,
    pub data_type: &'static str,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    Null,
    Binary(Vec<u8>),
    Utf8(Arc<str>),
    Int64(i64),
    UInt64(u64),
    Float64(f64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TypedQueryResult {
    pub columns: Vec<OutputColumn>,
    pub rows: Vec<Vec<TypedValue>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Integer {
    Signed,
    Unsigned,
    Value,
}

#[derive(Clone)]
struct Shape {
    column: OutputColumn,
    integer: Integer,
}

impl Shape {
    fn dynamic(name: String, nullable: bool) -> Self {
        Self {
            column: OutputColumn {
                name,
                data_type: "sqlite_dynamic",
                nullable,
            },
            integer: Integer::Value,
        }
    }
}

#[derive(Clone)]
struct Source {
    alias: String,
    table: String,
    columns: Vec<Shape>,
    // USING and NATURAL keys expose one coalesced unqualified output key.
    coalesced: HashSet<String>,
    hidden: HashSet<String>,
}

impl QuerySession {
    /// Execute through the common relational executor while retaining scalar
    /// values and the resolved output schema. CLI callers may keep using
    /// `execute`, whose result is intentionally formatted for display.
    pub fn execute_typed(
        &mut self,
        statement: &crate::sql::ast::Statement,
        dataset: Option<&Dataset>,
    ) -> Result<TypedQueryResult, DexSqlError> {
        let _precision = Precision::new();
        let crate::sql::ast::Statement::Query { sql } = statement else {
            self.execute(statement, dataset)?;
            return Ok(TypedQueryResult {
                columns: Vec::new(),
                rows: Vec::new(),
            });
        };
        let mut query = parse_compat(sql).map_err(DexSqlError::from_executor_string)?;
        let definitions = self.caches.definitions.borrow().clone();
        let shapes = query_shape(&query, &definitions, &mut HashSet::new());
        expand_wildcards(&mut query, &definitions, &mut HashSet::new());
        let empty = Dataset::default();
        let ds = dataset.unwrap_or(&empty);
        let (names, rows) = execute_query_rows(&query, ds, dataset, &self.caches, None, true)
            .map_err(DexSqlError::from_executor_string)?;
        let mut shapes = shapes;
        // Keep the executor's labels authoritative, including rewritten
        // scalar-subquery labels and VALUES column names.
        shapes.resize_with(names.len(), || Shape::dynamic(String::new(), true));
        shapes.truncate(names.len());
        for (shape, name) in shapes.iter_mut().zip(names) {
            shape.column.name = name;
        }
        let rows = rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        typed_value(
                            value,
                            shapes.get(index).map_or(Integer::Value, |s| s.integer),
                        )
                    })
                    .collect()
            })
            .collect();
        Ok(TypedQueryResult {
            columns: shapes.into_iter().map(|shape| shape.column).collect(),
            rows,
        })
    }
}

fn typed_value(value: Scalar, integer: Integer) -> TypedValue {
    match value {
        Scalar::Null => TypedValue::Null,
        Scalar::Blob(value) => TypedValue::Binary(value),
        Scalar::Text(value) => TypedValue::Utf8(value),
        Scalar::Int(value) if integer == Integer::Signed || value < 0 => TypedValue::Int64(value),
        Scalar::Int(value) => TypedValue::UInt64(value as u64),
        Scalar::Real(value) => TypedValue::Float64(value.parse().unwrap_or(f64::NAN)),
    }
}

/// Shared compatibility bridge: parse through the native AST and lower the
/// result into the legacy execution AST. Runtime planner modules use this
/// while their visitors are migrated off sqlparser enums.
pub(super) fn parse_compat(sql: &str) -> Result<Box<Query>, String> {
    let query = native::parse_query(sql).map_err(|error| match error.span {
        Some((start, end)) => format!("SQL parse error at {start}..{end}: {}", error.message),
        None => format!("SQL parse error: {}", error.message),
    })?;
    Ok(Box::new(compat_query(&query)?))
}

/// Convert the recovered native AST to the executor's older compatibility AST.
/// The executor still needs its established relational node shapes; parsing is
/// native, while this bridge keeps the execution migration incremental.
fn compat_query(query: &native::Query) -> Result<Query, String> {
    let with = if query.with.is_empty() {
        None
    } else {
        Some(compat_with(query)?)
    };
    let order_by = if query.order_by.is_empty() {
        None
    } else {
        Some(sqlparser::ast::OrderBy {
            kind: sqlparser::ast::OrderByKind::Expressions(
                query
                    .order_by
                    .iter()
                    .map(compat_order_by)
                    .collect::<Result<_, _>>()?,
            ),
            interpolate: None,
        })
    };
    Ok(Query {
        with,
        body: Box::new(compat_set_expr(&query.body)?),
        order_by,
        limit_clause: match (&query.limit, &query.offset) {
            (Some(limit), offset) => Some(sqlparser::ast::LimitClause::LimitOffset {
                limit: Some(compat_expr(limit)?),
                offset: match offset {
                    Some(value) => Some(sqlparser::ast::Offset {
                        value: compat_expr(value)?,
                        rows: sqlparser::ast::OffsetRows::None,
                    }),
                    None => None,
                },
                limit_by: Vec::new(),
            }),
            (None, Some(offset)) => Some(sqlparser::ast::LimitClause::LimitOffset {
                limit: None,
                offset: Some(sqlparser::ast::Offset {
                    value: compat_expr(offset)?,
                    rows: sqlparser::ast::OffsetRows::None,
                }),
                limit_by: Vec::new(),
            }),
            (None, None) => None,
        },
        fetch: None,
        locks: Vec::new(),
        for_clause: None,
        settings: None,
        format_clause: None,
        pipe_operators: Vec::new(),
    })
}

fn compat_with(query: &native::Query) -> Result<sqlparser::ast::With, String> {
    let recursive = query.with.iter().any(|cte| cte.recursive);
    Ok(sqlparser::ast::With {
        with_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
        recursive,
        cte_tables: query
            .with
            .iter()
            .map(compat_cte)
            .collect::<Result<_, _>>()?,
    })
}

fn compat_cte(cte: &native::Cte) -> Result<sqlparser::ast::Cte, String> {
    Ok(sqlparser::ast::Cte {
        alias: sqlparser::ast::TableAlias {
            explicit: false,
            name: ident(&cte.name),
            columns: cte
                .columns
                .iter()
                .map(|name| sqlparser::ast::TableAliasColumnDef {
                    name: ident(name),
                    data_type: None,
                })
                .collect(),
            at: None,
        },
        query: Box::new(compat_query(&cte.query)?),
        from: None,
        materialized: None,
        closing_paren_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
    })
}

fn compat_set_expr(expr: &native::SetExpr) -> Result<SetExpr, String> {
    Ok(match expr {
        native::SetExpr::Select(select) => SetExpr::Select(Box::new(compat_select(select)?)),
        native::SetExpr::Values(rows) => SetExpr::Values(sqlparser::ast::Values {
            explicit_row: false,
            value_keyword: false,
            rows: rows
                .iter()
                .map(|row| {
                    Ok(sqlparser::ast::Parens::with_empty_span(
                        row.iter().map(compat_expr).collect::<Result<_, _>>()?,
                    ))
                })
                .collect::<Result<_, String>>()?,
        }),
        native::SetExpr::SetOp {
            left,
            op,
            all,
            right,
        } => SetExpr::SetOperation {
            left: Box::new(compat_set_expr(left)?),
            op: match op {
                native::SetOperator::Union => sqlparser::ast::SetOperator::Union,
                native::SetOperator::Intersect => sqlparser::ast::SetOperator::Intersect,
                native::SetOperator::Except => sqlparser::ast::SetOperator::Except,
            },
            set_quantifier: if *all {
                sqlparser::ast::SetQuantifier::All
            } else {
                sqlparser::ast::SetQuantifier::None
            },
            right: Box::new(compat_set_expr(right)?),
        },
    })
}

fn compat_select(select: &native::Select) -> Result<Select, String> {
    Ok(Select {
        select_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
        optimizer_hints: Vec::new(),
        distinct: select
            .distinct
            .then_some(sqlparser::ast::Distinct::Distinct),
        select_modifiers: None,
        top: None,
        top_before_distinct: false,
        projection: select
            .projection
            .iter()
            .map(compat_select_item)
            .collect::<Result<_, _>>()?,
        exclude: None,
        into: None,
        from: select
            .from
            .iter()
            .map(compat_table_with_joins)
            .collect::<Result<_, _>>()?,
        lateral_views: Vec::new(),
        prewhere: None,
        selection: select.selection.as_ref().map(compat_expr).transpose()?,
        connect_by: Vec::new(),
        group_by: sqlparser::ast::GroupByExpr::Expressions(
            select
                .group_by
                .iter()
                .map(compat_expr)
                .collect::<Result<_, _>>()?,
            Vec::new(),
        ),
        cluster_by: Vec::new(),
        distribute_by: Vec::new(),
        sort_by: Vec::new(),
        having: select.having.as_ref().map(compat_expr).transpose()?,
        named_window: Vec::new(),
        qualify: None,
        window_before_qualify: false,
        value_table_mode: None,
        flavor: sqlparser::ast::SelectFlavor::Standard,
    })
}

fn compat_select_item(item: &native::SelectItem) -> Result<SelectItem, String> {
    Ok(match item {
        native::SelectItem::Wildcard => {
            SelectItem::Wildcard(sqlparser::ast::WildcardAdditionalOptions::default())
        }
        native::SelectItem::QualifiedWildcard(name) => SelectItem::QualifiedWildcard(
            sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(object_name(
                &name.split('.').map(str::to_owned).collect::<Vec<_>>(),
            )),
            sqlparser::ast::WildcardAdditionalOptions::default(),
        ),
        native::SelectItem::Expr { expr, alias } => match alias {
            Some(alias) => SelectItem::ExprWithAlias {
                expr: compat_expr(expr)?,
                alias: ident(alias),
            },
            None => SelectItem::UnnamedExpr(compat_expr(expr)?),
        },
    })
}

fn compat_table_with_joins(
    table: &native::TableRef,
) -> Result<sqlparser::ast::TableWithJoins, String> {
    let (relation, joins) = flatten_table(table)?;
    Ok(sqlparser::ast::TableWithJoins { relation, joins })
}

fn flatten_table(
    table: &native::TableRef,
) -> Result<(TableFactor, Vec<sqlparser::ast::Join>), String> {
    match table {
        native::TableRef::Join {
            left,
            kind,
            right,
            constraint,
        } => {
            let (relation, mut joins) = flatten_table(left)?;
            let right = compat_factor(right)?;
            let constraint = compat_join_constraint(constraint)?;
            let join_operator = match kind {
                native::JoinKind::Inner => sqlparser::ast::JoinOperator::Inner(constraint),
                native::JoinKind::Left => sqlparser::ast::JoinOperator::Left(constraint),
                native::JoinKind::Right => sqlparser::ast::JoinOperator::Right(constraint),
                native::JoinKind::Full => sqlparser::ast::JoinOperator::FullOuter(constraint),
                native::JoinKind::Cross => sqlparser::ast::JoinOperator::CrossJoin(constraint),
                native::JoinKind::Natural => {
                    sqlparser::ast::JoinOperator::Join(sqlparser::ast::JoinConstraint::Natural)
                }
            };
            joins.push(sqlparser::ast::Join {
                relation: right,
                global: false,
                join_operator,
            });
            Ok((relation, joins))
        }
        _ => Ok((compat_factor(table)?, Vec::new())),
    }
}

fn compat_factor(table: &native::TableRef) -> Result<TableFactor, String> {
    Ok(match table {
        native::TableRef::Table { name, alias } => TableFactor::Table {
            name: object_name(name),
            alias: alias.as_ref().map(|name| sqlparser::ast::TableAlias {
                explicit: false,
                name: ident(name),
                columns: Vec::new(),
                at: None,
            }),
            args: None,
            with_hints: Vec::new(),
            version: None,
            with_ordinality: false,
            partitions: Vec::new(),
            json_path: None,
            sample: None,
            index_hints: Vec::new(),
        },
        native::TableRef::Derived { query, alias } => TableFactor::Derived {
            lateral: false,
            subquery: Box::new(compat_query(query)?),
            alias: alias.as_ref().map(|name| sqlparser::ast::TableAlias {
                explicit: false,
                name: ident(name),
                columns: Vec::new(),
                at: None,
            }),
            sample: None,
        },
        native::TableRef::Join { .. } => return Err("nested join relation is not supported".into()),
    })
}

fn compat_join_constraint(constraint: &native::JoinConstraint) -> Result<JoinConstraint, String> {
    Ok(match constraint {
        native::JoinConstraint::None => JoinConstraint::None,
        native::JoinConstraint::On(expr) => JoinConstraint::On(compat_expr(expr)?),
        native::JoinConstraint::Using(names) => JoinConstraint::Using(
            names
                .iter()
                .map(|name| object_name(std::slice::from_ref(name)))
                .collect(),
        ),
    })
}

fn compat_order_by(order: &native::OrderBy) -> Result<sqlparser::ast::OrderByExpr, String> {
    Ok(sqlparser::ast::OrderByExpr {
        expr: compat_expr(&order.expr)?,
        options: sqlparser::ast::OrderByOptions {
            sort: Some(if order.asc {
                sqlparser::ast::OrderBySort::Asc
            } else {
                sqlparser::ast::OrderBySort::Desc
            }),
            nulls_first: order.nulls_first,
        },
        with_fill: None,
    })
}

fn compat_expr(expr: &native::Expr) -> Result<Expr, String> {
    use native::{Expr as NExpr, Literal, UnaryOp as NUnary};
    Ok(match expr {
        NExpr::Identifier(parts) => {
            if parts.len() == 1 {
                Expr::Identifier(ident(&parts[0]))
            } else {
                Expr::CompoundIdentifier(parts.iter().map(|part| ident(part)).collect())
            }
        }
        NExpr::Literal(literal) => Expr::Value(sqlparser::ast::ValueWithSpan {
            value: match literal {
                Literal::Null => Value::Null,
                Literal::Boolean(value) => Value::Boolean(*value),
                Literal::Number(value) => Value::Number(normalize_number(value), false),
                Literal::String(value) => Value::SingleQuotedString(value.clone()),
                Literal::Blob(value) => Value::HexStringLiteral(value.clone()),
            },
            span: sqlparser::tokenizer::Span::empty(),
        }),
        NExpr::Parameter(name) => Expr::Value(sqlparser::ast::ValueWithSpan {
            value: Value::Placeholder(name.clone().unwrap_or_else(|| "?".into())),
            span: sqlparser::tokenizer::Span::empty(),
        }),
        NExpr::Wildcard => {
            Expr::Wildcard(sqlparser::ast::helpers::attached_token::AttachedToken::empty())
        }
        NExpr::Unary { op, expr } => Expr::UnaryOp {
            op: match op {
                NUnary::Plus => UnaryOperator::Plus,
                NUnary::Minus => UnaryOperator::Minus,
                NUnary::Not => UnaryOperator::Not,
                NUnary::BitNot => UnaryOperator::BitwiseNot,
            },
            expr: Box::new(compat_expr(expr)?),
        },
        NExpr::Binary { left, op, right } => {
            if matches!(op, native::BinaryOp::Is | native::BinaryOp::IsNot)
                && matches!(right.as_ref(), NExpr::Literal(Literal::Null))
            {
                let value = Box::new(compat_expr(left)?);
                return Ok(if matches!(op, native::BinaryOp::IsNot) {
                    Expr::IsNotNull(value)
                } else {
                    Expr::IsNull(value)
                });
            }
            let left = Box::new(compat_expr(left)?);
            let right = Box::new(compat_expr(right)?);
            match op {
                native::BinaryOp::Like | native::BinaryOp::NotLike => Expr::Like {
                    negated: matches!(op, native::BinaryOp::NotLike),
                    any: false,
                    expr: left,
                    pattern: right,
                    escape_char: None,
                },
                native::BinaryOp::Glob | native::BinaryOp::NotGlob => Expr::BinaryOp {
                    left,
                    op: BinaryOperator::Glob,
                    right,
                },
                native::BinaryOp::Is => Expr::IsNotDistinctFrom(left, right),
                native::BinaryOp::IsNot => Expr::IsDistinctFrom(left, right),
                _ => Expr::BinaryOp {
                    left,
                    op: compat_binary_op(op)?,
                    right,
                },
            }
        }
        NExpr::Escape { expr, escape } => match compat_expr(expr)? {
            Expr::Like {
                negated,
                any,
                expr,
                pattern,
                ..
            } => Expr::Like {
                negated,
                any,
                expr,
                pattern,
                escape_char: Some(Box::new(compat_expr(escape)?)),
            },
            other => {
                return Err(format!(
                    "ESCAPE applied to unsupported expression {other:?}"
                ))
            }
        },
        NExpr::IsNull { expr, negated } => {
            if *negated {
                Expr::IsNotNull(Box::new(compat_expr(expr)?))
            } else {
                Expr::IsNull(Box::new(compat_expr(expr)?))
            }
        }
        NExpr::Between {
            expr,
            low,
            high,
            negated,
        } => Expr::Between {
            expr: Box::new(compat_expr(expr)?),
            negated: *negated,
            low: Box::new(compat_expr(low)?),
            high: Box::new(compat_expr(high)?),
        },
        NExpr::InList {
            expr,
            list,
            negated,
        } => Expr::InList {
            expr: Box::new(compat_expr(expr)?),
            list: list.iter().map(compat_expr).collect::<Result<_, _>>()?,
            negated: *negated,
        },
        NExpr::InSubquery {
            expr,
            query,
            negated,
        } => Expr::InSubquery {
            expr: Box::new(compat_expr(expr)?),
            subquery: Box::new(compat_query(query)?),
            negated: *negated,
        },
        NExpr::Exists { query, negated } => Expr::Exists {
            subquery: Box::new(compat_query(query)?),
            negated: *negated,
        },
        NExpr::Subquery(query) => Expr::Subquery(Box::new(compat_query(query)?)),
        NExpr::Function {
            name,
            args,
            distinct,
        } => Expr::Function(sqlparser::ast::Function {
            name: object_name(&name.split('.').map(str::to_owned).collect::<Vec<_>>()),
            uses_odbc_syntax: false,
            parameters: FunctionArguments::None,
            args: FunctionArguments::List(sqlparser::ast::FunctionArgumentList {
                duplicate_treatment: (*distinct)
                    .then_some(sqlparser::ast::DuplicateTreatment::Distinct),
                args: args
                    .iter()
                    .map(|arg| Ok(FunctionArg::Unnamed(compat_arg(arg)?)))
                    .collect::<Result<_, String>>()?,
                clauses: Vec::new(),
            }),
            within_group: Vec::new(),
            filter: None,
            null_treatment: None,
            over: None,
        }),
        NExpr::Case {
            operand,
            when_then,
            else_expr,
        } => Expr::Case {
            case_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
            end_token: sqlparser::ast::helpers::attached_token::AttachedToken::empty(),
            operand: operand
                .as_ref()
                .map(|expr| compat_expr(expr))
                .transpose()?
                .map(Box::new),
            conditions: when_then
                .iter()
                .map(|(condition, result)| {
                    Ok(sqlparser::ast::CaseWhen {
                        condition: compat_expr(condition)?,
                        result: compat_expr(result)?,
                    })
                })
                .collect::<Result<_, String>>()?,
            else_result: else_expr
                .as_ref()
                .map(|expr| compat_expr(expr))
                .transpose()?
                .map(Box::new),
        },
        NExpr::Cast { expr, data_type } => Expr::Cast {
            kind: sqlparser::ast::CastKind::Cast,
            expr: Box::new(compat_expr(expr)?),
            data_type: sqlparser::ast::DataType::Custom(
                object_name(&[data_type.clone()]),
                Vec::new(),
            ),
            format: None,
        },
    })
}

fn compat_arg(expr: &native::Expr) -> Result<FunctionArgExpr, String> {
    Ok(match expr {
        native::Expr::Wildcard => FunctionArgExpr::Wildcard,
        _ => FunctionArgExpr::Expr(compat_expr(expr)?),
    })
}

fn compat_binary_op(op: &native::BinaryOp) -> Result<BinaryOperator, String> {
    use native::BinaryOp as Op;
    Ok(match op {
        Op::Or => BinaryOperator::Or,
        Op::And => BinaryOperator::And,
        Op::Eq => BinaryOperator::Eq,
        Op::NotEq => BinaryOperator::NotEq,
        Op::Lt => BinaryOperator::Lt,
        Op::LtEq => BinaryOperator::LtEq,
        Op::Gt => BinaryOperator::Gt,
        Op::GtEq => BinaryOperator::GtEq,
        Op::Like | Op::NotLike => return Err("LIKE expressions must use native LIKE nodes".into()),
        Op::Glob | Op::NotGlob => return Err("GLOB expressions must use native LIKE nodes".into()),
        Op::Match | Op::NotMatch => BinaryOperator::Match,
        Op::Is => BinaryOperator::Eq,
        Op::IsNot => BinaryOperator::NotEq,
        Op::In | Op::NotIn | Op::Between | Op::NotBetween => {
            return Err("invalid binary membership operator".into())
        }
        Op::BitOr => BinaryOperator::BitwiseOr,
        Op::BitAnd => BinaryOperator::BitwiseAnd,
        Op::ShiftLeft => BinaryOperator::PGBitwiseShiftLeft,
        Op::ShiftRight => BinaryOperator::PGBitwiseShiftRight,
        Op::Add => BinaryOperator::Plus,
        Op::Sub => BinaryOperator::Minus,
        Op::Mul => BinaryOperator::Multiply,
        Op::Div => BinaryOperator::Divide,
        Op::Mod => BinaryOperator::Modulo,
        Op::Concat => BinaryOperator::StringConcat,
    })
}

fn ident(name: &str) -> sqlparser::ast::Ident {
    sqlparser::ast::Ident::new(name)
}

fn object_name(parts: &[String]) -> sqlparser::ast::ObjectName {
    sqlparser::ast::ObjectName::from(parts.iter().map(|part| ident(part)).collect::<Vec<_>>())
}

fn normalize_number(value: &str) -> String {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .map_or_else(|| value.to_owned(), |number| number.to_string())
}

/// Used by the temporary relation cache too: caching an intermediate result
/// must not format/reparse its scalar values.
pub(super) fn execute_rows(
    sql: &str,
    dataset: Option<&Dataset>,
    caches: &NamedCaches,
) -> Result<SetRows, String> {
    let _precision = Precision::new();
    let mut query = parse_compat(sql)?;
    expand_wildcards(
        &mut query,
        &caches.definitions.borrow(),
        &mut HashSet::new(),
    );
    let empty = Dataset::default();
    execute_query_rows(
        &query,
        dataset.unwrap_or(&empty),
        dataset,
        caches,
        None,
        true,
    )
}

fn with_definitions(
    query: &Query,
    definitions: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut definitions = definitions.clone();
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            let sql = if cte.alias.columns.is_empty() {
                cte.query.to_string()
            } else {
                format!(
                    "SELECT * FROM ({}) AS __dexsql_cte ({})",
                    cte.query,
                    cte.alias
                        .columns
                        .iter()
                        .map(|column| column.name.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            definitions.insert(cte.alias.name.value.to_ascii_lowercase(), sql);
        }
    }
    definitions
}

fn query_shape(
    query: &Query,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> Vec<Shape> {
    let definitions = with_definitions(query, definitions);
    body_shape(&query.body, &definitions, expanding)
}

fn body_shape(
    body: &SetExpr,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> Vec<Shape> {
    match body {
        SetExpr::Select(select) => {
            let sources = sources(select, definitions, expanding);
            select
                .projection
                .iter()
                .flat_map(|item| match item {
                    SelectItem::Wildcard(_) => wildcard_shapes(&sources, None),
                    SelectItem::QualifiedWildcard(kind, _) => {
                        let sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name) =
                            kind
                        else {
                            return Vec::new();
                        };
                        wildcard_shapes(&sources, Some(&name.to_string()))
                    }
                    _ => item_expr(item)
                        .map(|expr| {
                            let mut shape = expression_shape(expr, &sources);
                            shape.column.name = match item {
                                SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                                _ => expression_label(expr),
                            };
                            shape
                        })
                        .into_iter()
                        .collect(),
                })
                .collect()
        }
        SetExpr::Query(query) => query_shape(query, definitions, expanding),
        SetExpr::SetOperation { left, right, .. } => {
            let mut left = body_shape(left, definitions, expanding);
            let right = body_shape(right, definitions, expanding);
            for (left, right) in left.iter_mut().zip(right) {
                if left.column.data_type != right.column.data_type {
                    left.column.data_type = "sqlite_dynamic";
                }
                left.column.nullable |= right.column.nullable;
                if left.integer != right.integer {
                    left.integer = Integer::Value;
                }
            }
            left
        }
        SetExpr::Values(values) => {
            let Some(first) = values.rows.first() else {
                return Vec::new();
            };
            (0..first.content.len())
                .map(|index| {
                    let mut shape = Shape::dynamic(format!("column{}", index + 1), false);
                    let mut data_type = None;
                    let mut saw_negative = false;
                    let mut saw_integer = false;
                    let mut saw_nonnull = false;
                    for row in &values.rows {
                        let Some(expr) = row.content.get(index) else {
                            continue;
                        };
                        let value =
                            eval_scalar(expr, &RelRow::default(), &[]).unwrap_or(Scalar::Null);
                        let next = match value {
                            Scalar::Null => {
                                shape.column.nullable = true;
                                continue;
                            }
                            Scalar::Blob(_) => "binary",
                            Scalar::Text(_) => "utf8",
                            Scalar::Int(value) if value < 0 => {
                                saw_negative = true;
                                saw_integer = true;
                                saw_nonnull = true;
                                "int64"
                            }
                            Scalar::Int(_) => {
                                saw_integer = true;
                                saw_nonnull = true;
                                "uint64"
                            }
                            Scalar::Real(_) => "float64",
                        };
                        data_type = Some(match data_type {
                            Some(old) if old != next => "sqlite_dynamic",
                            _ => next,
                        });
                    }
                    shape.column.data_type = if saw_integer && data_type == Some("sqlite_dynamic") {
                        if saw_negative {
                            "int64"
                        } else {
                            "uint64"
                        }
                    } else if !saw_nonnull {
                        "utf8"
                    } else {
                        data_type.unwrap_or("sqlite_dynamic")
                    };
                    shape.integer = if shape.column.data_type == "int64" {
                        Integer::Signed
                    } else {
                        Integer::Value
                    };
                    shape
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

fn sources(
    select: &Select,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> Vec<Source> {
    let mut output: Vec<Source> = Vec::new();
    for from in &select.from {
        output.push(source(&from.relation, definitions, expanding));
        for join in &from.joins {
            let mut right = source(&join.relation, definitions, expanding);
            if let Ok((kind, constraint)) = relational::parts(&join.join_operator) {
                if matches!(kind, relational::Kind::Right | relational::Kind::Full) {
                    for source in &mut output {
                        for column in &mut source.columns {
                            column.column.nullable = true;
                        }
                    }
                }
                if matches!(kind, relational::Kind::Left | relational::Kind::Full) {
                    for column in &mut right.columns {
                        column.column.nullable = true;
                    }
                }
                let keys = match constraint {
                    JoinConstraint::Using(keys) => keys
                        .iter()
                        .map(|key| key.to_string().to_ascii_lowercase())
                        .collect(),
                    JoinConstraint::Natural => right
                        .columns
                        .iter()
                        .filter(|column| {
                            output.iter().any(|source| {
                                source
                                    .columns
                                    .iter()
                                    .any(|left| left.column.name == column.column.name)
                            })
                        })
                        .map(|column| column.column.name.to_ascii_lowercase())
                        .collect(),
                    _ => HashSet::new(),
                };
                right.hidden.extend(keys.iter().cloned());
                for key in keys {
                    if let Some(source) = output.iter_mut().find(|source| {
                        source
                            .columns
                            .iter()
                            .any(|column| column.column.name.eq_ignore_ascii_case(&key))
                    }) {
                        source.coalesced.insert(key);
                    }
                }
            }
            output.push(right);
        }
    }
    output
}

fn source(
    factor: &TableFactor,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) -> Source {
    let (table, alias, alias_columns, columns) = match factor {
        TableFactor::Table { name, alias, .. } => {
            let table = name
                .0
                .last()
                .and_then(|part| part.as_ident())
                .map(|id| id.value.to_ascii_lowercase())
                .unwrap_or_else(|| name.to_string().to_ascii_lowercase());
            let columns = if let Some(sql) = definitions.get(&table) {
                if expanding.insert(table.clone()) {
                    let columns = parse_compat(sql)
                        .map(|query| query_shape(&query, definitions, expanding))
                        .unwrap_or_default();
                    expanding.remove(&table);
                    columns
                } else {
                    Vec::new()
                }
            } else {
                crate::sql::schema::TABLES
                    .iter()
                    .find(|meta| meta.name == table)
                    .map(|meta| {
                        meta.columns
                            .iter()
                            .map(|column| {
                                let data_type = match column.sql_type {
                                    ty if ty.starts_with("UInt") => "uint64",
                                    ty if ty.starts_with("Int") => "int64",
                                    ty if ty.starts_with("Float") => "float64",
                                    ty if ty.contains("Utf8") => "utf8",
                                    ty if ty.contains("Binary") => "binary",
                                    _ => "sqlite_dynamic",
                                };
                                Shape {
                                    column: OutputColumn {
                                        name: column.name.into(),
                                        data_type,
                                        nullable: column.nullable,
                                    },
                                    integer: if data_type == "int64" {
                                        Integer::Signed
                                    } else {
                                        Integer::Unsigned
                                    },
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            (
                table.clone(),
                alias
                    .as_ref()
                    .map(|alias| alias.name.value.clone())
                    .unwrap_or(table),
                alias
                    .as_ref()
                    .map(|alias| alias.columns.as_slice())
                    .unwrap_or_default(),
                columns,
            )
        }
        TableFactor::Derived {
            subquery, alias, ..
        } => (
            String::new(),
            alias
                .as_ref()
                .map(|alias| alias.name.value.clone())
                .unwrap_or_default(),
            alias
                .as_ref()
                .map(|alias| alias.columns.as_slice())
                .unwrap_or_default(),
            query_shape(subquery, definitions, expanding),
        ),
        _ => (String::new(), String::new(), &[][..], Vec::new()),
    };
    let mut columns = columns;
    for (column, alias) in columns.iter_mut().zip(alias_columns) {
        column.column.name = alias.name.value.clone();
    }
    Source {
        alias,
        table,
        columns,
        coalesced: HashSet::new(),
        hidden: HashSet::new(),
    }
}

fn wildcard_shapes(sources: &[Source], qualifier: Option<&str>) -> Vec<Shape> {
    sources
        .iter()
        .filter(|source| {
            qualifier.is_none_or(|qualifier| source.alias.eq_ignore_ascii_case(qualifier))
        })
        .flat_map(|source| {
            source
                .columns
                .iter()
                .filter(|column| {
                    !(source.table == "classes"
                        && matches!(column.column.name.as_str(), "field_count" | "method_count"))
                        && (qualifier.is_some()
                            || !source
                                .hidden
                                .contains(&column.column.name.to_ascii_lowercase()))
                })
                .cloned()
        })
        .collect()
}

fn expression_shape(expr: &Expr, sources: &[Source]) -> Shape {
    let find = |name: &str, qualifier: Option<&str>| {
        sources
            .iter()
            .filter(|source| {
                qualifier.is_none_or(|qualifier| source.alias.eq_ignore_ascii_case(qualifier))
            })
            .flat_map(|source| &source.columns)
            .find(|column| column.column.name.eq_ignore_ascii_case(name))
            .cloned()
    };
    match expr {
        Expr::Identifier(id) => {
            find(&id.value, None).unwrap_or_else(|| Shape::dynamic(id.value.clone(), true))
        }
        Expr::CompoundIdentifier(ids) if ids.len() == 2 => find(&ids[1].value, Some(&ids[0].value))
            .unwrap_or_else(|| Shape::dynamic(ids[1].value.clone(), true)),
        Expr::Nested(expr) => expression_shape(expr, sources),
        Expr::Value(value) => Shape::dynamic(
            expression_label(expr),
            matches!(value.value, Value::Null | Value::HexStringLiteral(_)),
        ),
        Expr::UnaryOp {
            op: UnaryOperator::Minus | UnaryOperator::Plus,
            expr,
        } if matches!(expr.as_ref(), Expr::Value(_)) => expression_shape(expr, sources),
        Expr::Function(function) => {
            let name = function.name.to_string().to_ascii_lowercase();
            let mut shape = Shape::dynamic(name.clone(), true);
            if name == "count" {
                shape.column.data_type = "uint64";
                shape.column.nullable = false;
                shape.integer = Integer::Unsigned;
            } else if matches!(name.as_str(), "group_concat" | "string_agg") {
                shape.column.data_type = "utf8";
            } else if name == "abs" {
                shape.integer = Integer::Signed;
            } else if matches!(name.as_str(), "coalesce" | "ifnull") {
                if let FunctionArguments::List(args) = &function.args {
                    for arg in &args.args {
                        if let FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) = arg {
                            let mut argument = expression_shape(expr, sources);
                            if !argument.column.nullable {
                                if argument.column.data_type == "sqlite_dynamic" {
                                    if let Ok(value) = eval_scalar(expr, &RelRow::default(), &[]) {
                                        argument.column.data_type = match value {
                                            Scalar::Int(n) if n < 0 => "int64",
                                            Scalar::Int(_) => "uint64",
                                            Scalar::Text(_) => "utf8",
                                            Scalar::Real(_) => "float64",
                                            _ => "sqlite_dynamic",
                                        };
                                    }
                                }
                                return argument;
                            }
                        }
                    }
                }
            }
            shape
        }
        Expr::BinaryOp { left, op, right } => {
            let mut shape = Shape::dynamic(expression_label(expr), true);
            if matches!(op, BinaryOperator::StringConcat) {
                shape.column.data_type = "utf8";
                shape.column.nullable = false;
            } else if matches!(
                op,
                BinaryOperator::Modulo
                    | BinaryOperator::Eq
                    | BinaryOperator::NotEq
                    | BinaryOperator::Lt
                    | BinaryOperator::LtEq
                    | BinaryOperator::Gt
                    | BinaryOperator::GtEq
                    | BinaryOperator::And
                    | BinaryOperator::Or
                    | BinaryOperator::BitwiseAnd
                    | BinaryOperator::BitwiseOr
                    | BinaryOperator::BitwiseXor
                    | BinaryOperator::PGBitwiseShiftLeft
                    | BinaryOperator::PGBitwiseShiftRight
            ) {
                shape.integer = Integer::Signed;
            }
            if matches!(
                op,
                BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
            ) {
                let mut columns = HashSet::new();
                super::collect_expr_columns(expr, &mut columns);
                let canonical_identity = matches!(op, BinaryOperator::Plus)
                    && matches!(right.as_ref(), Expr::Value(value) if value.value.to_string() == "0");
                let left_shape = expression_shape(left, sources);
                let right_nonnegative = matches!(right.as_ref(), Expr::Value(value) if value.value.to_string().parse::<i64>().is_ok_and(|value| value >= 0));
                shape.integer = if canonical_identity
                    || (left_shape.integer == Integer::Unsigned && right_nonnegative)
                {
                    Integer::Unsigned
                } else if columns.is_empty() {
                    Integer::Value
                } else {
                    Integer::Signed
                };
            }
            shape
        }
        Expr::IsNull(_)
        | Expr::IsNotNull(_)
        | Expr::InList { .. }
        | Expr::Between { .. }
        | Expr::Like { .. }
        | Expr::InSubquery { .. }
        | Expr::Exists { .. } => {
            let mut shape = Shape::dynamic(expression_label(expr), true);
            shape.integer = Integer::Signed;
            shape
        }
        _ => Shape::dynamic(expression_label(expr), true),
    }
}

fn expand_wildcards(
    query: &mut Query,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) {
    let definitions = with_definitions(query, definitions);
    if let Some(with) = &mut query.with {
        for cte in &mut with.cte_tables {
            expand_wildcards(&mut cte.query, &definitions, expanding);
        }
    }
    expand_body(&mut query.body, &definitions, expanding);
}

fn expand_body(
    body: &mut SetExpr,
    definitions: &HashMap<String, String>,
    expanding: &mut HashSet<String>,
) {
    match body {
        SetExpr::Select(select) => {
            let sources = sources(select, definitions, expanding);
            let mut output = Vec::new();
            for item in &select.projection {
                let qualifier = match item {
                    SelectItem::Wildcard(_) => None,
                    SelectItem::QualifiedWildcard(
                        sqlparser::ast::SelectItemQualifiedWildcardKind::ObjectName(name),
                        _,
                    ) => Some(name.to_string()),
                    _ => {
                        output.push(item.clone());
                        continue;
                    }
                };
                let original_len = output.len();
                for source in &sources {
                    if qualifier
                        .as_ref()
                        .is_some_and(|qualifier| !source.alias.eq_ignore_ascii_case(qualifier))
                    {
                        continue;
                    }
                    for column in &source.columns {
                        let name = &column.column.name;
                        if source.table == "classes"
                            && matches!(name.as_str(), "field_count" | "method_count")
                            || qualifier.is_none()
                                && source.hidden.contains(&name.to_ascii_lowercase())
                        {
                            continue;
                        }
                        let expr = if source.alias.is_empty()
                            || qualifier.is_none()
                                && source.coalesced.contains(&name.to_ascii_lowercase())
                        {
                            Expr::Identifier(sqlparser::ast::Ident::new(name))
                        } else {
                            Expr::CompoundIdentifier(vec![
                                sqlparser::ast::Ident::new(&source.alias),
                                sqlparser::ast::Ident::new(name),
                            ])
                        };
                        output.push(SelectItem::UnnamedExpr(expr));
                    }
                }
                // Preserve an unresolved wildcard so the common resolver
                // emits its precise unknown-relation/cyclic-source error.
                if output.len() == original_len {
                    output.push(item.clone());
                }
            }
            select.projection = output;
            for table in &mut select.from {
                for factor in std::iter::once(&mut table.relation)
                    .chain(table.joins.iter_mut().map(|join| &mut join.relation))
                {
                    if let TableFactor::Derived { subquery, .. } = factor {
                        expand_wildcards(subquery, definitions, expanding);
                    }
                }
            }
        }
        SetExpr::Query(query) => expand_wildcards(query, definitions, expanding),
        SetExpr::SetOperation { left, right, .. } => {
            expand_body(left, definitions, expanding);
            expand_body(right, definitions, expanding);
        }
        _ => {}
    }
}

thread_local! {
    static PRECISE_OUTPUT_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn retains_precision() -> bool {
    PRECISE_OUTPUT_DEPTH.with(|depth| depth.get() != 0)
}

struct Precision;

impl Precision {
    fn new() -> Self {
        PRECISE_OUTPUT_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for Precision {
    fn drop(&mut self) {
        PRECISE_OUTPUT_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execute(sql: &str) -> TypedQueryResult {
        QuerySession::default()
            .execute_typed(&QuerySession::validate(sql).unwrap(), None)
            .unwrap()
    }

    #[test]
    fn text_and_blob_values_retain_their_actual_type() {
        let result = execute("SELECT '12','NULL',NULL,x'00ff',CAST(1 AS TEXT),1%2");
        assert_eq!(
            result.rows[0],
            vec![
                TypedValue::Utf8(Arc::from("12")),
                TypedValue::Utf8(Arc::from("NULL")),
                TypedValue::Null,
                TypedValue::Binary(vec![0, 255]),
                TypedValue::Utf8(Arc::from("1")),
                TypedValue::Int64(1)
            ]
        );
    }

    #[test]
    fn set_queries_and_ctes_keep_text_values() {
        let result =
            execute("WITH a AS (SELECT '12' AS n UNION ALL SELECT 'NULL') SELECT n FROM a");
        assert_eq!(
            result.rows,
            vec![
                vec![TypedValue::Utf8(Arc::from("12"))],
                vec![TypedValue::Utf8(Arc::from("NULL"))]
            ]
        );
    }

    #[test]
    fn cte_column_aliases_and_unknown_relation_errors_are_retained() {
        let result = execute("WITH a(n) AS (SELECT '12') SELECT * FROM a");
        assert_eq!(result.columns[0].name, "n");
        assert_eq!(result.rows, vec![vec![TypedValue::Utf8(Arc::from("12"))]]);
        let error = QuerySession::default()
            .execute_typed(
                &QuerySession::validate("SELECT * FROM does_not_exist").unwrap(),
                None,
            )
            .unwrap_err();
        assert_eq!(error.message, "unknown relation `does_not_exist`");
    }

    #[test]
    fn typed_averages_keep_full_precision() {
        let result = execute("WITH n AS (VALUES (1),(2),(2)) SELECT avg(column1) FROM n");
        assert_eq!(result.rows, vec![vec![TypedValue::Float64(5.0 / 3.0)]]);
    }

    #[test]
    fn output_schema_resolves_qualified_columns_and_outer_nulls() {
        let query = parse_compat("SELECT m.access_flags,c.access_flags,s.value FROM methods m JOIN classes c ON m.class_idx=c.class_idx LEFT JOIN method_strings s ON m.method_idx=s.method_idx").unwrap();
        let columns = query_shape(&query, &HashMap::new(), &mut HashSet::new());
        assert!(columns[0].column.nullable);
        assert!(!columns[1].column.nullable);
        assert!(columns[2].column.nullable);
    }

    #[test]
    fn duplicate_join_columns_are_projected_by_qualified_identity() {
        let mut query = parse_compat(
            "SELECT * FROM methods m JOIN method_strings s ON m.method_idx=s.method_idx",
        )
        .unwrap();
        expand_wildcards(&mut query, &HashMap::new(), &mut HashSet::new());
        let select = query.body.as_select().unwrap();
        assert_eq!(select.projection.len(), 22);
        assert!(select
            .projection
            .iter()
            .any(|item| item.to_string() == "m.file_id"));
        assert!(select
            .projection
            .iter()
            .any(|item| item.to_string() == "s.file_id"));
    }

    #[test]
    fn fixture_join_retains_duplicate_columns_and_null_extensions() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex");
        let dataset =
            Dataset::load_paths(&[root.join("alpha.dex"), root.join("beta.dex")]).unwrap();
        let sql = "SELECT * FROM methods m LEFT JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx ORDER BY m.file_id,m.method_idx,s.value";
        let result = QuerySession::default()
            .execute_typed(&QuerySession::validate(sql).unwrap(), Some(&dataset))
            .unwrap();
        assert_eq!(result.columns.len(), 22);
        assert_eq!(
            result
                .columns
                .iter()
                .filter(|column| column.name == "file_id")
                .count(),
            2
        );
        assert!(result.rows.iter().all(|row| row.len() == 22));
        assert!(result.columns[14..].iter().all(|column| column.nullable));
        assert!(result.rows.iter().any(|row| row[14..]
            .iter()
            .all(|value| matches!(value, TypedValue::Null))));
    }
}
