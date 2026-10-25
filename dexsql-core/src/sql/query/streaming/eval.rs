//! Row-local expressions prepared once before a stream is consumed.
//! Keep the general evaluator as fallback, while avoiding AST name formatting,
//! literal parsing and qualified-column construction in the hot loop.
use super::*;

#[derive(Clone)]
pub(super) enum Prepared {
    Literal(Scalar),
    Column(String),
    Binary(sqlparser::ast::BinaryOperator, Box<Self>, Box<Self>),
    Call(String, Vec<Self>),
    Fallback(Expr),
}

impl Prepared {
    pub(super) fn new(expr: &Expr) -> Self {
        match expr {
            Expr::Value(value) => scalar_from_value(value)
                .map(Self::Literal)
                .unwrap_or_else(|_| Self::Fallback(expr.clone())),
            Expr::Identifier(name) => Self::Column(name.value.to_ascii_lowercase()),
            Expr::CompoundIdentifier(parts) => Self::Column(
                parts
                    .iter()
                    .map(|part| part.value.to_ascii_lowercase())
                    .collect::<Vec<_>>()
                    .join("."),
            ),
            Expr::Nested(expr) => Self::new(expr),
            Expr::BinaryOp { left, op, right } => Self::Binary(
                op.clone(),
                Box::new(Self::new(left)),
                Box::new(Self::new(right)),
            ),
            Expr::Function(function)
                if function.over.is_none()
                    && function.filter.is_none()
                    && function.within_group.is_empty() =>
            {
                let name = function.name.to_string().to_ascii_lowercase();
                let FunctionArguments::List(args) = &function.args else {
                    return Self::Fallback(expr.clone());
                };
                if !args.clauses.is_empty() || args.duplicate_treatment.is_some() {
                    return Self::Fallback(expr.clone());
                }
                // The shared function implementations define the exact dialect
                // semantics; this only pre-resolves dispatch and arguments.
                if !matches!(
                    name.as_str(),
                    "length"
                        | "lower"
                        | "upper"
                        | "instr"
                        | "substr"
                        | "substring"
                        | "abs"
                        | "coalesce"
                        | "ifnull"
                        | "nullif"
                        | "trim"
                        | "ltrim"
                        | "rtrim"
                        | "replace"
                        | "typeof"
                        | "hex"
                        | "unicode"
                        | "char"
                        | "dex_java_name"
                ) {
                    return Self::Fallback(expr.clone());
                }
                let Some(args) = args
                    .args
                    .iter()
                    .map(|arg| match arg {
                        FunctionArg::Unnamed(FunctionArgExpr::Expr(expr)) => Some(Self::new(expr)),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()
                else {
                    return Self::Fallback(expr.clone());
                };
                Self::Call(name, args)
            }
            Expr::Substring {
                expr: value,
                substring_from: Some(start),
                substring_for,
                ..
            } => {
                let mut args = vec![Self::new(value), Self::new(start)];
                if let Some(length) = substring_for {
                    args.push(Self::new(length));
                }
                Self::Call("substr".into(), args)
            }
            _ => Self::Fallback(expr.clone()),
        }
    }

    pub(super) fn evaluate(&self, row: &RelRow) -> Result<Scalar, String> {
        self.evaluate_with(
            &mut |name| {
                row.values
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("unknown column '{name}'"))
            },
            row,
        )
    }

    pub(super) fn source_safe(&self) -> bool {
        match self {
            Self::Fallback(_) => false,
            Self::Binary(_, left, right) => left.source_safe() && right.source_safe(),
            Self::Call(_, args) => args.iter().all(Self::source_safe),
            _ => true,
        }
    }

    pub(super) fn source_columns_valid(&self, schema: &[String], alias: &str) -> bool {
        match self {
            Self::Column(name) => {
                let column = match name.split_once('.') {
                    Some((owner, column)) if owner.eq_ignore_ascii_case(alias) => column,
                    Some(_) => return false,
                    None => name.as_str(),
                };
                !matches!(
                    column,
                    "opcode_count" | "opcode_hex" | "access_flags" | "method_kind"
                ) && schema.iter().any(|name| name == column)
            }
            Self::Fallback(_) => false,
            Self::Binary(_, left, right) => {
                left.source_columns_valid(schema, alias)
                    && right.source_columns_valid(schema, alias)
            }
            Self::Call(_, args) => args
                .iter()
                .all(|arg| arg.source_columns_valid(schema, alias)),
            _ => true,
        }
    }

    pub(super) fn evaluate_with(
        &self,
        value: &mut impl FnMut(&str) -> Result<Scalar, String>,
        row: &RelRow,
    ) -> Result<Scalar, String> {
        use sqlparser::ast::BinaryOperator;
        match self {
            Self::Literal(value) => Ok(value.clone()),
            Self::Column(name) => value(name),
            Self::Binary(op, left, right) => {
                let left = left.evaluate_with(value, row)?;
                if *op == BinaryOperator::And && !matches!(left, Scalar::Null) && !left.truthy() {
                    return Ok(Scalar::Int(0));
                }
                if *op == BinaryOperator::Or && left.truthy() {
                    return Ok(Scalar::Int(1));
                }
                expressions::binary(op, &left, &right.evaluate_with(value, row)?)
            }
            Self::Call(name, args) => {
                // Scalar functions overwhelmingly have one to three inputs.
                // Keep their temporary cells on the stack instead of one
                // allocation per function per source row.
                let mut local = [Scalar::Null, Scalar::Null, Scalar::Null];
                let mut overflow = Vec::new();
                let values: &[Scalar] = if args.len() <= local.len() {
                    for (slot, arg) in local.iter_mut().zip(args) {
                        *slot = arg.evaluate_with(value, row)?;
                    }
                    &local[..args.len()]
                } else {
                    for arg in args {
                        overflow.push(arg.evaluate_with(value, row)?);
                    }
                    &overflow
                };
                if matches!(name.as_str(), "instr" | "substr" | "substring") {
                    eval_string_function(if name == "substring" { "substr" } else { name }, &values)
                } else {
                    scalar_functions::eval_scalar_function(name, &values)
                        .unwrap_or_else(|| Err(format!("unsupported scalar function '{name}'")))
                }
            }
            Self::Fallback(expr) => eval_scalar(expr, row, &[]),
        }
    }
}
