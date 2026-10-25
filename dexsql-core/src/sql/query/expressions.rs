//! SQLite expression semantics shared by projection, predicates and aggregates.
use super::*;
use sqlparser::ast::{BinaryOperator as Op, Expr, UnaryOperator};
use sqlparser::dialect::{Dialect as SqlDialect, SQLiteDialect};
use sqlparser::keywords::Keyword;

/// sqlparser's SQLite dialect omits SQLite's arbitrary `IS` operand.
#[derive(Debug)]
pub(super) struct Dialect;
impl SqlDialect for Dialect {
    fn dialect(&self) -> std::any::TypeId {
        std::any::TypeId::of::<SQLiteDialect>()
    }
    fn is_identifier_start(&self, ch: char) -> bool {
        SQLiteDialect {}.is_identifier_start(ch)
    }
    fn is_identifier_part(&self, ch: char) -> bool {
        SQLiteDialect {}.is_identifier_part(ch)
    }
    fn is_delimited_identifier_start(&self, ch: char) -> bool {
        SQLiteDialect {}.is_delimited_identifier_start(ch)
    }
    fn identifier_quote_style(&self, value: &str) -> Option<char> {
        SQLiteDialect {}.identifier_quote_style(value)
    }
    fn supports_filter_during_aggregation(&self) -> bool {
        true
    }
    fn supports_in_empty_list(&self) -> bool {
        true
    }
    fn supports_limit_comma(&self) -> bool {
        true
    }
    fn supports_notnull_operator(&self) -> bool {
        true
    }
    fn supports_comma_separated_trim(&self) -> bool {
        true
    }
    fn supports_numeric_literal_underscores(&self) -> bool {
        true
    }
    fn parse_infix(
        &self,
        parser: &mut sqlparser::parser::Parser,
        expr: &Expr,
        precedence: u8,
    ) -> Option<Result<Expr, sqlparser::parser::ParserError>> {
        if parser.parse_keyword(Keyword::IS) {
            let negated = parser.parse_keyword(Keyword::NOT);
            // Preserve truth tests, whose semantics differ from numeric = 1.
            for (keyword, test) in [(Keyword::NULL, 0), (Keyword::TRUE, 1), (Keyword::FALSE, 2)] {
                if parser.parse_keyword(keyword) {
                    let expr = Box::new(expr.clone());
                    return Some(Ok(match (test, negated) {
                        (0, false) => Expr::IsNull(expr),
                        (0, true) => Expr::IsNotNull(expr),
                        (1, false) => Expr::IsTrue(expr),
                        (1, true) => Expr::IsNotTrue(expr),
                        (2, false) => Expr::IsFalse(expr),
                        _ => Expr::IsNotFalse(expr),
                    }));
                }
            }
            let distinct = parser.parse_keywords(&[Keyword::DISTINCT, Keyword::FROM]);
            return Some(parser.parse_subexpr(precedence).map(|right| {
                if negated ^ distinct {
                    Expr::IsDistinctFrom(Box::new(expr.clone()), Box::new(right))
                } else {
                    Expr::IsNotDistinctFrom(Box::new(expr.clone()), Box::new(right))
                }
            }));
        }
        SQLiteDialect {}.parse_infix(parser, expr, precedence)
    }
}

pub(super) fn text(value: &Scalar) -> Option<String> {
    match value {
        Scalar::Null => None,
        Scalar::Blob(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => scalar_text(value),
    }
}

/// Longest SQLite numeric prefix. INTEGER casts deliberately ignore exponent.
fn number_prefix(value: &str, integer: bool) -> &str {
    let value = value.trim_start_matches(|ch: char| ch.is_ascii_whitespace());
    let bytes = value.as_bytes();
    let mut end = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    let start = end;
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    let mut digits = end - start;
    if !integer && bytes.get(end) == Some(&b'.') {
        end += 1;
        let start = end;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        digits += end - start;
    }
    if digits == 0 {
        return "";
    }
    if !integer && matches!(bytes.get(end), Some(b'e' | b'E')) {
        let exponent = end;
        end += 1;
        if matches!(bytes.get(end), Some(b'+' | b'-')) {
            end += 1;
        }
        let start = end;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            end = exponent;
        }
    }
    &value[..end]
}

pub(super) fn number(value: &Scalar) -> Scalar {
    match value {
        Scalar::Null | Scalar::Int(_) | Scalar::Real(_) => value.clone(),
        _ => {
            let value = text(value).unwrap_or_default();
            let prefix = number_prefix(&value, false);
            if prefix.is_empty() {
                Scalar::Int(0)
            } else if !prefix.contains(['.', 'e', 'E']) {
                prefix.parse::<i64>().map(Scalar::Int).unwrap_or_else(|_| {
                    scalar_functions::real_scalar(prefix.parse().unwrap_or(0.0))
                })
            } else {
                scalar_functions::real_scalar(prefix.parse().unwrap_or(0.0))
            }
        }
    }
}

pub(super) fn integer(value: &Scalar) -> i64 {
    match value {
        Scalar::Int(value) => *value,
        Scalar::Real(value) => value.parse::<f64>().unwrap_or(0.0) as i64,
        _ => {
            let value = text(value).unwrap_or_default();
            let prefix = number_prefix(&value, true);
            prefix.parse::<i64>().unwrap_or_else(|_| {
                if prefix.is_empty() {
                    0
                } else if prefix.starts_with('-') {
                    i64::MIN
                } else {
                    i64::MAX
                }
            })
        }
    }
}

pub(super) fn cast(value: &Scalar, target: &str) -> Scalar {
    if matches!(value, Scalar::Null) {
        return Scalar::Null;
    }
    let target = target.to_ascii_uppercase();
    if target.contains("INT") {
        Scalar::Int(integer(value))
    } else if target.contains("CHAR")
        || target.contains("CLOB")
        || target.contains("TEXT")
        || target.contains("STRING")
    {
        Scalar::text(text(value).unwrap_or_default())
    } else if target.contains("BLOB") {
        match value {
            Scalar::Blob(_) => value.clone(),
            _ => Scalar::Blob(text(value).unwrap_or_default().into_bytes()),
        }
    } else if target.contains("REAL") || target.contains("FLOA") || target.contains("DOUB") {
        scalar_functions::real_scalar(number(value).numeric().unwrap_or(0.0))
    } else {
        let value = number(value);
        match &value {
            Scalar::Real(text) => {
                let real = text.parse::<f64>().unwrap_or(0.0);
                if real >= i64::MIN as f64 && real < -(i64::MIN as f64) && real.fract() == 0.0 {
                    Scalar::Int(real as i64)
                } else {
                    value
                }
            }
            _ => value,
        }
    }
}

pub(super) fn binary(op: &Op, a: &Scalar, b: &Scalar) -> Result<Scalar, String> {
    if matches!(op, Op::And | Op::Or) {
        let a = (!matches!(a, Scalar::Null)).then(|| a.truthy());
        let b = (!matches!(b, Scalar::Null)).then(|| b.truthy());
        return Ok(match (op, a, b) {
            (Op::And, Some(false), _) | (Op::And, _, Some(false)) => Scalar::Int(0),
            (Op::Or, Some(true), _) | (Op::Or, _, Some(true)) => Scalar::Int(1),
            (_, Some(a), Some(b)) => Scalar::Int(if matches!(op, Op::And) {
                a && b
            } else {
                a || b
            } as i64),
            _ => Scalar::Null,
        });
    }
    if matches!(a, Scalar::Null) || matches!(b, Scalar::Null) {
        return Ok(Scalar::Null);
    }
    if matches!(op, Op::StringConcat) {
        return Ok(Scalar::text(format!(
            "{}{}",
            text(a).unwrap_or_default(),
            text(b).unwrap_or_default()
        )));
    }
    if matches!(op, Op::Glob) {
        return Ok(Scalar::Int(
            glob(&text(a).unwrap_or_default(), &text(b).unwrap_or_default()) as i64,
        ));
    }
    if matches!(
        op,
        Op::Eq | Op::NotEq | Op::Gt | Op::Lt | Op::GtEq | Op::LtEq
    ) {
        return Ok(Scalar::Int(eval_binary(op, a, b) as i64));
    }
    let a = number(a);
    let b = number(b);
    let (x, y) = (a.numeric().unwrap_or(0.0), b.numeric().unwrap_or(0.0));
    let ints = if let (Scalar::Int(x), Scalar::Int(y)) = (&a, &b) {
        Some((*x, *y))
    } else {
        None
    };
    match op {
        Op::Plus | Op::Minus | Op::Multiply => {
            if let Some((x, y)) = ints {
                let result = match op {
                    Op::Plus => x.checked_add(y),
                    Op::Minus => x.checked_sub(y),
                    _ => x.checked_mul(y),
                };
                if let Some(result) = result {
                    return Ok(Scalar::Int(result));
                }
            }
            Ok(scalar_functions::real_scalar(match op {
                Op::Plus => x + y,
                Op::Minus => x - y,
                _ => x * y,
            }))
        }
        Op::Divide => {
            if y == 0.0 {
                Ok(Scalar::Null)
            } else if let Some((x, y)) = ints {
                Ok(Scalar::Int(x.wrapping_div(y)))
            } else {
                Ok(scalar_functions::real_scalar(x / y))
            }
        }
        Op::Modulo => {
            let (x, y) = (integer(&a), integer(&b));
            if y == 0 {
                Ok(Scalar::Null)
            } else if ints.is_some() {
                Ok(Scalar::Int(x.wrapping_rem(y)))
            } else {
                Ok(scalar_functions::real_scalar(x.wrapping_rem(y) as f64))
            }
        }
        Op::BitwiseAnd
        | Op::BitwiseOr
        | Op::BitwiseXor
        | Op::PGBitwiseShiftLeft
        | Op::PGBitwiseShiftRight => {
            let (x, y) = (integer(&a), integer(&b));
            let left = |count: i64| {
                if count >= 64 {
                    0
                } else {
                    x.wrapping_shl(count as u32)
                }
            };
            let right = |count: i64| {
                if count >= 64 {
                    if x < 0 {
                        -1
                    } else {
                        0
                    }
                } else {
                    x >> count
                }
            };
            Ok(Scalar::Int(match op {
                Op::BitwiseAnd => x & y,
                Op::BitwiseOr => x | y,
                Op::BitwiseXor => x ^ y,
                Op::PGBitwiseShiftLeft => {
                    if y < 0 {
                        right(y.saturating_neg())
                    } else {
                        left(y)
                    }
                }
                _ => {
                    if y < 0 {
                        left(y.saturating_neg())
                    } else {
                        right(y)
                    }
                }
            }))
        }
        _ => Err(format!("unsupported binary operator {op}")),
    }
}

pub(super) fn evaluate(
    expr: &Expr,
    row: &RelRow,
    group: &[RelRow],
) -> Option<Result<Scalar, String>> {
    if !({
        matches!(
            expr,
            Expr::Case { .. }
                | Expr::Cast { .. }
                | Expr::IsNull(_)
                | Expr::IsNotNull(_)
                | Expr::IsTrue(_)
                | Expr::IsNotTrue(_)
                | Expr::IsFalse(_)
                | Expr::IsNotFalse(_)
                | Expr::IsDistinctFrom(..)
                | Expr::IsNotDistinctFrom(..)
                | Expr::Like { .. }
                | Expr::ILike { .. }
                | Expr::UnaryOp {
                    op: UnaryOperator::BitwiseNot,
                    ..
                }
        )
    }) {
        return None;
    }
    let scalar = |expr: &Expr| eval_scalar(expr, row, group);
    Some((|| {
        Ok(match expr {
            Expr::Case {
                operand,
                conditions,
                else_result,
                ..
            } => {
                let operand = operand.as_ref().map(|expr| scalar(expr)).transpose()?;
                for branch in conditions {
                    let condition = scalar(&branch.condition)?;
                    let matched = match &operand {
                        Some(value) => {
                            !matches!(value, Scalar::Null)
                                && !matches!(condition, Scalar::Null)
                                && value.sql_eq(&condition)
                        }
                        None => condition.truthy(),
                    };
                    if matched {
                        return scalar(&branch.result);
                    }
                }
                else_result
                    .as_ref()
                    .map(|expr| scalar(expr))
                    .transpose()?
                    .unwrap_or(Scalar::Null)
            }
            Expr::Cast {
                expr, data_type, ..
            } => cast(&scalar(expr)?, &data_type.to_string()),
            Expr::IsNull(expr) => Scalar::Int(matches!(scalar(expr)?, Scalar::Null) as i64),
            Expr::IsNotNull(expr) => Scalar::Int(!matches!(scalar(expr)?, Scalar::Null) as i64),
            Expr::IsTrue(operand)
            | Expr::IsNotTrue(operand)
            | Expr::IsFalse(operand)
            | Expr::IsNotFalse(operand) => {
                let value = scalar(operand)?;
                let truth = !matches!(value, Scalar::Null) && value.truthy();
                let falsity = !matches!(value, Scalar::Null) && !value.truthy();
                Scalar::Int(match expr {
                    Expr::IsTrue(_) => truth,
                    Expr::IsNotTrue(_) => !truth,
                    Expr::IsFalse(_) => falsity,
                    _ => !falsity,
                } as i64)
            }
            Expr::IsDistinctFrom(a, b) | Expr::IsNotDistinctFrom(a, b) => {
                let equal = scalar(a)?.sql_eq(&scalar(b)?);
                Scalar::Int(if matches!(expr, Expr::IsDistinctFrom(..)) {
                    !equal
                } else {
                    equal
                } as i64)
            }
            Expr::UnaryOp {
                op: UnaryOperator::BitwiseNot,
                expr,
            } => {
                let value = scalar(expr)?;
                if matches!(value, Scalar::Null) {
                    Scalar::Null
                } else {
                    Scalar::Int(!integer(&value))
                }
            }
            Expr::Like {
                expr,
                pattern,
                negated,
                escape_char,
                ..
            }
            | Expr::ILike {
                expr,
                pattern,
                negated,
                escape_char,
                ..
            } => {
                let value = scalar(expr)?;
                let pattern = scalar(pattern)?;
                if matches!(value, Scalar::Null) || matches!(pattern, Scalar::Null) {
                    return Ok(Scalar::Null);
                }
                let escape = if let Some(expr) = escape_char {
                    let value = scalar(expr)?;
                    let Scalar::Text(value) = value else {
                        return Err("ESCAPE expression must be a one-character string".into());
                    };
                    let mut chars = value.chars();
                    let first = chars
                        .next()
                        .ok_or("ESCAPE expression must be a one-character string")?;
                    if chars.next().is_some() {
                        return Err("ESCAPE expression must be a one-character string".into());
                    }
                    Some(first)
                } else {
                    None
                };
                let matched = like_match(
                    &text(&value).unwrap_or_default(),
                    &text(&pattern).unwrap_or_default(),
                    escape,
                );
                Scalar::Int((matched ^ *negated) as i64)
            }
            _ => unreachable!(),
        })
    })())
}

fn glob(value: &str, pattern: &str) -> bool {
    let value = value.chars().collect::<Vec<_>>();
    let pattern = pattern.chars().collect::<Vec<_>>();
    let mut current = vec![false; value.len() + 1];
    current[0] = true;
    let mut pos = 0;
    while pos < pattern.len() {
        let token = pattern[pos];
        pos += 1;
        let mut next = vec![false; value.len() + 1];
        if token == '*' {
            next[0] = current[0];
            for index in 1..=value.len() {
                next[index] = current[index] || next[index - 1];
            }
        } else {
            let mut class = None;
            if token == '[' {
                let mut end = pos + usize::from(pattern.get(pos) == Some(&'^'));
                if pattern.get(end) == Some(&']') {
                    end += 1;
                }
                while end < pattern.len() && pattern[end] != ']' {
                    end += 1;
                }
                if end == pattern.len() {
                    return false;
                }
                class = Some(&pattern[pos..end]);
                pos = end + 1;
            }
            for index in 0..value.len() {
                if !current[index] {
                    continue;
                }
                let matched = if let Some(class) = class {
                    let negated = class.first() == Some(&'^');
                    let mut cursor = usize::from(negated);
                    let mut found = false;
                    while cursor < class.len() {
                        if cursor + 2 < class.len() && class[cursor + 1] == '-' {
                            found |=
                                class[cursor] <= value[index] && value[index] <= class[cursor + 2];
                            cursor += 3;
                        } else {
                            found |= class[cursor] == value[index];
                            cursor += 1;
                        }
                    }
                    found ^ negated
                } else {
                    token == '?' || token == value[index]
                };
                next[index + 1] = matched;
            }
        }
        current = next;
    }
    current[value.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(sql: &str) -> QueryResult {
        execute_statement(
            sql,
            Some(&Dataset::default()),
            &NamedCaches::default(),
            None,
        )
        .unwrap()
    }
    #[test]
    fn null_truth_is_and_conditional_values_follow_sql_rules() {
        assert_eq!(query("SELECT NULL AND 0,NULL AND 1,NULL OR 1,NULL OR 0,NOT NULL,NULL=1,NULL IS NULL,NULL IS NOT NULL,'1' IS 1,1 IS 1.0").rows[0], ["0","NULL","1","NULL","NULL","NULL","1","0","0","1"]);
        assert_eq!(query("SELECT CASE NULL WHEN NULL THEN 1 ELSE 2 END,CASE WHEN NULL THEN 1 ELSE 2 END,CASE 1 WHEN 1.0 THEN 3 ELSE 4 END,CASE '1' WHEN 1 THEN 3 ELSE 4 END").rows[0], ["2","2","3","4"]);
        assert_eq!(query("SELECT 2 IS TRUE,'x' IS TRUE,NULL IS TRUE,NULL IS FALSE,NULL IS NOT TRUE,NULL IS NOT FALSE").rows[0], ["1","0","0","0","1","1"]);
    }
    #[test]
    fn numeric_coercion_preserves_integer_arithmetic_and_cast_affinity() {
        assert_eq!(query("SELECT '12'+3,'12x'+3,'x'+3,'1.5e2x'+3,'1e'+3,'1.0'+3,x'3132'+3,9007199254740993+0").rows[0], ["15","15","3","153.0","4","4.0","15","9007199254740993"]);
        assert_eq!(query("SELECT CAST('12x' AS INTEGER),CAST(' -12.5x' AS INTEGER),CAST('1e2' AS INTEGER),CAST('1e2' AS REAL),CAST('1e2' AS NUMERIC),CAST('bad' AS REAL),CAST(NULL AS TEXT),CAST('ab' AS BLOB),CAST(x'3132' AS TEXT)").rows[0], ["12","-12","1","100.0","100","0.0","NULL","6162","12"]);
        assert_eq!(
            query("SELECT '5.5'%2,-0.0,0.0*-1,'a'||12,'a'||NULL,x'3132'||'a'").rows[0],
            ["1.0", "0.0", "0.0", "a12", "NULL", "12a"]
        );
    }
    #[test]
    fn matching_has_literal_underscores_unless_escape_is_explicit() {
        assert_eq!(query("SELECT 'AbC' LIKE 'a%c','AbC' LIKE 'a_c','ABC' LIKE 'abc','abc' LIKE 'A_c' ESCAPE '!','a_b' LIKE 'a!_b' ESCAPE '!' ,'abc' GLOB 'a*','AbC' GLOB 'a*','b' GLOB '[^a]','b' GLOB '[!a]',NULL GLOB '*'").rows[0], ["1","0","1","1","1","1","0","1","0","NULL"]);
    }
    #[test]
    fn streaming_case_cast_and_group_aliases_match_generic_derived_rows() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/dex/alpha.dex");
        let ds = Dataset::load_paths(&[path]).unwrap();
        let caches = NamedCaches::default();
        for projection in [
            "CASE WHEN method_idx%2=0 THEN NULL ELSE CAST(method_idx AS TEXT) END AS k",
            "method_idx%4 AS k,count(*) AS n",
            "count(CASE WHEN method_idx%3=0 THEN NULL ELSE name END) AS n",
        ] {
            let suffix = if projection.contains("count(*)") {
                " GROUP BY k HAVING n>1 ORDER BY n DESC,k"
            } else if projection.starts_with("count(") {
                ""
            } else {
                " ORDER BY k"
            };
            let direct = execute_statement(
                &format!("SELECT {projection} FROM methods{suffix}"),
                Some(&ds),
                &caches,
                None,
            )
            .unwrap();
            let derived = execute_statement(
                &format!(
                    "SELECT {projection} FROM (SELECT method_idx,name FROM methods) t{suffix}"
                ),
                Some(&ds),
                &caches,
                None,
            )
            .unwrap();
            assert_eq!(direct.columns, derived.columns);
            assert_eq!(direct.rows, derived.rows);
        }
    }
}
