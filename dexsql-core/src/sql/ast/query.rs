//! Self-contained query AST and recursive-descent parser.
//!
//! This module is deliberately independent from `sqlparser`.  The reference
//! binary keeps the lexical and grammar front-end in `dexsql-ast`; the
//! execution pipeline still uses the compatibility AST elsewhere in the
//! workspace.  `parse_query` is the migration seam: callers can move from
//! `sqlparser::ast::Query` one relation at a time without changing the
//! tokenizer or validation policy.

use super::front::{validate, Statement as FrontStatement};
use super::token::{tokenize, Token, TokenKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub span: Option<(usize, usize)>,
}

impl ParseError {
    fn at(message: impl Into<String>, token: Option<&Token>) -> Self {
        Self {
            message: message.into(),
            span: token.map(|t| (t.start, t.end)),
        }
    }
    fn eof(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub with: Vec<Cte>,
    pub body: SetExpr,
    pub order_by: Vec<OrderBy>,
    pub limit: Option<Expr>,
    pub offset: Option<Expr>,
}

/// One read-only statement after the native front-end policy gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedStatement {
    Query(Query),
    CreateDefinition {
        name: String,
        query: Query,
        replace: bool,
        table: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cte {
    pub name: String,
    pub columns: Vec<String>,
    pub query: Box<Query>,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetExpr {
    Select(Select),
    Values(Vec<Vec<Expr>>),
    SetOp {
        left: Box<SetExpr>,
        op: SetOperator,
        all: bool,
        right: Box<SetExpr>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOperator {
    Union,
    Intersect,
    Except,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Select {
    pub distinct: bool,
    pub projection: Vec<SelectItem>,
    pub from: Vec<TableRef>,
    pub selection: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectItem {
    Expr { expr: Expr, alias: Option<String> },
    Wildcard,
    QualifiedWildcard(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableRef {
    Table {
        name: Vec<String>,
        alias: Option<String>,
    },
    Derived {
        query: Box<Query>,
        alias: Option<String>,
    },
    Join {
        left: Box<TableRef>,
        kind: JoinKind,
        right: Box<TableRef>,
        constraint: JoinConstraint,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
    Natural,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinConstraint {
    None,
    On(Expr),
    Using(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderBy {
    pub expr: Expr,
    pub asc: bool,
    pub nulls_first: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Literal {
    Null,
    Boolean(bool),
    Number(String),
    String(String),
    Blob(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    Plus,
    Minus,
    Not,
    BitNot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOp {
    Or,
    And,
    Eq,
    NotEq,
    Lt,
    LtEq,
    Gt,
    GtEq,
    Is,
    IsNot,
    Like,
    Glob,
    Match,
    NotLike,
    NotGlob,
    NotMatch,
    In,
    NotIn,
    Between,
    NotBetween,
    BitOr,
    BitAnd,
    ShiftLeft,
    ShiftRight,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Concat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Identifier(Vec<String>),
    Literal(Literal),
    Parameter(Option<String>),
    Wildcard,
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },
    /// SQLite's postfix `ESCAPE` operand on LIKE/GLOB/MATCH expressions.
    Escape {
        expr: Box<Expr>,
        escape: Box<Expr>,
    },
    IsNull {
        expr: Box<Expr>,
        negated: bool,
    },
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    InList {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    InSubquery {
        expr: Box<Expr>,
        query: Box<Query>,
        negated: bool,
    },
    Exists {
        query: Box<Query>,
        negated: bool,
    },
    Subquery(Box<Query>),
    Function {
        name: String,
        args: Vec<Expr>,
        distinct: bool,
    },
    Case {
        operand: Option<Box<Expr>>,
        when_then: Vec<(Expr, Expr)>,
        else_expr: Option<Box<Expr>>,
    },
    Cast {
        expr: Box<Expr>,
        data_type: String,
    },
}

/// Parse one validated SELECT/VALUES/WITH statement.  Comments and trailing
/// semicolons are accepted by the same scanner used by `validate`.
pub fn parse_query(sql: &str) -> Result<Query, ParseError> {
    let tokens = tokenize(sql).map_err(|e| ParseError {
        message: e.message,
        span: Some(e.span),
    })?;
    let mut p = Parser {
        sql,
        tokens,
        pos: 0,
    };
    let query = p.query(false)?;
    if p.peek().is_some_and(|t| t.kind == TokenKind::Semicolon) {
        p.pos += 1;
    }
    if let Some(t) = p.peek() {
        return Err(ParseError::at("trailing tokens after statement", Some(t)));
    }
    Ok(query)
}

/// Parse a complete read-only statement, including CREATE TEMP/VIEW query
/// definitions.  Statement-count and policy errors remain owned by `front`.
pub fn parse_statement(sql: &str) -> Result<ParsedStatement, ParseError> {
    let statement = validate(sql).map_err(|error| ParseError {
        message: error.render(),
        span: error.span,
    })?;
    match statement {
        FrontStatement::Query { sql } => parse_query(&sql).map(ParsedStatement::Query),
        FrontStatement::CreateDefinition {
            name,
            query,
            replace,
            table,
        } => parse_query(&query).map(|query| ParsedStatement::CreateDefinition {
            name,
            query,
            replace,
            table,
        }),
    }
}

struct Parser<'a> {
    sql: &'a str,
    tokens: Vec<Token>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
    fn text(&self, t: &Token) -> &'a str {
        t.text(self.sql)
    }
    fn kw(&self, word: &str) -> bool {
        self.peek().and_then(Token::keyword) == Some(word)
    }
    fn take_kw(&mut self, word: &str) -> bool {
        if self.kw(word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn take_kind(&mut self, kind: &TokenKind) -> bool {
        if self.peek().is_some_and(|t| &t.kind == kind) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_kw(&mut self, word: &str) -> Result<(), ParseError> {
        if self.take_kw(word) {
            Ok(())
        } else {
            Err(ParseError::at(
                format!("expected keyword {word}"),
                self.peek(),
            ))
        }
    }
    fn expect_kind(&mut self, kind: &TokenKind, message: &str) -> Result<(), ParseError> {
        if self.take_kind(kind) {
            Ok(())
        } else {
            Err(ParseError::at(message, self.peek()))
        }
    }
    fn identifier(&mut self) -> Result<String, ParseError> {
        let Some(t) = self.peek() else {
            return Err(ParseError::eof("expected an identifier"));
        };
        let result = match &t.kind {
            TokenKind::Ident { .. } => self.text(t).to_owned(),
            TokenKind::QuotedIdent => unquote(self.text(t)),
            _ => return Err(ParseError::at("expected an identifier", Some(t))),
        };
        self.pos += 1;
        Ok(result)
    }
    fn name(&mut self) -> Result<Vec<String>, ParseError> {
        let mut parts = vec![self.identifier()?];
        while self.take_kind(&TokenKind::Dot) {
            parts.push(self.identifier()?);
        }
        Ok(parts)
    }
    fn query(&mut self, stop_rparen: bool) -> Result<Query, ParseError> {
        let (with, recursive) = self.with_clause()?;
        let mut body = self.set_expr()?;
        while let Some(op) = self.set_operator() {
            self.pos += 1;
            let all = self.take_kw("ALL");
            let right = self.set_expr()?;
            body = SetExpr::SetOp {
                left: Box::new(body),
                op,
                all,
                right: Box::new(right),
            };
        }
        let mut order_by = Vec::new();
        if self.take_kw("ORDER") {
            self.expect_kw("BY")?;
            loop {
                let expr = self.expr(0)?;
                let asc = if self.take_kw("ASC") {
                    true
                } else {
                    !self.take_kw("DESC")
                };
                let nulls_first = if self.take_kw("NULLS") {
                    Some(if self.take_kw("FIRST") {
                        true
                    } else {
                        self.expect_kw("LAST")?;
                        false
                    })
                } else {
                    None
                };
                order_by.push(OrderBy {
                    expr,
                    asc,
                    nulls_first,
                });
                if !self.take_kind(&TokenKind::Comma) {
                    break;
                }
            }
        }
        let mut limit = None;
        let mut offset = None;
        if self.take_kw("LIMIT") {
            limit = Some(self.expr(0)?);
            if self.take_kw("OFFSET") {
                offset = Some(self.expr(0)?);
            } else if self.take_kind(&TokenKind::Comma) {
                offset = Some(limit.take().expect("limit just set"));
                limit = Some(self.expr(0)?);
            }
        } else if self.take_kw("OFFSET") {
            offset = Some(self.expr(0)?);
        }
        if stop_rparen && self.peek().is_none() {
            return Err(ParseError::eof("expected RParen"));
        }
        let _ = recursive;
        Ok(Query {
            with,
            body,
            order_by,
            limit,
            offset,
        })
    }
    fn with_clause(&mut self) -> Result<(Vec<Cte>, bool), ParseError> {
        if !self.take_kw("WITH") {
            return Ok((Vec::new(), false));
        }
        let recursive = self.take_kw("RECURSIVE");
        let mut list = Vec::new();
        loop {
            let name = self.identifier()?;
            let mut columns = Vec::new();
            if self.take_kind(&TokenKind::LParen) {
                loop {
                    columns.push(self.identifier()?);
                    if !self.take_kind(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            }
            self.expect_kw("AS")?;
            self.expect_kind(&TokenKind::LParen, "expected LParen")?;
            let query = self.query(true)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            list.push(Cte {
                name,
                columns,
                query: Box::new(query),
                recursive,
            });
            if !self.take_kind(&TokenKind::Comma) {
                break;
            }
        }
        Ok((list, recursive))
    }
    fn set_operator(&self) -> Option<SetOperator> {
        match self.peek().and_then(Token::keyword) {
            Some("UNION") => Some(SetOperator::Union),
            Some("INTERSECT") => Some(SetOperator::Intersect),
            Some("EXCEPT") => Some(SetOperator::Except),
            _ => None,
        }
    }
    fn set_expr(&mut self) -> Result<SetExpr, ParseError> {
        if self.take_kw("SELECT") {
            self.select().map(SetExpr::Select)
        } else if self.take_kw("VALUES") {
            self.values().map(SetExpr::Values)
        } else if self.take_kind(&TokenKind::LParen) {
            let q = self.query(true)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            Ok(q.body)
        } else {
            Err(ParseError::at("expected keyword select", self.peek()))
        }
    }
    fn values(&mut self) -> Result<Vec<Vec<Expr>>, ParseError> {
        let mut rows = Vec::new();
        loop {
            self.expect_kind(&TokenKind::LParen, "expected LParen")?;
            let mut row = Vec::new();
            loop {
                row.push(self.expr(0)?);
                if !self.take_kind(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            rows.push(row);
            if !self.take_kind(&TokenKind::Comma) {
                break;
            }
        }
        Ok(rows)
    }
    fn select(&mut self) -> Result<Select, ParseError> {
        let distinct = self.take_kw("DISTINCT");
        let mut projection = Vec::new();
        loop {
            if self.take_kind(&TokenKind::Op("*".to_owned())) {
                projection.push(SelectItem::Wildcard);
            } else {
                let expr = self.expr(0)?;
                if let Expr::Identifier(parts) = &expr {
                    if parts.last().is_some_and(|part| part == "*") {
                        let mut name = parts.clone();
                        name.pop();
                        projection.push(SelectItem::QualifiedWildcard(name.join(".")));
                    } else if self.take_kind(&TokenKind::Dot)
                        && self.take_kind(&TokenKind::Op("*".to_owned()))
                    {
                        projection.push(SelectItem::QualifiedWildcard(parts.join(".")));
                    } else {
                        let alias = self.alias();
                        projection.push(SelectItem::Expr { expr, alias });
                    }
                } else {
                    let alias = self.alias();
                    projection.push(SelectItem::Expr { expr, alias });
                }
            }
            if !self.take_kind(&TokenKind::Comma) {
                break;
            }
        }
        let mut from = Vec::new();
        if self.take_kw("FROM") {
            from.push(self.table_ref()?);
            while self.take_kind(&TokenKind::Comma) {
                from.push(self.table_ref()?);
            }
        }
        let selection = if self.take_kw("WHERE") {
            Some(self.expr(0)?)
        } else {
            None
        };
        let mut group_by = Vec::new();
        if self.take_kw("GROUP") {
            self.expect_kw("BY")?;
            loop {
                group_by.push(self.expr(0)?);
                if !self.take_kind(&TokenKind::Comma) {
                    break;
                }
            }
        }
        let having = if self.take_kw("HAVING") {
            Some(self.expr(0)?)
        } else {
            None
        };
        Ok(Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
        })
    }
    fn alias(&mut self) -> Option<String> {
        if self.take_kw("AS") {
            return self.identifier().ok();
        }
        let is_ident = self.peek().is_some_and(|t| {
            matches!(t.kind, TokenKind::QuotedIdent)
                || matches!(t.kind, TokenKind::Ident { .. })
                    && !matches!(
                        t.keyword(),
                        Some(
                            "FROM"
                                | "WHERE"
                                | "GROUP"
                                | "HAVING"
                                | "ORDER"
                                | "LIMIT"
                                | "OFFSET"
                                | "UNION"
                                | "INTERSECT"
                                | "EXCEPT"
                                | "JOIN"
                                | "LEFT"
                                | "RIGHT"
                                | "FULL"
                                | "INNER"
                                | "CROSS"
                                | "NATURAL"
                                | "ON"
                                | "USING"
                                | "WHEN"
                                | "THEN"
                                | "ELSE"
                                | "END"
                                | "AS"
                                | "AND"
                                | "OR"
                                | "ASC"
                                | "DESC"
                                | "NULLS"
                                | "ESCAPE"
                                | "WINDOW"
                                | "RETURNING"
                        )
                    )
        });
        if is_ident {
            self.identifier().ok()
        } else {
            None
        }
    }
    fn table_ref(&mut self) -> Result<TableRef, ParseError> {
        let mut left = if self.take_kind(&TokenKind::LParen) {
            let q = self.query(true)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            TableRef::Derived {
                query: Box::new(q),
                alias: self.alias(),
            }
        } else {
            let name = self.name()?;
            TableRef::Table {
                name,
                alias: self.alias(),
            }
        };
        loop {
            let natural = self.take_kw("NATURAL");
            let kind = if self.take_kw("LEFT") {
                self.take_kw("OUTER");
                JoinKind::Left
            } else if self.take_kw("RIGHT") {
                self.take_kw("OUTER");
                JoinKind::Right
            } else if self.take_kw("FULL") {
                self.take_kw("OUTER");
                JoinKind::Full
            } else if self.take_kw("CROSS") {
                JoinKind::Cross
            } else if natural {
                JoinKind::Natural
            } else if self.take_kw("INNER") {
                JoinKind::Inner
            } else if self.kw("JOIN") {
                JoinKind::Inner
            } else {
                break;
            };
            self.expect_kw("JOIN")?;
            let right = self.table_ref_atom()?;
            let constraint = if self.take_kw("ON") {
                JoinConstraint::On(self.expr(0)?)
            } else if self.take_kw("USING") {
                self.expect_kind(&TokenKind::LParen, "expected LParen")?;
                let mut names = Vec::new();
                loop {
                    names.push(self.identifier()?);
                    if !self.take_kind(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect_kind(&TokenKind::RParen, "expected RParen")?;
                JoinConstraint::Using(names)
            } else {
                JoinConstraint::None
            };
            left = TableRef::Join {
                left: Box::new(left),
                kind,
                right: Box::new(right),
                constraint,
            };
        }
        Ok(left)
    }
    fn table_ref_atom(&mut self) -> Result<TableRef, ParseError> {
        if self.take_kind(&TokenKind::LParen) {
            let q = self.query(true)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            Ok(TableRef::Derived {
                query: Box::new(q),
                alias: self.alias(),
            })
        } else {
            Ok(TableRef::Table {
                name: self.name()?,
                alias: self.alias(),
            })
        }
    }
    fn precedence(op: &str) -> Option<u8> {
        Some(match op {
            "OR" => 1,
            "AND" => 2,
            "=" | "==" | "!=" | "<>" | "<" | "<=" | ">" | ">=" | "IS" | "LIKE" | "GLOB"
            | "MATCH" | "IN" | "BETWEEN" => 3,
            "|" => 4,
            "&" => 5,
            "<<" | ">>" => 6,
            "+" | "-" => 7,
            "*" | "/" | "%" => 8,
            "||" => 9,
            _ => return None,
        })
    }
    fn expr(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut left = self.prefix()?;
        loop {
            let (op_text, keyword) = match self.peek() {
                Some(t) => (self.text(t).to_ascii_uppercase(), t.keyword().is_some()),
                None => break,
            };
            let mut op_name = op_text.clone();
            let mut negated = false;
            if op_name == "IS"
                && self.tokens.get(self.pos + 1).and_then(Token::keyword) == Some("NOT")
            {
                negated = true;
                self.pos += 1;
            }
            if keyword && self.kw("NOT") {
                let next = self.tokens.get(self.pos + 1).and_then(Token::keyword);
                if matches!(next, Some("IN" | "LIKE" | "GLOB" | "MATCH" | "BETWEEN")) {
                    negated = true;
                    self.pos += 1;
                    op_name = next.unwrap().to_owned();
                }
            }
            let Some(prec) = Self::precedence(&op_name) else {
                break;
            };
            if prec < min_prec {
                break;
            }
            self.pos += 1;
            if op_name == "IN" {
                if negated {}
                let (list, query) = self.in_rhs()?;
                left = match query {
                    Some(q) => Expr::InSubquery {
                        expr: Box::new(left),
                        query: Box::new(q),
                        negated,
                    },
                    None => Expr::InList {
                        expr: Box::new(left),
                        list,
                        negated,
                    },
                };
                continue;
            }
            if op_name == "BETWEEN" {
                let low = self.expr(prec + 1)?;
                self.expect_kw("AND")?;
                let high = self.expr(prec + 1)?;
                left = Expr::Between {
                    expr: Box::new(left),
                    low: Box::new(low),
                    high: Box::new(high),
                    negated,
                };
                continue;
            }
            let right = self.expr(prec + 1)?;
            let op = binary_op(&op_name, negated)
                .ok_or_else(|| ParseError::at("unsupported operator", self.peek()))?;
            left = Expr::Binary {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };
            if matches!(op_name.as_str(), "LIKE" | "GLOB" | "MATCH") && self.take_kw("ESCAPE") {
                left = Expr::Escape {
                    expr: Box::new(left),
                    escape: Box::new(self.expr(10)?),
                };
            }
        }
        Ok(left)
    }
    fn in_rhs(&mut self) -> Result<(Vec<Expr>, Option<Query>), ParseError> {
        self.expect_kind(&TokenKind::LParen, "expected LParen")?;
        if self.kw("SELECT") || self.kw("WITH") || self.kw("VALUES") {
            let q = self.query(true)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            return Ok((Vec::new(), Some(q)));
        }
        let mut list = Vec::new();
        if !self.take_kind(&TokenKind::RParen) {
            loop {
                list.push(self.expr(0)?);
                if !self.take_kind(&TokenKind::Comma) {
                    break;
                }
            }
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
        }
        Ok((list, None))
    }
    fn prefix(&mut self) -> Result<Expr, ParseError> {
        if self.take_kw("NOT") {
            return Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(self.expr(10)?),
            });
        }
        if self.take_kind(&TokenKind::Op("+".to_owned())) {
            return Ok(Expr::Unary {
                op: UnaryOp::Plus,
                expr: Box::new(self.expr(10)?),
            });
        }
        if self.take_kind(&TokenKind::Op("-".to_owned())) {
            return Ok(Expr::Unary {
                op: UnaryOp::Minus,
                expr: Box::new(self.expr(10)?),
            });
        }
        if self.take_kind(&TokenKind::Op("~".to_owned())) {
            return Ok(Expr::Unary {
                op: UnaryOp::BitNot,
                expr: Box::new(self.expr(10)?),
            });
        }
        if self.take_kind(&TokenKind::LParen) {
            if self.kw("SELECT") || self.kw("WITH") || self.kw("VALUES") {
                let q = self.query(true)?;
                self.expect_kind(&TokenKind::RParen, "expected RParen")?;
                return Ok(Expr::Subquery(Box::new(q)));
            }
            let e = self.expr(0)?;
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            return Ok(e);
        }
        let Some(t) = self.peek().cloned() else {
            return Err(ParseError::eof("expected an expression"));
        };
        match t.kind {
            TokenKind::Number => {
                self.pos += 1;
                Ok(Expr::Literal(Literal::Number(self.text(&t).to_owned())))
            }
            TokenKind::Str => {
                self.pos += 1;
                Ok(Expr::Literal(Literal::String(unquote(self.text(&t)))))
            }
            TokenKind::Blob => {
                self.pos += 1;
                Ok(Expr::Literal(Literal::Blob(
                    self.text(&t)[2..self.text(&t).len() - 1].to_owned(),
                )))
            }
            TokenKind::Op(ref op) if op == "?" => {
                self.pos += 1;
                Ok(Expr::Parameter(None))
            }
            TokenKind::Op(ref op) if op == "*" => {
                self.pos += 1;
                Ok(Expr::Wildcard)
            }
            TokenKind::Ident { .. } | TokenKind::QuotedIdent => {
                let kw = t.keyword().unwrap_or("").to_owned();
                self.pos += 1;
                if kw == "NULL" {
                    return Ok(Expr::Literal(Literal::Null));
                }
                if kw == "TRUE" {
                    return Ok(Expr::Literal(Literal::Boolean(true)));
                }
                if kw == "FALSE" {
                    return Ok(Expr::Literal(Literal::Boolean(false)));
                }
                if kw == "EXISTS" {
                    self.expect_kind(&TokenKind::LParen, "expected LParen")?;
                    let q = self.query(true)?;
                    self.expect_kind(&TokenKind::RParen, "expected RParen")?;
                    return Ok(Expr::Exists {
                        query: Box::new(q),
                        negated: false,
                    });
                }
                if kw == "CASE" {
                    return self.case_expr();
                }
                if kw == "CAST" {
                    return self.cast_expr();
                }
                let mut parts = vec![unquote(self.text(&t))];
                while self.take_kind(&TokenKind::Dot) {
                    if self.take_kind(&TokenKind::Op("*".to_owned())) {
                        parts.push("*".to_owned());
                        break;
                    }
                    parts.push(self.identifier()?);
                }
                if self.take_kind(&TokenKind::LParen) {
                    let distinct = self.take_kw("DISTINCT");
                    let mut args = Vec::new();
                    if !self.take_kind(&TokenKind::RParen) {
                        loop {
                            args.push(self.expr(0)?);
                            if !self.take_kind(&TokenKind::Comma) {
                                break;
                            }
                        }
                        self.expect_kind(&TokenKind::RParen, "expected RParen")?;
                    }
                    return Ok(Expr::Function {
                        name: parts.join("."),
                        args,
                        distinct,
                    });
                }
                Ok(Expr::Identifier(parts))
            }
            _ => Err(ParseError::at("expected an expression", Some(&t))),
        }
    }
    fn case_expr(&mut self) -> Result<Expr, ParseError> {
        let operand = if self.kw("WHEN") {
            None
        } else {
            Some(Box::new(self.expr(0)?))
        };
        let mut when_then = Vec::new();
        while self.take_kw("WHEN") {
            let w = self.expr(0)?;
            self.expect_kw("THEN")?;
            let t = self.expr(0)?;
            when_then.push((w, t));
        }
        let else_expr = if self.take_kw("ELSE") {
            Some(Box::new(self.expr(0)?))
        } else {
            None
        };
        self.expect_kw("END")?;
        Ok(Expr::Case {
            operand,
            when_then,
            else_expr,
        })
    }
    fn cast_expr(&mut self) -> Result<Expr, ParseError> {
        self.expect_kind(&TokenKind::LParen, "expected LParen")?;
        let expr = self.expr(0)?;
        self.expect_kw("AS")?;
        let mut ty = self.type_atom()?;
        while self.take_kind(&TokenKind::LParen) {
            ty.push('(');
            ty.push_str(&self.type_atom()?);
            while self.take_kind(&TokenKind::Comma) {
                ty.push(',');
                ty.push_str(&self.type_atom()?);
            }
            self.expect_kind(&TokenKind::RParen, "expected RParen")?;
            ty.push(')');
        }
        self.expect_kind(&TokenKind::RParen, "expected RParen")?;
        Ok(Expr::Cast {
            expr: Box::new(expr),
            data_type: ty,
        })
    }
    fn type_atom(&mut self) -> Result<String, ParseError> {
        let Some(token) = self.peek().cloned() else {
            return Err(ParseError::eof("expected a type name in CAST"));
        };
        match token.kind {
            TokenKind::Ident { .. } | TokenKind::QuotedIdent | TokenKind::Number => {
                self.pos += 1;
                Ok(self.text(&token).to_owned())
            }
            _ => Err(ParseError::at("expected a type name in CAST", Some(&token))),
        }
    }
}

fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('[') && s.ends_with(']')))
    {
        s[1..s.len() - 1].replace("\"\"", "\"")
    } else if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        s[1..s.len() - 1].replace("''", "'")
    } else {
        s.to_owned()
    }
}

fn binary_op(op: &str, negated: bool) -> Option<BinaryOp> {
    Some(match (op, negated) {
        ("OR", false) => BinaryOp::Or,
        ("AND", false) => BinaryOp::And,
        ("=", false) | ("==", false) => BinaryOp::Eq,
        ("!=", false) | ("<>", false) => BinaryOp::NotEq,
        ("<", false) => BinaryOp::Lt,
        ("<=", false) => BinaryOp::LtEq,
        (">", false) => BinaryOp::Gt,
        (">=", false) => BinaryOp::GtEq,
        ("IS", false) => BinaryOp::Is,
        ("IS", true) => BinaryOp::IsNot,
        ("LIKE", false) => BinaryOp::Like,
        ("LIKE", true) => BinaryOp::NotLike,
        ("GLOB", false) => BinaryOp::Glob,
        ("GLOB", true) => BinaryOp::NotGlob,
        ("MATCH", false) => BinaryOp::Match,
        ("MATCH", true) => BinaryOp::NotMatch,
        ("|", false) => BinaryOp::BitOr,
        ("&", false) => BinaryOp::BitAnd,
        ("<<", false) => BinaryOp::ShiftLeft,
        (">>", false) => BinaryOp::ShiftRight,
        ("+", false) => BinaryOp::Add,
        ("-", false) => BinaryOp::Sub,
        ("*", false) => BinaryOp::Mul,
        ("/", false) => BinaryOp::Div,
        ("%", false) => BinaryOp::Mod,
        ("||", false) => BinaryOp::Concat,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_relational_select() {
        let q = parse_query("SELECT a.id, count(*) AS n FROM foo AS a LEFT JOIN bar b ON a.id=b.id WHERE a.x IN (1, 2) GROUP BY a.id HAVING count(*) > 1 ORDER BY a.id DESC LIMIT 5 OFFSET 2").unwrap();
        assert_eq!(q.order_by.len(), 1);
        assert_eq!(q.limit, Some(Expr::Literal(Literal::Number("5".into()))));
        let SetExpr::Select(select) = q.body else {
            panic!("not select")
        };
        assert_eq!(select.projection.len(), 2);
        assert!(matches!(select.from[0], TableRef::Join { .. }));
        assert_eq!(select.group_by.len(), 1);
    }

    #[test]
    fn parses_cte_set_and_subqueries() {
        let q = parse_query("WITH x(v) AS (SELECT id FROM t) SELECT v FROM x WHERE EXISTS (SELECT 1 FROM y) UNION ALL VALUES (2)").unwrap();
        assert_eq!(q.with.len(), 1);
        assert!(matches!(
            q.body,
            SetExpr::SetOp {
                op: SetOperator::Union,
                all: true,
                ..
            }
        ));
    }

    #[test]
    fn parses_case_cast_and_literals() {
        let q = parse_query(
            "SELECT CASE WHEN a IS NULL THEN CAST(1 AS VARCHAR(10, 2)) ELSE x'0a' END FROM t",
        )
        .unwrap();
        let SetExpr::Select(s) = q.body else {
            panic!("not select")
        };
        assert!(matches!(
            s.projection[0],
            SelectItem::Expr {
                expr: Expr::Case { .. },
                ..
            }
        ));
    }

    #[test]
    fn parses_create_definition_through_front_policy() {
        let statement = parse_statement("CREATE TEMP TABLE scratch AS SELECT 1").unwrap();
        assert!(matches!(
            statement,
            ParsedStatement::CreateDefinition { table: true, .. }
        ));
    }

    #[test]
    fn parses_like_escape_as_postfix_expression() {
        let query = parse_query("SELECT name LIKE 'a!_b' ESCAPE '!' FROM methods").unwrap();
        let SetExpr::Select(select) = query.body else {
            panic!("not select")
        };
        assert!(matches!(
            select.projection[0],
            SelectItem::Expr {
                expr: Expr::Escape { .. },
                ..
            }
        ));
    }
}
