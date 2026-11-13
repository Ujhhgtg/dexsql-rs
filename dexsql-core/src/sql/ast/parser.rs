//! Compatibility entry points for the native query parser.
//!
//! The grammar lives in query.rs; this module keeps the historical parser
//! module path stable for workspace code while execution migration proceeds.

pub use super::query::ParseError;

/// Validate a query with the native recursive-descent grammar.
pub fn validate_query(sql: &str) -> Result<(), ParseError> {
    super::query::parse_query(sql).map(|_| ())
}

/// Legacy mapper retained only for source compatibility.
pub fn map_parser_error(message: &str, _sql: &str) -> (String, Option<(usize, usize)>) {
    (message.to_owned(), None)
}
