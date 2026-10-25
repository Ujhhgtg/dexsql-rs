//! SQL validation, planning, and execution share one module boundary.

pub mod ast;
pub mod exec;
pub mod ir;
pub mod lower;
pub mod optimizer;
pub mod query;
pub mod schema;
