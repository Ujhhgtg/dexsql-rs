//! Shared implementation of DEX loading and SQL execution.
//!
//! Embedders should use the stable `dexsql` crate. These modules are exposed
//! for the workspace's facade and command-line frontend; they are not a stable
//! public API. Command-line and MCP transport dependencies live in dexsql-cli.

mod archive;
pub mod dex;
mod mutf8;
pub mod sql;
