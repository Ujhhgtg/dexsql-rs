//! Annotation rendering lives in dexsql-core::dex so the SQL fast path and the
//! typed metadata API share one parser. This module keeps the original call sites.
pub(crate) use dexsql_core::dex::annotations::{class_annotations, method_annotations};
