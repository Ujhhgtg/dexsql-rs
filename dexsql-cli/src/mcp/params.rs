//! Typed MCP argument decoding shared by validation and worker dispatch.
//!
//! The reference uses serde's generated parameter wrappers. Keeping the same
//! required fields, defaults, enum variants, and integer widths also preserves
//! serde's error wording and its validation order for malformed maps.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DecodeMode {
    #[default]
    Summary,
    Smali,
    Context,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManifestMode {
    #[default]
    Summary,
    Xml,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResourceFormat {
    #[default]
    Auto,
    Hex,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpenDatasetArgs {
    #[serde(rename = "inputs")]
    _inputs: Vec<String>,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CloseDatasetArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DescribeTableArgs {
    #[serde(rename = "name")]
    _name: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NamedTempQuery {
    #[serde(rename = "name")]
    _name: String,
    #[serde(rename = "sql")]
    _sql: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "sql")]
    _sql: Vec<String>,
    #[serde(rename = "named_temp_queries", default)]
    _named_temp_queries: Vec<NamedTempQuery>,
    #[serde(rename = "limit", default)]
    _limit: Option<usize>,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timing", default)]
    _timing: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DecodeArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "file_id", default)]
    _file_id: Option<u32>,
    #[serde(rename = "method", default)]
    _method: Option<String>,
    #[serde(rename = "method_idx", default)]
    _method_idx: Option<u32>,
    #[serde(rename = "class", default)]
    _class: Option<String>,
    #[serde(rename = "mode", default)]
    _mode: Option<DecodeMode>,
    #[serde(rename = "method_offset", default)]
    _method_offset: usize,
    #[serde(rename = "method_limit", default)]
    _method_limit: Option<usize>,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "max_lines", default)]
    _max_lines: Option<usize>,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "input_index", default)]
    _input_index: Option<usize>,
    #[serde(rename = "mode", default)]
    _mode: ManifestMode,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "limit", default)]
    _limit: Option<usize>,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestComponentsArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "input_index", default)]
    _input_index: Option<usize>,
    #[serde(rename = "kind", default)]
    _kind: Option<String>,
    #[serde(rename = "only_exported", default)]
    _only_exported: bool,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "limit", default)]
    _limit: Option<usize>,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ListResourceFilesArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "input_index", default)]
    _input_index: Option<usize>,
    #[serde(rename = "prefix", default)]
    _prefix: Option<String>,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "limit", default)]
    _limit: Option<usize>,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadResourceArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "input_index", default)]
    _input_index: Option<usize>,
    #[serde(rename = "name")]
    _name: String,
    #[serde(rename = "format", default)]
    _format: ResourceFormat,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryResourcesArgs {
    #[serde(rename = "dataset_id")]
    _dataset_id: String,
    #[serde(rename = "input_index", default)]
    _input_index: Option<usize>,
    #[serde(rename = "resource_id", default)]
    _resource_id: Option<u32>,
    #[serde(rename = "name", default)]
    _name: Option<String>,
    #[serde(rename = "resource_type", default)]
    _resource_type: Option<String>,
    #[serde(rename = "contains", default)]
    _contains: Option<String>,
    #[serde(rename = "configuration", default)]
    _configuration: Option<String>,
    #[serde(rename = "offset", default)]
    _offset: usize,
    #[serde(rename = "limit", default)]
    _limit: Option<usize>,
    #[serde(rename = "max_bytes", default)]
    _max_bytes: Option<usize>,
    #[serde(rename = "compact", default)]
    _compact: bool,
    #[serde(rename = "timeout_ms", default)]
    _timeout_ms: Option<u64>,
}

/// Decode parameters exactly as the tool wrappers do, then pass canonical
/// values (including explicit defaults) to the dataset worker.
pub(super) fn normalize(name: &str, arguments: &Map<String, Value>) -> Result<Value, String> {
    fn decode<T: serde::de::DeserializeOwned + Serialize>(value: Value) -> Result<Value, String> {
        let parameters: T = serde_json::from_value(value).map_err(|error| error.to_string())?;
        serde_json::to_value(parameters).map_err(|error| error.to_string())
    }
    let value = Value::Object(arguments.clone());
    match name {
        "open_dataset" => decode::<OpenDatasetArgs>(value),
        "close_dataset" => decode::<CloseDatasetArgs>(value),
        "describe_table" => decode::<DescribeTableArgs>(value),
        "query" => decode::<QueryArgs>(value),
        "decode" => decode::<DecodeArgs>(value),
        "get_manifest" => decode::<ManifestArgs>(value),
        "get_manifest_components" => decode::<ManifestComponentsArgs>(value),
        "list_resource_files" => decode::<ListResourceFilesArgs>(value),
        "read_resource" => decode::<ReadResourceArgs>(value),
        "query_resources" => decode::<QueryResourcesArgs>(value),
        // These tools have no parameter wrapper and ignore extra arguments.
        _ => Ok(value),
    }
}

/// Validate the common semantic bounds after the parent has resolved a dataset
/// and checked its timeout. The order is observable when several fields are
/// invalid at once: byte budget, row limit, then the query batch constraints.
pub(super) fn range_error(name: &str, arguments: &Value, max_output_bytes: u64) -> Option<String> {
    if let Some(bytes) = arguments.get("max_bytes").and_then(Value::as_u64) {
        if !(4096..=max_output_bytes).contains(&bytes) {
            return Some(format!("max_bytes must be in 4096..={max_output_bytes}"));
        }
    }
    let row_limit = match name {
        "query" => Some(1000),
        "get_manifest" | "get_manifest_components" | "list_resource_files" | "query_resources" => {
            Some(200)
        }
        _ => None,
    };
    if let (Some(maximum), Some(limit)) =
        (row_limit, arguments.get("limit").and_then(Value::as_u64))
    {
        if !(1..=maximum).contains(&limit) {
            return Some(format!("limit must be in 1..={maximum}"));
        }
    }
    if name != "query" {
        return None;
    }
    let statements = arguments.get("sql").and_then(Value::as_array)?;
    let temporary = arguments
        .get("named_temp_queries")
        .and_then(Value::as_array);
    let temporary_count = temporary.map_or(0, Vec::len);
    let sql_bytes = statements
        .iter()
        .fold(0usize, |bytes, sql| {
            bytes.saturating_add(sql.as_str().map_or(0, str::len))
        })
        .saturating_add(temporary.map_or(0, |temporary| {
            temporary.iter().fold(0usize, |bytes, query| {
                bytes.saturating_add(query.get("sql").and_then(Value::as_str).map_or(0, str::len))
            })
        }));
    let offset = arguments.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(200);
    if statements.is_empty()
        || statements.len() > 16
        || statements
            .iter()
            .any(|sql| sql.as_str().is_none_or(|sql| sql.trim().is_empty()))
        || temporary_count > 16
        || sql_bytes > 64 * 1024
        || offset.saturating_add(limit) > 100_000
    {
        return Some("query requires 1..=16 non-empty statements, at most 16 temporary queries and 64 KiB of SQL; offset + limit must not exceed 100000".to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn query_defaults_match_worker_protocol() {
        assert_eq!(
            normalize(
                "query",
                &args(json!({"dataset_id":"dataset-1","sql":["SELECT 1"]}))
            )
            .unwrap(),
            json!({"dataset_id":"dataset-1","sql":["SELECT 1"],"named_temp_queries":[],
                "limit":null,"offset":0,"max_bytes":null,"compact":false,"timing":false,"timeout_ms":null})
        );
    }

    #[test]
    fn required_and_default_fields_reject_null() {
        for (tool, value, expected) in [
            (
                "close_dataset",
                json!({"dataset_id":null}),
                "invalid type: null, expected a string",
            ),
            (
                "query",
                json!({"dataset_id":"x","sql":[],"offset":null}),
                "invalid type: null, expected usize",
            ),
            (
                "query",
                json!({"dataset_id":"x","sql":[],"timing":null}),
                "invalid type: null, expected a boolean",
            ),
        ] {
            assert_eq!(normalize(tool, &args(value)).unwrap_err(), expected);
        }
    }

    #[test]
    fn nested_definitions_use_typed_parameters() {
        assert_eq!(
            normalize(
                "query",
                &args(json!({"dataset_id":"x","sql":[],"named_temp_queries":[null]}))
            )
            .unwrap_err(),
            "invalid type: null, expected struct NamedTempQuery"
        );
        assert_eq!(
            normalize("query", &args(json!({"dataset_id":"x","sql":[],"named_temp_queries":[{"name":"n","sql":"SELECT 1","other":true}]}))).unwrap_err(),
            "unknown field `other`, expected `name` or `sql`"
        );
    }

    #[test]
    fn integer_widths_and_error_order_follow_serde() {
        assert_eq!(
            normalize(
                "decode",
                &args(json!({"dataset_id":"x","method_idx":4294967296u64}))
            )
            .unwrap_err(),
            "invalid value: integer `4294967296`, expected u32"
        );
        assert_eq!(
            normalize("open_dataset", &args(json!({"inputs":{},"timeout_ms":[]}))).unwrap_err(),
            "invalid type: map, expected a sequence"
        );
        assert_eq!(
            normalize(
                "query",
                &args(json!({"dataset_id":{},"sql":[],"compact":[]}))
            )
            .unwrap_err(),
            "invalid type: sequence, expected a boolean"
        );
    }

    #[test]
    fn enum_wire_forms_are_canonicalized() {
        assert_eq!(
            normalize(
                "read_resource",
                &args(json!({"dataset_id":"x","name":"x","format":{"hex":null}}))
            )
            .unwrap()["format"],
            "hex"
        );
        assert_eq!(
            normalize("get_manifest", &args(json!({"dataset_id":"x","mode":null}))).unwrap_err(),
            "invalid type: null, expected string or map"
        );
    }
    #[test]
    fn semantic_limits_follow_reference_precedence() {
        assert_eq!(
            range_error("query", &json!({"sql":[],"limit":0,"max_bytes":0}), 131072).unwrap(),
            "max_bytes must be in 4096..=131072"
        );
        assert_eq!(
            range_error("query", &json!({"sql":[],"limit":0}), 131072).unwrap(),
            "limit must be in 1..=1000"
        );
        assert!(range_error("query", &json!({"sql":[";"],"offset":0}), 131072).is_none());
        assert!(
            range_error("query", &json!({"sql":[" "],"offset":0}), 131072)
                .unwrap()
                .starts_with("query requires")
        );
    }
}
