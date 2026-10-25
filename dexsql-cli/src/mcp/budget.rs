//! Serialized byte budgets for archive metadata pages.
//!
//! The worker reserves the longest possible pagination integers while sizing a
//! page. It also counts the worker's `resultType: complete` discriminator, even
//! when the negotiated public protocol omits that field.
use serde_json::{json, Value};

const METADATA_TOO_LARGE: &str = "result metadata exceeds max_bytes";
const ROW_TOO_LARGE: &str = "one row exceeds max_bytes; narrow the selection or read the corresponding XML/text resource in pages";

fn result(value: Value, compact: bool) -> Value {
    let error = value.get("error").is_some();
    json!({
        "content": if compact { Vec::new() } else { vec![json!({"type":"text","text":value.to_string()})] },
        "structuredContent": value,
        "isError": error,
        "resultType": "complete",
    })
}

fn error(message: &str) -> Value {
    json!({"error":{"kind":"output_too_large","message":message}})
}

/// Return a structured page whose worker envelope fits the requested budget.
/// `field` is the row array (`files`, `permissions`, `components`, or `values`).
/// The caller supplies its ordinary row-limited page and exact `total_rows`.
/// Errors are structured values as well and should use the usual MCP envelope.
pub(super) fn page(mut value: Value, field: &str, max_bytes: usize, compact: bool) -> Value {
    let Some(rows) = value.get_mut(field).and_then(Value::as_array_mut) else {
        return value;
    };
    let rows = std::mem::take(rows);
    let offset = value.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let total_rows = value.get("total_rows").and_then(Value::as_u64).unwrap_or(0);
    let mut probe = value.clone();
    probe["total_rows"] = json!(u64::MAX);
    probe["next_offset"] = json!(u64::MAX);
    probe["truncated"] = json!(true);
    if serialized_bytes(&probe, compact) > max_bytes {
        return error(METADATA_TOO_LARGE);
    }
    let mut accepted = Vec::with_capacity(rows.len());
    for row in rows {
        accepted.push(row);
        probe[field] = json!(accepted);
        if serialized_bytes(&probe, compact) > max_bytes {
            accepted.pop();
            if accepted.is_empty() {
                return error(ROW_TOO_LARGE);
            }
            break;
        }
    }
    let next = offset.saturating_add(accepted.len() as u64);
    value[field] = json!(accepted);
    value["next_offset"] = if next < total_rows {
        json!(next)
    } else {
        Value::Null
    };
    value["truncated"] = json!(next < total_rows);
    value
}

/// Count the complete internal worker result, including escaped text content.
pub(super) fn serialized_bytes(value: &Value, compact: bool) -> usize {
    serde_json::to_vec(&result(value.clone(), compact)).map_or(usize::MAX, |bytes| bytes.len())
}

/// Fit a whole SQL batch into one shared result budget. Unlike archive pages,
/// SQL cardinalities are already exact and only `next_offset` reserves its
/// maximum digit count while rows are admitted.
pub(super) fn query(mut value: Value, max_bytes: usize, compact: bool) -> Value {
    let Some(statements) = value.get_mut("statements").and_then(Value::as_array_mut) else {
        return value;
    };
    let mut pages = Vec::with_capacity(statements.len());
    for statement in statements {
        let rows = statement
            .get_mut("rows")
            .and_then(Value::as_array_mut)
            .map(std::mem::take)
            .unwrap_or_default();
        pages.push(rows);
    }
    let mut probe = value.clone();
    for statement in probe["statements"].as_array_mut().expect("statement array") {
        statement["next_offset"] = json!(u64::MAX);
        statement["truncated"] = json!(true);
    }
    if query_bytes(&probe, compact) > max_bytes {
        return error("query metadata exceeds max_bytes; request fewer columns/statements");
    }
    for (index, rows) in pages.into_iter().enumerate() {
        let offset = value["statements"][index]["offset"].as_u64().unwrap_or(0);
        let total_rows = value["statements"][index]["total_rows"]
            .as_u64()
            .unwrap_or(0);
        let mut accepted = Vec::with_capacity(rows.len());
        for row in rows {
            accepted.push(row);
            probe["statements"][index]["rows"] = json!(accepted);
            if query_bytes(&probe, compact) > max_bytes {
                accepted.pop();
                probe["statements"][index]["rows"] = json!(accepted);
                if accepted.is_empty() {
                    return json!({"error":{
                        "kind":"output_too_large",
                        "message":"one row does not fit the remaining result budget; query this statement alone, select fewer columns, or use substr() for a large value",
                        "statement_index": value["statements"][index]["statement_index"],
                        "row_offset":offset,
                    }});
                }
                break;
            }
        }
        let next = offset.saturating_add(accepted.len() as u64);
        let statement = &mut value["statements"][index];
        statement["rows"] = json!(accepted);
        statement["next_offset"] = if next < total_rows {
            json!(next)
        } else {
            Value::Null
        };
        statement["truncated"] = json!(next < total_rows);
    }
    value
}

fn query_bytes(value: &Value, compact: bool) -> usize {
    let mut envelope = result(value.clone(), false);
    if compact {
        envelope = super::compact_tool_result(envelope);
        envelope["resultType"] = json!("complete");
    }
    serde_json::to_vec(&envelope).map_or(usize::MAX, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_pagination_digits_and_worker_discriminator() {
        let value = json!({"dataset_id":"dataset-1","input_index":0,"files":[{"name":"x"}],
            "offset":0,"total_rows":1,"next_offset":null,"truncated":false});
        let mut probe = value.clone();
        probe["total_rows"] = json!(u64::MAX);
        probe["next_offset"] = json!(u64::MAX);
        probe["truncated"] = json!(true);
        let boundary = serialized_bytes(&probe, false);
        assert_eq!(page(value.clone(), "files", boundary, false), value);
        assert_eq!(
            page(value, "files", boundary - 1, false)["error"]["message"],
            ROW_TOO_LARGE
        );
    }

    #[test]
    fn errors_distinguish_metadata_and_first_row() {
        let value = json!({"metadata":"x".repeat(6000),"files":[],"offset":0,"total_rows":0});
        assert_eq!(
            page(value, "files", 4096, true)["error"]["message"],
            METADATA_TOO_LARGE
        );
        let value = json!({"files":[{"name":"x".repeat(6000)}],"offset":0,"total_rows":1});
        assert_eq!(
            page(value, "files", 4096, true)["error"]["message"],
            ROW_TOO_LARGE
        );
    }

    #[test]
    fn compact_envelope_can_return_more_rows() {
        let value = json!({"files":[{"name":"x".repeat(1400)},{"name":"y".repeat(1400)}],
            "offset":0,"total_rows":2,"next_offset":null,"truncated":false});
        let regular = page(value.clone(), "files", 4096, false);
        assert_eq!(regular["files"].as_array().unwrap().len(), 1);
        assert_eq!(regular["next_offset"], 1);
        let compact = page(value, "files", 4096, true);
        assert_eq!(compact["files"].as_array().unwrap().len(), 2);
        assert_eq!(compact["next_offset"], Value::Null);
    }
    #[test]
    fn query_rows_share_the_batch_budget() {
        let statement = json!({"statement_index":0,"kind":"query","sql":"SELECT x",
            "columns":[{"name":"x","data_type":"utf8","nullable":false}],
            "rows":[[{"type":"utf8","value":"x".repeat(1300)}],[{"type":"utf8","value":"y".repeat(1300)}]],
            "offset":0,"next_offset":null,"total_rows":2,"truncated":false});
        let value = json!({"dataset_id":"dataset-1","diagnostics":[],"statements":[statement]});
        let page = query(value.clone(), 4096, false);
        assert_eq!(page["statements"][0]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(page["statements"][0]["next_offset"], 1);
        let page = query(value, 4096, true);
        assert_eq!(page["statements"][0]["rows"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn oversized_sql_metadata_and_values_have_distinct_errors() {
        let value = json!({"dataset_id":"dataset-1","diagnostics":[],"statements":[{
            "statement_index":2,"kind":"query","sql":"SELECT ".repeat(1000),"columns":[],
            "rows":[[{"type":"utf8","value":"x".repeat(6000)}]],"offset":4,
            "next_offset":null,"total_rows":5,"truncated":false}]});
        assert_eq!(
            query(value.clone(), 4096, false)["error"]["message"],
            "query metadata exceeds max_bytes; request fewer columns/statements"
        );
        let page = query(value, 4096, true);
        assert_eq!(page["error"]["statement_index"], 2);
        assert_eq!(page["error"]["row_offset"], 4);
    }
}
