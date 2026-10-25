//! Newline-delimited JSON-RPC MCP server for dexsql.
//!
//! The transport deliberately stays dependency-light: one JSON-RPC message per
//! line on stdin/stdout, with all expensive work isolated behind a bounded
//! admission gate.  The data model is the same `Dataset`/`decode` model used by
//! the CLI; this module only adapts it to MCP's typed, paged result envelope.
// Keep the SQL relation executor shared with the CLI.  The MCP endpoint uses
// the same parser/scanners, so joins and every normalized DEX relation follow
// one implementation instead of diverging in a second handwritten subset.
use dexsql_core::sql::query as query_engine;
mod resources;

use dexsql_core::dex::{decode, Dataset};
use dexsql_core::sql::schema;
use futures_util::StreamExt;
use rmcp::model::{
    CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock,
    Implementation, ListResourcesResult, ListToolsResult, ProgressNotificationParam,
    ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ServerCapabilities, ServerConfig, Tool,
};
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::codec::{FramedRead, FramedWrite};
use zip::ZipArchive;

pub const TABLES: &[&str] = &[
    "dex_files",
    "map_items",
    "id_items",
    "strings",
    "type_ids",
    "types",
    "type_lists",
    "type_list_entries",
    "proto_ids",
    "protos",
    "proto_params",
    "field_ids",
    "fields",
    "method_ids",
    "method_opcodes",
    "class_data_methods",
    "methods",
    "method_handles",
    "call_sites",
    "call_site_args",
    "encoded_arrays",
    "encoded_array_values",
    "encoded_array_owners",
    "class_defs",
    "classes",
    "class_interfaces",
    "class_data_items",
    "class_fields",
    "class_static_values",
    "class_methods",
    "hiddenapi_flags",
    "code_items",
    "try_items",
    "catch_handlers",
    "debug_info",
    "debug_parameters",
    "debug_positions",
    "debug_locals",
    "debug_opcodes",
    "annotation_directories",
    "annotation_directory_entries",
    "annotation_sets",
    "annotation_set_entries",
    "annotation_set_ref_lists",
    "annotation_set_refs",
    "annotations",
    "annotation_elements",
    "method_refs",
    "method_numbers",
    "method_using_numbers",
    "method_strings",
    "method_calls",
    "method_field_accesses",
    "method_used_types",
    "annotation_values",
    "annotation_elements_resolved",
];

#[derive(Debug, Clone)]
pub struct Config {
    pub timeout_ms: u64,
    pub max_datasets: usize,
    pub max_pending: usize,
    pub max_input_bytes: u64,
    pub max_dex_bytes: u64,
    pub max_total_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_resource_bytes: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            max_datasets: 4,
            max_pending: 16,
            max_input_bytes: 1 << 30,
            max_dex_bytes: 1 << 30,
            max_total_input_bytes: 2 << 30,
            max_output_bytes: 128 << 10,
            max_resource_bytes: 64 << 20,
        }
    }
}
#[derive(Debug)]
struct Entry {
    paths: Vec<PathBuf>,
    dataset: Option<Arc<Dataset>>,
    session: Arc<Mutex<query_engine::QuerySession>>,
    source_bytes: u64,
    archive_inputs: Vec<usize>,
    prepare_ms: f64,
    resource_cache: Option<CachedResourceTable>,
    archive_stamps: HashMap<usize, (u64, u128)>,
}
#[derive(Debug, Clone)]
struct CachedResourceTable {
    len: u64,
    modified_nanos: u128,
    rows: Vec<Value>,
}
#[derive(Debug, Default)]
struct State {
    next_id: u64,
    opening: usize,
    opening_bytes: u64,
    datasets: HashMap<String, Entry>,
}
/// A semaphore for queued and running heavy operations.  Admission is
/// non-blocking: callers over the configured bound get a deterministic
/// `server_busy` response rather than an unbounded queue.
#[derive(Debug)]
struct Admission {
    state: Mutex<usize>,
    max: usize,
}
impl Admission {
    fn new(max: usize) -> Self {
        Self {
            state: Mutex::new(0),
            max,
        }
    }
    fn try_acquire(&self) -> bool {
        let mut n = self.state.lock().expect("admission lock");
        if *n >= self.max || self.max == 0 {
            return false;
        }
        *n += 1;
        true
    }
    fn release(&self) {
        let mut n = self.state.lock().expect("admission lock");
        *n = n.saturating_sub(1);
    }
}
/// Serve MCP requests from stdin/stdout through rmcp's Tokio stdio transport.
///
/// rmcp owns framing, lifecycle negotiation, request dispatch, and cancellation
/// propagation.  The existing synchronous dataset/query implementation is
/// isolated behind `spawn_blocking` in `RmcpHandler`, so expensive DEX work
/// cannot stall the transport reader or writer.
pub fn serve_stdio(config: Config) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async move {
        let handler = RmcpHandler::new(config);
        // The reference uses rmcp's sink/stream adapter around the JSON-line
        // codec.  Keeping the framed reader in a `take_while` stream preserves
        // rmcp's stdio shutdown semantics: malformed input ends the stream,
        // while valid requests continue to be dispatched concurrently.
        let reader = FramedRead::new(
            tokio::io::stdin(),
            rmcp::transport::async_rw::JsonRpcMessageCodec::<
                rmcp::model::ClientJsonRpcMessage,
            >::new_with_max_length(256 * 1024),
        );
        let stream = reader
            .take_while(|message| std::future::ready(message.is_ok()))
            .map(|message| message.expect("framed reader ended after an error"));
        let writer = FramedWrite::new(
            tokio::io::stdout(),
            rmcp::transport::async_rw::JsonRpcMessageCodec::<
                rmcp::model::ServerJsonRpcMessage,
            >::default(),
        );
        let transport = rmcp::transport::sink_stream::SinkStreamTransport::new(writer, stream);
        let service = handler.serve(transport).await.map_err(io::Error::other)?;
        service.waiting().await.map_err(io::Error::other)?;
        Ok(())
    })
}

fn try_close_argument_dataset(params: &Value, state: &Arc<Mutex<State>>) {
    let Some(id) = params
        .get("arguments")
        .and_then(|args| args.get("dataset_id"))
        .and_then(Value::as_str)
        .or_else(|| params.get("dataset_id").and_then(Value::as_str))
    else {
        return;
    };
    if let Ok(mut guard) = state.try_lock() {
        guard.datasets.remove(id);
    }
}

fn archive_stamp(path: &Path) -> (u64, u128) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return (0, 0);
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    (metadata.len(), modified)
}
fn json_type_label(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => format!("boolean `{value}`"),
        Value::Number(value) => {
            if value.is_i64() || value.is_u64() {
                format!("integer `{value}`")
            } else {
                format!("number `{value}`")
            }
        }
        Value::String(value) => format!("string {value:?}"),
        Value::Array(_) => "sequence".to_owned(),
        Value::Object(_) => "map".to_owned(),
    }
}

/// rmcp server adapter for the existing dexsql tool implementation.
///
/// The query, decode, and archive code predates the rmcp integration and is
/// intentionally synchronous.  Keeping that implementation behind this small
/// adapter lets rmcp retain ownership of the protocol lifecycle while all
/// potentially expensive work runs on Tokio's blocking pool.
#[derive(Clone)]
struct RmcpHandler {
    state: Arc<Mutex<State>>,
    admission: Arc<Admission>,
    config: Config,
}

impl RmcpHandler {
    fn new(config: Config) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            admission: Arc::new(Admission::new(config.max_pending)),
            config,
        }
    }

    fn server_info() -> ServerConfig {
        let version = option_env!("DEXSQL_BUILD_COMMIT")
            .map(|commit| format!("{}+{commit}", env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_resources()
                .enable_tools()
                .build(),
        )
        .with_server_info(Implementation::new("dexsql", version))
        .with_instructions(
            "Analyze Android DEX/APK using read-only SQL, paged smali and APK Manifest/resources. Use resources/list for the complete English documentation catalog, including unlinked pages. Read relevant pages using the URIs returned by the catalog. Inspect the schema, open_dataset, then query/decode or resource tools. Reuse dataset_id and close unused datasets. Follow next_offset; query paging re-executes SQL and needs stable ORDER BY. Classes default to method summaries. Running timeout/cancellation closes that dataset; reopen it to continue. list_datasets reports quotas. int64/uint64 cells are exact decimal strings.",
        )
    }

    fn tools() -> Vec<Tool> {
        tool_specs()
            .into_iter()
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect()
    }

    fn resources() -> Vec<Resource> {
        resource_specs()
            .into_iter()
            .filter_map(|value| serde_json::from_value(value).ok())
            .collect()
    }

    fn parameter_error(message: impl Into<String>) -> CallToolResult {
        CallToolResult::error(vec![ContentBlock::text(format!(
            "failed to deserialize parameters: {}",
            message.into()
        ))])
    }

    /// Match rmcp's generated `Parameters<T>` behavior for the synchronous tool
    /// dispatcher: typed wrappers reject unknown fields and report missing
    /// required fields as tool-level deserialization errors.
    fn validate_arguments(name: &str, arguments: &Map<String, Value>) -> Option<CallToolResult> {
        let (fields, required): (&[&str], &[&str]) = match name {
            "open_dataset" => (&["inputs", "timeout_ms"], &["inputs"]),
            "close_dataset" => (&["dataset_id"], &["dataset_id"]),
            "describe_table" => (&["name"], &["name"]),
            "query" => (
                &[
                    "dataset_id",
                    "sql",
                    "named_temp_queries",
                    "limit",
                    "offset",
                    "max_bytes",
                    "compact",
                    "timing",
                    "timeout_ms",
                ],
                &["dataset_id", "sql"],
            ),
            "decode" => (
                &[
                    "dataset_id",
                    "file_id",
                    "method",
                    "method_idx",
                    "class",
                    "mode",
                    "method_offset",
                    "method_limit",
                    "offset",
                    "max_lines",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "get_manifest" => (
                &[
                    "dataset_id",
                    "input_index",
                    "mode",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "get_manifest_components" => (
                &[
                    "dataset_id",
                    "input_index",
                    "kind",
                    "offset",
                    "limit",
                    "only_exported",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "list_resource_files" => (
                &[
                    "dataset_id",
                    "input_index",
                    "prefix",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "read_resource" => (
                &[
                    "dataset_id",
                    "input_index",
                    "name",
                    "format",
                    "offset",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id", "name"],
            ),
            "query_resources" => (
                &[
                    "dataset_id",
                    "input_index",
                    "resource_id",
                    "name",
                    "resource_type",
                    "contains",
                    "configuration",
                    "offset",
                    "limit",
                    "max_bytes",
                    "timeout_ms",
                    "compact",
                ],
                &["dataset_id"],
            ),
            "list_datasets" | "list_tables" => return None,
            _ => return None,
        };
        if let Some(field) = arguments
            .keys()
            .find(|field| !fields.contains(&field.as_str()))
        {
            let expected = if fields.len() == 1 {
                format!("expected `{}`", fields[0])
            } else if name == "open_dataset" {
                format!("expected `{}` or `{}`", fields[0], fields[1])
            } else {
                format!(
                    "expected one of {}",
                    fields
                        .iter()
                        .map(|field| format!("`{field}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Some(Self::parameter_error(format!(
                "unknown field `{field}`, {expected}"
            )));
        }
        if let Some(field) = required
            .iter()
            .find(|field| !arguments.contains_key(**field))
        {
            return Some(Self::parameter_error(format!("missing field `{field}`")));
        }
        // serde's generated wrappers report primitive type failures before the
        // tool implementation gets a chance to validate semantic ranges.
        let string_fields = [
            "dataset_id",
            "name",
            "method",
            "class",
            "kind",
            "prefix",
            "format",
            "resource_type",
            "contains",
            "configuration",
            "mode",
        ];
        if let Some((_, value)) = arguments.iter().find(|(field, value)| {
            string_fields.contains(&field.as_str()) && !value.is_string() && !value.is_null()
        }) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a string",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("timeout_ms") {
            if let Some(number) = value.as_i64() {
                if number < 0 {
                    return Some(Self::parameter_error(format!(
                        "invalid value: integer `{number}`, expected u64"
                    )));
                }
            } else if !value.is_u64() && !value.is_null() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected u64",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("timing") {
            if !value.is_boolean() && !value.is_null() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a boolean",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("compact") {
            if !value.is_boolean() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a boolean",
                    json_type_label(value)
                )));
            }
        }
        let usize_fields = [
            "input_index",
            "offset",
            "limit",
            "max_bytes",
            "method_offset",
            "method_limit",
            "max_lines",
        ];
        let u32_fields = ["file_id", "method_idx", "resource_id"];
        for (field, value) in arguments {
            let expected = if usize_fields.contains(&field.as_str()) {
                Some("usize")
            } else if u32_fields.contains(&field.as_str()) {
                Some("u32")
            } else {
                None
            };
            let Some(expected) = expected else { continue };
            if value.is_null() {
                continue;
            }
            if let Some(number) = value.as_i64() {
                if number < 0 {
                    return Some(Self::parameter_error(format!(
                        "invalid value: integer `{number}`, expected {expected}"
                    )));
                }
            } else if value.as_u64().is_none() {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected {expected}",
                    json_type_label(value)
                )));
            }
        }
        if let Some(value) = arguments.get("inputs").filter(|value| !value.is_array()) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a sequence",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("inputs").and_then(Value::as_array) {
            if let Some(item) = value.iter().find(|item| !item.is_string()) {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a string",
                    json_type_label(item)
                )));
            }
        }
        if let Some(value) = arguments.get("sql").filter(|value| !value.is_array()) {
            return Some(Self::parameter_error(format!(
                "invalid type: {}, expected a sequence",
                json_type_label(value)
            )));
        }
        if let Some(value) = arguments.get("sql").and_then(Value::as_array) {
            if let Some(item) = value.iter().find(|item| !item.is_string()) {
                return Some(Self::parameter_error(format!(
                    "invalid type: {}, expected a string",
                    json_type_label(item)
                )));
            }
        }
        let variants: &[(&str, &[&str])] = match name {
            "read_resource" => &[("format", &["auto", "hex"])],
            "get_manifest" => &[("mode", &["summary", "xml"])],
            "decode" => &[("mode", &["summary", "smali", "context"])],
            _ => &[],
        };
        for (field, values) in variants {
            if let Some(value) = arguments.get(*field).and_then(Value::as_str) {
                if !values.contains(&value) {
                    let expected = if values.len() == 2 {
                        format!("`{}` or `{}`", values[0], values[1])
                    } else {
                        format!(
                            "one of {}",
                            values
                                .iter()
                                .map(|value| format!("`{value}`"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    };
                    return Some(Self::parameter_error(format!(
                        "unknown variant `{value}`, expected {expected}"
                    )));
                }
            }
        }
        None
    }

    async fn run_tool(
        &self,
        params: CallToolRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let started = Instant::now();
        if !Self::tools()
            .iter()
            .any(|tool| tool.name.as_ref() == params.name.as_ref())
        {
            return Err(McpError::invalid_params("tool not found", None));
        }
        let arguments = Value::Object(params.arguments.unwrap_or_default());
        if let Some(arguments_object) = arguments.as_object() {
            if let Some(error) = Self::validate_arguments(params.name.as_ref(), arguments_object) {
                return Ok(error);
            }
        }
        let request = json!({
            "name": params.name.as_ref(),
            "arguments": arguments,
        });
        let request_for_close = request.clone();
        let worker_dataset_id = request
            .get("arguments")
            .and_then(|arguments| arguments.get("dataset_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let requested_timeout = request
            .get("arguments")
            .and_then(|value| value.get("timeout_ms"))
            .and_then(Value::as_u64);
        let timeout_ms = match requested_timeout {
            Some(value) if value == 0 || value > self.config.timeout_ms => {
                return Ok(CallToolResult::structured_error(json!({
                    "error": {
                        "kind": "invalid_input",
                        "message": format!(
                            "timeout_ms must be in 1..={}",
                            self.config.timeout_ms
                        ),
                    }
                })));
            }
            Some(value) => value,
            None => self.config.timeout_ms,
        };
        if !self.admission.try_acquire() {
            return Ok(CallToolResult::structured_error(json!({
                "error": {
                    "kind": "server_busy",
                    "message": "request queue full",
                }
            })));
        }
        let progress_token = context.meta.get_progress_token();
        if params.name.as_ref() == "open_dataset" {
            if let Some(token) = progress_token.clone() {
                let _ = context.peer.notify_progress(ProgressNotificationParam::new(
                    token, started.elapsed().as_secs_f64(),
                ).with_message("preparing dataset; elapsed 0.0s (elapsed time, not completion percentage)")).await;
            }
        }
        let state = Arc::clone(&self.state);
        let config = self.config.clone();
        let admission = Arc::clone(&self.admission);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_worker = Arc::clone(&cancelled);
        let worker_state = Arc::clone(&state);
        let worker = tokio::task::spawn_blocking(move || {
            let result = crate::mcp::call_tool(&request, &state, &config);
            // A blocking operation cannot be force-aborted safely.  If rmcp
            // cancelled or timed out this request while it was running, close
            // a dataset that the operation may have created before returning.
            if cancelled_worker.load(Ordering::Relaxed) {
                if let Some(dataset_id) = worker_dataset_id.as_deref() {
                    if let Ok(mut guard) = worker_state.lock() {
                        guard.datasets.remove(dataset_id);
                    }
                }
                if let Ok(value) = &result {
                    if let Some(dataset_id) = value
                        .get("structuredContent")
                        .and_then(|content| content.get("dataset_id"))
                        .and_then(Value::as_str)
                    {
                        if let Ok(mut guard) = worker_state.lock() {
                            guard.datasets.remove(dataset_id);
                        }
                    }
                }
            }
            admission.release();
            result
        });
        let deadline = Duration::from_millis(timeout_ms);
        let result = tokio::select! {
            _ = context.ct.cancelled() => {
                cancelled.store(true, Ordering::Relaxed);
                try_close_argument_dataset(&request_for_close, &self.state);
                return Err(McpError::internal_error("task cancelled for reason", None));
            }
            result = tokio::time::timeout(deadline, worker) => result,
        };
        let value = match result {
            Ok(Ok(Ok(value))) => value,
            Ok(Ok(Err((_, message)))) => tool_error_result("invalid_request", &message),
            Ok(Err(error)) => {
                try_close_argument_dataset(&request_for_close, &self.state);
                return Err(McpError::internal_error(
                    format!("worker failed: {error}"),
                    None,
                ));
            }
            Err(_) => {
                cancelled.store(true, Ordering::Relaxed);
                try_close_argument_dataset(&request_for_close, &self.state);
                let dataset_id = request_for_close
                    .get("arguments")
                    .and_then(|value| value.get("dataset_id"))
                    .and_then(Value::as_str);
                let (dataset_id, dataset_closed, message) = match dataset_id {
                    Some(dataset_id) => (
                        Value::String(dataset_id.to_owned()),
                        true,
                        "running computation was terminated and this dataset was closed; call open_dataset to use it again",
                    ),
                    None => (
                        Value::Null,
                        false,
                        "request ended before a dataset operation completed; existing datasets remain open",
                    ),
                };
                return Ok(CallToolResult::structured_error(json!({
                    "dataset_id": dataset_id,
                    "error": {
                        "dataset_closed": dataset_closed,
                        "kind": "timeout",
                        "message": message,
                    },
                })));
            }
        };
        let compact = request_for_close
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| {
                matches!(
                    name,
                    "decode"
                        | "get_manifest"
                        | "get_manifest_components"
                        | "list_resource_files"
                        | "query"
                        | "query_resources"
                        | "read_resource"
                )
            })
            && request_for_close
                .get("arguments")
                .and_then(|arguments| arguments.get("compact"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
        let value = if compact {
            compact_tool_result(value)
        } else {
            value
        };
        if params.name.as_ref() != "open_dataset" {
            if let Some(token) = progress_token {
                let _ = context
                    .peer
                    .notify_progress(
                        ProgressNotificationParam::new(token, started.elapsed().as_secs_f64())
                            .with_message("completed"),
                    )
                    .await;
            }
        }
        serde_json::from_value(value).map_err(|error| {
            McpError::internal_error(format!("failed to serialize tool result: {error}"), None)
        })
    }
}

impl ServerHandler for RmcpHandler {
    fn get_info(&self) -> ServerConfig {
        Self::server_info()
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let mut result = ListToolsResult::with_all_items(Self::tools());
        if context.protocol_version() == Some(rmcp::model::ProtocolVersion::V_2026_07_28) {
            result.ttl_ms = Some(0);
            result.cache_scope = Some(CacheScope::Public);
        }
        std::future::ready(Ok(result))
    }

    fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListResourcesResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let mut result = ListResourcesResult::with_all_items(Self::resources());
        if context.protocol_version() == Some(rmcp::model::ProtocolVersion::V_2026_07_28) {
            result.ttl_ms = Some(0);
            result.cache_scope = Some(CacheScope::Private);
        }
        std::future::ready(Ok(result))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ReadResourceResponse, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let uri = request.uri.clone();
        let value = resources_read(&json!({"uri": uri}));
        let result = value
            .map_err(|_| {
                McpError::resource_not_found(
                    "unknown DexSQL documentation resource",
                    Some(json!({"uri": request.uri})),
                )
            })
            .and_then(|value| {
                serde_json::from_value::<ReadResourceResult>(value).map_err(|error| {
                    McpError::internal_error(format!("failed to serialize resource: {error}"), None)
                })
            })
            .map(|mut result| {
                // rmcp serializes these cache hints on the reference server
                // even for the 2024-11-05 negotiation.
                result.ttl_ms = Some(0);
                result.cache_scope = Some(CacheScope::Private);
                ReadResourceResponse::from(result)
            });
        std::future::ready(result)
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResponse, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        async move { self.run_tool(request, context).await.map(Into::into) }
    }
}

fn tool_specs() -> Vec<Value> {
    let defs = [
        (
            "open_dataset",
            "Open local DEX/APK/JAR/ZIP paths as an isolated reusable dataset. Resource-only archives are supported. Input/session quotas and operation deadlines apply. Close unused datasets to release memory.",
            json!({"inputs":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":64},"timeout_ms":{"type":["integer","null"],"minimum":1}}),
            vec!["inputs"],
        ),
        (
            "list_datasets",
            "List open datasets and server quotas/usage. Counts include opening datasets and accepted work still holding a closed dataset.",
            json!({}),
            vec![],
        ),
        (
            "close_dataset",
            "Close a dataset and release its worker. New requests fail; already accepted requests may finish, with deadlines still enforced.",
            json!({"dataset_id":{"type":"string"}}),
            vec!["dataset_id"],
        ),
        (
            "list_tables",
            "List all built-in SQL tables and views; no dataset is needed.",
            json!({}),
            vec![],
        ),
        (
            "describe_table",
            "Describe a built-in SQL table or view; no dataset is needed.",
            json!({"name":{"type":"string"}}),
            vec!["name"],
        ),
        (
            "query",
            "Run a read-only SQL batch with exact typed cells, byte/row budgets and per-statement next_offset. Use stable ORDER BY when paging; SQL is re-executed against the current lazy session definitions on each page; CREATE definitions persist until DROP, replacement or dataset close. Running timeout/cancellation closes only this dataset. Use resources/list to discover the documentation.",
            json!({"dataset_id":{"type":"string"},"sql":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":16},"limit":{"type":["integer","null"],"minimum":1,"maximum":1000},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"named_temp_queries":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"sql":{"type":"string"}},"required":["name","sql"]}},"timing":{"type":"boolean"},"timeout_ms":{"type":["integer","null"]}}),
            vec!["dataset_id", "sql"],
        ),
        (
            "decode",
            "Inspect a method or class. Exactly one method descriptor, method_idx (with file_id), or class descriptor is required. Classes default to paginated summaries; methods default to paginated smali. Follow next_offset for exact text continuation; context mode lists original line numbers for labels and catch directives. Query SQL tables for annotations and debug metadata.",
            json!({"dataset_id":{"type":"string"},"method":{"type":["string","null"]},"method_idx":{"type":["integer","null"]},"file_id":{"type":["integer","null"]},"class":{"type":["string","null"]},"mode":{"type":["string","null"],"enum":["summary","smali","context",null]},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"max_lines":{"type":["integer","null"],"minimum":1,"maximum":1000},"method_offset":{"type":"integer","minimum":0},"method_limit":{"type":["integer","null"],"minimum":1,"maximum":50},"timeout_ms":{"type":["integer","null"]}}),
            vec!["dataset_id"],
        ),
        (
            "get_manifest",
            "Read an APK Manifest as a summary (including paged permissions) or paged decoded XML. input_index refers to open_dataset.inputs; choose it when several archives are open. Does not require DEX or Java decompilation.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"mode":{"type":"string","enum":["summary","xml"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "get_manifest_components",
            "Page Manifest components, names/descriptors, launcher intent filters, aliases and exported configuration. Exported state is manifest-derived and is not a claim of runtime accessibility. Includes explicit and SDK-dependent default states.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"kind":{"type":["string","null"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"only_exported":{"type":"boolean"},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "list_resource_files",
            "Page archive entry names and sizes, optionally filtered by prefix (res/, assets/, lib/). Names identify entries for read_resource; files are never extracted.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"prefix":{"type":["string","null"]},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
        (
            "read_resource",
            "Read one exact APK archive entry in bounded pages. Binary Android XML is decoded; UTF-8 text is preserved; other bytes use hex. Follow next_offset in page (text) or the result (hex). The resource-entry size quota applies before decompression.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"name":{"type":"string"},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":["integer","null"],"minimum":0},"format":{"type":"string","enum":["auto","hex"]},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id", "name"],
        ),
        (
            "query_resources",
            "Query resources.arsc by numeric ID, exact type/name, type, name substring or configuration. Returns matching configurations with raw values and named references; complex resources are flattened into ordered map items. Separate from DEX strings.",
            json!({"dataset_id":{"type":"string"},"input_index":{"type":["integer","null"],"minimum":0},"resource_id":{"type":["integer","null"],"minimum":0},"name":{"type":["string","null"]},"resource_type":{"type":["string","null"]},"contains":{"type":["string","null"]},"configuration":{"type":["string","null"]},"offset":{"type":"integer","minimum":0},"limit":{"type":["integer","null"],"minimum":1,"maximum":200},"max_bytes":{"type":["integer","null"],"minimum":0},"timeout_ms":{"type":["integer","null"],"minimum":0}}),
            vec!["dataset_id"],
        ),
    ];
    let mut out = Vec::new();
    for (name, desc, props, required) in defs {
        let mut props = props;
        enrich_generated_input_schema(name, &mut props);
        let mut s = Map::new();
        // schemars emits the compact `{properties:{},type:object}` shape for
        // no-argument tools.  Other request types carry the draft marker,
        // closed-world flag, and required list.
        let bare_object = matches!(name, "list_datasets" | "list_tables");
        if !bare_object {
            s.insert(
                "$schema".into(),
                json!("https://json-schema.org/draft/2020-12/schema"),
            );
        }
        s.insert("type".into(), json!("object"));
        if !bare_object {
            s.insert("additionalProperties".into(), json!(false));
        }
        s.insert("properties".into(), props);
        if !bare_object {
            s.insert("required".into(), json!(required));
        }
        if matches!(name, "list_datasets" | "list_tables") {
            s.remove("$schema");
            s.remove("additionalProperties");
            s.remove("required");
        }
        if let Some(defs) = generated_input_defs(name) {
            s.insert("$defs".into(), defs);
        }
        let read_only = name != "open_dataset" && name != "close_dataset";
        let annotations = if read_only {
            if matches!(name, "decode" | "query") {
                json!({"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false})
            } else {
                json!({"readOnlyHint":true,"openWorldHint":false})
            }
        } else {
            json!({"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false})
        };
        let mut tool = json!({"name":name,"description":desc,"inputSchema":Value::Object(s),"annotations":annotations});
        if let Some(schema) = generated_output_schema(name) {
            tool["outputSchema"] = schema;
        }
        out.push(tool);
    }
    // rmcp preserves the declaration order. Keep the public order identical
    // to the reference server so clients that snapshot tools/list remain
    // stable across releases.
    const ORDER: &[&str] = &[
        "close_dataset",
        "decode",
        "describe_table",
        "get_manifest",
        "get_manifest_components",
        "list_datasets",
        "list_resource_files",
        "list_tables",
        "open_dataset",
        "query",
        "query_resources",
        "read_resource",
    ];
    out.sort_by_key(|tool| {
        ORDER
            .iter()
            .position(|name| *name == tool["name"].as_str().unwrap_or(""))
            .unwrap_or(usize::MAX)
    });
    out
}

/// These are the exact output schemas emitted by schemars 1.2.2 for the
/// protocol result structs.  Keeping them as JSON fixtures avoids silently
/// dropping nested `$defs` when the hand-written transport is used.
fn generated_output_schema(name: &str) -> Option<Value> {
    let source = match name {
        "query" => include_str!("schemas/query_output.json"),
        "decode" => include_str!("schemas/decode_output.json"),
        _ => return None,
    };
    Some(serde_json::from_str(source).expect("embedded generated output schema"))
}

/// Add the details that `schemars` emits for protocol enums and documented
/// request fields.  Keeping this in one small post-processing pass lets the
/// hand-written dispatch table stay readable while preserving the public
/// `$defs`/description shape produced by the reference rmcp server.
fn enrich_generated_input_schema(name: &str, props: &mut Value) {
    let Some(object) = props.as_object_mut() else {
        return;
    };
    if matches!(
        name,
        "decode"
            | "get_manifest"
            | "get_manifest_components"
            | "list_resource_files"
            | "query"
            | "query_resources"
            | "read_resource"
    ) {
        object.insert(
            "compact".into(),
            json!({
                "description":"Opt in to one structuredContent representation (content is empty). Query columns become\nnames and cells use null/string/number or [i|u|b|f, string]; SQL is omitted. Default false.",
                "type":"boolean"
            }),
        );
    }
    match name {
        "open_dataset" => {
            prop_desc(
                object,
                "inputs",
                "Local DEX/APK/JAR/ZIP paths, resolved relative to the server working directory.",
            );
            prop_desc(
                object,
                "timeout_ms",
                "Optional shorter operation deadline; cannot exceed the server's timeout.",
            );
            prop_format(object, "timeout_ms", "uint64");
        }
        "query" => {
            prop_desc(object, "sql", "Read-only SQL statements. VIEW and TEMP definitions are lazy and persist in this dataset\nuntil DROP, redefinition, or close_dataset; results are not cached across calls.");
            prop_desc(object, "limit", "Returned rows per statement, default 200; use a deterministic ORDER BY when paging.");
            prop_desc(object, "offset", "Rows to skip in each statement's result, default 0. offset + limit is at most 100000.");
            prop_desc(
                object,
                "max_bytes",
                "Optional lower serialized result-byte budget; rows are never silently clipped.",
            );
            prop_desc(object, "named_temp_queries", "Lazy named SELECT definitions, retained in this dataset with the same lifetime as TEMP tables.");
            prop_default(object, "named_temp_queries", json!([]));
            prop_default(object, "offset", json!(0));
            prop_default(object, "timing", json!(false));
            prop_format(object, "limit", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
            prop_minimum(object, "timeout_ms", 0);
            if let Some(named) = object
                .get_mut("named_temp_queries")
                .and_then(Value::as_object_mut)
            {
                named.insert("items".into(), json!({"$ref":"#/$defs/NamedTempQuery"}));
            }
        }
        "decode" => {
            prop_desc(
                object,
                "method",
                "Exact DEX descriptor. Supply exactly one of method, method_idx, or class.",
            );
            prop_desc(
                object,
                "method_idx",
                "DEX-local method index; requires file_id.",
            );
            prop_desc(
                object,
                "max_lines",
                "Maximum lines in one text page, default 200, maximum 1000.",
            );
            prop_desc(
                object,
                "method_limit",
                "Methods per class page, default 20, maximum 50.",
            );
            prop_desc(object, "mode", "Defaults to summary for a class, smali for a method. Context lists original label/catch lines.");
            prop_desc(
                object,
                "method_offset",
                "Class method-list offset, ordered by method_idx.",
            );
            prop_desc(object, "offset", "UTF-8 byte offset into one method's smali/context text; continue with next_offset.");
            prop_default(object, "method_offset", json!(0));
            prop_default(object, "offset", json!(0));
            prop_format(object, "file_id", "uint32");
            prop_format(object, "method_idx", "uint32");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "max_lines", "uint");
            prop_format(object, "method_offset", "uint");
            prop_format(object, "method_limit", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "timeout_ms", "uint64");
            prop_minimum(object, "file_id", 0);
            prop_minimum(object, "method_idx", 0);
            prop_minimum(object, "timeout_ms", 0);
            if let Some(mode) = object.get_mut("mode") {
                *mode = json!({"anyOf":[{"$ref":"#/$defs/DecodeMode"},{"type":"null"}],"description":"Defaults to summary for a class, smali for a method. Context lists original label/catch lines."});
            }
        }
        "get_manifest" => {
            prop_desc(
                object,
                "input_index",
                "Index in open_dataset.inputs; required when several archive inputs are present.",
            );
            prop_desc(
                object,
                "offset",
                "Permission-row offset in summary mode, UTF-8 byte offset in XML mode.",
            );
            prop_default(object, "mode", json!("summary"));
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "timeout_ms", "uint64");
            if let Some(mode) = object.get_mut("mode") {
                *mode = json!({"$ref":"#/$defs/ManifestMode","default":"summary"});
            }
        }
        "get_manifest_components" => {
            prop_desc(
                object,
                "kind",
                "Optional activity, activity-alias, service, receiver, or provider filter.",
            );
            prop_desc(
                object,
                "only_exported",
                "Filter by manifest-derived exported state; does not imply runtime accessibility.",
            );
            prop_default(object, "offset", json!(0));
            prop_default(object, "only_exported", json!(false));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        "list_resource_files" => {
            prop_desc(
                object,
                "prefix",
                "Case-sensitive archive-entry prefix, for example res/layout/ or assets/.",
            );
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        "read_resource" => {
            prop_desc(
                object,
                "name",
                "Exact archive entry name. No files are extracted to the filesystem.",
            );
            prop_desc(
                object,
                "offset",
                "Byte offset in decoded UTF-8 text, or original bytes when encoding is hex.",
            );
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "offset", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
            if let Some(format_value) = object.get_mut("format") {
                *format_value = json!({"$ref":"#/$defs/ResourceFormat","default":"auto"});
            }
        }
        "query_resources" => {
            prop_desc(
                object,
                "resource_id",
                "Resource ID, for example 2130771968 (0x7f010000).",
            );
            prop_desc(
                object,
                "name",
                "Exact type/name or package:type/name, for example string/app_name.",
            );
            prop_desc(
                object,
                "resource_type",
                "Resource type, for example string, layout, id, style, or array.",
            );
            prop_desc(
                object,
                "contains",
                "Case-sensitive substring of the resource name.",
            );
            prop_desc(object, "configuration", "Exact qualifier string from a previous result. Empty string selects the default config.");
            prop_default(object, "offset", json!(0));
            prop_format(object, "input_index", "uint");
            prop_format(object, "resource_id", "uint32");
            prop_format(object, "offset", "uint");
            prop_format(object, "limit", "uint");
            prop_format(object, "max_bytes", "uint");
            prop_format(object, "timeout_ms", "uint64");
        }
        _ => {}
    }
}

fn prop_desc(object: &mut Map<String, Value>, field: &str, text: &str) {
    if let Some(value) = object.get_mut(field).and_then(Value::as_object_mut) {
        value.insert("description".into(), json!(text));
    }
}

fn prop_format(object: &mut Map<String, Value>, field: &str, text: &str) {
    if let Some(value) = object.get_mut(field).and_then(Value::as_object_mut) {
        value.insert("format".into(), json!(text));
    }
}

fn prop_default(object: &mut Map<String, Value>, field: &str, value: Value) {
    if let Some(property) = object.get_mut(field).and_then(Value::as_object_mut) {
        property.insert("default".into(), value);
    }
}

fn prop_minimum(object: &mut Map<String, Value>, field: &str, value: i64) {
    if let Some(property) = object.get_mut(field).and_then(Value::as_object_mut) {
        property.insert("minimum".into(), json!(value));
    }
}

fn generated_input_defs(name: &str) -> Option<Value> {
    match name {
        "decode" => Some(json!({"DecodeMode": {
            "description": "Which `decode` view a request asks for. A class selection defaults to [`Self::Summary`] and a\nmethod selection to [`Self::Smali`] (see [`run`]).\n\n`JsonSchema` is derived here for the same reason as `apk::manifest::ManifestMode`: the MCP tool's\nparameter schema is generated from this type (it is re-exported as\n`cli::mcp::protocol::DecodeMode`), so the published schema and the implemented behaviour cannot\ndisagree.",
            "oneOf": [
                {"const":"summary","description":"Method METADATA only: descriptor, access flags, code units, registers, try count.","type":"string"},
                {"const":"smali","description":"The complete smali text of each selected method, paged by UTF-8 byte offset.","type":"string"},
                {"const":"context","description":"The smali text with every original label/catch/method line prefixed by its zero-based line\nnumber — the view a caller uses to talk about a line it saw somewhere else.","type":"string"}
            ]
        }})),
        "get_manifest" => Some(json!({"ManifestMode": {
            "description": "Which `AndroidManifest.xml` view a `get_manifest` request asks for.\n\n`JsonSchema` is derived here because the MCP tool definition is generated from this type (it is\nre-exported as `cli::mcp::protocol::ManifestMode`), so the published parameter schema and the\nimplemented behaviour cannot disagree.",
            "oneOf": [
                {"const":"summary","description":"Structured summary: manifest/application/uses-sdk attributes, target SDK, component counts,\nand a paged `permissions` list.","type":"string"},
                {"const":"xml","description":"The complete decoded XML, paged by UTF-8 byte offset.","type":"string"}
            ]
        }})),
        "read_resource" => Some(json!({"ResourceFormat": {
            "description": "The `read_resource` output format: decide from the bytes, or force hex.\n\n`JsonSchema` is derived here for the same reason as `manifest::ManifestMode`: the MCP tool's\nparameter schema is generated from this type, which is re-exported as\n`cli::mcp::protocol::ResourceFormat`.",
            "enum":["auto","hex"],"type":"string"
        }})),
        "query" => Some(json!({"NamedTempQuery": {
            "additionalProperties":false,
            "properties":{"name":{"type":"string"},"sql":{"type":"string"}},
            "required":["name","sql"],"type":"object"
        }})),
        _ => None,
    }
}
pub(crate) use resources::{resource_specs, resources_read};
fn call_tool(p: &Value, state: &Arc<Mutex<State>>, cfg: &Config) -> Result<Value, (i32, String)> {
    let name = p
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tool name is required".into()))?;
    let a = p.get("arguments").cloned().unwrap_or_else(|| json!({}));
    if !a.is_object() {
        return Err((-32602, "tool arguments must be an object".into()));
    }
    if let Some(max) = a.get("max_bytes").and_then(Value::as_u64) {
        if !(4096..=cfg.max_output_bytes).contains(&max) {
            return Ok(tool_error_result(
                "invalid_input",
                &format!("max_bytes must be in 4096..={}", cfg.max_output_bytes),
            ));
        }
    }
    let value = match name {
        "open_dataset" => open_dataset(&a, state, cfg),
        "list_datasets" => Ok(list_datasets(state, cfg)),
        "close_dataset" => close_dataset(&a, state),
        "list_tables" => Ok(json!({"tables":TABLES})),
        "describe_table" => describe_table(&a),
        "query" => query(&a, state),
        "decode" => decode_tool(&a, state, cfg),
        "get_manifest" => get_manifest(&a, state, cfg.max_resource_bytes),
        "get_manifest_components" => get_manifest_components(&a, state, cfg.max_resource_bytes),
        "list_resource_files" => list_resource_files(&a, state),
        "read_resource" => read_resource(&a, state, cfg.max_resource_bytes),
        "query_resources" => query_resources(&a, state),
        _ => Err((-32602, format!("unknown tool: {name}"))),
    };
    match value {
        Ok(value) => {
            let text = serde_json::to_string(&value).map_err(|e| (-32603, e.to_string()))?;
            if text.len() as u64 > cfg.max_output_bytes {
                return Ok(tool_error_result(
                    "output_limit",
                    "serialized result exceeds --max-output-bytes",
                ));
            }
            Ok(
                json!({"content":[{"type":"text","text":text}],"isError":value.get("error").is_some(),"structuredContent":value}),
            )
        }
        Err((_, message)) => {
            if name == "open_dataset" {
                return Ok(tool_error_result("invalid_input", &message));
            }
            if name == "describe_table" {
                return Ok(tool_error_result("unknown_table", &message));
            }
            if message.contains("archive input") {
                return Ok(tool_error_result("not_archive", &message));
            }
            if message.starts_with("archive entry not found:") {
                return Ok(tool_error_result("not_found", &message));
            }
            if message.starts_with("offset ") || message.starts_with("offset must") {
                return Ok(tool_error_result("invalid_range", &message));
            }
            if message.starts_with("kind must") {
                return Ok(tool_error_result("invalid_input", &message));
            }
            if message == "archive changed; close and reopen the dataset" {
                return Ok(tool_error_result("source_changed", &message));
            }
            if let Some(dataset) = message.strip_prefix("unknown dataset_id: ") {
                return Ok(tool_error_result(
                    "unknown_dataset",
                    &format!("dataset \"{dataset}\" is not open; call open_dataset first"),
                ));
            }
            if let Some(column) = message
                .strip_prefix("unknown column '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown column `{column}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else if let Some(relation) = message
                .strip_prefix("unknown relation '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown relation `{relation}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else if let Some(table) = message
                .strip_prefix("unknown table '")
                .and_then(|value| value.strip_suffix('\''))
            {
                let value = json!({"error":{"input":Value::Null,"kind":"invalid_query","message":format!("unknown relation `{table}`"),"source":Value::Null,"stage":"execute_sql","statement_index":0}});
                Ok(
                    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true}),
                )
            } else {
                Ok(tool_error_result("invalid_request", &message))
            }
        }
    }
}

fn tool_error_result(kind: &str, message: &str) -> Value {
    let value = json!({"error":{"kind":kind,"message":message}});
    json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":true})
}

fn compact_tool_result(value: Value) -> Value {
    let is_error = value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if is_error {
        let mut structured = value
            .get("structuredContent")
            .cloned()
            .unwrap_or(Value::Null);
        if let Some(message) = structured
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
        {
            if let Some(dataset) = message.strip_prefix("unknown dataset_id: ") {
                structured = json!({"error":{"kind":"unknown_dataset","message":format!("dataset \"{dataset}\" is not open; call open_dataset first")}});
            }
        }
        return json!({"content":[],"structuredContent":structured,"isError":true});
    }
    let mut structured = value
        .get("structuredContent")
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(statements) = structured
        .get_mut("statements")
        .and_then(Value::as_array_mut)
    {
        for statement in statements {
            if let Some(object) = statement.as_object_mut() {
                if let Some(columns) = object.get_mut("columns").and_then(Value::as_array_mut) {
                    for column in columns.iter_mut() {
                        if let Some(name) = column.get("name").cloned() {
                            *column = name;
                        }
                    }
                }
                object.remove("sql");
                object.remove("sql_truncated");
                if let Some(rows) = object.get_mut("rows").and_then(Value::as_array_mut) {
                    for row in rows {
                        if let Some(cells) = row.as_array_mut() {
                            for cell in cells {
                                *cell = compact_cell(cell.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    json!({"content":[],"structuredContent":structured,"isError":false})
}

fn compact_cell(cell: Value) -> Value {
    let Some(kind) = cell.get("type").and_then(Value::as_str) else {
        return cell;
    };
    let value = cell.get("value").cloned().unwrap_or(Value::Null);
    match kind {
        "null" | "utf8" => value,
        "int64" => json!(["i", value]),
        "uint64" | "uint32" => json!(["u", value]),
        "binary" => json!(["b", value]),
        "float64" => {
            if value.is_number() {
                value
            } else {
                json!(["f", value])
            }
        }
        _ => value,
    }
}
fn open_dataset(
    a: &Value,
    state: &Arc<Mutex<State>>,
    cfg: &Config,
) -> Result<Value, (i32, String)> {
    let started = Instant::now();
    let arr = a
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or((-32602, "inputs is required".into()))?;
    if arr.is_empty() || arr.len() > 64 {
        return Err((-32602, "inputs must contain 1..=64 paths".into()));
    }
    let mut paths = Vec::with_capacity(arr.len());
    for value in arr {
        let path = value
            .as_str()
            .ok_or((-32602, "inputs entries must be strings".into()))?;
        if path.is_empty() {
            return Err((-32602, "inputs entries must not be empty".into()));
        }
        paths.push(PathBuf::from(path));
    }
    for path in &paths {
        std::fs::metadata(path).map_err(|error| (-32000, error.to_string()))?;
    }
    let bytes = paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum::<u64>();
    if bytes > cfg.max_input_bytes {
        return Err((-32000, "input byte quota exceeded".into()));
    }
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    if g.datasets.len().saturating_add(g.opening) >= cfg.max_datasets {
        return Err((-32000, "maximum datasets exceeded".into()));
    }
    let open_bytes = g
        .datasets
        .values()
        .map(|entry| entry.source_bytes)
        .sum::<u64>();
    if open_bytes
        .saturating_add(g.opening_bytes)
        .saturating_add(bytes)
        > cfg.max_total_input_bytes
    {
        return Err((
            -32000,
            "input byte budgets exhausted; close unused datasets before opening another".into(),
        ));
    }
    g.opening += 1;
    g.opening_bytes = g.opening_bytes.saturating_add(bytes);
    drop(g);
    let load_paths = paths
        .iter()
        .filter(|path| is_dex(path) || (is_archive(path) && archive_contains_dex(path)))
        .cloned()
        .collect::<Vec<_>>();
    let load_result = if load_paths.is_empty() {
        Ok(None)
    } else {
        Dataset::load_paths(&load_paths).map(Some)
    };
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    g.opening = g.opening.saturating_sub(1);
    g.opening_bytes = g.opening_bytes.saturating_sub(bytes);
    let ds = match load_result {
        Ok(ds) => ds,
        Err(error) => return Err((-32000, format!("load_failed: {error}"))),
    };
    let dex_bytes = ds
        .as_ref()
        .map(|dataset| dataset.files.iter().map(|file| file.byte_len).sum::<u64>())
        .unwrap_or(0);
    if dex_bytes > cfg.max_dex_bytes {
        return Err((
            -32000,
            "dataset exceeds --max-dex-bytes (uncompressed DEX bytes)".into(),
        ));
    }
    g.next_id += 1;
    let id = format!("dataset-{}", g.next_id);
    let n = ds.as_ref().map_or(0, |ds| ds.files.len());
    let archive_inputs = paths
        .iter()
        .enumerate()
        .filter_map(|(index, path)| is_archive(path).then_some(index))
        .collect::<Vec<_>>();
    let archive_stamps = archive_inputs
        .iter()
        .map(|&index| (index, archive_stamp(&paths[index])))
        .collect::<HashMap<_, _>>();
    let inputs = paths.clone();
    let prepare_ms = started.elapsed().as_secs_f64() * 1000.0;
    g.datasets.insert(
        id.clone(),
        Entry {
            paths,
            dataset: ds.map(Arc::new),
            session: Arc::new(Mutex::new(query_engine::QuerySession::default())),
            source_bytes: bytes,
            archive_inputs: archive_inputs.clone(),
            prepare_ms,
            resource_cache: None,
            archive_stamps,
        },
    );
    Ok(json!({
        "archive_inputs": archive_inputs,
        "dataset_id": id,
        "has_dex": n > 0,
        "input_bytes": bytes,
        "inputs": inputs,
        "prepare_ms": prepare_ms
    }))
}
fn list_datasets(state: &Arc<Mutex<State>>, cfg: &Config) -> Value {
    let g = state.lock().expect("state lock");
    let datasets: Vec<Value> = g
        .datasets
        .iter()
        .map(|(id, e)| {
            json!({
                "archive_inputs": e.archive_inputs,
                "dataset_id": id,
                "has_dex": e.dataset.as_ref().is_some_and(|ds| !ds.files.is_empty()),
                "input_bytes": e.source_bytes,
                "inputs": e.paths,
                "prepare_ms": e.prepare_ms
            })
        })
        .collect();
    let input_bytes = g.datasets.values().map(|e| e.source_bytes).sum::<u64>();
    json!({
        "admitted_requests": g.opening,
        "datasets": datasets,
        "limits": {
            "max_datasets": cfg.max_datasets,
            "max_dex_bytes": cfg.max_dex_bytes,
            "max_input_bytes": cfg.max_input_bytes,
            "max_output_bytes": cfg.max_output_bytes,
            "max_pending": cfg.max_pending,
            "max_resource_bytes": cfg.max_resource_bytes,
            "max_total_input_bytes": cfg.max_total_input_bytes,
            "timeout_ms": cfg.timeout_ms
        },
        "running_requests": g.opening,
        "usage": {"datasets": g.datasets.len(), "input_bytes": input_bytes}
    })
}
fn close_dataset(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    if g.datasets.remove(id).is_none() {
        return Err((-32001, format!("unknown dataset_id: {id}")));
    }
    Ok(json!({"dataset_id":id,"closed":true}))
}
fn describe_table(a: &Value) -> Result<Value, (i32, String)> {
    let name = a
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "name is required".into()))?;
    let table = schema::TABLES
        .iter()
        .find(|table| table.name == name)
        .ok_or((-32002, format!("unknown table: {name}")))?;
    let columns = table
        .columns
        .iter()
        .filter(|column| name != "classes" || !matches!(column.name, "field_count" | "method_count"))
        .map(|column| {
            json!({
                "name":column.name,
                "data_type": if column.nullable { format!("{}?", column.sql_type) } else { column.sql_type.to_owned() }
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({"name":table.name,"columns":columns}))
}
fn query(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let dataset = e.dataset.as_ref().cloned().ok_or((
        -32005,
        "dataset has no DEX files; archive-only datasets support archive tools only".into(),
    ))?;
    let session = Arc::clone(&e.session);
    drop(g);
    let sql = a
        .get("sql")
        .and_then(Value::as_array)
        .ok_or((-32602, "sql is required".into()))?;
    if sql.is_empty() || sql.len() > 16 {
        return Err((-32602, "sql must contain 1..16 statements".into()));
    }
    let named: &[Value] = a
        .get("named_temp_queries")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    if named.len() > 16 {
        return Err((
            -32602,
            "named_temp_queries must contain at most 16 entries".into(),
        ));
    }
    let total_sql = sql
        .iter()
        .map(|s| s.as_str().map(str::len).unwrap_or(0))
        .sum::<usize>()
        + named
            .iter()
            .map(|entry| {
                entry
                    .get("sql")
                    .and_then(Value::as_str)
                    .map(str::len)
                    .unwrap_or(0)
            })
            .sum::<usize>();
    if total_sql > 64 * 1024 {
        return Err((-32602, "SQL input exceeds 64KiB".into()));
    }
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match a.get("limit") {
        None | Some(Value::Null) => 200usize,
        Some(value) => {
            let n = value
                .as_u64()
                .ok_or((-32602, "limit must be an integer or null".into()))?
                as usize;
            if !(1..=1000).contains(&n) {
                return Err((-32602, "limit must be between 1 and 1000".into()));
            }
            n
        }
    };
    if offset.saturating_add(limit) > 100_000 {
        return Err((-32602, "offset + limit must be at most 100000".into()));
    }
    let max_bytes = checked_u64(a, "max_bytes")?;
    let started = Instant::now();
    let timing = a.get("timing").and_then(Value::as_bool).unwrap_or(false);
    let mut session = session
        .lock()
        .map_err(|_| (-32603, "SQL session lock poisoned".into()))?;
    session.begin_request();
    let sql_error = |error: query_engine::DexSqlError, index: usize| {
        json!({"error":{"input":Value::Null,"kind":error.code,"message":error.message,
            "source":error.source,"stage":error.stage,"statement_index":index}})
    };
    let mut validated = Vec::with_capacity(sql.len());
    for (index, value) in sql.iter().enumerate() {
        let text = value
            .as_str()
            .ok_or((-32602, "sql entries must be strings".into()))?;
        match query_engine::QuerySession::validate(text) {
            Ok(statement) => validated.push(statement),
            Err(error) => return Ok(sql_error(error, index)),
        }
    }
    let mut names = std::collections::HashSet::new();
    for entry in named {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "named temporary query name is required".into()))?;
        let text = entry
            .get("sql")
            .and_then(Value::as_str)
            .ok_or((-32602, "named temporary query sql is required".into()))?;
        if name.is_empty() || !valid_identifier(name) {
            return Err((-32602, format!("invalid temporary query name: {name}")));
        }
        if !names.insert(name.to_ascii_lowercase()) {
            return Err((-32602, format!("duplicate temporary query: {name}")));
        }
        if let Err(error) = session.define(name, text) {
            return Ok(sql_error(error, 0));
        }
    }
    let mut statements = Vec::with_capacity(sql.len());
    for (index, statement) in validated.iter().enumerate() {
        let text = sql[index].as_str().expect("validated SQL string");
        let execute_started = Instant::now();
        let result = match session.execute(statement, Some(&dataset)) {
            Ok(result) => result,
            Err(error) => return Ok(sql_error(error, index)),
        };
        let mut value = literal_select(text.trim().trim_end_matches(';').trim(), index, text)
            .unwrap_or_else(|| query_result_to_statement(&result, index, text));
        if matches!(
            statement,
            dexsql_core::sql::ast::Statement::CreateDefinition { .. }
        ) {
            value["kind"] = json!("create_temp_table");
        }
        if timing {
            value["execute_ms"] = json!(execute_started.elapsed().as_secs_f64() * 1000.0);
        }
        apply_page(&mut value, offset, limit)?;
        if let Some(max) = max_bytes {
            truncate_statement_bytes(&mut value, max as usize);
        }
        statements.push(value);
    }
    let rewrites = sql
        .iter()
        .filter_map(Value::as_str)
        .filter(|sql| !sql.trim_start().to_ascii_lowercase().starts_with("create "))
        .map(|sql| session.optimizer_rewrite_count(sql))
        .sum::<usize>();
    let diagnostics = if rewrites == 0 {
        vec![]
    } else {
        vec![
            json!({"code":"sql_static_optimizer_rewrite","message":format!("sql_static_optimizer rewrites={rewrites}")}),
        ]
    };
    let mut value = json!({"dataset_id":id,"statements":statements,"diagnostics":diagnostics});
    if timing {
        let total = started.elapsed().as_secs_f64() * 1000.0;
        value["timing"] = json!({"cache_total_ms":0.0,"load_inputs_ms":0.0,"parse_ms":0.0,
            "sql_wall_ms":total,"table_build_ms":0.0,"total_ms":total});
    }
    Ok(value)
}

fn checked_u64(a: &Value, key: &str) -> Result<Option<u64>, (i32, String)> {
    match a.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or((
            -32602,
            format!("{key} must be a non-negative integer or null"),
        )),
    }
}
fn valid_identifier(name: &str) -> bool {
    name.chars().enumerate().all(|(i, ch)| {
        ch == '_' || ch.is_ascii_alphanumeric() && (i > 0 || ch.is_ascii_alphabetic())
    })
}
fn literal_select(text: &str, index: usize, sql: &str) -> Option<Value> {
    let projection = text
        .strip_prefix("SELECT")
        .or_else(|| text.strip_prefix("select"))?
        .trim();
    if projection.is_empty() || projection.contains(" from ") || projection.contains(" FROM ") {
        return None;
    }
    let mut columns = Vec::new();
    let mut row = Vec::new();
    for raw in projection.split(',') {
        let expression = raw.trim();
        let (expression, name) = if let Some((value, alias)) = expression.rsplit_once(" AS ") {
            (value.trim(), alias.trim().to_owned())
        } else if let Some((value, alias)) = expression.rsplit_once(" as ") {
            (value.trim(), alias.trim().to_owned())
        } else {
            (expression, "column".to_owned())
        };
        let is_null = expression.eq_ignore_ascii_case("null");
        let cell = if is_null {
            json!({"type":"null","value":Value::Null})
        } else if expression.len() >= 3
            && (expression.starts_with("x'") || expression.starts_with("X'"))
            && expression.ends_with('\'')
            && expression[2..expression.len() - 1].len() % 2 == 0
            && expression[2..expression.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            json!({"type":"binary","value":expression[2..expression.len() - 1].to_ascii_lowercase()})
        } else if let Ok(value) = expression.parse::<i64>() {
            if value < 0 {
                typed_i64(value)
            } else {
                typed_u64(value as u64)
            }
        } else if let Ok(value) = expression.parse::<u64>() {
            if value <= i64::MAX as u64 {
                typed_u64(value)
            } else {
                typed_f64(value as f64)
            }
        } else if let Ok(value) = expression.parse::<f64>() {
            typed_f64(value)
        } else if expression.len() >= 2
            && expression.starts_with('\'')
            && expression.ends_with('\'')
        {
            typed_utf8(&expression[1..expression.len() - 1])
        } else {
            return None;
        };
        columns.push(json!({"name":name,"data_type":"sqlite_dynamic","nullable":is_null || cell.get("type").and_then(Value::as_str) == Some("binary")}));
        row.push(cell);
    }
    Some(
        json!({"statement_index":index,"sql":sql,"kind":"query","columns":columns,"rows":[row],"total_rows":1,"truncated":false,"offset":0,"next_offset":Value::Null}),
    )
}

fn query_result_to_statement(result: &query_engine::QueryResult, index: usize, sql: &str) -> Value {
    let sql_lower = sql.to_ascii_lowercase();
    let columns = result
        .columns
        .iter()
        .enumerate()
        .map(|(index, name)| {
            let lookup_name = name
                .rsplit_once('.')
                .map_or(name.as_str(), |(_, value)| value);
            let meta = schema::TABLES.iter().find_map(|table| {
                table
                    .columns
                    .iter()
                    .find(|column| column.name.eq_ignore_ascii_case(lookup_name))
            });
            let data_type = meta
                .map(|column| match column.sql_type {
                    "UInt32" | "UInt64" => "uint64",
                    "Int64" => "int64",
                    "Float64" => "float64",
                    "Utf8" | "Utf8View" => "utf8",
                    "Binary" => "binary",
                    _ => "sqlite_dynamic",
                })
                .unwrap_or_else(|| {
                    if sql_lower.contains("count(") {
                        "uint64"
                    } else {
                        "sqlite_dynamic"
                    }
                });
            let nullable = if sql_lower.contains("count(") {
                false
            } else {
                meta.map_or_else(
                    || {
                        sql_lower
                            .split(" from ")
                            .next()
                            .is_some_and(|projection| projection.contains('('))
                            || result.rows.iter().any(|row| {
                                row.get(index)
                                    .is_none_or(|value| value.eq_ignore_ascii_case("null"))
                            })
                    },
                    |column| column.nullable,
                )
            };
            json!({
                "name": name,
                "data_type": data_type,
                "nullable": nullable
            })
        })
        .collect::<Vec<_>>();
    let rows = result
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(column, value)| {
                    let data_type = columns
                        .get(column)
                        .and_then(|column| column.get("data_type"))
                        .and_then(Value::as_str)
                        .unwrap_or("sqlite_dynamic");
                    rendered_cell(value, data_type)
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    json!({
        "statement_index": index,
        "sql": sql,
        "kind": "query",
        "columns": columns,
        "rows": rows,
        "total_rows": result.rows.len(),
        "truncated": false,
        "offset": 0
    })
}

fn rendered_cell(value: &str, data_type: &str) -> Value {
    if value.eq_ignore_ascii_case("null") {
        return json!({"type":"null","value":Value::Null});
    }
    let base = data_type.trim_end_matches('?');
    if base.eq_ignore_ascii_case("uint32") {
        if let Ok(n) = value.parse::<u32>() {
            return typed_u32(n);
        }
    } else if base.eq_ignore_ascii_case("uint64") {
        if let Ok(n) = value.parse::<u64>() {
            return typed_u64(n);
        }
    } else if base.eq_ignore_ascii_case("int64") {
        if let Ok(n) = value.parse::<i64>() {
            return typed_i64(n);
        }
    } else if base.eq_ignore_ascii_case("float64") {
        if let Ok(n) = value.parse::<f64>() {
            return typed_f64(n);
        }
    } else if base.eq_ignore_ascii_case("utf8") {
        return typed_utf8(unescape_engine_text(value));
    } else if base.eq_ignore_ascii_case("binary") {
        return json!({"type":"binary","value":unescape_engine_text(value)});
    }
    if let Ok(n) = value.parse::<i64>() {
        if n < 0 {
            typed_i64(n)
        } else {
            typed_u64(n as u64)
        }
    } else if let Ok(n) = value.parse::<f64>() {
        typed_f64(n)
    } else {
        typed_utf8(unescape_engine_text(value))
    }
}

/// The CLI Scalar renderer escapes control characters for its text table.
/// MCP cells carry the original UTF-8 string and therefore must undo that
/// presentation escaping before serialization.
fn unescape_engine_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('u') => {
                let mut code = String::new();
                if chars.next() == Some('{') {
                    for ch in chars.by_ref() {
                        if ch == '}' {
                            break;
                        }
                        code.push(ch);
                    }
                }
                if let Ok(value) = u32::from_str_radix(&code, 16) {
                    if let Some(decoded) = char::from_u32(value) {
                        out.push(decoded);
                    }
                }
            }
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}
fn apply_page(statement: &mut Value, offset: usize, limit: usize) -> Result<(), (i32, String)> {
    let Some(object) = statement.as_object_mut() else {
        return Ok(());
    };
    let total = object
        .get("total_rows")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    let rows = object
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let start = offset.min(total);
    let end = (start + limit).min(total);
    let page = if rows.len() == total {
        rows[start.min(rows.len())..end.min(rows.len())].to_vec()
    } else {
        rows
    };
    object.insert("rows".into(), Value::Array(page));
    object.insert("offset".into(), json!(offset));
    object.insert("truncated".into(), json!(end < total));
    object.insert(
        "next_offset".into(),
        if end < total { json!(end) } else { Value::Null },
    );
    Ok(())
}
fn truncate_statement_bytes(statement: &mut Value, max: usize) {
    loop {
        let too_large = serde_json::to_vec(&*statement)
            .map(|bytes| bytes.len())
            .unwrap_or(usize::MAX)
            > max;
        if !too_large {
            break;
        }
        let popped = statement
            .get_mut("rows")
            .and_then(Value::as_array_mut)
            .and_then(Vec::pop)
            .is_some();
        if !popped {
            break;
        }
    }
    if let Some(object) = statement.as_object_mut() {
        object.insert("bytes_limited".into(), json!(true));
    }
}

fn typed_u32(value: u32) -> Value {
    json!({"type":"uint32","value":value})
}
fn typed_u64(value: u64) -> Value {
    json!({"type":"uint64","value":value.to_string()})
}
fn typed_i64(value: i64) -> Value {
    json!({"type":"int64","value":value.to_string()})
}
fn typed_f64(value: f64) -> Value {
    if value.is_finite() {
        json!({"type":"float64","value":value})
    } else {
        json!({"type":"float64","value":value.to_string()})
    }
}
fn typed_utf8(value: impl AsRef<str>) -> Value {
    json!({"type":"utf8","value":value.as_ref()})
}
fn decode_tool(a: &Value, state: &Arc<Mutex<State>>, cfg: &Config) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let guard = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let entry = guard
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let dataset = entry.dataset.as_ref().ok_or((
        -32005,
        "dataset has no DEX files; archive-only datasets support archive tools only".into(),
    ))?;
    let class_name = a.get("class").and_then(Value::as_str);
    let method = a.get("method").and_then(Value::as_str);
    let method_idx = a
        .get("method_idx")
        .and_then(Value::as_u64)
        .map(|n| n as u32);
    let fid = a.get("file_id").and_then(Value::as_u64).map(|n| n as u32);
    let mode = a.get("mode").and_then(Value::as_str).unwrap_or_else(|| {
        if class_name.is_some() {
            "summary"
        } else {
            "smali"
        }
    });
    let failure = |kind, message| decode_error(id, kind, message, None, None);
    if usize::from(method.is_some())
        + usize::from(method_idx.is_some())
        + usize::from(class_name.is_some())
        != 1
    {
        return Ok(failure(
            "invalid_input",
            "specify exactly one of method, method_idx, or class",
        ));
    }
    if method_idx.is_some() && fid.is_none() {
        return Ok(failure("invalid_input", "method_idx requires file_id"));
    }
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let method_offset = checked_u64(a, "method_offset")?.unwrap_or(0) as usize;
    let max_lines = checked_u64(a, "max_lines")?.unwrap_or(200) as usize;
    let method_limit = checked_u64(a, "method_limit")?.unwrap_or(20) as usize;
    let max_bytes = checked_u64(a, "max_bytes")?.unwrap_or(cfg.max_output_bytes) as usize;
    let compact = a.get("compact").and_then(Value::as_bool).unwrap_or(false);
    if !(1..=1000).contains(&max_lines) {
        return Ok(failure("invalid_input", "limit must be in 1..=1000"));
    }
    if !(1..=50).contains(&method_limit) {
        return Ok(failure("invalid_input", "limit must be in 1..=50"));
    }
    if class_name.is_none() && method_offset != 0 {
        return Ok(failure(
            "invalid_input",
            "method_offset is only valid with class selection",
        ));
    }
    if mode == "summary" && offset != 0 {
        return Ok(failure("invalid_input", "summary mode has no text offset"));
    }
    // Select definitions, rather than every method_id: referenced external
    // methods have no method body and are not valid decode targets.
    let mut candidates = Vec::new();
    for file in dataset
        .files
        .iter()
        .filter(|file| fid.is_none_or(|id| id == file.file_id))
    {
        if let Some(class) = class_name {
            if let Some(class) = file
                .classes
                .iter()
                .find(|c| file.type_descriptor(c.class_idx) == class)
            {
                let mut methods = class.methods.clone();
                methods.sort_unstable_by_key(|method| method.method_idx);
                candidates.push((file, methods));
            }
        } else {
            let index = method_idx.or_else(|| {
                method.and_then(|descriptor| decode::method_index_for_descriptor(file, descriptor))
            });
            if let Some(index) = index {
                if let Some(definition) = file
                    .class_for_method(index)
                    .and_then(|class| class.methods.iter().find(|m| m.method_idx == index))
                {
                    candidates.push((file, vec![*definition]));
                }
            }
        }
    }
    if candidates.is_empty() {
        return Ok(decode_error(
            id,
            "not_found",
            if class_name.is_some() {
                "class is not defined in the selected DEX"
            } else {
                "method is not defined in the selected DEX"
            },
            fid,
            method_idx,
        ));
    }
    if candidates.len() > 1 {
        let files = candidates
            .iter()
            .map(|(file, _)| file.file_id)
            .collect::<std::collections::BTreeSet<_>>();
        return Ok(failure(
            "ambiguous",
            &format!(
                "{} occurs in multiple DEX files; supply file_id from {files:?}",
                if class_name.is_some() {
                    "class"
                } else {
                    "method"
                }
            ),
        ));
    }
    let (file, methods) = candidates.pop().expect("one decode candidate");
    let total = methods.len();
    if method_offset > total {
        return Ok(failure(
            "invalid_range",
            "method_offset exceeds total_methods",
        ));
    }
    let end = method_offset.saturating_add(method_limit).min(total);
    let mut result = json!({
        "dataset_id": id, "mode": mode, "methods": [], "total_methods": total,
        "method_offset": method_offset, "next_method_offset": Value::Null,
    });
    for definition in &methods[method_offset..end] {
        let idx = definition.method_idx;
        let cached = file.code_items.get(idx as usize).and_then(Option::as_ref);
        let decoded = if cached.is_none() {
            match file.decode_code_item(idx) {
                Ok(code) => code,
                Err(error) => {
                    return Ok(decode_error(
                        id,
                        "decode_error",
                        &error.to_string(),
                        Some(file.file_id),
                        Some(idx),
                    ))
                }
            }
        } else {
            None
        };
        let code = cached.or(decoded.as_ref());
        let mut row = json!({
            "file_id": file.file_id, "method_idx": idx, "descriptor": file.method_descriptor(idx),
            "access_flags": definition.access_flags, "next_offset": Value::Null,
            "code_units": code.map(|c| c.insns.len()), "try_count": code.map(|c| c.tries.len()),
            "registers": code.map(|c| c.registers_size),
        });
        let text = if mode != "summary" {
            match render_method(file, idx, Some(definition.access_flags), mode) {
                Ok((declaration, text)) => {
                    row["declaration"] = json!(declaration);
                    if add_smali_page(&mut row, &text, offset, max_bytes, Some(max_lines)).is_err()
                    {
                        return Ok(failure("invalid_range", "offset must be a UTF-8 boundary within the text; use the returned next_offset"));
                    }
                    Some(text)
                }
                Err((_, message)) => {
                    return Ok(decode_error(
                        id,
                        "decode_error",
                        &message,
                        Some(file.file_id),
                        Some(idx),
                    ))
                }
            }
        } else {
            None
        };
        result["methods"]
            .as_array_mut()
            .expect("methods array")
            .push(row);
        let returned = result["methods"].as_array().expect("methods array").len();
        let next_method = method_offset + returned;
        result["next_method_offset"] = if next_method < total {
            json!(next_method)
        } else {
            Value::Null
        };
        if decode_result_bytes(&result, compact) > max_bytes {
            let row_index = returned - 1;
            if let Some(text) = text {
                // Prefer complete lines. If one line is longer than the whole
                // budget, the last resort is a UTF-8-safe prefix of that line.
                let current_len = result["methods"][row_index]["smali"]
                    .as_str()
                    .map_or(0, str::len);
                let mut boundaries = text[offset..offset + current_len]
                    .match_indices('\n')
                    .map(|(i, _)| i + 1)
                    .collect::<Vec<_>>();
                if boundaries.last().copied() != Some(current_len) {
                    boundaries.push(current_len);
                }
                let mut low = 0;
                let mut high = boundaries.len();
                while low < high {
                    let mid = low + (high - low) / 2;
                    add_smali_page(
                        &mut result["methods"][row_index],
                        &text,
                        offset,
                        boundaries[mid],
                        Some(max_lines),
                    )?;
                    if decode_result_bytes(&result, compact) <= max_bytes {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                if low > 0 {
                    add_smali_page(
                        &mut result["methods"][row_index],
                        &text,
                        offset,
                        boundaries[low - 1],
                        Some(max_lines),
                    )?;
                    break;
                }
                if returned == 1 {
                    let mut low = 0;
                    let mut high = current_len;
                    while low < high {
                        let mid = low + (high - low).div_ceil(2);
                        add_smali_page(
                            &mut result["methods"][row_index],
                            &text,
                            offset,
                            mid,
                            Some(max_lines),
                        )?;
                        if decode_result_bytes(&result, compact) <= max_bytes {
                            low = mid;
                        } else {
                            high = mid - 1;
                        }
                    }
                    add_smali_page(
                        &mut result["methods"][row_index],
                        &text,
                        offset,
                        low,
                        Some(max_lines),
                    )?;
                    if low > 0 {
                        break;
                    }
                }
            }
            result["methods"]
                .as_array_mut()
                .expect("methods array")
                .pop();
            result["next_method_offset"] = json!(next_method - 1);
            if returned == 1 {
                return Ok(failure(
                    "output_limit",
                    "serialized result exceeds --max-output-bytes",
                ));
            }
            break;
        }
    }
    Ok(result)
}

fn decode_error(
    id: &str,
    kind: &str,
    message: &str,
    file_id: Option<u32>,
    method_idx: Option<u32>,
) -> Value {
    json!({"dataset_id": id, "error": {
        "kind": kind, "message": message, "file_id": file_id,
        "method_idx": method_idx, "code_unit_offset": Value::Null,
    }})
}

fn decode_result_bytes(value: &Value, compact: bool) -> usize {
    let content = if compact {
        json!([])
    } else {
        json!([{"type":"text", "text":value.to_string()}])
    };
    json!({"content":content, "structuredContent":value, "isError":false})
        .to_string()
        .len()
}

fn render_method(
    file: &dexsql_core::dex::DexFile,
    idx: u32,
    flags: Option<u32>,
    mode: &str,
) -> Result<(String, String), (i32, String)> {
    let rendered = decode::render_method_with_flags(file, idx, flags)
        .map_err(|error| (-32000, error.to_string()))?;
    // CLI output adds a source header and a blank line between method blocks.
    // MCP offsets address exactly one method block, including its final LF.
    let body = rendered
        .strip_prefix("# file_id=")
        .and_then(|_| rendered.split_once('\n').map(|(_, body)| body))
        .unwrap_or(&rendered);
    let body = body.strip_suffix('\n').unwrap_or(body);
    let (declaration, tail) = body.split_once('\n').unwrap_or((body, ""));
    let mut declaration = declaration.to_owned();
    if flags.is_some_and(|flags| flags & 0x20000 != 0) {
        if let Some((prefix, method)) = declaration.rsplit_once(' ') {
            declaration = format!("{prefix} declared-synchronized {method}");
        }
    }
    let mut text = format!("{declaration}\n{tail}");
    if mode == "context" {
        let mut context = "# Original zero-based smali line numbers; labels retain method-relative code-unit offsets.\n".to_owned();
        for (line, value) in text.lines().enumerate() {
            let trimmed = value.trim_start();
            if trimmed.starts_with(".method ")
                || trimmed.starts_with(".registers ")
                || trimmed.starts_with(':')
                || trimmed.starts_with(".catch")
            {
                context.push_str(&format!("line {line}: {value}\n"));
            }
        }
        text = context;
    }
    Ok((declaration, text))
}

fn add_smali_page(
    row: &mut Value,
    text: &str,
    offset: usize,
    max_bytes: usize,
    max_lines: Option<usize>,
) -> Result<(), (i32, String)> {
    if offset > text.len() || !text.is_char_boundary(offset) {
        return Err((
            -32602,
            "offset must be a UTF-8 boundary within the text; use the returned next_offset".into(),
        ));
    }
    let tail = &text[offset..];
    let mut end = tail.len().min(max_bytes.max(4));
    while end > 0 && !tail.is_char_boundary(end) {
        end -= 1;
    }
    if let Some(limit) = max_lines {
        if let Some((last, _)) = tail[..end].match_indices('\n').nth(limit - 1) {
            end = last + 1;
        }
    }
    let finish = offset + end;
    let start_line = text[..offset].bytes().filter(|byte| *byte == b'\n').count();
    let end_line = start_line + tail[..end].bytes().filter(|byte| *byte == b'\n').count();
    row["smali"] = json!(&tail[..end]);
    row["offset"] = json!(offset);
    row["total_bytes"] = json!(text.len());
    row["total_lines"] = json!(text.lines().count());
    row["start_line"] = json!(start_line);
    row["end_line"] = json!(end_line);
    row["starts_mid_line"] = json!(offset > 0 && text.as_bytes()[offset - 1] != b'\n');
    row["ends_mid_line"] = json!(finish > 0 && text.as_bytes()[finish - 1] != b'\n');
    row["next_offset"] = if finish < text.len() {
        json!(finish)
    } else {
        Value::Null
    };
    Ok(())
}

fn query_resources(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 100,
        Some(value) if (1..=200).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let max_bytes = match checked_u64(a, "max_bytes")? {
        None => 131_072,
        Some(value) if (4_096..=131_072).contains(&value) => value as usize,
        Some(_) => return Err((-32602, "max_bytes must be in 4096..=131072".into())),
    };
    let mut g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let entry = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let path = zip_path(
        entry,
        a.get("input_index")
            .and_then(Value::as_u64)
            .map(|value| value as usize),
    )?
    .to_owned();
    let stamp = archive_stamp(&path);
    let cached = entry.resource_cache.clone();
    let rows = if let Some(cache) = cached {
        if (cache.len, cache.modified_nanos) != stamp {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
        cache.rows
    } else {
        let file = std::fs::File::open(&path).map_err(|error| (-32000, error.to_string()))?;
        let mut archive =
            ZipArchive::new(file).map_err(|error| (-32000, format!("invalid archive: {error}")))?;
        let mut item = archive
            .by_name("resources.arsc")
            .map_err(|_| (-32004, "resource table resources.arsc was not found".into()))?;
        if item.size() > 256 * 1024 * 1024 {
            return Err((-32000, "resource table exceeds size limit".into()));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut item, &mut bytes)
            .map_err(|error| (-32000, error.to_string()))?;
        let parsed = parse_resources_arsc(&bytes)
            .map_err(|error| (-32006, format!("resources_parse_error: {error}")))?;
        if let Some(entry) = g.datasets.get_mut(id) {
            entry.resource_cache = Some(CachedResourceTable {
                len: stamp.0,
                modified_nanos: stamp.1,
                rows: parsed.clone(),
            });
        }
        parsed
    };
    let resource_id = match a.get("resource_id").and_then(Value::as_u64) {
        Some(value) if value > u32::MAX as u64 => {
            return Err((-32602, "resource_id must fit in uint32".into()))
        }
        Some(value) => Some(value as u32),
        None => None,
    };
    let name = a.get("name").and_then(Value::as_str);
    let resource_type = a.get("resource_type").and_then(Value::as_str);
    let contains = a.get("contains").and_then(Value::as_str);
    let configuration = a.get("configuration").and_then(Value::as_str);
    let mut rows = rows
        .into_iter()
        .filter(|row| {
            resource_id.is_none_or(|value| row["resource_id"].as_u64() == Some(value as u64))
                && name.is_none_or(|value| row["name"].as_str() == Some(value))
                && resource_type.is_none_or(|value| row["resource_type"].as_str() == Some(value))
                && contains.is_none_or(|value| {
                    row["name"]
                        .as_str()
                        .is_some_and(|text| text.contains(value))
                })
                && configuration.is_none_or(|value| row["configuration"].as_str() == Some(value))
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left["resource_id"]
            .as_u64()
            .cmp(&right["resource_id"].as_u64())
            .then(
                left["configuration"]
                    .as_str()
                    .cmp(&right["configuration"].as_str()),
            )
    });
    let total = rows.len();
    if offset > total {
        return Err((
            -32602,
            format!("offset {offset} exceeds total_rows {total}"),
        ));
    }
    let start = offset.min(total);
    let end = (start + limit).min(total);
    let mut page = rows[start..end].to_vec();
    // MCP carries both a text and structured copy of the result.  The native
    // service accounts both serialized copies while paging resource metadata;
    // keep the internal resource_type key in this accounting, then remove it
    // from the public rows below.
    while !page.is_empty() {
        let next = if start + page.len() < total {
            Some(start + page.len())
        } else {
            None::<usize>
        };
        let probe = json!({
            "dataset_id": id,
            "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
            "next_offset": next,
            "offset": offset,
            "reference_policy": "references are named, not recursively evaluated; query the referenced ID and configuration to continue",
            "total_rows": total,
            "truncated": next.is_some(),
            "values": &page,
        });
        let bytes = serde_json::to_vec(&probe).map_or(usize::MAX, |value| value.len());
        if bytes.saturating_mul(2) <= max_bytes {
            break;
        }
        page.pop();
    }
    if page.is_empty() && start < total {
        return Err((-32000, "resource metadata exceeds max_bytes".into()));
    }
    // resource_type is an implementation detail used for filtering.  The
    // reference result schema exposes only the resource name and value type.
    for row in &mut page {
        if let Some(object) = row.as_object_mut() {
            object.remove("resource_type");
        }
    }
    let page_end = start + page.len();
    Ok(json!({
        "dataset_id": id,
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "next_offset": if page_end < total { Some(page_end) } else { None::<usize> },
        "offset": offset,
        "reference_policy": "references are named, not recursively evaluated; query the referenced ID and configuration to continue",
        "total_rows": total,
        "truncated": page_end < total,
        "values": page
    }))
}

fn parse_resources_arsc(bytes: &[u8]) -> Result<Vec<Value>, String> {
    // The reference uses apk-info-axml 1.0.13.  In particular, its ARSC
    // parser understands sparse/offset16 entry tables, compact entries,
    // extended ResTable_config qualifiers and complex map values.  Keeping
    // those details in the same parser avoids silently dropping configurations
    // or flattening bags to a placeholder.
    use apk_info_axml::structs::{ResTableEntry, ResourceValueType};
    use apk_info_axml::ARSC;
    use std::collections::HashMap;

    fn package_name(name: &[u8; 256]) -> String {
        let units = name
            .as_chunks::<2>()
            .0
            .iter()
            .map(|part| u16::from_le_bytes([part[0], part[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
    }
    fn value_type_name(value: &ResourceValueType) -> String {
        match value {
            ResourceValueType::Null => "Null".into(),
            ResourceValueType::Reference => "Reference".into(),
            ResourceValueType::Attribute => "Attribute".into(),
            ResourceValueType::String => "String".into(),
            ResourceValueType::Float => "Float".into(),
            ResourceValueType::Dimension => "Dimension".into(),
            ResourceValueType::Fraction => "Fraction".into(),
            ResourceValueType::DynamicReference => "DynamicReference".into(),
            ResourceValueType::DynamicAttribute => "DynamicAttribute".into(),
            ResourceValueType::Dec => "Dec".into(),
            ResourceValueType::Hex => "Hex".into(),
            ResourceValueType::Boolean => "Boolean".into(),
            ResourceValueType::ColorArgb8 => "ColorArgb8".into(),
            ResourceValueType::ColorRgb8 => "ColorRgb8".into(),
            ResourceValueType::ColorArgb4 => "ColorArgb4".into(),
            ResourceValueType::ColorRgb4 => "ColorRgb4".into(),
            ResourceValueType::Unknown(value) => format!("Unknown({value})"),
        }
    }

    let mut input = bytes;
    let arsc = ARSC::new(&mut input).map_err(|error| error.to_string())?;
    let packages = arsc.packages().collect::<Vec<_>>();
    let mut package_names = HashMap::<u8, String>::with_capacity(packages.len());
    for package in &packages {
        package_names.insert(
            (package.header.id & 0xff) as u8,
            package_name(&package.header.name),
        );
    }
    // Return the package-qualified resource name used by the MCP result.  The
    // Android framework package is usually not embedded in an APK's table, so
    // system IDs intentionally remain unresolved (null reference_name).
    let resource_name = |id: u32| -> Option<String> {
        let local = arsc.get_resource_name(id)?;
        let package = package_names.get(&((id >> 24) as u8))?;
        Some(format!("{package}:{local}"))
    };
    let mut rows = Vec::new();
    for package in packages {
        let package_id = package.header.id & 0xff;
        let package_text = package_name(&package.header.name);
        for (config, type_map) in &package.resources {
            let configuration = config.as_string();
            for (&type_id, entries) in type_map {
                let type_name = package
                    .type_strings
                    .strings
                    .get(type_id.saturating_sub(1) as usize)
                    .cloned()
                    .unwrap_or_else(|| format!("type{type_id}"));
                for (position, entry) in entries.entries.iter().enumerate() {
                    let entry_id = entries
                        .entry_ids
                        .as_ref()
                        .and_then(|ids| ids.get(position).copied())
                        .unwrap_or(position as u16) as u32;
                    let resource_id = (package_id << 24) | ((type_id as u32) << 16) | entry_id;
                    let resource_id_hex = format!("0x{resource_id:08x}");
                    let name = match entry {
                        ResTableEntry::Compact(value) => package
                            .key_strings
                            .strings
                            .get(value.key as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::Complex(value) => package
                            .key_strings
                            .strings
                            .get(value.index as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::Default(value) => package
                            .key_strings
                            .strings
                            .get(value.index as usize)
                            .cloned()
                            .unwrap_or_else(|| format!("entry{entry_id}")),
                        ResTableEntry::NoEntry => continue,
                    };
                    let full_name = format!("{type_name}/{name}");
                    match entry {
                        ResTableEntry::Complex(value) => {
                            let item_count = value.values.len();
                            if item_count == 0 {
                                rows.push(json!({
                                    "configuration": configuration,
                                    "item_count": 0,
                                    "name": full_name,
                                    "package": package_text,
                                    "parent_id": value.parent,
                                    "resource_type": type_name,
                                    "resource_id": resource_id,
                                    "resource_id_hex": resource_id_hex,
                                }));
                                continue;
                            }
                            for (item_index, map) in value.values.iter().enumerate() {
                                let mut row = json!({
                                    "configuration": configuration,
                                    "item_count": item_count,
                                    "item_index": item_index,
                                    "item_name": resource_name(map.name),
                                    "item_name_id": map.name,
                                    "name": full_name,
                                    "package": package_text,
                                    "parent_id": value.parent,
                                    "resource_type": type_name,
                                    "raw_data": map.value.data,
                                    "resource_id": resource_id,
                                    "resource_id_hex": resource_id_hex,
                                    "value": render_resource_value(&arsc, &package_names, &map.value),
                                    "value_type": value_type_name(&map.value.data_type),
                                });
                                add_reference_fields(&mut row, &resource_name, &map.value);
                                rows.push(row);
                            }
                        }
                        ResTableEntry::Compact(value) => {
                            // Compact entries contain no typed Res_value.  The
                            // reference implementation treats them as raw
                            // hexadecimal data and still emits all scalar keys.
                            rows.push(json!({
                                "configuration": configuration,
                                "name": full_name,
                                "package": package_text,
                                "resource_type": type_name,
                                "raw_data": value.data,
                                "resource_id": resource_id,
                                "resource_id_hex": resource_id_hex,
                                "value": format!("0x{:08x}", value.data),
                                "value_type": "Hex",
                            }));
                        }
                        ResTableEntry::Default(value) => {
                            let mut row = json!({
                                "configuration": configuration,
                                "name": full_name,
                                "package": package_text,
                                "resource_type": type_name,
                                "raw_data": value.value.data,
                                "resource_id": resource_id,
                                "resource_id_hex": resource_id_hex,
                                "value": render_resource_value(&arsc, &package_names, &value.value),
                                "value_type": value_type_name(&value.value.data_type),
                            });
                            add_reference_fields(&mut row, &resource_name, &value.value);
                            rows.push(row);
                        }
                        ResTableEntry::NoEntry => unreachable!(),
                    }
                }
            }
        }
    }
    Ok(rows)
}

fn render_resource_value(
    arsc: &apk_info_axml::ARSC,
    package_names: &std::collections::HashMap<u8, String>,
    value: &apk_info_axml::structs::ResourceValue,
) -> String {
    use apk_info_axml::structs::ResourceValueType;
    match value.data_type {
        ResourceValueType::Reference | ResourceValueType::DynamicReference => {
            resource_value_name(arsc, package_names, value.data)
                .map(|name| format!("@{name}"))
                .unwrap_or_else(|| format!("@0x{:08x}", value.data))
        }
        ResourceValueType::Attribute | ResourceValueType::DynamicAttribute => {
            resource_value_name(arsc, package_names, value.data)
                .map(|name| format!("?{name}"))
                .unwrap_or_else(|| format!("?0x{:08x}", value.data))
        }
        _ => arsc.value_to_string(value),
    }
}

fn resource_value_name(
    arsc: &apk_info_axml::ARSC,
    package_names: &std::collections::HashMap<u8, String>,
    id: u32,
) -> Option<String> {
    let local = arsc.get_resource_name(id)?;
    let package = package_names.get(&((id >> 24) as u8))?;
    Some(format!("{package}:{local}"))
}

fn add_reference_fields(
    row: &mut Value,
    resource_name: &impl Fn(u32) -> Option<String>,
    value: &apk_info_axml::structs::ResourceValue,
) {
    use apk_info_axml::structs::ResourceValueType;
    if matches!(
        value.data_type,
        ResourceValueType::Reference
            | ResourceValueType::DynamicReference
            | ResourceValueType::Attribute
            | ResourceValueType::DynamicAttribute
    ) {
        row["reference_id"] = json!(value.data);
        row["reference_name"] = resource_name(value.data)
            .map(Value::String)
            .unwrap_or(Value::Null);
    }
}

fn is_dex(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|x| x.eq_ignore_ascii_case("dex"))
}
fn is_archive(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .is_some_and(|x| matches!(x.to_ascii_lowercase().as_str(), "apk" | "jar" | "zip"))
}
fn archive_contains_dex(path: &Path) -> bool {
    raw_zip_names(path)
        .iter()
        .any(|name| name.to_ascii_lowercase().ends_with(".dex"))
}
fn zip_path(entry: &Entry, input_index: Option<usize>) -> Result<&PathBuf, (i32, String)> {
    let archives = entry
        .paths
        .iter()
        .enumerate()
        .filter(|(_, path)| is_archive(path))
        .map(|(idx, _)| idx)
        .collect::<Vec<_>>();
    let idx = match input_index {
        Some(idx) => {
            if !archives.contains(&idx) {
                return Err((
                    -32602,
                    "input_index does not identify an archive input".into(),
                ));
            }
            idx
        }
        None if archives.len() == 1 => archives[0],
        None if archives.is_empty() => return Err((-32602, "dataset has no archive input".into())),
        None => {
            return Err((
                -32602,
                "input_index is required when a dataset contains multiple archive inputs".into(),
            ))
        }
    };
    let path = &entry.paths[idx];
    if let Some(stamp) = entry.archive_stamps.get(&idx) {
        if *stamp != archive_stamp(path) {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
    }
    if let Some(cache) = &entry.resource_cache {
        if (cache.len, cache.modified_nanos) != archive_stamp(path) {
            return Err((
                -32000,
                "archive changed; close and reopen the dataset".into(),
            ));
        }
    }
    Ok(path)
}

/// Return archive entry names exactly as stored in central-directory headers.
/// The `zip` crate applies Info-ZIP Unicode Path overrides; Android's
/// libziparchive intentionally uses the raw header name instead.
fn raw_zip_names(path: &Path) -> Vec<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Some(eocd) = bytes.windows(4).rposition(|window| window == b"PK\x05\x06") else {
        return Vec::new();
    };
    let count = bytes
        .get(eocd + 10..eocd + 12)
        .map(|value| u16::from_le_bytes([value[0], value[1]]) as usize)
        .unwrap_or(0);
    let offset = bytes
        .get(eocd + 16..eocd + 20)
        .map(|value| u32::from_le_bytes([value[0], value[1], value[2], value[3]]) as usize)
        .unwrap_or(bytes.len());
    let mut cursor = offset;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.get(cursor..cursor + 4) != Some(&b"PK\x01\x02"[..]) {
            break;
        }
        let name_len = u16::from_le_bytes([bytes[cursor + 28], bytes[cursor + 29]]) as usize;
        let flags = u16::from_le_bytes([bytes[cursor + 8], bytes[cursor + 9]]);
        let extra_len = u16::from_le_bytes([bytes[cursor + 30], bytes[cursor + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[cursor + 32], bytes[cursor + 33]]) as usize;
        let start = cursor + 46;
        let end = start.saturating_add(name_len);
        let Some(raw) = bytes.get(start..end) else {
            break;
        };
        let decoded = if flags & 0x0800 != 0 {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            use codepage_437::{FromCp437, CP437_CONTROL};
            String::from_cp437(raw.to_vec(), &CP437_CONTROL)
        };
        names.push(decoded);
        cursor = end.saturating_add(extra_len).saturating_add(comment_len);
    }
    names
}

fn list_resource_files(a: &Value, state: &Arc<Mutex<State>>) -> Result<Value, (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 200,
        Some(value) if (1..=200).contains(&(value as usize)) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let prefix = a.get("prefix").and_then(Value::as_str);
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let path = zip_path(
        e,
        a.get("input_index")
            .and_then(Value::as_u64)
            .map(|x| x as usize),
    )?;
    let file = std::fs::File::open(path).map_err(|x| (-32000, x.to_string()))?;
    let mut zip = ZipArchive::new(file).map_err(|x| (-32000, format!("invalid archive: {x}")))?;
    let raw_names = raw_zip_names(path);
    let mut rows = Vec::new();
    for i in 0..zip.len() {
        let item = zip.by_index(i).map_err(|x| (-32000, x.to_string()))?;
        let entry_name = raw_names
            .get(i)
            .map(String::as_str)
            .unwrap_or_else(|| item.name());
        if item.is_dir() || prefix.is_some_and(|p| !entry_name.starts_with(p)) {
            continue;
        }
        rows.push(json!({
            "bytes": item.size(),
            "compressed_bytes": item.compressed_size(),
            "crc32": item.crc32(),
            "directory": item.is_dir(),
            "entry_index": i,
            "name": entry_name
        }));
    }
    rows.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    let start = offset.min(rows.len());
    let end = (start + limit).min(rows.len());
    Ok(json!({
        "dataset_id": id,
        "files": rows[start..end],
        "input_index": a.get("input_index").cloned().unwrap_or_else(|| json!(0)),
        "next_offset": if end < rows.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "total_rows": rows.len(),
        "truncated": end < rows.len()
    }))
}

fn resource_page_budget(a: &Value) -> Result<usize, (i32, String)> {
    let budget = match checked_u64(a, "max_bytes")? {
        None => 131_072,
        Some(value) if (4_096..=131_072).contains(&value) => value as usize,
        Some(_) => return Err((-32602, "max_bytes must be in 4096..=131072".into())),
    };
    Ok(
        if a.get("compact").and_then(Value::as_bool).unwrap_or(false) {
            budget * 2
        } else {
            budget
        },
    )
}

fn archive_resource(
    a: &Value,
    state: &Arc<Mutex<State>>,
    name: &str,
    resource_limit: u64,
) -> Result<(Vec<u8>, usize), (i32, String)> {
    let id = a
        .get("dataset_id")
        .and_then(Value::as_str)
        .ok_or((-32602, "dataset_id is required".into()))?;
    let g = state
        .lock()
        .map_err(|_| (-32603, "state lock poisoned".into()))?;
    let e = g
        .datasets
        .get(id)
        .ok_or((-32001, format!("unknown dataset_id: {id}")))?;
    let input_index = a
        .get("input_index")
        .and_then(Value::as_u64)
        .map(|x| x as usize);
    let path = zip_path(e, input_index)?;
    let input_index = input_index.unwrap_or_else(|| {
        e.paths
            .iter()
            .position(|candidate| std::ptr::eq(candidate, path))
            .unwrap_or(0)
    });
    let file = std::fs::File::open(path).map_err(|x| (-32000, x.to_string()))?;
    let mut zip = ZipArchive::new(file).map_err(|x| (-32000, format!("invalid archive: {x}")))?;
    let entry_index = raw_zip_names(path)
        .iter()
        .position(|entry| entry == name)
        .ok_or_else(|| (-32004, format!("archive entry not found: {name}")))?;
    let mut item = zip
        .by_index(entry_index)
        .map_err(|_| (-32004, format!("archive entry not found: {name}")))?;
    if item.size() > resource_limit {
        return Err((-32000, "resource exceeds size limit".into()));
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut item, &mut bytes).map_err(|x| (-32000, x.to_string()))?;
    Ok((bytes, input_index))
}

fn resource_text_page(text: &str, offset: usize, budget: usize) -> Result<Value, (i32, String)> {
    if offset > text.len() || !text.is_char_boundary(offset) {
        return Err((
            -32602,
            "offset must be a UTF-8 boundary within the text; use the returned next_offset".into(),
        ));
    }
    let mut end = offset.saturating_add(budget / 4).min(text.len());
    while end > offset && !text.is_char_boundary(end) {
        end -= 1;
    }
    if end < text.len() {
        if let Some(newline) = text[offset..end].rfind('\n') {
            end = offset + newline + 1;
        }
    }
    Ok(json!({
        "end_line": text[..end].bytes().filter(|byte| *byte == b'\n').count(),
        "ends_mid_line": end < text.len() && end > 0 && text.as_bytes()[end - 1] != b'\n',
        "next_offset": if end < text.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "start_line": text[..offset].bytes().filter(|byte| *byte == b'\n').count(),
        "starts_mid_line": offset > 0 && text.as_bytes()[offset - 1] != b'\n',
        "text": &text[offset..end],
        "total_bytes": text.len()
    }))
}

fn read_resource(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let name = a
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "name is required".into()))?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let budget = resource_page_budget(a)?;
    let format = a.get("format").and_then(Value::as_str).unwrap_or("auto");
    if !matches!(format, "auto" | "hex") {
        return Err((-32602, "format must be auto or hex".into()));
    }
    let (bytes, input_index) = archive_resource(a, state, name, resource_limit)?;
    let binary_xml = bytes.starts_with(b"\x03\x00\x08\x00");
    if format != "hex" {
        let text = if binary_xml {
            decode_binary_xml(&bytes).ok()
        } else {
            std::str::from_utf8(&bytes).ok().map(str::to_owned)
        };
        if let Some(text) = text {
            return Ok(json!({
                "dataset_id": a["dataset_id"],
                "encoding": "utf8",
                "input_index": input_index,
                "kind": if binary_xml { "android_xml" } else { "text" },
                "name": name,
                "page": resource_text_page(&text, offset, budget)?,
                "source_bytes": bytes.len()
            }));
        }
    }
    if offset > bytes.len() {
        return Err((-32602, "offset exceeds resource size".into()));
    }
    let end = offset.saturating_add(budget / 8).min(bytes.len());
    let text = bytes[offset..end]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Ok(json!({
        "content": text,
        "dataset_id": a["dataset_id"],
        "encoding": "hex",
        "input_index": input_index,
        "kind": "binary",
        "name": name,
        "next_offset": if end < bytes.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "source_bytes": bytes.len(),
        "total_bytes": bytes.len()
    }))
}

fn manifest_xml(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<(String, usize), (i32, String)> {
    let (bytes, input_index) = archive_resource(a, state, "AndroidManifest.xml", resource_limit)?;
    let xml = if bytes.starts_with(b"\x03\x00\x08\x00") {
        decode_binary_xml(&bytes)
    } else {
        String::from_utf8(bytes).map_err(|error| error.to_string())
    }
    .map_err(|error| (-32006, format!("manifest_parse_error: {error}")))?;
    Ok((xml, input_index))
}

fn get_manifest(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let mode = a.get("mode").and_then(Value::as_str).unwrap_or("summary");
    if !matches!(mode, "summary" | "xml") {
        return Err((-32602, "mode must be summary or xml".into()));
    }
    let budget = resource_page_budget(a)?;
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 100,
        Some(value) if (1..=200).contains(&value) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    let (xml, input_index) = manifest_xml(a, state, resource_limit)?;
    if mode == "xml" {
        return Ok(json!({
            "dataset_id": a["dataset_id"],
            "input_index": input_index,
            "page": resource_text_page(&xml, offset, budget)?
        }));
    }
    let summary = manifest_summary(&xml);
    let permissions = manifest_permissions(&xml);
    if offset > permissions.len() {
        return Err((
            -32602,
            format!("offset {offset} exceeds total_rows {}", permissions.len()),
        ));
    }
    let start = offset;
    let end = start.saturating_add(limit).min(permissions.len());
    Ok(json!({
        "application": summary["application"].clone(),
        "component_counts": summary["component_counts"].clone(),
        "dataset_id": a["dataset_id"],
        "input_index": input_index,
        "manifest": summary["manifest"].clone(),
        "next_offset": if end < permissions.len() { Some(end) } else { None::<usize> },
        "offset": offset,
        "permissions": permissions[start..end].to_vec(),
        "target_sdk": summary["target_sdk"].clone(),
        "total_rows": permissions.len(),
        "truncated": end < permissions.len(),
        "uses_sdk": summary["uses_sdk"].clone()
    }))
}

fn get_manifest_components(
    a: &Value,
    state: &Arc<Mutex<State>>,
    resource_limit: u64,
) -> Result<Value, (i32, String)> {
    let offset = checked_u64(a, "offset")?.unwrap_or(0) as usize;
    let limit = match checked_u64(a, "limit")? {
        None => 100,
        Some(value) if (1..=200).contains(&value) => value as usize,
        Some(_) => return Err((-32602, "limit must be between 1 and 200".into())),
    };
    resource_page_budget(a)?;
    let (xml, input_index) = manifest_xml(a, state, resource_limit)?;
    let type_filter = a.get("kind").and_then(Value::as_str);
    if type_filter.is_some_and(|kind| {
        ![
            "activity",
            "activity-alias",
            "service",
            "receiver",
            "provider",
        ]
        .contains(&kind)
    }) {
        return Err((
            -32602,
            "kind must be activity, activity-alias, service, receiver, or provider".into(),
        ));
    }
    let only_exported = a
        .get("only_exported")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let components = parse_manifest_components(&xml)
        .into_iter()
        .filter(|component| {
            type_filter.is_none_or(|kind| component["type"].as_str() == Some(kind))
                && (!only_exported || component["exported"] == json!(true))
        })
        .map(|component| json!({
            "attributes": component["attributes"].clone(),
            "descriptor": component["name"].as_str().map(|name| format!("L{};", name.replace('.', "/"))),
            "enabled": component["enabled"].clone(),
            "exported": component["exported"].clone(),
            "exported_reason": component["exported_reason"].clone(),
            "intent_filters": component["intent_filters"].clone(),
            "kind": component["type"].clone(),
            "launcher_intent": component["launcher_intent"].clone(),
            "metadata": component["metadata"].clone(),
            "name": component["name"].clone(),
            "target_activity": component["target_activity"].clone()
        }))
        .collect::<Vec<_>>();
    let total = components.len();
    if offset > total {
        return Err((
            -32602,
            format!("offset {offset} exceeds total_rows {total}"),
        ));
    }
    let start = offset;
    let end = start.saturating_add(limit).min(total);
    Ok(json!({
        "components": &components[start..end],
        "dataset_id": a["dataset_id"],
        "exported_assumption": "Android API 17+; manifest configuration only, excluding runtime state and permission checks",
        "input_index": input_index,
        "next_offset": if end < total { Some(end) } else { None::<usize> },
        "offset": offset,
        "target_sdk": manifest_summary(&xml)["target_sdk"].clone(),
        "total_rows": total,
        "truncated": end < total
    }))
}

fn decode_binary_xml(bytes: &[u8]) -> Result<String, String> {
    let mut input = bytes;
    let axml = apk_info_axml::AXML::new(&mut input, None)
        .map_err(|error| format!("binary XML parse error: {error}"))?;
    Ok(axml.get_xml_string())
}

fn manifest_summary(xml: &str) -> Value {
    let mut root = xml_tag_attrs(xml, "manifest");
    let mut sdk = xml_tag_attrs(xml, "uses-sdk");
    let mut application = xml_tag_attrs(xml, "application");
    normalize_manifest_attrs(&mut root);
    normalize_manifest_attrs(&mut sdk);
    normalize_manifest_attrs(&mut application);
    root.remove("xmlns:android");
    let mut component_counts = serde_json::Map::new();
    for component in parse_manifest_components(xml) {
        if let Some(kind) = component["type"].as_str() {
            let count = component_counts
                .get(kind)
                .and_then(Value::as_u64)
                .unwrap_or(0);
            component_counts.insert(kind.to_owned(), json!(count + 1));
        }
    }
    json!({
        "application": application,
        "component_counts": component_counts,
        "manifest": root,
        "target_sdk": manifest_target_sdk(&sdk),
        "uses_sdk": sdk
    })
}

fn manifest_permissions(xml: &str) -> Vec<Value> {
    xml_elements(
        xml,
        &["uses-permission", "uses-permission-sdk-23", "permission"],
    )
    .into_iter()
    .map(|element| json!({"attributes": element.attributes, "kind": element.name}))
    .collect()
}

fn normalize_manifest_attrs(attrs: &mut HashMap<String, String>) {
    for value in attrs.values_mut() {
        if let Some(hex) = value.strip_prefix("@0x") {
            *value = format!("@{hex}");
        }
    }
    if let Some(value) = attrs.get_mut("android:protectionLevel") {
        if value == "0x00000002" || value == "2" {
            *value = "signature".into();
        }
    }
    if let Some(value) = attrs.get_mut("android:theme") {
        if value == "@01030011" {
            *value = "@android:style/Theme.Translucent.NoTitleBar.Fullscreen".into();
        }
    }
}

struct ManifestTag<'a> {
    name: &'a str,
    attributes: &'a str,
    start: usize,
    end: usize,
    closing: bool,
    empty: bool,
}

fn next_manifest_tag<'a>(xml: &'a str, cursor: &mut usize) -> Option<ManifestTag<'a>> {
    while let Some(relative) = xml.get(*cursor..)?.find('<') {
        let start = *cursor + relative;
        if xml[start..].starts_with("<!--") {
            *cursor = start + xml[start..].find("-->")? + 3;
            continue;
        }
        let bytes = xml.as_bytes();
        let mut end = start + 1;
        let mut quote = None;
        while end < bytes.len() {
            let byte = bytes[end];
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() && matches!(byte, b'\'' | b'"') {
                quote = Some(byte);
            } else if quote.is_none() && byte == b'>' {
                break;
            }
            end += 1;
        }
        if end == bytes.len() {
            *cursor = end;
            return None;
        }
        *cursor = end + 1;
        let inside = xml[start + 1..end].trim();
        if inside.starts_with(['?', '!']) {
            continue;
        }
        let closing = inside.starts_with('/');
        let inside = inside.trim_start_matches('/');
        let name_len = inside
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(inside.len());
        return Some(ManifestTag {
            name: &inside[..name_len],
            attributes: &inside[name_len..],
            start,
            end: end + 1,
            closing,
            empty: inside.ends_with('/'),
        });
    }
    None
}

struct ManifestElement<'a> {
    name: &'a str,
    attributes: HashMap<String, String>,
    body: &'a str,
}

fn xml_elements<'a>(xml: &'a str, wanted: &[&str]) -> Vec<ManifestElement<'a>> {
    let mut elements = Vec::new();
    let mut cursor = 0;
    while let Some(tag) = next_manifest_tag(xml, &mut cursor) {
        if tag.closing || !wanted.contains(&tag.name) {
            continue;
        }
        let body = if tag.empty {
            ""
        } else {
            let mut close_cursor = tag.end;
            let mut depth = 1;
            let mut body_end = xml.len();
            while let Some(close) = next_manifest_tag(xml, &mut close_cursor) {
                if close.name != tag.name {
                    continue;
                }
                if close.closing {
                    depth -= 1;
                    if depth == 0 {
                        body_end = close.start;
                        cursor = close.end;
                        break;
                    }
                } else if !close.empty {
                    depth += 1;
                }
            }
            &xml[tag.end..body_end]
        };
        let mut attributes = parse_attrs(tag.attributes);
        normalize_manifest_attrs(&mut attributes);
        elements.push(ManifestElement {
            name: tag.name,
            attributes,
            body,
        });
    }
    elements
}

fn xml_tag_attrs(xml: &str, wanted: &str) -> HashMap<String, String> {
    let mut cursor = 0;
    while let Some(tag) = next_manifest_tag(xml, &mut cursor) {
        if tag.name == wanted && !tag.closing {
            return parse_attrs(tag.attributes);
        }
    }
    HashMap::new()
}

fn parse_attrs(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'>'
        {
            i += 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        let key = &text[start..i];
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'=') {
            i += 1;
        }
        if i >= bytes.len() || !matches!(bytes[i], b'\'' | b'"') {
            continue;
        }
        let quote = bytes[i];
        i += 1;
        let val_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        let value = text[val_start..i]
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&");
        out.insert(key.to_owned(), value);
        i += usize::from(i < bytes.len());
    }
    out
}

fn manifest_target_sdk(sdk: &HashMap<String, String>) -> Option<u64> {
    sdk.get("android:targetSdkVersion")
        .or_else(|| sdk.get("android:minSdkVersion"))
        .map_or(Some(1), |value| value.parse().ok())
}

fn manifest_bool(value: Option<&String>, default: Option<bool>) -> Option<bool> {
    match value.map(String::as_str) {
        None => default,
        Some("true" | "1" | "0xffffffff") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) => None,
    }
}

fn manifest_class_name(name: &str, package: &str) -> String {
    if name.starts_with('.') {
        format!("{package}{name}")
    } else if !name.contains('.') && !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_owned()
    }
}

fn parse_manifest_components(xml: &str) -> Vec<Value> {
    let root = xml_tag_attrs(xml, "manifest");
    let package = root.get("package").map(String::as_str).unwrap_or_default();
    let target_sdk = manifest_target_sdk(&xml_tag_attrs(xml, "uses-sdk"));
    let applications = xml_elements(xml, &["application"]);
    let Some(application) = applications.first() else {
        return Vec::new();
    };
    let application_enabled =
        manifest_bool(application.attributes.get("android:enabled"), Some(true));
    xml_elements(
        application.body,
        &[
            "activity-alias",
            "activity",
            "service",
            "receiver",
            "provider",
        ],
    )
    .into_iter()
    .map(|element| {
        let attrs = element.attributes;
        let name = attrs
            .get("android:name")
            .or_else(|| attrs.get("name"))
            .map(|name| manifest_class_name(name, package))
            .unwrap_or_default();
        let target_activity = attrs
            .get("android:targetActivity")
            .or_else(|| attrs.get("targetActivity"))
            .map(|name| manifest_class_name(name, package));
        let intent_filters = parse_manifest_intent_filters(element.body);
        let explicit = attrs
            .get("android:exported")
            .or_else(|| attrs.get("exported"));
        let (exported, exported_reason) = if explicit.is_some() {
            (manifest_bool(explicit, None), "explicit")
        } else if element.name == "provider" {
            (
                target_sdk.map(|sdk| sdk < 17),
                "provider_target_sdk_default",
            )
        } else if !intent_filters.is_empty() && target_sdk.is_none_or(|sdk| sdk >= 31) {
            (None, "explicit_exported_required_or_target_sdk_unknown")
        } else {
            (Some(!intent_filters.is_empty()), "intent_filter_default")
        };
        let component_enabled = manifest_bool(
            attrs
                .get("android:enabled")
                .or_else(|| attrs.get("enabled")),
            Some(true),
        );
        let enabled = match (application_enabled, component_enabled) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        };
        let launcher = intent_filters.iter().any(|filter| {
            filter["actions"].as_array().is_some_and(|actions| {
                actions
                    .iter()
                    .any(|action| action == "android.intent.action.MAIN")
            }) && filter["categories"].as_array().is_some_and(|categories| {
                categories
                    .iter()
                    .any(|category| category == "android.intent.category.LAUNCHER")
            })
        });
        json!({
            "attributes": attrs,
            "type": element.name,
            "name": name,
            "exported": exported,
            "exported_reason": exported_reason,
            "target_activity": target_activity,
            "intent_filters": intent_filters,
            "metadata": parse_manifest_metadata(element.body),
            "enabled": enabled,
            "launcher_intent": launcher,
        })
    })
    .collect()
}

fn parse_manifest_intent_filters(fragment: &str) -> Vec<Value> {
    xml_elements(fragment, &["intent-filter"])
        .into_iter()
        .map(|element| {
            let names = |tag| xml_elements(element.body, &[tag]).into_iter()
                .filter_map(|element| element.attributes.get("android:name").or_else(|| element.attributes.get("name")).cloned())
                .collect::<Vec<_>>();
            let data = xml_elements(element.body, &["data"]).into_iter().map(|element| element.attributes).collect::<Vec<_>>();
            json!({"actions": names("action"), "attributes": element.attributes, "categories": names("category"), "data": data})
        })
        .collect()
}

fn parse_manifest_metadata(fragment: &str) -> Vec<Value> {
    xml_elements(fragment, &["meta-data"])
        .into_iter()
        .map(|element| json!(element.attributes))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog() {
        assert!(TABLES.contains(&"methods"));
        assert!(tool_specs().iter().any(|x| x["name"] == "open_dataset"));
    }
    #[test]
    fn tool_order_and_exact_query_schema() {
        let specs = tool_specs();
        let names = specs
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "close_dataset",
                "decode",
                "describe_table",
                "get_manifest",
                "get_manifest_components",
                "list_datasets",
                "list_resource_files",
                "list_tables",
                "open_dataset",
                "query",
                "query_resources",
                "read_resource"
            ]
        );
        let query = tool_specs()
            .into_iter()
            .find(|tool| tool["name"] == "query")
            .unwrap();
        assert_eq!(
            query["inputSchema"]["required"],
            json!(["dataset_id", "sql"])
        );
        assert_eq!(query["inputSchema"]["properties"]["sql"]["maxItems"], 16);
        assert_eq!(query["inputSchema"]["properties"]["limit"]["maximum"], 1000);
        assert!(query.get("outputSchema").is_some());
        let manifest = specs
            .iter()
            .find(|tool| tool["name"] == "get_manifest")
            .unwrap();
        assert!(manifest["inputSchema"]["properties"]
            .get("input_index")
            .is_some());
        assert!(manifest["inputSchema"]["properties"]
            .get("timeout_ms")
            .is_some());
        let resources = specs
            .iter()
            .find(|tool| tool["name"] == "query_resources")
            .unwrap();
        assert!(resources["inputSchema"]["properties"]
            .get("resource_id")
            .is_some());
        let read = specs
            .iter()
            .find(|tool| tool["name"] == "read_resource")
            .unwrap();
        assert_eq!(
            read["inputSchema"]["properties"]["format"]["$ref"],
            "#/$defs/ResourceFormat"
        );
    }
    #[test]
    fn describe_uses_complete_generated_schema() {
        let value = describe_table(&json!({"name":"methods"})).unwrap();
        assert_eq!(value["columns"].as_array().unwrap().len(), 14);
        assert_eq!(
            value["columns"][0],
            json!({"name":"file_id","data_type":"UInt32"})
        );
        assert!(describe_table(&json!({"name":"not_a_table"})).is_err());
    }
    #[test]
    fn server_info_advertises_the_active_rmcp_capabilities() {
        let info = serde_json::to_value(RmcpHandler::server_info()).unwrap();
        assert_eq!(info["serverInfo"]["name"], "dexsql");
        assert!(info["capabilities"].get("tools").is_some());
        assert!(info["capabilities"].get("resources").is_some());
        assert!(info["instructions"]
            .as_str()
            .unwrap()
            .contains("open_dataset"));
    }
    #[test]
    fn query_validation_and_page_helpers() {
        let state = Arc::new(Mutex::new(State::default()));
        let bad = query(&json!({"dataset_id":"missing","sql":[]}), &state).unwrap_err();
        assert_eq!(bad.0, -32001);
        let mut statement = json!({"rows":[1,2,3],"total_rows":3});
        apply_page(&mut statement, 1, 1).unwrap();
        assert_eq!(statement["rows"], json!([2]));
        assert_eq!(statement["next_offset"], 2);
    }
    #[test]
    fn manifest_components_use_application_scope_and_three_valued_flags() {
        let xml = r#"<manifest package="example.app">
          <uses-sdk android:targetSdkVersion="34"/>
          <queries><provider android:authorities="external"/></queries>
          <application android:enabled="false">
            <activity android:name=".Main" android:enabled="@bool/enabled">
              <intent-filter><action android:name="example.OPEN"/></intent-filter>
            </activity>
            <service android:name="Background" android:exported="false"/>
          </application>
        </manifest>"#;
        let components = parse_manifest_components(xml);
        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["name"], "example.app.Main");
        assert_eq!(components[0]["enabled"], false);
        assert!(components[0]["exported"].is_null());
        assert_eq!(components[1]["name"], "example.app.Background");
        assert_eq!(components[1]["enabled"], false);
        assert_eq!(components[1]["exported"], false);
        let unresolved = parse_manifest_components(
            r#"<manifest package="example.app"><application><service android:name=".Unknown" android:enabled="@bool/enabled"/></application></manifest>"#,
        );
        assert!(unresolved[0]["enabled"].is_null());
    }
    #[test]
    fn tool_errors_match_mcp_envelope() {
        let error = tool_error_result("unknown_dataset", "dataset is missing");
        assert_eq!(error["isError"], true);
        assert_eq!(
            error["structuredContent"]["error"]["kind"],
            "unknown_dataset"
        );
    }
    #[test]
    fn literal_query_cells_are_typed() {
        let statement =
            literal_select("SELECT 1, -1, 1.5, NULL", 0, "SELECT 1, -1, 1.5, NULL").unwrap();
        assert_eq!(
            statement["rows"][0][0],
            json!({"type":"uint64","value":"1"})
        );
        assert_eq!(
            statement["rows"][0][1],
            json!({"type":"int64","value":"-1"})
        );
        assert_eq!(statement["rows"][0][2]["type"], "float64");
        assert_eq!(statement["rows"][0][3], json!({"type":"null","value":null}));
    }
    #[test]
    fn every_resource_has_catalog_and_content() {
        for spec in resource_specs() {
            let uri = spec["uri"].as_str().unwrap();
            let page = resources_read(&json!({"uri":uri})).unwrap();
            assert!(page["contents"][0]["text"].as_str().unwrap().len() > 20);
        }
        assert!(resources_read(&json!({"uri":"dexsql://missing.md"})).is_err());
    }
}
