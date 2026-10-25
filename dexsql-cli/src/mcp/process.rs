//! Session ownership and the reference's single heavy-operation queue.
//!
//! A worker owns one prepared dataset. The parent retains only metadata and
//! process handles, so cancellation can kill and reap computation immediately.
use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
struct Worker {
    terminated: AtomicBool,
    child: Mutex<Child>,
    pipe: Mutex<(ChildStdin, BufReader<ChildStdout>)>,
}

impl Worker {
    fn spawn(threads: Option<usize>) -> io::Result<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        if let Some(threads) = threads {
            command.args(["--threads", &threads.to_string()]);
        }
        let mut child = command
            .args(["mcp", "--worker"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().expect("piped worker stdin");
        let output = BufReader::new(child.stdout.take().expect("piped worker stdout"));
        Ok(Self {
            terminated: AtomicBool::new(false),
            child: Mutex::new(child),
            pipe: Mutex::new((input, output)),
        })
    }

    fn call(&self, operation: &str, arguments: &Value, max_output: usize) -> io::Result<Value> {
        let mut pipe = self.pipe.lock().expect("worker pipe");
        writeln!(
            pipe.0,
            "{}",
            json!({"operation":operation,"arguments":arguments})
        )?;
        pipe.0.flush()?;
        let mut line = Vec::new();
        let read = pipe
            .1
            .by_ref()
            .take(max_output as u64 + 2)
            .read_until(b'\n', &mut line)?;
        if read == 0 || read > max_output + 1 || line.last() != Some(&b'\n') {
            return Err(io::Error::other(
                "dataset worker exited or returned an oversized/incomplete reply",
            ));
        }
        let mut reply: Value = serde_json::from_slice(&line)
            .map_err(|_| io::Error::other("invalid dataset worker reply"))?;
        reply
            .as_object_mut()
            .ok_or_else(|| io::Error::other("invalid dataset worker reply"))?
            .remove("resultType");
        Ok(reply)
    }

    fn terminate(&self) {
        self.terminated.store(true, Ordering::Relaxed);
        let mut child = self.child.lock().expect("worker process");
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[derive(Debug, Default)]
struct Usage {
    datasets: usize,
    bytes: u64,
}

#[derive(Debug)]
struct Reservation {
    usage: Arc<Mutex<Usage>>,
    bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self.usage.lock().expect("dataset quota");
        usage.datasets -= 1;
        usage.bytes -= self.bytes;
    }
}

#[derive(Debug)]
struct Slot {
    worker: Arc<Worker>,
    metadata: Value,
    _reservation: Reservation,
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    datasets: HashMap<String, Arc<Slot>>,
}

pub(super) struct Server {
    config: Config,
    threads: Option<usize>,
    registry: Mutex<Registry>,
    usage: Arc<Mutex<Usage>>,
    admission: Arc<Semaphore>,
    running: Arc<Semaphore>,
}

impl Server {
    pub fn new(config: Config, threads: Option<usize>) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(config.max_pending)),
            running: Arc::new(Semaphore::new(1)),
            config,
            threads,
            registry: Mutex::new(Registry::default()),
            usage: Arc::new(Mutex::new(Usage::default())),
        }
    }

    fn dataset(&self, arguments: &Value) -> Result<Arc<Slot>, Value> {
        let id = arguments["dataset_id"].as_str().expect("typed dataset id");
        self.registry
            .lock()
            .expect("dataset registry")
            .datasets
            .get(id)
            .cloned()
            .ok_or_else(|| {
                tool_error_result(
                    "unknown_dataset",
                    &format!("dataset \"{id}\" is not open; call open_dataset first"),
                )
            })
    }

    fn reserve(&self, arguments: &Value) -> Result<(Reservation, Vec<String>), Value> {
        let inputs = arguments["inputs"].as_array().expect("typed inputs");
        if inputs.is_empty() || inputs.len() > 64 {
            return Err(tool_error_result(
                "invalid_input",
                "inputs must contain 1..=64 paths",
            ));
        }
        let mut paths = Vec::new();
        let mut bytes = 0u64;
        for input in inputs {
            let path = input.as_str().expect("typed input path");
            if path.is_empty() || path.len() > 4096 {
                return Err(tool_error_result(
                    "invalid_input",
                    "input path is empty or too long",
                ));
            }
            let metadata = std::fs::metadata(path)
                .map_err(|error| tool_error_result("invalid_input", &error.to_string()))?;
            if !metadata.is_file() {
                return Err(tool_error_result(
                    "invalid_input",
                    "input must be a regular file",
                ));
            }
            bytes = bytes.saturating_add(metadata.len());
            paths.push(path.to_owned());
        }
        if bytes > self.config.max_input_bytes {
            return Err(tool_error_result(
                "invalid_input",
                "dataset exceeds --max-input-bytes",
            ));
        }
        let mut usage = self.usage.lock().expect("dataset quota");
        if usage.datasets >= self.config.max_datasets
            || usage.bytes.saturating_add(bytes) > self.config.max_total_input_bytes
        {
            return Err(tool_error_result(
                "session_quota_exceeded",
                "dataset/input-byte quota exhausted; close unused datasets before opening another",
            ));
        }
        usage.datasets += 1;
        usage.bytes += bytes;
        Ok((
            Reservation {
                usage: self.usage.clone(),
                bytes,
            },
            paths,
        ))
    }

    fn list(&self) -> Value {
        let registry = self.registry.lock().expect("dataset registry");
        let mut datasets = registry
            .datasets
            .values()
            .map(|slot| slot.metadata.clone())
            .collect::<Vec<_>>();
        datasets.sort_by(|a, b| a["dataset_id"].as_str().cmp(&b["dataset_id"].as_str()));
        let usage = self.usage.lock().expect("dataset quota");
        envelope(json!({"datasets":datasets,"limits":self.config,
            "admitted_requests":self.config.max_pending - self.admission.available_permits(),
            "running_requests":1-self.running.available_permits(),
            "usage":{"datasets":usage.datasets,"input_bytes":usage.bytes}}))
    }

    pub async fn run(
        &self,
        name: &str,
        arguments: Value,
        context: &rmcp::service::RequestContext<RoleServer>,
        started: Instant,
    ) -> Result<Value, McpError> {
        if name == "list_datasets" {
            return Ok(self.list());
        }
        if name == "close_dataset" {
            let id = arguments["dataset_id"].as_str().expect("typed dataset id");
            let slot = self
                .registry
                .lock()
                .expect("dataset registry")
                .datasets
                .remove(id);
            return Ok(if slot.is_some() {
                envelope(json!({"dataset_id":id,"closed":true}))
            } else {
                tool_error_result(
                    "unknown_dataset",
                    &format!("dataset \"{id}\" is not open; call open_dataset first"),
                )
            });
        }
        if matches!(name, "describe_table" | "list_tables") {
            return super::call_tool(
                &json!({"name":name,"arguments":arguments}),
                &Arc::new(Mutex::new(State::default())),
                &self.config,
            )
            .map_err(|(_, message)| McpError::internal_error(message, None));
        }
        let slot = if name == "open_dataset" {
            None
        } else {
            match self.dataset(&arguments) {
                Ok(slot) => Some(slot),
                Err(error) => return Ok(error),
            }
        };
        let timeout_ms = arguments
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(self.config.timeout_ms);
        if timeout_ms == 0 || timeout_ms > self.config.timeout_ms {
            return Ok(tool_error_result(
                "invalid_input",
                &format!("timeout_ms must be in 1..={}", self.config.timeout_ms),
            ));
        }
        if let Some(max) = arguments.get("max_bytes").and_then(Value::as_u64) {
            if !(4096..=self.config.max_output_bytes).contains(&max) {
                return Ok(tool_error_result(
                    "invalid_input",
                    &format!(
                        "max_bytes must be in 4096..={}",
                        self.config.max_output_bytes
                    ),
                ));
            }
        }
        let _admitted = match self.admission.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Ok(tool_error_result(
                    "server_busy",
                    "request queue is full; retry after an active request completes",
                ))
            }
        };
        let deadline = tokio::time::Instant::from_std(started + Duration::from_millis(timeout_ms));
        let progress = context.meta.get_progress_token();
        if name == "open_dataset" && self.running.available_permits() > 0 {
            notify_phase(context, progress.clone(), "preparing dataset", started).await;
        }
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now()
                + if name == "open_dataset" && self.running.available_permits() > 0 {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(1)
                },
            Duration::from_secs(2),
        );
        let mut was_queued = false;
        let acquire = self.running.clone().acquire_owned();
        tokio::pin!(acquire);
        let running: OwnedSemaphorePermit = loop {
            tokio::select! {
                _ = context.ct.cancelled() => return Err(McpError::internal_error("task cancelled for reason",None)),
                _ = tokio::time::sleep_until(deadline) => return Ok(timeout_result(None)),
                permit = &mut acquire => break permit.expect("operation queue open"),
                _ = ticks.tick(), if progress.is_some() => {
                    was_queued = true;
                    notify_phase(context, progress.clone(), "queued", started).await;
                }
            }
        };
        if was_queued {
            notify_phase(
                context,
                progress.clone(),
                if name == "open_dataset" {
                    "preparing dataset"
                } else {
                    "running"
                },
                started,
            )
            .await;
        }
        if slot
            .as_ref()
            .is_some_and(|slot| slot.worker.terminated.load(Ordering::Relaxed))
        {
            return Ok(tool_error_result(
                "dataset_closed",
                "an earlier operation terminated this dataset; call open_dataset again",
            ));
        }
        let opening = if name == "open_dataset" {
            match self.reserve(&arguments) {
                Ok(value) => Some(value),
                Err(error) => return Ok(error),
            }
        } else {
            None
        };
        let worker = match &slot {
            Some(slot) => slot.worker.clone(),
            None => match Worker::spawn(self.threads) {
                Ok(worker) => Arc::new(worker),
                Err(error) => return Ok(tool_error_result("worker_error", &error.to_string())),
            },
        };
        let operation = operation_name(name).expect("heavy tool operation");
        let worker_arguments = if let Some((reservation, paths)) = &opening {
            json!({"inputs":paths,"input_bytes":reservation.bytes,"options":self.config})
        } else {
            arguments.clone()
        };
        let remote = worker.clone();
        let max_output = self.config.max_output_bytes as usize;
        let mut task = tokio::task::spawn_blocking(move || {
            remote.call(operation, &worker_arguments, max_output)
        });
        let reply = loop {
            tokio::select! {
                _ = context.ct.cancelled() => {
                    worker.terminate();
                    let _ = task.await;
                    if let Some(slot) = &slot { self.remove_slot(&arguments, slot); }
                    return Err(McpError::internal_error("task cancelled for reason",None));
                }
                _ = tokio::time::sleep_until(deadline) => {
                    worker.terminate();
                    let _ = task.await;
                    if let Some(slot) = &slot { self.remove_slot(&arguments, slot); }
                    return Ok(timeout_result(slot.as_ref().and_then(|_| arguments["dataset_id"].as_str())));
                }
                reply = &mut task => break reply,
                _ = ticks.tick(), if progress.is_some() => {
                    notify_phase(context, progress.clone(), if name == "open_dataset" { "preparing dataset" } else { "running" }, started).await;
                }
            }
        };
        let mut reply = match reply {
            Ok(Ok(reply)) => reply,
            error => {
                worker.terminate();
                if let Some(slot) = &slot {
                    self.remove_slot(&arguments, slot);
                }
                let message = match error {
                    Ok(Err(error)) => error.to_string(),
                    _ => {
                        "dataset worker exited or returned an oversized/incomplete reply".to_owned()
                    }
                };
                return Ok(envelope(
                    json!({"dataset_id":arguments.get("dataset_id").cloned().unwrap_or(Value::Null),
                    "error":{"dataset_closed":slot.is_some(),"kind":"worker_failed","message":message}}),
                ));
            }
        };
        if let Some((reservation, paths)) = opening {
            if reply["isError"] != true {
                let mut registry = self.registry.lock().expect("dataset registry");
                registry.next_id += 1;
                let id = format!("dataset-{}", registry.next_id);
                let mut metadata = reply["structuredContent"].clone();
                metadata["dataset_id"] = json!(id);
                metadata["inputs"] = json!(paths);
                metadata["input_bytes"] = json!(reservation.bytes);
                metadata["prepare_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
                registry.datasets.insert(
                    id,
                    Arc::new(Slot {
                        worker,
                        metadata: metadata.clone(),
                        _reservation: reservation,
                    }),
                );
                reply = envelope(metadata);
            }
        }
        drop(running);
        if name != "open_dataset" {
            if let Some(token) = progress {
                let _ = context
                    .peer
                    .notify_progress(
                        ProgressNotificationParam::new(token, started.elapsed().as_secs_f64())
                            .with_message("completed"),
                    )
                    .await;
            }
        }
        Ok(reply)
    }

    fn remove_slot(&self, arguments: &Value, slot: &Arc<Slot>) {
        let id = arguments["dataset_id"].as_str().expect("typed dataset id");
        let mut registry = self.registry.lock().expect("dataset registry");
        if registry
            .datasets
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, slot))
        {
            registry.datasets.remove(id);
        }
    }
}

async fn notify_phase(
    context: &rmcp::service::RequestContext<RoleServer>,
    token: Option<rmcp::model::ProgressToken>,
    phase: &str,
    started: Instant,
) {
    if let Some(token) = token {
        let elapsed = started.elapsed().as_secs_f64();
        let _ = context
            .peer
            .notify_progress(
                ProgressNotificationParam::new(token, elapsed).with_message(format!(
                    "{phase}; elapsed {elapsed:.1}s (elapsed time, not completion percentage)"
                )),
            )
            .await;
    }
}

fn timeout_result(id: Option<&str>) -> Value {
    let message = if id.is_some() {
        "running computation was terminated and this dataset was closed; call open_dataset to use it again"
    } else {
        "request ended before a dataset operation completed; existing datasets remain open"
    };
    envelope(
        json!({"dataset_id":id,"error":{"dataset_closed":id.is_some(),"kind":"timeout","message":message}}),
    )
}

fn envelope(value: Value) -> Value {
    json!({"content":[{"type":"text","text":value.to_string()}],"isError":value.get("error").is_some(),"structuredContent":value})
}

fn operation_name(tool: &str) -> Option<&'static str> {
    Some(match tool {
        "open_dataset" => "open",
        "query" => "query",
        "decode" => "decode",
        "get_manifest" => "manifest",
        "get_manifest_components" => "manifest_components",
        "list_resource_files" => "resource_files",
        "read_resource" => "read_resource",
        "query_resources" => "resource_values",
        _ => return None,
    })
}

pub(super) fn serve_worker() -> io::Result<()> {
    let state = Arc::new(Mutex::new(State::default()));
    let mut config = Config::default();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    loop {
        let mut bytes = Vec::new();
        let read = reader
            .by_ref()
            .take(256 * 1024 + 1)
            .read_until(b'\n', &mut bytes)?;
        if read == 0 {
            return Ok(());
        }
        if read > 256 * 1024 {
            return Err(io::Error::other("worker request exceeds input budget"));
        }
        let request: Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        let operation = request["operation"]
            .as_str()
            .ok_or_else(|| io::Error::other("invalid worker operation"))?;
        let name = match operation {
            "open" => "open_dataset",
            "query" => "query",
            "decode" => "decode",
            "manifest" => "get_manifest",
            "manifest_components" => "get_manifest_components",
            "resource_files" => "list_resource_files",
            "read_resource" => "read_resource",
            "resource_values" => "query_resources",
            _ => return Err(io::Error::other("invalid worker operation")),
        };
        let raw = request["arguments"]
            .as_object()
            .ok_or_else(|| io::Error::other("invalid worker arguments"))?;
        let arguments = if operation == "open" {
            config = serde_json::from_value(request["arguments"]["options"].clone())
                .map_err(io::Error::other)?;
            let _: Vec<String> = serde_json::from_value(request["arguments"]["inputs"].clone())
                .map_err(io::Error::other)?;
            let _: u64 = serde_json::from_value(request["arguments"]["input_bytes"].clone())
                .map_err(io::Error::other)?;
            Value::Object(raw.clone())
        } else {
            params::normalize(name, raw).map_err(io::Error::other)?
        };
        let range_error = params::range_error(name, &arguments, config.max_output_bytes);
        let input_validation = if operation == "open" {
            let paths = arguments["inputs"]
                .as_array()
                .expect("typed worker inputs")
                .iter()
                .map(|path| PathBuf::from(path.as_str().expect("typed worker input")))
                .collect::<Vec<_>>();
            input::validate(&paths, &config)
        } else {
            None
        };
        let opened = !state.lock().expect("worker dataset").datasets.is_empty();
        let mut reply = if opened && operation == "open" {
            tool_error_result("worker_already_open", "worker already owns a dataset")
        } else if !opened && operation != "open" {
            tool_error_result("worker_not_open", "open must be the first worker operation")
        } else if let Some(value) = input_validation {
            value
        } else if operation == "open"
            && arguments["inputs"]
                .as_array()
                .expect("typed worker inputs")
                .iter()
                .any(|path| std::fs::metadata(path.as_str().expect("typed worker input")).is_err())
        {
            tool_error_result(
                "input_error",
                &format!(
                    "input_error: {}",
                    arguments["inputs"]
                        .as_array()
                        .expect("typed worker inputs")
                        .iter()
                        .find_map(|path| std::fs::metadata(
                            path.as_str().expect("typed worker input")
                        )
                        .err())
                        .expect("missing input error")
                ),
            )
        } else if operation == "open"
            && arguments["inputs"]
                .as_array()
                .expect("validated worker inputs")
                .iter()
                .filter_map(|path| {
                    std::fs::metadata(path.as_str().expect("validated worker path")).ok()
                })
                .map(|metadata| metadata.len())
                .sum::<u64>()
                != arguments["input_bytes"]
                    .as_u64()
                    .expect("validated input bytes")
        {
            tool_error_result(
                "source_changed",
                "source size changed while opening; retry open_dataset",
            )
        } else if let Some(message) = range_error {
            tool_error_result("invalid_input", &message)
        } else {
            if operation != "open" {
                let mut state = state.lock().expect("worker dataset");
                let prior = state
                    .datasets
                    .keys()
                    .next()
                    .expect("opened dataset")
                    .clone();
                let entry = state.datasets.remove(&prior).expect("opened dataset");
                state.datasets.insert(
                    arguments["dataset_id"]
                        .as_str()
                        .expect("typed dataset id")
                        .to_owned(),
                    entry,
                );
            }
            super::call_tool(&json!({"name":name,"arguments":arguments}), &state, &config)
                .map_err(|(_, message)| io::Error::other(message))?
        };
        if operation == "open" && reply["isError"] != true {
            let mut value = reply["structuredContent"].clone();
            for key in ["dataset_id", "inputs", "input_bytes"] {
                value.as_object_mut().expect("open metadata").remove(key);
            }
            reply = envelope(value);
        }
        if arguments["compact"].as_bool() == Some(true) {
            reply = compact_tool_result(reply);
        }
        reply["resultType"] = json!("complete");
        writeln!(writer, "{reply}")?;
        writer.flush()?;
    }
}
