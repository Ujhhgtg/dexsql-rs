use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

struct Mcp {
    child: Child,
    output: BufReader<ChildStdout>,
    id: u64,
}

impl Mcp {
    fn new() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_dexsql"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut client = Self {
            child,
            output,
            id: 0,
        };
        let reply = client.call(
            "initialize",
            json!({
                "protocolVersion":"2024-11-05", "capabilities":{},
                "clientInfo":{"name":"mcp-contract-test","version":"1"}
            }),
        );
        assert_eq!(reply["result"]["serverInfo"]["name"], "dexsql");
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
        client
    }

    fn send(&mut self, value: Value) {
        let input = self.child.stdin.as_mut().unwrap();
        writeln!(input, "{value}").unwrap();
        input.flush().unwrap();
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.submit(method, params);
        self.receive(id)
    }

    fn submit(&mut self, method: &str, params: Value) -> u64 {
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        id
    }

    fn receive(&mut self, id: u64) -> Value {
        loop {
            let mut line = String::new();
            assert_ne!(
                self.output.read_line(&mut line).unwrap(),
                0,
                "MCP closed early"
            );
            let reply: Value = serde_json::from_str(&line).unwrap();
            if reply["id"] == id {
                return reply;
            }
        }
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.call("tools/call", json!({"name":name,"arguments":arguments}))["result"].clone()
    }

    fn open(&mut self) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/dex/alpha.dex");
        let result = self.tool("open_dataset", json!({"inputs":[path]}));
        assert_eq!(result["isError"], false, "{result}");
        result["structuredContent"]["dataset_id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        for _ in 0..100 {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn workers(client: &Mcp) -> Vec<u32> {
    let mut children = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{}/task", client.child.id()))
        .unwrap()
        .flatten()
    {
        let Ok(text) = std::fs::read_to_string(task.path().join("children")) else {
            continue;
        };
        children.extend(
            text.split_whitespace()
                .map(|pid| pid.parse::<u32>().unwrap()),
        );
    }
    children.sort_unstable();
    children.dedup();
    children
}

#[cfg(target_os = "linux")]
fn signal(pid: u32, name: &str) {
    assert!(Command::new("kill")
        .args([name, &pid.to_string()])
        .status()
        .unwrap()
        .success());
}

#[test]
#[cfg(target_os = "linux")]
fn mcp_queued_timeout_preserves_datasets_and_running_cancel_reaps_worker() {
    let mut client = Mcp::new();
    let first = client.open();
    let first_pid = workers(&client)[0];
    let second = client.open();
    signal(first_pid, "-STOP");
    let running = client.submit(
        "tools/call",
        json!({"name":"query","arguments":{
            "dataset_id":first,"sql":["SELECT 1"],"timeout_ms":2000
        }}),
    );
    // A metadata response confirms that the earlier request was accepted;
    // wait for the single execution permit to be occupied before queueing.
    for _ in 0..100 {
        let status = client.tool("list_datasets", json!({}));
        if status["structuredContent"]["running_requests"] == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let queued = client.tool(
        "query",
        json!({"dataset_id":second,"sql":["SELECT 2"],"timeout_ms":30}),
    );
    assert_eq!(queued["structuredContent"]["error"]["kind"], "timeout");
    assert_eq!(
        queued["structuredContent"]["error"]["dataset_closed"],
        false
    );
    let status = client.tool("list_datasets", json!({}));
    assert_eq!(status["structuredContent"]["usage"]["datasets"], 2);
    client.send(
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":running}}),
    );
    let mut remaining = 2;
    for _ in 0..100 {
        let status = client.tool("list_datasets", json!({}));
        remaining = status["structuredContent"]["usage"]["datasets"]
            .as_u64()
            .unwrap();
        if remaining == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert_eq!(remaining, 1);
    assert!(
        !std::path::Path::new(&format!("/proc/{first_pid}")).exists(),
        "worker must be reaped"
    );
    let result = client.tool("query", json!({"dataset_id":second,"sql":["SELECT 2"]}));
    assert_eq!(result["isError"], false, "{result}");
}

#[test]
#[cfg(target_os = "linux")]
fn mcp_worker_crash_closes_only_its_dataset() {
    let mut client = Mcp::new();
    let first = client.open();
    let first_pid = workers(&client)[0];
    let second = client.open();
    signal(first_pid, "-KILL");
    let failed = client.tool("query", json!({"dataset_id":first,"sql":["SELECT 1"]}));
    assert_eq!(
        failed["structuredContent"]["error"]["kind"],
        "worker_failed"
    );
    assert_eq!(failed["structuredContent"]["error"]["dataset_closed"], true);
    let result = client.tool("query", json!({"dataset_id":second,"sql":["SELECT 2"]}));
    assert_eq!(result["isError"], false, "{result}");
    let status = client.tool("list_datasets", json!({}));
    assert_eq!(status["structuredContent"]["usage"]["datasets"], 1);
}

#[test]
fn mcp_preserves_scalar_types_and_duplicate_join_columns() {
    let mut client = Mcp::new();
    let id = client.open();
    let result = client.tool("query", json!({"dataset_id":id,"sql":[
        "SELECT 'NULL','12',NULL,x'00ff',CAST(1 AS TEXT)",
        "SELECT 1 AS n UNION ALL SELECT 2",
        "SELECT * FROM methods m JOIN method_strings s ON m.file_id=s.file_id AND m.method_idx=s.method_idx LIMIT 1"
    ]}));
    assert_eq!(result["isError"], false, "{result}");
    let statements = &result["structuredContent"]["statements"];
    assert_eq!(
        statements[0]["rows"][0][0],
        json!({"type":"utf8","value":"NULL"})
    );
    assert_eq!(
        statements[0]["rows"][0][1],
        json!({"type":"utf8","value":"12"})
    );
    assert_eq!(statements[0]["rows"][0][2]["type"], "null");
    assert_eq!(
        statements[0]["rows"][0][3],
        json!({"type":"binary","value":"00ff"})
    );
    assert_eq!(
        statements[0]["rows"][0][4],
        json!({"type":"utf8","value":"1"})
    );
    assert_eq!(statements[1]["total_rows"], 2);
    assert_eq!(statements[2]["columns"].as_array().unwrap().len(), 22);
    assert_eq!(statements[2]["rows"][0].as_array().unwrap().len(), 22);
}

#[test]
fn mcp_skips_unreadable_archive_dex_members_and_renumbers_files() {
    let path = std::env::temp_dir().join(format!("dexsql-mcp-mixed-{}.apk", std::process::id()));
    let mut archive = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    archive.start_file("classes.dex", options).unwrap();
    archive.write_all(b"invalid dex").unwrap();
    archive.start_file("classes2.dex", options).unwrap();
    archive
        .write_all(
            &std::fs::read(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../fixtures/dex/alpha.dex"
            ))
            .unwrap(),
        )
        .unwrap();
    archive.finish().unwrap();
    let mut client = Mcp::new();
    let result = client.tool("open_dataset", json!({"inputs":[path]}));
    assert_eq!(result["isError"], false, "{result}");
    let id = &result["structuredContent"]["dataset_id"];
    let result = client.tool("query", json!({"dataset_id":id,"sql":["SELECT file_id,entry_name FROM dex_files ORDER BY file_id"]}));
    assert_eq!(result["isError"], false, "{result}");
    let statement = &result["structuredContent"]["statements"][0];
    assert_eq!(statement["total_rows"], 1);
    assert_eq!(statement["rows"][0][0]["value"], "0");
    assert_eq!(statement["rows"][0][1]["value"], "classes2.dex");
    client.tool("close_dataset", json!({"dataset_id":id}));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn mcp_keeps_sql_definitions_and_validation_errors() {
    let mut client = Mcp::new();
    let id = client.open();
    let result = client.tool(
        "query",
        json!({"dataset_id":id,"sql":[
            "CREATE TEMP TABLE chosen AS SELECT method_idx FROM methods WHERE method_idx<2",
            "SELECT count(*) FROM chosen"
        ]}),
    );
    assert_eq!(result["isError"], false, "{result}");
    assert_eq!(
        result["structuredContent"]["statements"][0]["kind"],
        "create_temp_table"
    );
    let result = client.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT count(*) FROM chosen"]}),
    );
    assert_eq!(
        result["structuredContent"]["statements"][0]["rows"][0][0]["value"],
        "2"
    );
    let result = client.tool("query", json!({"dataset_id":id,"sql":["SELECT"]}));
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["error"]["stage"],
        "validate_sql"
    );
    assert_eq!(
        result["structuredContent"]["error"]["message"],
        "expected an expression"
    );
}

#[test]
fn mcp_validates_arguments_and_uses_reference_schema() {
    let mut client = Mcp::new();
    let result = client.tool("describe_table", json!({"name":"classes"}));
    let columns = result["structuredContent"]["columns"].as_array().unwrap();
    assert_eq!(columns.len(), 8);
    assert_eq!(columns[7]["name"], "source_file");
    let result = client.tool("query", json!({"dataset_id":"absent","sql":[]}));
    assert_eq!(
        result["structuredContent"]["error"]["kind"],
        "unknown_dataset"
    );
    let id = client.open();
    let result = client.tool(
        "query",
        json!({"dataset_id":id,"sql":["SELECT 1"],"max_bytes":128}),
    );
    assert_eq!(
        result["structuredContent"]["error"]["kind"],
        "invalid_input"
    );
    let result = client.tool(
        "read_resource",
        json!({"dataset_id":id,"name":"x","format":"text"}),
    );
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("expected `auto` or `hex`"));
}

#[test]
fn mcp_decodes_smali_without_cli_headers() {
    let mut client = Mcp::new();
    let id = client.open();
    let result = client.tool(
        "decode",
        json!({"dataset_id":id,"method_idx":0,"file_id":0}),
    );
    assert_eq!(result["isError"], false, "{result}");
    let body = &result["structuredContent"];
    assert!(body.get("next_method_offset").is_some());
    let page = &body["methods"][0];
    assert!(page["smali"].as_str().unwrap().starts_with(".method "));
    assert!(page.get("total_lines").is_some());
    assert!(page.get("declaration").is_some());
}
