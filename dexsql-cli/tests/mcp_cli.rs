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
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
