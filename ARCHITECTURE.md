# dexsql workspace

The workspace has three crates with one-way dependencies:

```text
dexsql-cli ──→ dexsql ──→ dexsql-core
     └─────────────────→ dexsql-core
```

- `dexsql` is the embedded library. It owns the stable `Engine`, options,
  results, errors, and metadata API. Existing callers keep the same crate name
  and imports.
- `dexsql-core` contains DEX loading and SQL execution. Its modules are shared
  implementation details for the library and CLI, rather than separate crates
  with independent release cycles.
- `dexsql-cli` builds the `dexsql` executable. It owns command parsing, MCP
  transport, MCP tools, and the documentation embedded in MCP resources. The
  embedded library does not depend on clap, Tokio, or MCP packages.

## Source layout

```text
dexsql/src/              embedded API and metadata documents
dexsql/tests/            public API integration tests
dexsql-core/src/
  archive.rs             APK/ZIP inflation
  mutf8.rs               DEX modified UTF-8 decoding
  dex/                   DEX data, caches, metadata indexes, smali decoding
  sql/
    ast/                 tokenizer, validation, session statement syntax
    schema.rs            relation schemas
    ir.rs                typed columns and plans
    lower.rs             SQL-to-plan lowering
    optimizer.rs         optimization passes
    exec.rs              execution kernels
    query/               SQL evaluation and shared query request handling
dexsql-core/tests/       SQL front-end integration tests
dexsql-core/examples/    execution and planning probes
dexsql-cli/src/
  main.rs                executable entry point
  cli.rs                 commands and arguments
  mcp/                   MCP server, resources, and response schemas
dexsql-cli/mcp-docs/     embedded MCP documentation
dexsql-cli/tests/        executable contract tests
```

Small implementation components remain modules. Add a crate only when it needs
an independent consumer, dependency boundary, or release lifecycle.

## Build and validation

```sh
cargo build --release -p dexsql-cli
cargo check --workspace --all-targets
cargo test --workspace --all-targets
cargo test --workspace --doc
cargo tree -p dexsql
```

The executable remains `target/release/dexsql`; commands, SQL semantics, and
the `dexsql` library API do not change with this organization. Default workspace
builds include the executable and embedded library. MCP remains available as
`dexsql mcp`.

## MCP implementation

The CLI owns the rmcp 3.5.1 transport, matching the version identified in the
reference executable. The obsolete handwritten JSON-RPC dispatcher and SQL
fallback executor have been removed. MCP queries use the core validator and
session executor, sharing each immutable dataset and retaining temporary
definitions between requests. Resource tools parse complete manifests before
applying output pagination.

Heavy operations run through one bounded queue. Each open dataset is owned by a
dedicated hidden `mcp --worker` child using newline JSON IPC; the parent kills
and reaps that child on timeout, cancellation, or malformed/oversized replies.
The execution semaphore permits one heavy operation at a time while accepted
queued work retains its dataset quota. EOF drains accepted requests before
workers are reaped.

Compatibility tests cover protocol negotiation, request validation, SQL
sessions, typed errors, byte offsets, smali pages, and archive resources.
Only documentation branding changes `DexSQL` to `dexsql`; reference diagnostic
strings retain their original spelling.

Optimizer diagnostics use recovered structural rules with a fallback for plans
outside the measured reference corpus. Queries without a complete ordering key
retain the reference's unspecified tie ordering; differential tests compare
those rows by their defined stable fields.
