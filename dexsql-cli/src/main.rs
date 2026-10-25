//! Command-line entry point for dexsql, including its MCP stdio server.

mod cli;
mod mcp;

fn main() {
    if let Err(error) = cli::run(std::env::args_os().skip(1)) {
        if !error.to_string().is_empty() {
            eprintln!("Error: {error}");
        }
        std::process::exit(error.exit_code());
    }
}
