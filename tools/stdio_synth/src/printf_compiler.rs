//! printf table compiler.
//!
//! Reads spec/printf_grammar.json and emits crates/frankenlibc-core/src/stdio/printf_tables.rs

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use stdio_synth::{PrintfGrammar, emit_printf_table_source, generate_printf_table};

#[derive(Parser, Debug)]
#[command(name = "printf-compile")]
#[command(about = "Compile printf grammar to dispatch table")]
struct Args {
    /// Path to printf_grammar.json
    #[arg(short, long, default_value = "spec/printf_grammar.json")]
    grammar: PathBuf,

    /// Output path for generated Rust source
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Print table to stdout instead of writing file
    #[arg(long)]
    stdout: bool,

    /// Only validate grammar, don't generate
    #[arg(long)]
    validate_only: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let grammar_path = resolve_tool_path(&args.grammar);

    eprintln!("[printf-compile] Loading grammar from {:?}", grammar_path);
    let grammar = PrintfGrammar::load(&grammar_path)?;

    eprintln!(
        "[printf-compile] Grammar v{}: {} conversions, {} flags, {} length modifiers",
        grammar.version,
        grammar.conversion.len(),
        grammar.flag_set.len(),
        grammar.length_modifier.len()
    );

    if args.validate_only {
        eprintln!("[printf-compile] Validation complete");
        return Ok(());
    }

    let table = generate_printf_table(&grammar);

    // Count valid entries
    let valid_count = table
        .iter()
        .filter(|r| r.handler != stdio_synth::PrintfHandler::Invalid)
        .count();
    eprintln!(
        "[printf-compile] Generated table: {} valid entries out of 256",
        valid_count
    );

    let source = emit_printf_table_source(&table);

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(&source);
    let hash = hasher.finalize();
    let hash_prefix = hex::encode(&hash[..8]);
    eprintln!("[printf-compile] Source hash prefix: {}", hash_prefix);

    if args.stdout {
        println!("{}", source);
    } else if let Some(output_path) = args.output {
        std::fs::write(&output_path, &source)?;
        eprintln!("[printf-compile] Wrote {}", output_path.display());
    } else {
        let default_output = default_core_snapshot_path("printf_tables.rs");
        std::fs::write(&default_output, &source)?;
        eprintln!("[printf-compile] Wrote {}", default_output.display());
    }

    Ok(())
}

fn resolve_tool_path(path: &Path) -> PathBuf {
    if path.exists() {
        return path.to_path_buf();
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let joined = manifest_dir.join(path);
    if joined.exists() {
        joined
    } else {
        path.to_path_buf()
    }
}

fn default_core_snapshot_path(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/frankenlibc-core/src/stdio")
        .join(file_name)
}

// Add hex encoding helper since we're not using an external crate
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
