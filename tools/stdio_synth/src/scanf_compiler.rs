//! scanf grammar validator / compiler entrypoint.
//!
//! Reads spec/scanf_grammar.json and emits crates/frankenlibc-core/src/stdio/scanf_tables.rs.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use stdio_synth::{ScanfGrammar, emit_scanf_table_source, generate_scanf_table};

#[derive(Parser, Debug)]
#[command(name = "scanf-compile")]
#[command(about = "Validate scanf grammar and prepare for table generation")]
struct Args {
    /// Path to scanf_grammar.json
    #[arg(short, long, default_value = "spec/scanf_grammar.json")]
    grammar: PathBuf,

    /// Output path for generated Rust source
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Print table to stdout instead of writing file
    #[arg(long)]
    stdout: bool,

    /// Only validate grammar, don't emit an output artifact
    #[arg(long)]
    validate_only: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    eprintln!("[scanf-compile] Loading grammar from {:?}", args.grammar);
    let grammar = ScanfGrammar::load(&args.grammar)?;

    eprintln!(
        "[scanf-compile] Grammar v{}: {} conversions, {} length modifiers, assignment suppression {}",
        grammar.version,
        grammar.conversion.len(),
        grammar.length_modifier.len(),
        if grammar.assignment_suppression {
            "enabled"
        } else {
            "disabled"
        }
    );

    let mut conversions = grammar.conversion.keys().cloned().collect::<Vec<_>>();
    conversions.sort();
    eprintln!(
        "[scanf-compile] Supported conversions: {}",
        conversions.join(" ")
    );

    if let Some(ref scanset) = grammar.scanset {
        eprintln!(
            "[scanf-compile] Scanset support: negation={}, ranges={}, leading ]={}",
            scanset.supports_negation,
            scanset.supports_ranges,
            scanset.first_char_may_be_closing_bracket
        );
    }

    if args.validate_only {
        eprintln!("[scanf-compile] Validation complete");
        return Ok(());
    }

    let table = generate_scanf_table(&grammar);
    let valid_count = table
        .iter()
        .filter(|route| route.handler != stdio_synth::ScanfHandler::Invalid)
        .count();
    eprintln!(
        "[scanf-compile] Generated table: {} valid entries out of 256",
        valid_count
    );

    let source = emit_scanf_table_source(&table);
    let mut hasher = Sha256::new();
    hasher.update(&source);
    let hash = hasher.finalize();
    let hash_prefix = hex::encode(&hash[..8]);
    eprintln!("[scanf-compile] Source hash prefix: {}", hash_prefix);

    if args.stdout {
        println!("{}", source);
    } else if let Some(output_path) = args.output {
        std::fs::write(&output_path, &source)?;
        eprintln!("[scanf-compile] Wrote {}", output_path.display());
    } else {
        let default_output =
            PathBuf::from("../../crates/frankenlibc-core/src/stdio/scanf_tables.rs");
        std::fs::write(&default_output, &source)?;
        eprintln!("[scanf-compile] Wrote {}", default_output.display());
    }

    Ok(())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
