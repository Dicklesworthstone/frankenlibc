//! Symmetry artifact generator for generated stdio tables.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use stdio_synth::{
    PrintfGrammar, ScanfGrammar, emit_symmetry_artifact, generate_printf_table,
    generate_scanf_table,
};

#[derive(Parser, Debug)]
#[command(name = "symmetry-emit")]
#[command(about = "Emit deterministic stdio route symmetry classes derived from generated tables")]
struct Args {
    /// Path to printf_grammar.json
    #[arg(long, default_value = "spec/printf_grammar.json")]
    printf_grammar: PathBuf,

    /// Path to scanf_grammar.json
    #[arg(long, default_value = "spec/scanf_grammar.json")]
    scanf_grammar: PathBuf,

    /// Output path for generated symmetry artifact
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Print the generated artifact to stdout
    #[arg(long)]
    stdout: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let printf_grammar_path = resolve_tool_path(&args.printf_grammar);
    let scanf_grammar_path = resolve_tool_path(&args.scanf_grammar);

    eprintln!(
        "[symmetry-emit] Loading printf grammar from {:?}",
        printf_grammar_path
    );
    let printf_grammar = PrintfGrammar::load(&printf_grammar_path)?;
    eprintln!(
        "[symmetry-emit] Loading scanf grammar from {:?}",
        scanf_grammar_path
    );
    let scanf_grammar = ScanfGrammar::load(&scanf_grammar_path)?;

    let printf_table = generate_printf_table(&printf_grammar);
    let scanf_table = generate_scanf_table(&scanf_grammar);
    let artifact =
        emit_symmetry_artifact(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);

    let mut hasher = Sha256::new();
    hasher.update(&artifact);
    let hash = hasher.finalize();
    let hash_prefix = hex::encode(&hash[..8]);
    eprintln!(
        "[symmetry-emit] Symmetry artifact hash prefix: {}",
        hash_prefix
    );

    if args.stdout {
        println!("{}", artifact);
    } else if let Some(output_path) = args.output {
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&output_path, &artifact)?;
        eprintln!("[symmetry-emit] Wrote {}", output_path.display());
    } else {
        let default_output = PathBuf::from("synth/symmetry.json");
        if let Some(parent) = default_output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&default_output, &artifact)?;
        eprintln!("[symmetry-emit] Wrote {}", default_output.display());
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

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
