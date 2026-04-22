//! SMT proof artifact generator for generated stdio tables.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::path::PathBuf;
use stdio_synth::{
    PrintfGrammar, ScanfGrammar, emit_smt_proof_source, generate_printf_table, generate_scanf_table,
};

#[derive(Parser, Debug)]
#[command(name = "smt-prove")]
#[command(about = "Generate SMT-LIB obligations for printf/scanf dispatch tables")]
struct Args {
    /// Path to printf_grammar.json
    #[arg(long, default_value = "spec/printf_grammar.json")]
    printf_grammar: PathBuf,

    /// Path to scanf_grammar.json
    #[arg(long, default_value = "spec/scanf_grammar.json")]
    scanf_grammar: PathBuf,

    /// Output path for generated SMT-LIB
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Print the generated SMT-LIB to stdout
    #[arg(long)]
    stdout: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let printf_grammar_path = resolve_tool_path(&args.printf_grammar);
    let scanf_grammar_path = resolve_tool_path(&args.scanf_grammar);

    eprintln!(
        "[smt-prove] Loading printf grammar from {:?}",
        printf_grammar_path
    );
    let printf_grammar = PrintfGrammar::load(&printf_grammar_path)?;
    eprintln!(
        "[smt-prove] Loading scanf grammar from {:?}",
        scanf_grammar_path
    );
    let scanf_grammar = ScanfGrammar::load(&scanf_grammar_path)?;

    let printf_table = generate_printf_table(&printf_grammar);
    let scanf_table = generate_scanf_table(&scanf_grammar);
    let source =
        emit_smt_proof_source(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);

    let mut hasher = Sha256::new();
    hasher.update(&source);
    let hash = hasher.finalize();
    let hash_prefix = hex::encode(&hash[..8]);
    eprintln!("[smt-prove] Proof artifact hash prefix: {}", hash_prefix);
    eprintln!(
        "[smt-prove] Covered routes: printf={}, scanf={}",
        printf_grammar.conversion.len(),
        scanf_grammar.conversion.len()
    );

    if args.stdout {
        println!("{}", source);
    } else if let Some(output_path) = args.output {
        std::fs::write(&output_path, &source)?;
        eprintln!("[smt-prove] Wrote {}", output_path.display());
    } else {
        let default_output = PathBuf::from("proof/stdio_tables.smt2");
        if let Some(parent) = default_output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&default_output, &source)?;
        eprintln!("[smt-prove] Wrote {}", default_output.display());
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
