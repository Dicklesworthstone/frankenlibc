//! One-shot artifact generator for the full stdio synthesis pipeline.

use clap::Parser;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use stdio_synth::{
    PrintfGrammar, ScanfGrammar, build_pipeline_artifacts, emit_pipeline_manifest,
    generate_printf_table, generate_scanf_table,
};

#[derive(Parser, Debug)]
#[command(name = "pipeline-emit")]
#[command(about = "Emit the full deterministic stdio synthesis artifact set and manifest")]
struct Args {
    /// Path to printf_grammar.json
    #[arg(long, default_value = "spec/printf_grammar.json")]
    printf_grammar: PathBuf,

    /// Path to scanf_grammar.json
    #[arg(long, default_value = "spec/scanf_grammar.json")]
    scanf_grammar: PathBuf,

    /// Root directory for generated artifacts
    #[arg(long, default_value = ".")]
    output_root: PathBuf,

    /// Verify that the checked-in frankenlibc-core stdio snapshots match the generated tables
    #[arg(long)]
    check_core_snapshots: bool,

    /// Print the generated manifest to stdout
    #[arg(long)]
    manifest_stdout: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let printf_grammar_path = resolve_tool_path(&args.printf_grammar);
    let scanf_grammar_path = resolve_tool_path(&args.scanf_grammar);

    eprintln!(
        "[pipeline-emit] Loading printf grammar from {:?}",
        printf_grammar_path
    );
    let printf_grammar = PrintfGrammar::load(&printf_grammar_path)?;
    eprintln!(
        "[pipeline-emit] Loading scanf grammar from {:?}",
        scanf_grammar_path
    );
    let scanf_grammar = ScanfGrammar::load(&scanf_grammar_path)?;

    let printf_table = generate_printf_table(&printf_grammar);
    let scanf_table = generate_scanf_table(&scanf_grammar);
    let artifacts =
        build_pipeline_artifacts(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);
    let manifest =
        emit_pipeline_manifest(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);

    if args.check_core_snapshots {
        verify_core_snapshot(
            "printf",
            &core_snapshot_path("printf_tables.rs"),
            artifacts
                .get("synth/printf_table.rs")
                .expect("pipeline artifacts include printf table"),
        )?;
        verify_core_snapshot(
            "scanf",
            &core_snapshot_path("scanf_tables.rs"),
            artifacts
                .get("synth/scanf_table.rs")
                .expect("pipeline artifacts include scanf table"),
        )?;
    }

    for (relative_path, contents) in &artifacts {
        let output_path = args.output_root.join(relative_path);
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&output_path, contents)?;
        eprintln!("[pipeline-emit] Wrote {}", output_path.display());
    }

    let manifest_path = args.output_root.join("synth/manifest.json");
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&manifest_path, &manifest)?;

    let mut hasher = Sha256::new();
    hasher.update(manifest.as_bytes());
    let hash = hasher.finalize();
    let hash_prefix = hex::encode(&hash[..8]);
    eprintln!("[pipeline-emit] Manifest hash prefix: {}", hash_prefix);
    eprintln!("[pipeline-emit] Wrote {}", manifest_path.display());

    if args.manifest_stdout {
        println!("{}", manifest);
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

fn core_snapshot_path(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/frankenlibc-core/src/stdio")
        .join(file_name)
}

fn verify_core_snapshot(
    label: &str,
    snapshot_path: &Path,
    expected_contents: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let current = std::fs::read_to_string(snapshot_path)?;
    if current != expected_contents {
        return Err(format!(
            "[pipeline-emit] {label} core snapshot drift detected at {}",
            snapshot_path.display()
        )
        .into());
    }

    eprintln!("[pipeline-emit] Verified {}", snapshot_path.display());
    Ok(())
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
