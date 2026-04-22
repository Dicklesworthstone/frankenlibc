use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use stdio_synth::{
    PrintfGrammar, ScanfGrammar, build_pipeline_artifacts, build_pipeline_manifest,
    generate_printf_table, generate_scanf_table,
};

const PRINTF_GRAMMAR_PATH: &str = "../../tools/stdio_synth/spec/printf_grammar.json";
const SCANF_GRAMMAR_PATH: &str = "../../tools/stdio_synth/spec/scanf_grammar.json";
const PRINTF_SNAPSHOT_PATH: &str = "src/stdio/printf_tables.rs";
const SCANF_SNAPSHOT_PATH: &str = "src/stdio/scanf_tables.rs";
const BOUNDS_AUDIT_FIXTURE_PATH: &str = "src/malloc/bounds_audit_fixture.json";

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be available for frankenlibc-core build script"),
    );
    let out_dir = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR must be available for frankenlibc-core build script"),
    )
    .join("stdio_synth");

    let printf_grammar_path = manifest_dir.join(PRINTF_GRAMMAR_PATH);
    let scanf_grammar_path = manifest_dir.join(SCANF_GRAMMAR_PATH);
    let printf_snapshot_path = manifest_dir.join(PRINTF_SNAPSHOT_PATH);
    let scanf_snapshot_path = manifest_dir.join(SCANF_SNAPSHOT_PATH);
    let bounds_audit_fixture_path = manifest_dir.join(BOUNDS_AUDIT_FIXTURE_PATH);

    emit_rerun_if_changed(&printf_grammar_path);
    emit_rerun_if_changed(&scanf_grammar_path);
    emit_rerun_if_changed(&printf_snapshot_path);
    emit_rerun_if_changed(&scanf_snapshot_path);
    emit_rerun_if_changed(&bounds_audit_fixture_path);
    println!(
        "cargo:rustc-env=FRANKENLIBC_CORE_BOUNDS_AUDIT_PATH={}",
        bounds_audit_fixture_path.display()
    );

    let printf_grammar = PrintfGrammar::load(&printf_grammar_path).unwrap_or_else(|err| {
        panic!(
            "failed to load stdio synth printf grammar {}: {err}",
            printf_grammar_path.display()
        )
    });
    let scanf_grammar = ScanfGrammar::load(&scanf_grammar_path).unwrap_or_else(|err| {
        panic!(
            "failed to load stdio synth scanf grammar {}: {err}",
            scanf_grammar_path.display()
        )
    });

    let printf_table = generate_printf_table(&printf_grammar);
    let scanf_table = generate_scanf_table(&scanf_grammar);
    let artifacts =
        build_pipeline_artifacts(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table);

    verify_snapshot(
        &printf_snapshot_path,
        artifacts
            .get("synth/printf_table.rs")
            .expect("printf table artifact missing from pipeline"),
        "printf",
    );
    verify_snapshot(
        &scanf_snapshot_path,
        artifacts
            .get("synth/scanf_table.rs")
            .expect("scanf table artifact missing from pipeline"),
        "scanf",
    );

    write_artifacts(&out_dir, &artifacts);
    write_manifest(
        &out_dir.join("synth/manifest.json"),
        &build_pipeline_manifest(&printf_grammar, &scanf_grammar, &printf_table, &scanf_table),
    );
}

fn emit_rerun_if_changed(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn verify_snapshot(snapshot_path: &Path, expected_contents: &str, label: &str) {
    let actual_contents = fs::read_to_string(snapshot_path).unwrap_or_else(|err| {
        panic!(
            "failed to read checked-in {label} stdio snapshot {}: {err}",
            snapshot_path.display()
        )
    });

    if actual_contents != expected_contents {
        panic!(
            "{label} stdio snapshot drift detected at {}. Regenerate it via tools/stdio_synth.",
            snapshot_path.display()
        );
    }
}

fn write_artifacts(out_dir: &Path, artifacts: &std::collections::BTreeMap<String, String>) {
    for (relative_path, contents) in artifacts {
        let artifact_path = out_dir.join(relative_path);
        if let Some(parent) = artifact_path.parent() {
            fs::create_dir_all(parent).unwrap_or_else(|err| {
                panic!(
                    "failed to create stdio synth artifact directory {}: {err}",
                    parent.display()
                )
            });
        }
        fs::write(&artifact_path, contents).unwrap_or_else(|err| {
            panic!(
                "failed to write stdio synth artifact {}: {err}",
                artifact_path.display()
            )
        });
    }
}

fn write_manifest(manifest_path: &Path, manifest: &stdio_synth::PipelineManifest) {
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            panic!(
                "failed to create stdio synth manifest directory {}: {err}",
                parent.display()
            )
        });
    }

    let mut manifest_json =
        serde_json::to_string_pretty(manifest).expect("stdio synth manifest must serialize");
    manifest_json.push('\n');
    fs::write(manifest_path, manifest_json).unwrap_or_else(|err| {
        panic!(
            "failed to write stdio synth manifest {}: {err}",
            manifest_path.display()
        )
    });
}
