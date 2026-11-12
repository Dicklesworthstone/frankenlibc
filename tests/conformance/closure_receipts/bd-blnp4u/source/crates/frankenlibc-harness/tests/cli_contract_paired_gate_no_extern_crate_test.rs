//! Meta-gate: no paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` declares an `extern crate` line
//! (bd-lgoua). Rust 2018+ resolves crate imports via `use` statements
//! without `extern crate`; the presence of `extern crate` indicates
//! stale code carried over from Rust 2015 or from a copy-paste from
//! an older codebase.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn count_extern_crate_declarations(body: &str) -> usize {
    body.lines()
        .filter(|line| line.trim_start().starts_with("extern crate"))
        .count()
}

#[test]
fn no_paired_gate_test_declares_extern_crate() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let count = count_extern_crate_declarations(&body);
        if count > 0 {
            violations.push(format!(
                "{stem}: declares {count} `extern crate` line(s) (Rust 2018+ doesn't need them)"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test extern-crate violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn extern_crate_counter_handles_canonical_forms() {
    assert_eq!(count_extern_crate_declarations("extern crate foo;"), 1);
    assert_eq!(
        count_extern_crate_declarations("  extern crate foo;\nfn x() {}"),
        1
    );
    assert_eq!(
        count_extern_crate_declarations("use std::path;\nfn x() {}"),
        0
    );
    assert_eq!(count_extern_crate_declarations("// extern crate foo;"), 0);
}

#[test]
fn test_extern_symbols_audit_passes_across_workspace_and_ci_wires_gate() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_test_extern_symbols.sh");
    let ci_script = root.join("scripts/ci.sh");
    let ci_body = std::fs::read_to_string(&ci_script)
        .map_err(|e| format!("read {}: {e}", ci_script.display()))?;
    let audit_pos = ci_body
        .find("scripts/check_test_extern_symbols.sh")
        .ok_or_else(|| "scripts/ci.sh must wire scripts/check_test_extern_symbols.sh".to_owned())?;
    let cargo_check_pos = ci_body
        .find("run_remote_cargo check --workspace --all-targets --keep-going")
        .ok_or_else(|| "scripts/ci.sh missing cargo check --workspace --all-targets".to_owned())?;
    assert!(
        audit_pos < cargo_check_pos,
        "check_test_extern_symbols.sh must run before cargo check in scripts/ci.sh"
    );

    let out = std::process::Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .map_err(|e| format!("spawn check_test_extern_symbols.sh: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "check_test_extern_symbols.sh failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout
            .contains("PASS: every declared extern symbol resolves against the scanned libraries"),
        "unexpected stdout:\n{stdout}"
    );
    Ok(())
}

#[test]
fn test_extern_symbols_audit_rejects_phantom_extern_and_broken_zz_probe() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_test_extern_symbols.sh");
    let unique = format!(
        "frankenlibc-extern-audit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let base = Path::new("/tmp").join(unique);
    let valid_dir = base.join("valid");
    let phantom_dir = base.join("phantom");
    let syntax_dir = base.join("syntax");
    std::fs::create_dir_all(&valid_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&phantom_dir).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&syntax_dir).map_err(|e| e.to_string())?;

    // 1. Positive control: valid zz_*.rs probe referencing libgcc_s (_Unwind_Find_FDE) + libm (ynf).
    std::fs::write(
        valid_dir.join("zz_valid_probe.rs"),
        "unsafe extern \"C\" {\n    fn _Unwind_Find_FDE(pc: *const core::ffi::c_void) -> *const core::ffi::c_void;\n    fn ynf(n: i32, x: f32) -> f32;\n}\n#[test]\nfn smoke() {}\n",
    )
    .map_err(|e| e.to_string())?;
    let ok_out = std::process::Command::new("bash")
        .arg(&script)
        .arg(&valid_dir)
        .current_dir(&root)
        .output()
        .map_err(|e| e.to_string())?;
    let ok_stdout = String::from_utf8_lossy(&ok_out.stdout);
    assert!(ok_out.status.success(), "expected PASS, got:\n{ok_stdout}");
    assert!(ok_stdout.contains("zz_probes=1"));

    // 2. Negative control A: phantom extern symbol fails while _Unwind_Find_FDE is NOT flagged.
    std::fs::write(
        phantom_dir.join("zz_phantom_probe.rs"),
        "unsafe extern \"C\" {\n    fn _Unwind_Find_FDE(pc: *const core::ffi::c_void) -> *const core::ffi::c_void;\n    fn frankenlibc_nonexistent_phantom_symbol_xyz();\n}\n",
    )
    .map_err(|e| e.to_string())?;
    let bad_ext = std::process::Command::new("bash")
        .arg(&script)
        .arg(&phantom_dir)
        .current_dir(&root)
        .output()
        .map_err(|e| e.to_string())?;
    let bad_ext_stdout = String::from_utf8_lossy(&bad_ext.stdout);
    assert!(!bad_ext.status.success(), "phantom extern must fail");
    assert!(bad_ext_stdout.contains("frankenlibc_nonexistent_phantom_symbol_xyz"));
    assert!(!bad_ext_stdout.contains("_Unwind_Find_FDE"));

    // 3. Negative control B: syntax-broken zz_*.rs probe fails immediately.
    std::fs::write(
        syntax_dir.join("zz_broken_syntax_probe.rs"),
        "#[test]\nfn broken( {\n",
    )
    .map_err(|e| e.to_string())?;
    let bad_syn = std::process::Command::new("bash")
        .arg(&script)
        .arg(&syntax_dir)
        .current_dir(&root)
        .output()
        .map_err(|e| e.to_string())?;
    let bad_syn_stdout = String::from_utf8_lossy(&bad_syn.stdout);
    assert!(
        !bad_syn.status.success(),
        "syntax-broken zz_ probe must fail"
    );
    assert!(
        bad_syn_stdout.contains("zz_*.rs probe(s) failed syntax parse"),
        "unexpected output:\n{bad_syn_stdout}"
    );
    Ok(())
}
