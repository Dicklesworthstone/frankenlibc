//! End-to-end verification for confined `libarchive` 4-arm security qualification
//! (`bd-reality-202609-lx578q.15.3` & `bd-reality-202609-lx578q.15.4`: `SQ` S08–S24).

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fl_libarchive_qual_e2e_{}_{}_{}",
            std::process::id(),
            id,
            tag
        ));
        fs::create_dir_all(&dir).expect("create unique test temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn find_warm_rch_release_cdylib(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(".rch-target-") {
            continue;
        }
        let candidate = entry.path().join("release/libfrankenlibc_abi.so");
        if let Ok(meta) = fs::metadata(&candidate)
            && meta.is_file()
        {
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_none_or(|(prev, _)| mtime > *prev) {
                best = Some((mtime, candidate));
            }
        }
    }
    best.map(|(_, p)| p)
}

fn ensure_release_cdylib(root: &Path) -> PathBuf {
    if let Ok(explicit) = std::env::var("FRANKENLIBC_LIB") {
        let p = PathBuf::from(explicit);
        assert!(p.is_file(), "FRANKENLIBC_LIB missing: {}", p.display());
        return p;
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target_dir).join("release/libfrankenlibc_abi.so");
        if candidate.is_file() {
            return candidate;
        }
    }
    for rel in [
        "target/release/libfrankenlibc_abi.so",
        ".rch-target/release/libfrankenlibc_abi.so",
    ] {
        let candidate = root.join(rel);
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Some(warm) = find_warm_rch_release_cdylib(root) {
        return warm;
    }
    let status = Command::new("cargo")
        .current_dir(root)
        .args(["build", "-p", "frankenlibc-abi", "--release"])
        .status()
        .expect("build release libfrankenlibc_abi.so");
    assert!(
        status.success(),
        "release libfrankenlibc_abi.so build failed"
    );
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target_dir).join("release/libfrankenlibc_abi.so");
        if candidate.is_file() {
            return candidate;
        }
    }
    for rel in [
        "target/release/libfrankenlibc_abi.so",
        ".rch-target/release/libfrankenlibc_abi.so",
    ] {
        let candidate = root.join(rel);
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Some(warm) = find_warm_rch_release_cdylib(root) {
        return warm;
    }
    panic!("built release libfrankenlibc_abi.so not found");
}

fn copy_dir_flat(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create relocated bundle dir");
    for entry in fs::read_dir(src).expect("read bundle dir") {
        let entry = entry.expect("dir entry");
        let src_p = entry.path();
        let dst_p = dst.join(entry.file_name());
        assert!(
            src_p.is_file(),
            "expected flat regular file in bundle: {}",
            src_p.display()
        );
        fs::copy(&src_p, &dst_p).expect("copy bundle file");
    }
}

#[test]
fn libarchive_confined_4arm_qualification_bundle_relocation_and_revocation_e2e() {
    let root = workspace_root();
    let runner = root.join("tests/cve_arena/runner.sh");
    let report = root.join("tests/cve_arena/report.sh");
    let manifest = root.join("tests/cve_arena/qualification_manifest.v1.json");
    let release_so = ensure_release_cdylib(&root);

    // 1. Negative control (S07): forced missing isolation fails closed before child execution.
    let missing_iso_tmp = TestDir::new("missing_iso");
    let missing_iso_dir = missing_iso_tmp.path().join("iso_blocked");
    let missing_iso_out = Command::new("bash")
        .arg(&runner)
        .arg("--qualification-manifest")
        .arg(&manifest)
        .arg("--results-dir")
        .arg(&missing_iso_dir)
        .env("FRANKENLIBC_LIB", &release_so)
        .env("CVE_ARENA_FORCE_MISSING_ISOLATION", "1")
        .output()
        .expect("run missing isolation negative control");
    assert_eq!(
        missing_iso_out.status.code(),
        Some(2),
        "missing isolation must fail closed with exit 2"
    );
    let iso_doc: Value = serde_json::from_str(
        &fs::read_to_string(missing_iso_dir.join("isolation_status.json"))
            .expect("isolation_status.json must be written"),
    )
    .expect("parse isolation_status.json");
    assert_eq!(iso_doc["status"], "blocked_missing_isolation");

    // 2. Full confined qualification execution (S08-S11, S13-S18, S20, S22, S23).
    let bundle_tmp = TestDir::new("bundle");
    let bundle_dir = bundle_tmp.path().join("qualification_bundle");
    let qual_out = Command::new("bash")
        .arg(&runner)
        .arg("--qualification-manifest")
        .arg(&manifest)
        .arg("--results-dir")
        .arg(&bundle_dir)
        .arg("--demo")
        .env("FRANKENLIBC_LIB", &release_so)
        .output()
        .expect("run full libarchive qualification");
    assert!(
        qual_out.status.success(),
        "libarchive qualification failed (rc={:?}):\nstdout={}\nstderr={}",
        qual_out.status.code(),
        String::from_utf8_lossy(&qual_out.stdout),
        String::from_utf8_lossy(&qual_out.stderr)
    );
    let demo_stdout = String::from_utf8_lossy(&qual_out.stdout);
    assert!(
        demo_stdout.contains("[DEMO] profile=libarchive-confined-archive-worker-v1"),
        "expected concise S20 demo output, got: {demo_stdout}"
    );

    // 3. Negative control (S05/S16): non-empty results-dir must be rejected before overwriting.
    let reuse_out = Command::new("bash")
        .arg(&runner)
        .arg("--qualification-manifest")
        .arg(&manifest)
        .arg("--results-dir")
        .arg(&bundle_dir)
        .env("FRANKENLIBC_LIB", &release_so)
        .output()
        .expect("run non-empty results-dir negative control");
    assert_eq!(
        reuse_out.status.code(),
        Some(2),
        "reusing non-empty results-dir must fail closed with exit 2"
    );

    // 4. Verify primary S09/S11 (ZIP), S14 (RAR), S10 (benign), S15 (perf), S17 (lifecycle), S23 (holdout).
    let zip_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("zip_s08_s11.json")).expect("read zip_s08_s11.json"),
    )
    .expect("parse zip_s08_s11.json");
    assert_eq!(zip_doc["baseline_harm_observed"], true);
    assert_eq!(zip_doc["strict_ablation_harm_observed"], true);
    assert_eq!(zip_doc["hardened_harm_excluded"], true);
    assert_eq!(zip_doc["unpublished_corrupt_output_enforced"], true);
    assert_eq!(zip_doc["arms"]["F"]["publication"]["published"], false);
    assert_eq!(zip_doc["arms"]["F"]["dimensions"]["qualified_card"], true);

    let rar_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("rar_s13_s14.json")).expect("read rar_s13_s14.json"),
    )
    .expect("parse rar_s13_s14.json");
    assert_eq!(rar_doc["baseline_harm_observed"], true);
    assert_eq!(rar_doc["strict_ablation_harm_observed"], true);
    assert_eq!(rar_doc["hardened_harm_excluded"], true);
    assert_eq!(rar_doc["arms"]["F"]["synthetic_marker_disclosed"], false);
    assert_eq!(rar_doc["arms"]["F"]["dimensions"]["qualified_card"], true);

    let benign_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("benign_s10.json")).expect("read benign_s10.json"),
    )
    .expect("parse benign_s10.json");
    assert_eq!(benign_doc["all_passed"], true);
    assert_eq!(benign_doc["cells"].as_array().map(Vec::len), Some(5));

    let perf_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("performance_s15.json"))
            .expect("read performance_s15.json"),
    )
    .expect("parse performance_s15.json");
    assert_eq!(
        perf_doc["paired_blocks_raw"].as_array().map(Vec::len),
        Some(30)
    );
    assert!(
        perf_doc["hardened_vs_stock_ratio"]["point"]
            .as_f64()
            .unwrap_or(0.0)
            > 0.0
    );

    let s17_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("lifecycle_s17.json"))
            .expect("read lifecycle_s17.json"),
    )
    .expect("parse lifecycle_s17.json");
    assert_eq!(s17_doc["all_passed"], true);
    assert_eq!(s17_doc["published_files_after_failures"], 0);
    assert_eq!(s17_doc["controls"].as_array().map(Vec::len), Some(6));

    let s23_doc: Value = serde_json::from_str(
        &fs::read_to_string(bundle_dir.join("holdout_s23.json")).expect("read holdout_s23.json"),
    )
    .expect("parse holdout_s23.json");
    assert_eq!(s23_doc["all_passed"], true);
    let s23_cases = s23_doc["cases"].as_array().expect("s23 cases");
    assert_eq!(s23_cases.len(), 5);
    let inlined_case = s23_cases
        .iter()
        .find(|c| c["case_id"] == "S23_holdout_boundary_inlined_direct_write_bypass")
        .expect("inlined bypass case present");
    assert_eq!(inlined_case["oracle"]["watchpoint_triggered"], true);
    assert_eq!(inlined_case["dimensions"]["qualification"], "unsupported");
    assert_eq!(inlined_case["honest_non_promotion_verified"], true);

    // 5. S18 & S19: Relocate bundle to an isolated clean directory and verify zero local paths + independent recomputation.
    let relocated_tmp = TestDir::new("relocated");
    let relocated_dir = relocated_tmp.path().join("clean_room_bundle");
    copy_dir_flat(&bundle_dir, &relocated_dir);

    for entry in fs::read_dir(&relocated_dir).expect("read relocated_dir") {
        let p = entry.expect("entry").path();
        let text = fs::read_to_string(&p).expect("utf8 bundle file");
        assert!(
            !text.contains("/data/projects") && !text.contains("/data/tmp"),
            "machine-local path leaked in {}",
            p.display()
        );
    }

    let verify_ok = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            relocated_dir.to_str().unwrap(),
            "--verify",
        ])
        .output()
        .expect("verify relocated bundle");
    assert!(
        verify_ok.status.success(),
        "relocated bundle verification failed: stdout={} stderr={}",
        String::from_utf8_lossy(&verify_ok.stdout),
        String::from_utf8_lossy(&verify_ok.stderr)
    );
    let verify_doc: Value = serde_json::from_str(&String::from_utf8_lossy(&verify_ok.stdout))
        .expect("parse verify json");
    assert_eq!(verify_doc["status"], "verified");

    // 6. S24: 1-byte tampering of candidate DSO, manifest, or bundle evidence triggers superseded/revoked.
    let tamper_tmp = TestDir::new("tamper");
    let tampered_so = tamper_tmp.path().join("tampered_libfrankenlibc_abi.so");
    let mut so_bytes = fs::read(&release_so).expect("read release_so");
    let last_idx = so_bytes.len() - 1;
    so_bytes[last_idx] ^= 0x01;
    fs::write(&tampered_so, &so_bytes).expect("write tampered_so");

    let sup_so = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            relocated_dir.to_str().unwrap(),
            "--verify",
            "--check-candidate-lib",
            tampered_so.to_str().unwrap(),
        ])
        .output()
        .expect("verify tampered candidate lib");
    assert!(
        !sup_so.status.success(),
        "1-byte altered candidate .so must fail verification"
    );
    let sup_so_doc: Value =
        serde_json::from_str(&String::from_utf8_lossy(&sup_so.stdout)).expect("parse sup_so json");
    assert_eq!(sup_so_doc["status"], "superseded");

    let tampered_manifest = tamper_tmp.path().join("tampered_manifest.json");
    let mut man_bytes = fs::read(&manifest).expect("read manifest");
    man_bytes.push(b' ');
    fs::write(&tampered_manifest, &man_bytes).expect("write tampered manifest");

    let sup_man = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            relocated_dir.to_str().unwrap(),
            "--verify",
            "--check-manifest",
            tampered_manifest.to_str().unwrap(),
        ])
        .output()
        .expect("verify tampered manifest");
    assert!(
        !sup_man.status.success(),
        "1-byte altered manifest must fail verification"
    );
    let sup_man_doc: Value = serde_json::from_str(&String::from_utf8_lossy(&sup_man.stdout))
        .expect("parse sup_man json");
    assert_eq!(sup_man_doc["status"], "superseded");

    let tampered_bundle = tamper_tmp.path().join("tampered_bundle");
    copy_dir_flat(&relocated_dir, &tampered_bundle);
    let mut zbytes = fs::read(tampered_bundle.join("zip_s08_s11.json")).expect("read zip json");
    zbytes.push(b'\n');
    fs::write(tampered_bundle.join("zip_s08_s11.json"), &zbytes).expect("write tampered zip json");

    let rev_out = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            tampered_bundle.to_str().unwrap(),
            "--verify",
        ])
        .output()
        .expect("verify tampered bundle");
    assert!(
        !rev_out.status.success(),
        "1-byte altered bundle file must be revoked"
    );
    let rev_doc: Value =
        serde_json::from_str(&String::from_utf8_lossy(&rev_out.stdout)).expect("parse rev json");
    assert_eq!(rev_doc["status"], "revoked");

    let symlink_bundle = tamper_tmp.path().join("symlink_bundle");
    copy_dir_flat(&relocated_dir, &symlink_bundle);
    symlink("/etc/hosts", symlink_bundle.join("escape.link")).expect("plant symlink");
    let sym_out = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            symlink_bundle.to_str().unwrap(),
            "--verify",
        ])
        .output()
        .expect("verify symlink bundle");
    assert!(
        !sym_out.status.success(),
        "symlink inside bundle must be rejected"
    );
    let sym_doc: Value =
        serde_json::from_str(&String::from_utf8_lossy(&sym_out.stdout)).expect("parse sym json");
    assert_eq!(sym_doc["status"], "invalid_bundle");
}

#[test]
fn committed_libarchive_qualification_bundle_relocation_tamper_and_s22_docs_e2e() {
    let root = workspace_root();
    let report = root.join("tests/cve_arena/report.sh");
    let manifest = root.join("tests/cve_arena/qualification_manifest.v1.json");
    let committed_bundle = root.join("tests/cve_arena/results/libarchive_qualification_v1");
    assert!(
        committed_bundle.is_dir(),
        "committed portable qualification bundle must exist at {}",
        committed_bundle.display()
    );

    // S18 & S19: Relocate committed bundle to an isolated clean directory and verify zero local paths + independent recomputation.
    let relocated_tmp = TestDir::new("committed_relocated");
    let relocated_dir = relocated_tmp.path().join("clean_room_bundle");
    copy_dir_flat(&committed_bundle, &relocated_dir);

    let mut file_count = 0usize;
    for entry in fs::read_dir(&relocated_dir).expect("read relocated_dir") {
        let p = entry.expect("entry").path();
        file_count += 1;
        let text = fs::read_to_string(&p).expect("utf-8 bundle file");
        assert!(
            !text.contains("/data/projects") && !text.contains("/data/tmp"),
            "bundle file {} leaked machine-local path",
            p.display()
        );
    }
    assert_eq!(file_count, 12, "expected 12 flat files in portable bundle");

    let verify_out = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            relocated_dir.to_str().unwrap(),
            "--verify",
            "--check-manifest",
            manifest.to_str().unwrap(),
        ])
        .output()
        .expect("run clean-room bundle verification");
    assert!(
        verify_out.status.success(),
        "clean-room bundle verification failed: stdout={} stderr={}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr)
    );
    let verify_doc: Value = serde_json::from_str(&String::from_utf8_lossy(&verify_out.stdout))
        .expect("parse verify json");
    assert_eq!(verify_doc["status"], "verified");
    assert_eq!(verify_doc["verified_files"], 11);
    assert_eq!(verify_doc["zip_s09_s11_recomputed"], true);
    assert_eq!(verify_doc["rar_s14_recomputed"], true);
    assert_eq!(verify_doc["holdout_s23_passed"], true);
    assert_eq!(verify_doc["inlined_bypass_marked_unsupported"], true);

    // S20 & S23: Raw JSONL observations + holdout & S22 disposition checks.
    let obs_raw = fs::read_to_string(relocated_dir.join("observations.jsonl"))
        .expect("read observations.jsonl");
    let obs_lines: Vec<&str> = obs_raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        obs_lines.len() >= 15,
        "expected >= 15 structured JSONL observation records, got {}",
        obs_lines.len()
    );
    for line in &obs_lines {
        let rec: Value = serde_json::from_str(line).expect("valid JSONL observation record");
        assert!(rec.get("milestone").is_some() || rec.get("event").is_some());
    }

    let s22_doc: Value = serde_json::from_str(
        &fs::read_to_string(relocated_dir.join("s22_disposition.json"))
            .expect("read s22_disposition.json"),
    )
    .expect("parse s22_disposition.json");
    let expected_qual = s22_doc["profile_qualification"]
        .as_str()
        .expect("profile_qualification string");

    // S24: 1-byte tamper negative controls on manifest, JSONL log, and artifact identities.
    let tamper_tmp = TestDir::new("committed_tamper");
    let tampered_manifest = tamper_tmp.path().join("tampered_manifest.json");
    let mut man_bytes = fs::read(&manifest).expect("read manifest");
    man_bytes.push(b'\n');
    fs::write(&tampered_manifest, &man_bytes).expect("write tampered manifest");
    let sup_out = Command::new("bash")
        .arg(&report)
        .args([
            "--qualification",
            relocated_dir.to_str().unwrap(),
            "--verify",
            "--check-manifest",
            tampered_manifest.to_str().unwrap(),
        ])
        .output()
        .expect("verify tampered manifest");
    assert!(!sup_out.status.success());
    let sup_doc: Value =
        serde_json::from_str(&String::from_utf8_lossy(&sup_out.stdout)).expect("parse sup json");
    assert_eq!(sup_doc["status"], "superseded");

    for target_file in ["observations.jsonl", "artifact_identities.json"] {
        let tb = tamper_tmp.path().join(format!("tamper_{target_file}"));
        copy_dir_flat(&relocated_dir, &tb);
        let mut bytes = fs::read(tb.join(target_file)).expect("read target file");
        bytes.push(b' ');
        fs::write(tb.join(target_file), &bytes).expect("write tampered file");
        let rev_out = Command::new("bash")
            .arg(&report)
            .args(["--qualification", tb.to_str().unwrap(), "--verify"])
            .output()
            .expect("verify tampered file");
        assert!(
            !rev_out.status.success(),
            "1-byte tamper of {target_file} must fail closed"
        );
        let rev_doc: Value = serde_json::from_str(&String::from_utf8_lossy(&rev_out.stdout))
            .expect("parse rev json");
        assert_eq!(rev_doc["status"], "revoked");
    }

    // S22: Honest documentation alignment across SECURITY.md, DEPLOYMENT.md, and docs/gentoo/security-validation.md.
    let security_md = fs::read_to_string(root.join("SECURITY.md")).expect("read SECURITY.md");
    let deployment_md = fs::read_to_string(root.join("DEPLOYMENT.md")).expect("read DEPLOYMENT.md");
    let gentoo_md = fs::read_to_string(root.join("docs/gentoo/security-validation.md"))
        .expect("read docs/gentoo/security-validation.md");

    assert!(security_md.contains("libarchive-confined-archive-worker-v1"));
    assert!(security_md.contains(expected_qual));
    assert!(security_md.contains("S23_holdout_boundary_inlined_direct_write_bypass"));
    assert!(security_md.contains("unsupported"));
    assert!(deployment_md.contains("libarchive-confined-archive-worker-v1"));
    assert!(deployment_md.contains(expected_qual));
    assert!(gentoo_md.contains("FRANKENLIBC_LOG=/results/frankenlibc.jsonl"));
    assert!(!gentoo_md.contains("FRANKENLIBC_LOG_FILE"));
    assert!(!gentoo_md.contains("healing_action_count / 10"));
    assert!(gentoo_md.contains("unqualified"));
}
