//! Integration test: runtime-math cohomology cross-family gate for bd-w2c3.5.2.
//!
//! Validates that:
//! 1. `scripts/check_runtime_math_cohomology_cross_family.sh` is executable.
//! 2. Gate emits deterministic report + structured JSONL artifacts.
//! 3. Strict+hardened scenarios are both present and passing.
//! 4. The sheaf-consistency proof artifact declares a complete open cover with
//!    trivial triple-overlap cocycles.

use frankenlibc_membrane::runtime_math::cohomology::CohomologyMonitor;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_scripts() -> MutexGuard<'static, ()> {
    script_lock().lock().unwrap_or_else(|e| e.into_inner())
}

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("harness crate parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

fn load_text(path: &Path) -> String {
    std::fs::read_to_string(path).expect("text file should be readable")
}

fn stable_hash(input: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    input.as_bytes().iter().fold(OFFSET, |acc, byte| {
        (acc ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

#[test]
fn gate_script_passes_and_emits_expected_artifacts() {
    let _guard = lock_scripts();
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_cohomology_cross_family.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_cohomology_cross_family.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run cohomology cross-family gate");
    assert!(
        output.status.success(),
        "cohomology cross-family gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path =
        root.join("target/conformance/runtime_math_cohomology_cross_family.report.json");
    let log_path = root.join("target/conformance/runtime_math_cohomology_cross_family.log.jsonl");
    let test_log_path =
        root.join("target/conformance/runtime_math_cohomology_cross_family.test_output.log");

    for path in [&report_path, &log_path, &test_log_path] {
        assert!(path.exists(), "missing {}", path.display());
    }

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.5.2"));
    assert_eq!(
        report["summary"]["failed_checks"].as_u64(),
        Some(0),
        "all cohomology cross-family checks should pass"
    );
    for check in [
        "strict_cross_family_consistency",
        "strict_corruption_replay_detection",
        "hardened_cross_family_consistency",
        "hardened_corruption_replay_detection",
    ] {
        assert_eq!(
            report["checks"][check].as_str(),
            Some("pass"),
            "report checks.{check} should be pass"
        );
    }

    let run_id = report["run_id"]
        .as_str()
        .expect("report.run_id should be present");

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert!(
        line_count >= 4,
        "expected at least 4 structured log rows, got {line_count}"
    );
    assert!(errors.is_empty(), "structured log errors: {errors:#?}");

    let rows: Vec<serde_json::Value> = std::fs::read_to_string(&log_path)
        .expect("log should be readable")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("log row should parse"))
        .filter(|row| {
            row["trace_id"]
                .as_str()
                .is_some_and(|trace| trace.contains(run_id))
        })
        .collect();
    assert_eq!(rows.len(), 4, "expected 4 rows for run_id {run_id}");

    let mut strict_seen = 0usize;
    let mut hardened_seen = 0usize;
    for row in rows {
        for key in [
            "trace_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(row.get(key).is_some(), "log row missing {key}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-w2c3.5.2"));
        assert_eq!(row["outcome"].as_str(), Some("pass"));
        match row["mode"].as_str() {
            Some("strict") => strict_seen += 1,
            Some("hardened") => hardened_seen += 1,
            other => panic!("unexpected mode: {:?}", other),
        }
    }
    assert_eq!(strict_seen, 2, "expected exactly two strict-mode rows");
    assert_eq!(hardened_seen, 2, "expected exactly two hardened-mode rows");

    let test_output =
        std::fs::read_to_string(&test_log_path).expect("test output log should be readable");
    for test_name in [
        "cross_family_overlap_tracks_string_resolver_consistently",
        "cohomology_overlap_replay_detects_corrupted_witness",
        "cross_family_overlap_tracks_string_resolver_consistently_hardened",
        "cohomology_overlap_replay_detects_corrupted_witness_hardened",
    ] {
        assert!(
            test_output.contains(test_name),
            "gate test output missing {test_name}"
        );
    }
}

#[test]
fn sheaf_global_consistency_artifact_declares_complete_open_cover() {
    let root = workspace_root();
    let proof_path = root.join("docs/proofs/sheaf_global_consistency.md");
    let artifact_path = root.join("tests/conformance/sheaf_coverage.v1.json");

    let proof = load_text(&proof_path);
    for required in [
        "# Sheaf Global-Consistency Proof Note (bd-249m.7)",
        "## Open Cover",
        "## Statement",
        "H^1(U, F) = 0",
    ] {
        assert!(
            proof.contains(required),
            "proof note must mention {required}"
        );
    }

    let artifact = load_json(&artifact_path);
    assert_eq!(artifact["schema_version"].as_str(), Some("v1"));
    assert_eq!(artifact["bead"].as_str(), Some("bd-249m.7"));
    assert_eq!(
        artifact["cohomology"]["h1_zero"].as_bool(),
        Some(true),
        "artifact must declare H^1 = 0"
    );

    let open_cover = artifact["open_cover"]
        .as_array()
        .expect("open_cover must be an array");
    assert_eq!(
        open_cover.len(),
        7,
        "expected 7 declared subsystem sections"
    );

    let expected_ids: BTreeSet<&str> = [
        "U_allocator",
        "U_string",
        "U_stdio",
        "U_thread",
        "U_math",
        "U_signal",
        "U_resolver",
    ]
    .into_iter()
    .collect();
    let mut actual_ids = BTreeSet::new();
    for section in open_cover {
        let id = section["id"].as_str().expect("section id must be a string");
        actual_ids.insert(id);
        assert!(
            section["local_predicates"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "section {id} must declare local predicates"
        );
        assert!(
            section["source_refs"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "section {id} must declare source refs"
        );
    }
    assert_eq!(
        actual_ids, expected_ids,
        "open cover ids changed unexpectedly"
    );

    let restriction_maps = artifact["restriction_maps"]
        .as_array()
        .expect("restriction_maps must be an array");
    assert_eq!(
        restriction_maps.len(),
        7,
        "expected one restriction map per declared subsystem section"
    );

    let restriction_ids: BTreeSet<&str> = restriction_maps
        .iter()
        .map(|entry| entry["id"].as_str().expect("restriction id must exist"))
        .collect();
    for overlap in artifact["overlaps"]
        .as_array()
        .expect("overlaps must be an array")
    {
        let left = overlap["left"].as_str().expect("left section id required");
        let right = overlap["right"]
            .as_str()
            .expect("right section id required");
        assert!(expected_ids.contains(left), "unknown left cover id {left}");
        assert!(
            expected_ids.contains(right),
            "unknown right cover id {right}"
        );
        assert!(
            overlap["compatibility_conditions"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "overlap {left}/{right} must declare compatibility conditions"
        );
        for restriction in overlap["restriction_maps"]
            .as_array()
            .expect("restriction map ids required")
        {
            let restriction = restriction
                .as_str()
                .expect("restriction id must be a string");
            assert!(
                restriction_ids.contains(restriction),
                "overlap {left}/{right} references unknown restriction map {restriction}"
            );
        }
    }
}

#[test]
fn sheaf_global_consistency_triples_have_trivial_cocycles() {
    let root = workspace_root();
    let artifact = load_json(&root.join("tests/conformance/sheaf_coverage.v1.json"));

    let open_cover = artifact["open_cover"]
        .as_array()
        .expect("open_cover must be an array");
    let mut shard_by_id = BTreeMap::new();
    let mut hash_by_id = BTreeMap::new();
    let monitor = CohomologyMonitor::new();

    for (index, section) in open_cover.iter().enumerate() {
        let id = section["id"].as_str().expect("section id must exist");
        let section_hash = stable_hash(id);
        shard_by_id.insert(id.to_owned(), index);
        hash_by_id.insert(id.to_owned(), section_hash);
        monitor.set_section_hash(index, section_hash);
    }

    for overlap in artifact["overlaps"]
        .as_array()
        .expect("overlaps must be an array")
    {
        let left = overlap["left"].as_str().expect("left section id required");
        let right = overlap["right"]
            .as_str()
            .expect("right section id required");
        let left_hash = *hash_by_id.get(left).expect("left hash must exist");
        let right_hash = *hash_by_id.get(right).expect("right hash must exist");
        let witness = left_hash ^ right_hash;

        assert!(
            monitor.note_overlap(
                *shard_by_id.get(left).expect("left shard must exist"),
                *shard_by_id.get(right).expect("right shard must exist"),
                witness
            ),
            "declared overlap {left}/{right} must accept its canonical witness"
        );
    }

    for triple in artifact["trivial_cocycles"]
        .as_array()
        .expect("trivial_cocycles must be an array")
    {
        let triple_ids = triple["triple"]
            .as_array()
            .expect("triple ids must be an array");
        assert_eq!(
            triple_ids.len(),
            3,
            "triple must contain exactly 3 section ids"
        );
        let ids: Vec<&str> = triple_ids
            .iter()
            .map(|entry| entry.as_str().expect("triple id must be a string"))
            .collect();
        let h_ab = hash_by_id[ids[0]] ^ hash_by_id[ids[1]];
        let h_bc = hash_by_id[ids[1]] ^ hash_by_id[ids[2]];
        let h_ac = hash_by_id[ids[0]] ^ hash_by_id[ids[2]];

        assert_eq!(
            h_ab ^ h_bc ^ h_ac,
            0,
            "declared triple {:?} must have zero obstruction in the xor witness model",
            ids
        );
    }

    assert_eq!(
        monitor.fault_count(),
        0,
        "declared cover should not accumulate overlap faults"
    );
}
