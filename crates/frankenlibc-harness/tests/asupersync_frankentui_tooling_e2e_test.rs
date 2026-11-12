#![cfg(all(feature = "asupersync-tooling", feature = "frankentui-ui"))]

//! End-to-end verification for `bd-reality-202609-lx578q.16` & `.16.1`:
//! 1. 10-run seeded determinism + multi-seed schedule variation via
//!    `asupersync-conformance` over real `frankenlibc_membrane::ebr::EbrCollector`.
//! 2. Schedule-dependent premature-unpin EBR bug detection producing
//!    `ReplayOutcome::CodeFailure` + delta-debugged `frankenlibc.lab_witness.v1`
//!    minimal witness JSONL (`shrunk_steps < original_steps`).
//! 3. Clean `ReplayOutcome::ToolFailure` separation when the Lab adapter is
//!    disabled or unavailable.
//! 4. Deterministic `frankentui-ui` (`ftui-harness`) snapshot rendering,
//!    buffer checksums, and 1-row visual regression detection.
//! 5. Runtime dependency boundary validation at `HEAD` + negative control
//!    proving synthetic companion-crate injection into `frankenlibc-abi` fails
//!    closed with `runtime_dependency_leakage`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_harness::asupersync_lab_replay::{
    DetectionEnv, LabTaskOp, LabToolingMode, ReplayOutcome, ReplayRecord, execute_seeded_lab_replay,
};
use frankenlibc_harness::diff::render_ftui_raw_diff;
use frankenlibc_harness::kernel_snapshot::{SnapshotMode, build_kernel_snapshot_fixture};
use frankenlibc_harness::snapshot_diff::{
    DiffMode, compare_ftui_snapshots, compute_ftui_snapshot_checksum, diff_kernel_snapshots,
    render_ftui,
};
use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn make_replay_record(trace_class: &str, seed: u64) -> ReplayRecord {
    let input = format!("target/conformance/{trace_class}.input.jsonl");
    let expected = format!("target/conformance/{trace_class}.expected.jsonl");
    let observed = format!("target/conformance/{trace_class}.observed.jsonl");
    ReplayRecord {
        schema_version: "v1".to_string(),
        trace_class: trace_class.to_string(),
        virtual_time_seed: seed,
        schedule_decisions: vec!["lab:ebr:pin".into(), "lab:ebr:advance".into()],
        replay_inputs: vec![input.clone()],
        expected_outputs: vec![expected.clone()],
        artifact_refs: vec![input, expected, observed],
        source_commit: "a".repeat(40),
    }
}

fn safe_ebr_worker_queues() -> Vec<Vec<LabTaskOp>> {
    vec![
        vec![
            LabTaskOp::PublishItem { item_id: 100 },
            LabTaskOp::PinEpoch,
            LabTaskOp::AccessItem { item_id: 100 },
            LabTaskOp::UnpinEpoch,
            LabTaskOp::RetireItem { item_id: 100 },
        ],
        vec![
            LabTaskOp::PublishItem { item_id: 200 },
            LabTaskOp::PinEpoch,
            LabTaskOp::AccessItem { item_id: 200 },
            LabTaskOp::UnpinEpoch,
            LabTaskOp::RetireItem { item_id: 200 },
        ],
        vec![
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::PinEpoch,
            LabTaskOp::UnpinEpoch,
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::TryAdvanceEpoch,
        ],
    ]
}

fn buggy_premature_unpin_worker_queues() -> Vec<Vec<LabTaskOp>> {
    // Worker 0 publishes item 77, pins, prematurely unpins BEFORE reading item 77,
    // and then accesses item 77. Worker 1 retires item 77 (once published, or in
    // concurrent interleavings) and advances epochs 4 times; Worker 2 adds benign
    // scheduling noise that delta debugging must strip from the minimal witness.
    vec![
        vec![
            LabTaskOp::PublishItem { item_id: 77 },
            LabTaskOp::PinEpoch,
            LabTaskOp::UnpinEpoch,
            LabTaskOp::PublishItem { item_id: 901 },
            LabTaskOp::AccessItem { item_id: 77 },
            LabTaskOp::PublishItem { item_id: 902 },
        ],
        vec![
            LabTaskOp::PinEpoch,
            LabTaskOp::UnpinEpoch,
            LabTaskOp::RetireItem { item_id: 77 },
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::TryAdvanceEpoch,
            LabTaskOp::TryAdvanceEpoch,
        ],
        vec![
            LabTaskOp::PublishItem { item_id: 903 },
            LabTaskOp::PinEpoch,
            LabTaskOp::UnpinEpoch,
        ],
    ]
}

#[test]
fn seeded_lab_replay_ten_runs_byte_identical_and_distinct_seeds_vary_schedule() {
    let queues = safe_ebr_worker_queues();
    let mode = LabToolingMode::LinkedCrate { override_var: None };
    let record = make_replay_record("membrane.ebr.safe_grace_period", 0x2026_1111_5EED_0001);

    let baseline =
        execute_seeded_lab_replay(&record, &mode, &queues).expect("baseline replay must validate");
    assert_eq!(baseline.outcome, ReplayOutcome::Pass);
    assert_eq!(baseline.virtual_clock_ticks, 16);
    assert_eq!(baseline.schedule_trace.len(), 16);
    assert_eq!(baseline.total_retired, 2);
    assert!(baseline.shrunk_witness_jsonl.is_none());
    assert_eq!(baseline.suite.total, 1);
    assert_eq!(baseline.suite.passed, 1);
    assert_eq!(baseline.suite.failed, 0);
    assert!(
        !baseline.suite.results[0].events.is_empty(),
        "asupersync ConformanceTestLogger events must be captured"
    );
    assert_eq!(baseline.suite.results[0].result.checkpoints.len(), 2);

    let baseline_trace_bytes =
        serde_json::to_vec(&baseline.schedule_trace).expect("serialize schedule_trace");
    let baseline_checkpoints_bytes =
        serde_json::to_vec(&baseline.suite.results[0].result.checkpoints)
            .expect("serialize suite checkpoints");

    for run_idx in 1..10 {
        let repeat =
            execute_seeded_lab_replay(&record, &mode, &queues).expect("repeat replay must pass");
        assert_eq!(
            repeat.outcome,
            ReplayOutcome::Pass,
            "run {run_idx} must pass"
        );
        assert_eq!(
            serde_json::to_vec(&repeat.schedule_trace).expect("serialize repeat trace"),
            baseline_trace_bytes,
            "run {run_idx} schedule_trace must be byte-identical for fixed virtual_time_seed"
        );
        assert_eq!(
            serde_json::to_vec(&repeat.suite.results[0].result.checkpoints)
                .expect("serialize repeat checkpoints"),
            baseline_checkpoints_bytes,
            "run {run_idx} checkpoints must be byte-identical for fixed virtual_time_seed"
        );
        assert_eq!(repeat.final_epoch, baseline.final_epoch);
        assert_eq!(repeat.total_reclaimed, baseline.total_reclaimed);
    }

    let mut distinct_traces = BTreeSet::new();
    for seed in [
        0x1111_u64, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888,
    ] {
        let seeded_record = make_replay_record("membrane.ebr.safe_grace_period", seed);
        let exec = execute_seeded_lab_replay(&seeded_record, &mode, &queues)
            .expect("seeded replay must validate");
        assert_eq!(
            exec.outcome,
            ReplayOutcome::Pass,
            "safe EBR workload must pass under every schedule (seed={seed:#x})"
        );
        distinct_traces.insert(exec.schedule_trace.join("|"));
    }
    assert!(
        distinct_traces.len() >= 4,
        "varying virtual_time_seed must explore genuinely distinct schedules, got {} unique traces",
        distinct_traces.len()
    );
}

#[test]
fn seeded_lab_replay_catches_schedule_dependent_ebr_bug_and_emits_shrunk_witness_jsonl() {
    let queues = buggy_premature_unpin_worker_queues();
    let mode = LabToolingMode::LinkedCrate { override_var: None };

    let mut found_pass_seed: Option<u64> = None;
    let mut found_failure = None;

    for seed in 1_u64..=512 {
        let rec = make_replay_record("membrane.ebr.premature_unpin", seed);
        let exec =
            execute_seeded_lab_replay(&rec, &mode, &queues).expect("buggy trace must validate");
        match exec.outcome {
            ReplayOutcome::Pass => {
                if found_pass_seed.is_none() {
                    found_pass_seed = Some(seed);
                }
            }
            ReplayOutcome::CodeFailure { ref signature }
                if signature.contains("ebr_use_after_reclaim(worker=W0,item=77,pinned=false") =>
            {
                if found_failure.is_none() {
                    found_failure = Some((seed, exec));
                }
            }
            ReplayOutcome::CodeFailure { .. } => {}
            ReplayOutcome::ToolFailure { reason } => {
                panic!("unexpected ToolFailure during linked replay: {reason}");
            }
        }
        if found_pass_seed.is_some() && found_failure.is_some() {
            break;
        }
    }

    assert!(
        found_pass_seed.is_some(),
        "premature-unpin workload must pass under benign interleavings (proving schedule dependence)"
    );
    let (failing_seed, failing_exec) = found_failure
        .expect("seeded Lab replay must discover an interleaving triggering ebr_use_after_reclaim");

    let ReplayOutcome::CodeFailure { ref signature } = failing_exec.outcome else {
        unreachable!("matched CodeFailure above");
    };
    assert!(
        signature.starts_with("membrane.ebr.premature_unpin::invariant_violation="),
        "unexpected signature format (seed={failing_seed:#x}): {signature}"
    );
    assert!(
        signature.ends_with(";shrunk_steps=6"),
        "delta-debugging shrinker must isolate the exact 6-step causal witness, got: {signature}"
    );
    assert_eq!(failing_exec.suite.total, 1);
    assert_eq!(failing_exec.suite.passed, 0);
    assert_eq!(failing_exec.suite.failed, 1);

    let witness_jsonl = failing_exec
        .shrunk_witness_jsonl
        .as_deref()
        .expect("CodeFailure must emit shrunk_witness_jsonl");
    let rows: Vec<Value> = witness_jsonl
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("valid JSONL witness row"))
        .collect();
    assert_eq!(
        rows.len(),
        7,
        "expected 1 witness_header + 6 witness_step rows, got:\n{witness_jsonl}"
    );
    for row in &rows {
        assert_eq!(row["schema_version"], "frankenlibc.lab_witness.v1");
    }

    let header = &rows[0];
    assert_eq!(header["event"], "witness_header");
    assert_eq!(header["trace_class"], "membrane.ebr.premature_unpin");
    assert_eq!(header["virtual_time_seed"], failing_seed);
    let original_steps = header["original_steps"].as_u64().expect("original_steps");
    let shrunk_steps = header["shrunk_steps"].as_u64().expect("shrunk_steps");
    assert_eq!(shrunk_steps, 6);
    assert!(
        shrunk_steps < original_steps,
        "witness must shrink noise steps: shrunk={shrunk_steps} original={original_steps}"
    );

    // Verify no noise items (901, 902, 903) or redundant Pin/Unpin remain in the minimal witness.
    for step_row in &rows[1..] {
        assert_eq!(step_row["event"], "witness_step");
        let rendered = step_row["op"].to_string();
        assert!(
            !rendered.contains("901") && !rendered.contains("902") && !rendered.contains("903"),
            "noise operations must be eliminated from minimal witness: {rendered}"
        );
    }
}

#[test]
fn seeded_lab_replay_reports_tool_failure_distinctly_when_lab_adapter_unavailable() {
    let queues = buggy_premature_unpin_worker_queues();
    let record = make_replay_record("membrane.ebr.tool_probe", 0xABCD_1234);

    let unavailable_modes = [
        LabToolingMode::SimulatedUnavailable {
            detail: "synthetic_adapter_missing".to_string(),
        },
        LabToolingMode::LinkedCrate {
            override_var: Some("0".to_string()),
        },
        LabToolingMode::ExternalProbe(DetectionEnv {
            override_var: None,
            asupersync_dir: PathBuf::from("/nonexistent-asupersync-wave52-probe"),
            path_search_paths: Vec::new(),
        }),
    ];

    for (idx, mode) in unavailable_modes.iter().enumerate() {
        let exec = execute_seeded_lab_replay(&record, mode, &queues)
            .expect("unavailable Lab adapter must still validate ReplayRecord");
        match exec.outcome {
            ReplayOutcome::ToolFailure { ref reason } => {
                assert!(
                    reason.contains("asupersync tool unavailable"),
                    "mode {idx} reason must identify missing tool: {reason}"
                );
                assert!(
                    reason.contains("membrane.ebr.tool_probe"),
                    "mode {idx} reason must include trace_class: {reason}"
                );
            }
            other => panic!("mode {idx} expected ToolFailure, got {other:?}"),
        }
        assert_eq!(exec.virtual_clock_ticks, 0);
        assert!(exec.schedule_trace.is_empty());
        assert!(exec.shrunk_witness_jsonl.is_none());
        assert_eq!(exec.suite.passed, 0);
        assert_eq!(exec.suite.failed, 1);
    }
}

#[test]
fn frankentui_snapshot_golden_checksum_is_deterministic_and_catches_one_row_regression() {
    let golden = build_kernel_snapshot_fixture(0x5CA1_AB1E, 32, SnapshotMode::Both);
    let identical_current = build_kernel_snapshot_fixture(0x5CA1_AB1E, 32, SnapshotMode::Both);

    let baseline_report =
        diff_kernel_snapshots(&golden, &identical_current, DiffMode::Strict, false)
            .expect("baseline snapshot diff");

    let expected_plain_ui = render_ftui(&baseline_report, false, 120);
    let expected_ansi_ui = render_ftui(&baseline_report, true, 120);
    let expected_checksum = compute_ftui_snapshot_checksum(&baseline_report, 120);

    assert!(
        expected_plain_ui.contains("runtime_math snapshot diff (mode=strict"),
        "ftui table must include mode/scenario title:\n{expected_plain_ui}"
    );
    assert!(expected_plain_ui.contains("OK"));
    assert!(!expected_plain_ui.contains("ALERT"));
    assert!(
        expected_checksum.starts_with("blake3:") || !expected_checksum.is_empty(),
        "buffer checksum must be non-empty"
    );

    for repeat in 0..5 {
        assert_eq!(
            render_ftui(&baseline_report, false, 120),
            expected_plain_ui,
            "repeat {repeat}: ftui plain snapshot must be byte-exact"
        );
        assert_eq!(
            render_ftui(&baseline_report, true, 120),
            expected_ansi_ui,
            "repeat {repeat}: ftui ANSI snapshot must be byte-exact"
        );
        assert_eq!(
            compute_ftui_snapshot_checksum(&baseline_report, 120),
            expected_checksum,
            "repeat {repeat}: ftui buffer checksum must be deterministic"
        );
    }

    let self_cmp = compare_ftui_snapshots(0, &baseline_report, &baseline_report, 120);
    assert!(
        self_cmp.pass,
        "identical snapshots must pass FrameComparator"
    );
    assert_eq!(self_cmp.mismatch_count, 0);

    // Inject a synthetic 1-row regression exceeding full_validation_trigger_ppm threshold (10_000).
    let mut regressed_fixture = identical_current;
    regressed_fixture
        .strict
        .as_mut()
        .expect("strict mode present")
        .snapshot
        .full_validation_trigger_ppm += 25_000;

    let regressed_report =
        diff_kernel_snapshots(&golden, &regressed_fixture, DiffMode::Strict, false)
            .expect("regressed snapshot diff");
    let regressed_plain_ui = render_ftui(&regressed_report, false, 120);
    let regressed_checksum = compute_ftui_snapshot_checksum(&regressed_report, 120);

    assert_ne!(regressed_checksum, expected_checksum);
    assert!(
        regressed_plain_ui.contains("ALERT"),
        "1-row threshold regression must render ALERT in ftui output:\n{regressed_plain_ui}"
    );

    let regression_cmp = compare_ftui_snapshots(1, &baseline_report, &regressed_report, 120);
    assert!(
        !regression_cmp.pass,
        "1-row regression must fail FrameComparator"
    );
    assert!(
        regression_cmp.mismatch_count > 0,
        "FrameComparator must report non-zero mismatched cells"
    );

    let raw_visual_diff = render_ftui_raw_diff(&expected_plain_ui, &regressed_plain_ui);
    assert!(
        !raw_visual_diff.is_empty(),
        "ftui_harness::diff_text must produce non-empty structured visual diff"
    );
    assert!(
        raw_visual_diff.contains("ALERT")
            && raw_visual_diff.contains("full_validation_trigger_ppm"),
        "visual diff must pinpoint the regressed row:\n{raw_visual_diff}"
    );
}

#[test]
fn tooling_dependency_boundary_passes_at_head_and_rejects_synthetic_runtime_leakage() {
    let root = workspace_root();
    let script = root.join("scripts/check_tooling_dependency_boundary.sh");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let scratch = std::env::temp_dir().join(format!(
        "frankenlibc-wave52-boundary-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&scratch).expect("create temp scratch dir");

    // 1. Positive gate at HEAD (with default = ["asupersync-tooling", "frankentui-ui"]).
    let head_report = scratch.join("head.report.json");
    let head_log = scratch.join("head.log.jsonl");
    let head_out = Command::new("bash")
        .arg(&script)
        .arg("--validate-only")
        .current_dir(&root)
        .env("TOOLING_DEP_BOUNDARY_REPORT", &head_report)
        .env("TOOLING_DEP_BOUNDARY_LOG", &head_log)
        .output()
        .expect("run check_tooling_dependency_boundary.sh at HEAD");
    assert!(
        head_out.status.success(),
        "check_tooling_dependency_boundary.sh must pass at HEAD:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&head_out.stdout),
        String::from_utf8_lossy(&head_out.stderr)
    );
    let head_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&head_report).expect("read head report"))
            .expect("parse head report");
    assert_eq!(head_json["outcome"], "pass");
    assert_eq!(head_json["summary"]["runtime_dependency_leakage_count"], 0);

    // 2. Negative control: inject `asupersync-conformance` into a synthetic copy of
    //    `crates/frankenlibc-abi/Cargo.toml` and verify the gate fails closed with
    //    `runtime_dependency_leakage`.
    let real_abi_manifest = std::fs::read_to_string(root.join("crates/frankenlibc-abi/Cargo.toml"))
        .expect("read real frankenlibc-abi Cargo.toml");
    let poisoned_abi_manifest = real_abi_manifest.replacen(
        "[dependencies]\n",
        "[dependencies]\nasupersync-conformance = { workspace = true }\n",
        1,
    );
    assert_ne!(
        poisoned_abi_manifest, real_abi_manifest,
        "poisoned manifest must inject companion dependency"
    );
    let poisoned_abi_path = scratch.join("poisoned_abi_Cargo.toml");
    std::fs::write(&poisoned_abi_path, poisoned_abi_manifest).expect("write poisoned Cargo.toml");

    let neg_report = scratch.join("neg.report.json");
    let neg_log = scratch.join("neg.log.jsonl");
    let neg_out = Command::new("bash")
        .arg(&script)
        .arg("--validate-only")
        .current_dir(&root)
        .env("TOOLING_DEP_BOUNDARY_ABI_CARGO", &poisoned_abi_path)
        .env("TOOLING_DEP_BOUNDARY_REPORT", &neg_report)
        .env("TOOLING_DEP_BOUNDARY_LOG", &neg_log)
        .output()
        .expect("run negative-control check_tooling_dependency_boundary.sh");
    assert!(
        !neg_out.status.success(),
        "synthetic runtime companion dependency leakage must fail closed"
    );
    let neg_json: Value =
        serde_json::from_str(&std::fs::read_to_string(&neg_report).expect("read neg report"))
            .expect("parse neg report");
    assert_eq!(neg_json["outcome"], "fail");
    assert_eq!(neg_json["failure_signature"], "runtime_dependency_leakage");
}
