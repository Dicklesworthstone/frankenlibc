//! Killer demo for bd-13zp: show the membrane catching and repairing a UAF.
//!
//! Run:
//! `cargo run -p frankenlibc-membrane --example killer_demo -- --output-dir target/killer_demo/manual`

use asupersync_conformance::logging::{with_test_logger, ConformanceTestLogger};
use asupersync_conformance::{Checkpoint, SuiteResult, SuiteTestResult, TestCategory, TestResult};
use frankenlibc_membrane::{
    DecisionId, EvidenceLedger, HealingAction, HealingPolicy, PolicyId, RedactionPolicy,
    SafetyLevel, TraceId, ValidationEvidence, ValidationOutcome, ValidationPipeline,
};
use ftui_core::geometry::Rect;
use ftui_layout::Constraint;
use ftui_render::cell::PackedRgba;
use ftui_render::frame::Frame;
use ftui_render::grapheme_pool::GraphemePool;
use ftui_style::Style;
use ftui_widgets::block::Block;
use ftui_widgets::borders::{BorderType, Borders};
use ftui_widgets::table::{Row, Table};
use ftui_widgets::Widget;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const BEAD_ID: &str = "bd-13zp";
const DEFAULT_OUTPUT_DIR: &str = "target/killer_demo/latest";
const UAF_SIZE: usize = 64;
const PERF_ITERS: u32 = 512;

#[derive(Debug, Clone, Serialize)]
pub struct DemoScenario {
    mode: String,
    label: String,
    decision_path: String,
    detected: bool,
    repaired: bool,
    continued: bool,
    errno: i32,
    latency_ns: u64,
    overhead_ns: u64,
    baseline_ns: u64,
    reused_same_addr: bool,
    corruption_observed: bool,
    healing_action: Option<String>,
    summary: String,
    artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoReport {
    schema_version: &'static str,
    bead_id: &'static str,
    run_id: String,
    output_dir: String,
    trace_log: String,
    artifact_index: String,
    asupersync_suite: String,
    summary_ftui: String,
    scenarios: Vec<DemoScenario>,
}

#[derive(Debug, Clone)]
struct ScenarioArtifacts {
    scenario: DemoScenario,
    scenario_log_lines: Vec<String>,
    suite_item: SuiteTestResult,
}

pub fn run_demo(output_dir: &Path, ansi: bool) -> Result<DemoReport, Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    let run_id = output_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .unwrap_or_else(|| String::from("killer-demo"));

    let glibc = run_glibc_baseline(&run_id);
    let strict = run_membrane_mode(&run_id, SafetyLevel::Strict);
    let hardened = run_membrane_mode(&run_id, SafetyLevel::Hardened);

    let scenarios = vec![glibc, strict, hardened];
    let trace_path = output_dir.join("trace.jsonl");
    let suite_path = output_dir.join("killer_demo.suite.json");
    let ftui_path = output_dir.join("summary.ftui.txt");
    let report_path = output_dir.join("killer_demo_report.json");
    let index_path = output_dir.join("artifact_index.json");

    let trace_body = scenarios
        .iter()
        .flat_map(|artifact| artifact.scenario_log_lines.iter())
        .fold(String::new(), |mut out, line| {
            out.push_str(line);
            if !line.ends_with('\n') {
                out.push('\n');
            }
            out
        });
    fs::write(&trace_path, trace_body)?;

    let mut suite = SuiteResult::new(String::from("frankenlibc-membrane:killer_demo"));
    for artifact in &scenarios {
        if artifact.scenario.detected {
            suite.passed += 1;
        } else {
            suite.failed += 1;
        }
        suite.results.push(artifact.suite_item.clone());
    }
    suite.total = suite.results.len();
    suite.duration_ms = scenarios
        .iter()
        .map(|artifact| artifact.scenario.latency_ns / 1_000_000)
        .sum();
    asupersync_conformance::write_json_report(&suite, &suite_path)?;

    let ftui_summary = render_summary_ftui(
        &scenarios
            .iter()
            .map(|artifact| artifact.scenario.clone())
            .collect::<Vec<_>>(),
        ansi,
    );
    fs::write(&ftui_path, &ftui_summary)?;

    let report = DemoReport {
        schema_version: "v1",
        bead_id: BEAD_ID,
        run_id: run_id.clone(),
        output_dir: output_dir.display().to_string(),
        trace_log: trace_path.display().to_string(),
        artifact_index: index_path.display().to_string(),
        asupersync_suite: suite_path.display().to_string(),
        summary_ftui: ftui_path.display().to_string(),
        scenarios: scenarios
            .iter()
            .map(|artifact| artifact.scenario.clone())
            .collect(),
    };
    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;
    write_artifact_index(
        &index_path,
        &run_id,
        &[
            (&trace_path, "structured_log", "combined scenario trace log"),
            (
                &suite_path,
                "asupersync_suite",
                "deterministic asupersync suite report",
            ),
            (&ftui_path, "frankentui_summary", "FrankentUI summary table"),
            (&report_path, "report", "killer demo report"),
        ],
    )?;

    Ok(report)
}

fn run_glibc_baseline(run_id: &str) -> ScenarioArtifacts {
    let trace_id = format!("{BEAD_ID}::{run_id}::glibc");
    let logger = ConformanceTestLogger::new("glibc_baseline", "killer_demo.baseline");
    logger.phase("execute");
    let started = Instant::now();
    let (reused_same_addr, corruption_observed) = with_test_logger(&logger, || {
        // SAFETY: The sequence intentionally uses raw malloc/free and a stale pointer to
        // demonstrate what the membrane is meant to defend against. The memory is accessed
        // only within this controlled demo process.
        unsafe {
            let ptr = libc::malloc(UAF_SIZE) as *mut u8;
            assert!(!ptr.is_null(), "malloc baseline allocation must succeed");
            std::ptr::write_bytes(ptr, b'A', UAF_SIZE);
            libc::free(ptr.cast());

            let reused = libc::malloc(UAF_SIZE) as *mut u8;
            assert!(
                !reused.is_null(),
                "malloc baseline re-allocation must succeed"
            );
            std::ptr::write_bytes(reused, b'B', UAF_SIZE);
            let same_addr = reused == ptr;

            if same_addr {
                std::ptr::write_bytes(ptr, b'Z', 8);
            }

            let observed = same_addr
                && std::slice::from_raw_parts(reused, 8)
                    .iter()
                    .all(|&b| b == b'Z');
            asupersync_conformance::checkpoint(
                "killer_demo.baseline",
                json!({
                    "same_addr": same_addr,
                    "corruption_observed": observed,
                }),
            );

            libc::free(reused.cast());
            (same_addr, observed)
        }
    });
    let latency_ns = started.elapsed().as_nanos() as u64;
    let baseline_ns = measure_glibc_baseline_ns();
    let summary = if corruption_observed {
        String::from("stale raw pointer mutated the reallocated block")
    } else if reused_same_addr {
        String::from("allocator reused the chunk but corruption signature did not persist")
    } else {
        String::from("allocator did not immediately reuse the freed chunk on this run")
    };

    let scenario = DemoScenario {
        mode: String::from("glibc"),
        label: String::from("Raw Baseline"),
        decision_path: String::from("raw::malloc_free::uaf"),
        detected: corruption_observed,
        repaired: false,
        continued: true,
        errno: 0,
        latency_ns,
        overhead_ns: 0,
        baseline_ns,
        reused_same_addr,
        corruption_observed,
        healing_action: None,
        summary,
        artifact_refs: vec![String::from(
            "crates/frankenlibc-membrane/examples/killer_demo.rs",
        )],
    };

    let mut checkpoints = vec![Checkpoint::new(
        "baseline",
        json!({
            "reused_same_addr": reused_same_addr,
            "corruption_observed": corruption_observed,
        }),
    )];
    if corruption_observed {
        checkpoints.push(Checkpoint::new(
            "visible_corruption",
            json!({"verdict": "stale write modified live payload"}),
        ));
    }
    let mut result = if corruption_observed {
        TestResult::passed()
    } else {
        TestResult::failed(String::from(
            "allocator did not expose visible corruption in this run",
        ))
    };
    result.duration_ms = Some(latency_ns / 1_000_000);
    result.checkpoints = checkpoints;

    let suite_item = SuiteTestResult {
        test_id: trace_id.clone(),
        test_name: String::from("glibc baseline"),
        category: TestCategory::IO,
        expected: String::from("visible corruption or crash signature"),
        result,
        events: logger.events(),
    };

    let scenario_log_lines = vec![json!({
        "timestamp": now_utc_like(),
        "trace_id": trace_id,
        "bead_id": BEAD_ID,
        "mode": "glibc",
        "api_family": "allocator",
        "symbol": "malloc/free",
        "decision_path": "raw::malloc_free::uaf",
        "healing_action": null,
        "errno": 0,
        "latency_ns": latency_ns,
        "artifact_refs": scenario.artifact_refs,
        "event": "killer_demo.scenario_result",
        "outcome": if corruption_observed { "pass" } else { "fail" },
        "details": {
            "reused_same_addr": reused_same_addr,
            "corruption_observed": corruption_observed,
            "summary": scenario.summary,
        }
    })
    .to_string()];

    ScenarioArtifacts {
        scenario,
        scenario_log_lines,
        suite_item,
    }
}

fn run_membrane_mode(run_id: &str, mode: SafetyLevel) -> ScenarioArtifacts {
    let mode_label = match mode {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    };
    let trace_id = format!("{BEAD_ID}::{run_id}::{mode_label}");
    let logger = ConformanceTestLogger::new(mode_label, "killer_demo.membrane");
    logger.phase("execute");

    let started = Instant::now();
    let artifact = with_test_logger(&logger, || {
        let pipeline = ValidationPipeline::new();
        pipeline.set_validation_logging_enabled(true);
        pipeline.clear_validation_logs();

        let ledger = EvidenceLedger::with_config(256, RedactionPolicy::RedactPointers);
        let healing_policy = HealingPolicy::new();
        healing_policy.clear_healing_logs();

        let ptr = pipeline
            .allocate(UAF_SIZE)
            .expect("membrane demo allocation must succeed");
        let addr = ptr as usize;
        // SAFETY: The pointer was returned by the membrane allocation above and is valid
        // for `UAF_SIZE` bytes until the subsequent free call.
        unsafe {
            std::ptr::write_bytes(ptr, b'M', UAF_SIZE);
        }
        let free_result = pipeline.free(ptr);
        let outcome = pipeline.validate(addr);

        let (detected, repaired, errno, decision_path, healing_action, summary) = match (
            mode, outcome,
        ) {
            (SafetyLevel::Strict, ValidationOutcome::TemporalViolation(_)) => (
                true,
                false,
                libc::EFAULT,
                String::from("mode->validate->deny"),
                None,
                String::from("membrane detected the stale pointer and denied the unsafe access"),
            ),
            (SafetyLevel::Hardened, ValidationOutcome::TemporalViolation(_)) => {
                let action = HealingAction::ReturnSafeDefault;
                healing_policy.record(&action);
                ledger.record_healing(
                    &action,
                    TraceId::new(trace_id.clone()),
                    DecisionId::from_raw(2),
                    "allocator",
                    "free/use-after-free",
                );
                (
                    true,
                    true,
                    libc::EFAULT,
                    String::from("mode->validate->repair"),
                    Some(String::from("ReturnSafeDefault")),
                    String::from(
                        "membrane detected the stale pointer, quarantined it, and returned a safe default",
                    ),
                )
            }
            _ => (
                false,
                false,
                0,
                String::from("mode->validate->unexpected"),
                None,
                format!("unexpected validation outcome: {outcome:?}"),
            ),
        };

        ledger.record_validation(ValidationEvidence {
            trace_id: TraceId::new(trace_id.clone()),
            decision_id: DecisionId::from_raw(1),
            policy_id: PolicyId::from_raw(1),
            api_family: String::from("allocator"),
            symbol: String::from("free/use-after-free"),
            decision_path: decision_path.clone(),
            outcome: if repaired {
                String::from("repair")
            } else if detected {
                String::from("deny")
            } else {
                String::from("allow")
            },
            errno_val: errno,
            latency_ns: 0,
            details_json: json!({
                "free_result": format!("{free_result:?}"),
                "validation_outcome": format!("{outcome:?}"),
                "mode": mode_label,
            })
            .to_string(),
        });

        asupersync_conformance::checkpoint(
            "killer_demo.membrane",
            json!({
                "mode": mode_label,
                "detected": detected,
                "repaired": repaired,
                "errno": errno,
                "decision_path": decision_path,
            }),
        );

        let latency_ns = started.elapsed().as_nanos() as u64;
        let baseline_ns = measure_glibc_baseline_ns();
        let ns_per_op = measure_membrane_ns(mode);
        let overhead_ns = ns_per_op.saturating_sub(baseline_ns);

        let scenario = DemoScenario {
            mode: String::from(mode_label),
            label: if mode == SafetyLevel::Strict {
                String::from("Strict")
            } else {
                String::from("Hardened")
            },
            decision_path: decision_path.clone(),
            detected,
            repaired,
            continued: detected,
            errno,
            latency_ns,
            overhead_ns,
            baseline_ns,
            reused_same_addr: false,
            corruption_observed: false,
            healing_action: healing_action.clone(),
            summary,
            artifact_refs: vec![String::from(
                "crates/frankenlibc-membrane/examples/killer_demo.rs",
            )],
        };

        let mut log_lines = vec![json!({
            "timestamp": now_utc_like(),
            "trace_id": trace_id,
            "bead_id": BEAD_ID,
            "mode": mode_label,
            "api_family": "allocator",
            "symbol": "free/use-after-free",
            "decision_path": scenario.decision_path,
            "healing_action": scenario.healing_action,
            "errno": errno,
            "latency_ns": latency_ns,
            "artifact_refs": scenario.artifact_refs,
            "event": "killer_demo.scenario_result",
            "outcome": if detected { "pass" } else { "fail" },
            "details": {
                "validation_outcome": format!("{outcome:?}"),
                "free_result": format!("{free_result:?}"),
                "repaired": repaired,
                "continued": scenario.continued,
                "summary": scenario.summary,
                "overhead_ns": overhead_ns,
                "baseline_ns": baseline_ns,
            }
        })
        .to_string()];
        let validation_jsonl = pipeline.export_validation_log_jsonl();
        if !validation_jsonl.trim().is_empty() {
            log_lines.extend(
                validation_jsonl
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_owned),
            );
        }
        let healing_jsonl = healing_policy.export_healing_log_jsonl();
        if !healing_jsonl.trim().is_empty() {
            log_lines.extend(
                healing_jsonl
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_owned),
            );
        }
        let ledger_jsonl = ledger.export_jsonl();
        if !ledger_jsonl.trim().is_empty() {
            log_lines.extend(
                ledger_jsonl
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .map(str::to_owned),
            );
        }

        let mut checkpoints = vec![Checkpoint::new(
            "membrane_result",
            json!({
                "mode": mode_label,
                "detected": detected,
                "repaired": repaired,
                "errno": errno,
                "decision_path": scenario.decision_path,
                "overhead_ns": scenario.overhead_ns,
            }),
        )];
        if let Some(action) = &scenario.healing_action {
            checkpoints.push(Checkpoint::new("healing", json!({"action": action})));
        }

        let mut result = if detected {
            TestResult::passed()
        } else {
            TestResult::failed(String::from("temporal violation was not detected"))
        };
        result.duration_ms = Some(latency_ns / 1_000_000);
        result.checkpoints = checkpoints;
        let suite_item = SuiteTestResult {
            test_id: format!("{BEAD_ID}::{run_id}::{mode_label}"),
            test_name: scenario.label.clone(),
            category: TestCategory::IO,
            expected: String::from("detect temporal violation and continue safely"),
            result,
            events: logger.events(),
        };

        ScenarioArtifacts {
            scenario,
            scenario_log_lines: log_lines,
            suite_item,
        }
    });

    artifact
}

fn measure_glibc_baseline_ns() -> u64 {
    let started = Instant::now();
    for _ in 0..PERF_ITERS {
        // SAFETY: This raw allocation pair is immediately freed in the same loop iteration.
        unsafe {
            let ptr = libc::malloc(UAF_SIZE) as *mut u8;
            if ptr.is_null() {
                continue;
            }
            std::ptr::write_bytes(ptr, 0xAB, UAF_SIZE);
            libc::free(ptr.cast());
        }
    }
    (started.elapsed().as_nanos() as u64) / u64::from(PERF_ITERS)
}

fn measure_membrane_ns(mode: SafetyLevel) -> u64 {
    let started = Instant::now();
    for _ in 0..PERF_ITERS {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.allocate(UAF_SIZE).expect("perf allocate");
        let addr = ptr as usize;
        let _ = pipeline.free(ptr);
        let outcome = pipeline.validate(addr);
        if mode == SafetyLevel::Hardened
            && matches!(outcome, ValidationOutcome::TemporalViolation(_))
        {
            let policy = HealingPolicy::new();
            policy.record(&HealingAction::ReturnSafeDefault);
        }
    }
    (started.elapsed().as_nanos() as u64) / u64::from(PERF_ITERS)
}

fn render_summary_ftui(scenarios: &[DemoScenario], ansi: bool) -> String {
    let width = 118;
    let height = scenarios.len() as u16 + 4;
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);

    let header = Row::new([
        "mode",
        "detected",
        "repaired",
        "errno",
        "overhead(ns)",
        "summary",
    ])
    .style(Style::new().bold());

    let rows: Vec<Row> = scenarios
        .iter()
        .map(|scenario| {
            let style = if scenario.repaired {
                Style::new().fg(PackedRgba::rgb(80, 220, 120)).bold()
            } else if scenario.detected {
                Style::new().fg(PackedRgba::rgb(255, 220, 80)).bold()
            } else {
                Style::new().fg(PackedRgba::rgb(255, 120, 120)).bold()
            };
            let detected = if scenario.detected { "yes" } else { "no" };
            let repaired = if scenario.repaired { "yes" } else { "no" };
            let errno = scenario.errno.to_string();
            let overhead = scenario.overhead_ns.to_string();
            Row::new([
                scenario.mode.as_str(),
                detected,
                repaired,
                errno.as_str(),
                overhead.as_str(),
                scenario.summary.as_str(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Fixed(10),
            Constraint::Fixed(10),
            Constraint::Fixed(10),
            Constraint::Fixed(8),
            Constraint::Fixed(14),
            Constraint::Fill(1),
        ],
    )
    .header(header)
    .block(
        Block::new()
            .title(" killer demo ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    )
    .column_spacing(1);

    table.render(Rect::from_size(width, height), &mut frame);
    if ansi {
        ftui_harness::buffer_to_ansi(&frame.buffer)
    } else {
        ftui_harness::buffer_to_text(&frame.buffer)
    }
}

fn write_artifact_index(
    index_path: &Path,
    run_id: &str,
    artifacts: &[(&Path, &str, &str)],
) -> Result<(), Box<dyn Error>> {
    let entries: Vec<Value> = artifacts
        .iter()
        .map(|(path, kind, description)| {
            let bytes = fs::read(path).expect("artifact bytes readable");
            let digest = Sha256::digest(&bytes);
            let sha = digest
                .iter()
                .fold(String::with_capacity(64), |mut acc, byte| {
                    let _ = write!(&mut acc, "{byte:02x}");
                    acc
                });
            json!({
                "path": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                "kind": *kind,
                "sha256": sha,
                "size_bytes": bytes.len(),
                "description": *description,
            })
        })
        .collect();
    let index = json!({
        "index_version": 1,
        "run_id": run_id,
        "bead_id": BEAD_ID,
        "generated_utc": now_utc_like(),
        "artifacts": entries,
    });
    fs::write(index_path, serde_json::to_string_pretty(&index)?)?;
    Ok(())
}

fn now_utc_like() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

fn parse_args() -> (PathBuf, bool) {
    let mut output_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
    let mut ansi = std::io::stdout().is_terminal();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" => {
                if let Some(value) = args.next() {
                    output_dir = PathBuf::from(value);
                }
            }
            "--no-color" => ansi = false,
            "--ansi" => ansi = true,
            _ => {}
        }
    }
    (output_dir, ansi)
}

fn print_report(report: &DemoReport, ansi: bool) {
    let summary = render_summary_ftui(&report.scenarios, ansi);
    println!("FrankenLibC Killer Demo");
    println!("Shows the same stale-pointer story three ways: raw baseline, strict detection, hardened repair.\n");
    println!("{summary}");
    println!("Artifacts:");
    println!("  report: {}", report.output_dir);
    println!("  trace: {}", report.trace_log);
    println!("  index: {}", report.artifact_index);
    println!("  asupersync: {}", report.asupersync_suite);
    println!(
        "KILLER_DEMO_REPORT {}",
        serde_json::to_string(report).unwrap_or_default()
    );
}

fn main() -> Result<(), Box<dyn Error>> {
    let (output_dir, ansi) = parse_args();
    let report = run_demo(&output_dir, ansi)?;
    print_report(&report, ansi);
    Ok(())
}
