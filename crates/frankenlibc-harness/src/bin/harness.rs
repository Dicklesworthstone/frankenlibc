//! CLI entrypoint for frankenlibc conformance harness.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::process::Stdio;
use std::time::{Duration, Instant};

use frankenlibc_harness::conformance_matrix::{CaseExecution, ConformanceMatrixReport};
use frankenlibc_harness::healing_oracle::HealingOracleReport;
use frankenlibc_harness::shadow_run::{ProcessShadowExecutor, ShadowRunConfig, ShadowRunManifest};
use frankenlibc_harness::structured_log::{LogEmitter, LogEntry, LogLevel, Outcome, StreamKind};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

const CONFORMANCE_LOG_BEAD_ID: &str = "bd-2hh.7";
const CONFORMANCE_LOG_GATE: &str = "conformance_matrix";
const CONFORMANCE_WARN_BUDGET_PERCENT: u64 = 80;
const HEALING_LOG_GATE: &str = "healing_oracle";

/// Conformance tooling for frankenlibc.
#[derive(Debug, Parser)]
#[command(name = "frankenlibc-harness")]
#[command(about = "Conformance testing harness for frankenlibc")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Capture host glibc behavior as fixture files.
    Capture {
        /// Input template directory for fixture JSON files.
        #[arg(long, default_value = "tests/conformance/fixtures")]
        input: PathBuf,
        /// Output directory for fixture JSON files.
        #[arg(long)]
        output: PathBuf,
        /// Function family to capture (e.g., "string", "malloc").
        #[arg(long)]
        family: String,
    },
    /// Verify our implementation against captured fixtures.
    Verify {
        /// Directory containing fixture JSON files.
        #[arg(long)]
        fixture: PathBuf,
        /// Output report path (markdown).
        #[arg(long)]
        report: Option<PathBuf>,
        /// Optional fixed timestamp string for deterministic report generation.
        #[arg(long)]
        timestamp: Option<String>,
    },
    /// Generate traceability matrix.
    Traceability {
        /// Input support matrix JSON path.
        #[arg(long, default_value = "support_matrix.json")]
        support_matrix: PathBuf,
        /// Fixture directory path.
        #[arg(long, default_value = "tests/conformance/fixtures")]
        fixture: PathBuf,
        /// Input conformance matrix JSON path.
        #[arg(long, default_value = "tests/conformance/conformance_matrix.v1.json")]
        conformance_matrix: PathBuf,
        /// Integration C fixture specification path.
        #[arg(long, default_value = "tests/conformance/c_fixture_spec.json")]
        c_fixture_spec: PathBuf,
        /// Output markdown path.
        #[arg(long)]
        output_md: PathBuf,
        /// Output JSON path.
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Generate machine-readable docs reality report from support matrix taxonomy.
    RealityReport {
        /// Input support matrix JSON path.
        #[arg(long, default_value = "support_matrix.json")]
        support_matrix: PathBuf,
        /// Output JSON path (if omitted, prints to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate POSIX conformance coverage report across symbols.
    PosixConformanceReport {
        /// Input support matrix JSON path.
        #[arg(long, default_value = "support_matrix.json")]
        support_matrix: PathBuf,
        /// Fixture directory path.
        #[arg(long, default_value = "tests/conformance/fixtures")]
        fixture: PathBuf,
        /// Input conformance matrix JSON path.
        #[arg(long, default_value = "tests/conformance/conformance_matrix.v1.json")]
        conformance_matrix: PathBuf,
        /// Output JSON report path.
        #[arg(
            long,
            default_value = "target/conformance/posix_conformance_report.current.v1.json"
        )]
        output: PathBuf,
    },
    /// Generate POSIX obligation traceability matrix across unit + C fixture packs.
    PosixObligationReport {
        /// Input support matrix JSON path.
        #[arg(long, default_value = "support_matrix.json")]
        support_matrix: PathBuf,
        /// Fixture directory path.
        #[arg(long, default_value = "tests/conformance/fixtures")]
        fixture: PathBuf,
        /// Input conformance matrix JSON path.
        #[arg(long, default_value = "tests/conformance/conformance_matrix.v1.json")]
        conformance_matrix: PathBuf,
        /// Integration C fixture specification path.
        #[arg(long, default_value = "tests/conformance/c_fixture_spec.json")]
        c_fixture_spec: PathBuf,
        /// Output JSON report path.
        #[arg(
            long,
            default_value = "target/conformance/posix_obligation_matrix.current.v1.json"
        )]
        output: PathBuf,
    },
    /// Generate errno + edge-case prioritization report across high-impact APIs.
    ErrnoEdgeReport {
        /// Input support matrix JSON path.
        #[arg(long, default_value = "support_matrix.json")]
        support_matrix: PathBuf,
        /// Fixture directory path.
        #[arg(long, default_value = "tests/conformance/fixtures")]
        fixture: PathBuf,
        /// Input conformance matrix JSON path.
        #[arg(long, default_value = "tests/conformance/conformance_matrix.v1.json")]
        conformance_matrix: PathBuf,
        /// Output JSON report path.
        #[arg(
            long,
            default_value = "target/conformance/errno_edge_report.current.v1.json"
        )]
        output: PathBuf,
    },
    /// Run membrane-specific verification tests.
    VerifyMembrane {
        /// Runtime mode to test (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Output report path.
        #[arg(
            long,
            default_value = "target/conformance/healing_oracle.current.v1.json"
        )]
        output: PathBuf,
        /// Structured JSONL output path for healing-oracle case events.
        #[arg(long, default_value = "target/conformance/healing_oracle.log.jsonl")]
        log: PathBuf,
        /// Logical campaign identifier used in trace ids.
        #[arg(long, default_value = "healing_oracle")]
        campaign: String,
        /// Return non-zero when any oracle case fails.
        #[arg(long)]
        fail_on_mismatch: bool,
    },
    /// Validate a structured-log + artifact-index evidence bundle.
    EvidenceCompliance {
        /// Workspace root used for fallback artifact resolution.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log path.
        #[arg(long)]
        log: PathBuf,
        /// Artifact index JSON path.
        #[arg(long)]
        artifact_index: PathBuf,
        /// Optional output path for triage JSON report (if omitted, prints to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a trace-to-decision explainability workbench from structured logs.
    ExplainabilityWorkbench {
        /// Structured JSONL log path.
        #[arg(long)]
        log: PathBuf,
        /// Optional artifact-index JSON path used for trace joins.
        #[arg(long)]
        artifact_index: Option<PathBuf>,
        /// Optional trace id filter.
        #[arg(long)]
        trace_id: Option<String>,
        /// Optional scenario id filter.
        #[arg(long)]
        scenario_id: Option<String>,
        /// Output format: `json` (default), `plain`, or `ftui` (requires `frankentui-ui`).
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path (if omitted, prints to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Emit ANSI color/styling (only when `frankentui-ui` is enabled and `--format ftui`).
        #[arg(long)]
        ansi: bool,
        /// Render width for the UI table (only when `frankentui-ui` is enabled and `--format ftui`).
        #[arg(long, default_value_t = 140)]
        width: u16,
    },
    /// Decode exported evidence symbol records and emit an explainable proof report.
    DecodeEvidence {
        /// Input path containing concatenated 256-byte `EvidenceSymbolRecord` blobs.
        #[arg(long)]
        input: PathBuf,
        /// Optional epoch filter (only decode this epoch id).
        #[arg(long)]
        epoch_id: Option<u64>,
        /// Output format: `json` (default), `plain`, or `ftui` (requires `frankentui-ui`).
        #[arg(long, default_value = "json")]
        format: String,
        /// Output file path (if omitted, prints to stdout).
        #[arg(long)]
        output: Option<PathBuf>,
        /// Emit ANSI color/styling (only when `frankentui-ui` is enabled and `--format ftui`).
        #[arg(long)]
        ansi: bool,
        /// Render width for the UI table (only when `frankentui-ui` is enabled and `--format ftui`).
        #[arg(long, default_value_t = 140)]
        width: u16,
    },
    /// Capture deterministic runtime_math kernel snapshots as a fixture.
    SnapshotKernel {
        /// Output path for fixture JSON.
        #[arg(long)]
        output: PathBuf,
        /// Mode to capture (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Root seed (decimal or 0x...).
        #[arg(long, default_value = "0xDEAD_BEEF")]
        seed: String,
        /// Number of decision steps to run.
        #[arg(long, default_value_t = 128)]
        steps: u32,
    },
    /// Diff two runtime_math kernel snapshot fixtures (golden vs current).
    DiffKernelSnapshot {
        /// Golden fixture path.
        #[arg(
            long,
            default_value = "tests/runtime_math/golden/kernel_snapshot_smoke.v1.json"
        )]
        golden: PathBuf,
        /// Current fixture path (optional; if missing, one will be generated in-memory).
        #[arg(
            long,
            default_value = "target/runtime_math_golden/kernel_snapshot_smoke.v1.json"
        )]
        current: PathBuf,
        /// Mode to diff (`strict` or `hardened`).
        #[arg(long, default_value = "strict")]
        mode: String,
        /// Include all snapshot fields (not only the curated key set).
        #[arg(long)]
        all: bool,
        /// Emit ANSI color/styling (only when `frankentui-ui` is enabled).
        #[arg(long)]
        ansi: bool,
        /// Render width for the UI table (only when `frankentui-ui` is enabled).
        #[arg(long, default_value_t = 120)]
        width: u16,
    },
    /// Generate a strict-vs-hardened regression report for runtime_math (runs two subprocesses).
    KernelRegressionReport {
        /// Output report path (markdown). If omitted, prints to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Root seed (decimal or 0x...).
        #[arg(long, default_value = "0xDEAD_BEEF")]
        seed: String,
        /// Number of decision steps to run for kernel evolution.
        #[arg(long, default_value_t = 256)]
        steps: u32,
        /// Microbench warmup iterations.
        #[arg(long, default_value_t = 10_000)]
        warmup_iters: u64,
        /// Microbench sample count.
        #[arg(long, default_value_t = 25)]
        samples: usize,
        /// Microbench iterations per sample.
        #[arg(long, default_value_t = 50_000)]
        iters: u64,
        /// Snapshot trend stride (steps between Pareto points).
        #[arg(long, default_value_t = 32)]
        trend_stride: u32,
    },
    /// Internal: emit per-mode JSON metrics for the regression report.
    ///
    /// This is a separate command because FRANKENLIBC_MODE is process-immutable.
    KernelRegressionMode {
        /// Expected mode (`strict` or `hardened`) for cross-checking env config.
        #[arg(long)]
        mode: String,
        /// Root seed (decimal or 0x...).
        #[arg(long, default_value = "0xDEAD_BEEF")]
        seed: String,
        /// Number of decision steps to run for kernel evolution.
        #[arg(long, default_value_t = 256)]
        steps: u32,
        /// Microbench warmup iterations.
        #[arg(long, default_value_t = 10_000)]
        warmup_iters: u64,
        /// Microbench sample count.
        #[arg(long, default_value_t = 25)]
        samples: usize,
        /// Microbench iterations per sample.
        #[arg(long, default_value_t = 50_000)]
        iters: u64,
        /// Snapshot trend stride (steps between Pareto points).
        #[arg(long, default_value_t = 32)]
        trend_stride: u32,
    },
    /// Validate runtime_math decision-law linkage for all production controllers.
    RuntimeMathLinkageProofs {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_linkage_proofs.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_linkage_proofs.report.json"
        )]
        report: PathBuf,
    },
    /// Validate the discrete HJI viability artifact and runtime wiring.
    RuntimeMathHjiViabilityProofs {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_hji_viability_proofs.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_hji_viability_proofs.report.json"
        )]
        report: PathBuf,
    },
    /// Prove CPOMDP safety feasibility for the repair-policy abstraction.
    RuntimeMathCpomdpFeasibilityProofs {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_cpomdp_feasibility_proofs.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_cpomdp_feasibility_proofs.report.json"
        )]
        report: PathBuf,
        /// CPOMDP feasibility artifact output path.
        #[arg(long, default_value = "target/conformance/cpomdp_feasibility.json")]
        feasibility_artifact: PathBuf,
        /// CPOMDP epsilon-sensitivity artifact output path.
        #[arg(long, default_value = "target/conformance/cpomdp_sensitivity.json")]
        sensitivity_artifact: PathBuf,
    },
    /// Validate runtime_math determinism + invariants for decide/observe integration.
    RuntimeMathDeterminismProofs {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_determinism_proofs.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_determinism_proofs.report.json"
        )]
        report: PathBuf,
    },
    /// Validate strict-vs-hardened divergence bounds for runtime_math decisions.
    RuntimeMathDivergenceBounds {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_divergence_bounds.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/runtime_math_divergence_bounds.report.json"
        )]
        report: PathBuf,
    },
    /// Validate the proof-obligation binder, unit-test pack, and snapshot parity.
    ProofBinderProofs {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_binder_proofs.log.jsonl"
        )]
        log: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_binder_proofs.report.json"
        )]
        report: PathBuf,
        /// Fresh validator snapshot output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_binder_validation.current.v1.json"
        )]
        validator_report: PathBuf,
    },
    /// Run the proof-chain E2E gate over binder integrity, dashboard totals, and contradictions.
    ProofChainE2e {
        /// Workspace root used for resolving canonical artifacts.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Structured JSONL log output path.
        #[arg(long, default_value = "target/conformance/proof_chain_e2e.log.jsonl")]
        log: PathBuf,
        /// JSON report output path.
        #[arg(long, default_value = "target/conformance/proof_chain_e2e.report.json")]
        report: PathBuf,
        /// Nested proof-binder log output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_chain_e2e.proof_binder.log.jsonl"
        )]
        binder_log: PathBuf,
        /// Nested proof-binder report output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_chain_e2e.proof_binder.report.json"
        )]
        binder_report: PathBuf,
        /// Fresh validator snapshot output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_chain_e2e.validator.current.v1.json"
        )]
        validator_report: PathBuf,
        /// Generated cross-report consistency output path.
        #[arg(
            long,
            default_value = "target/conformance/proof_chain_e2e.cross_report.current.v1.json"
        )]
        cross_report: PathBuf,
    },
    /// Build an operator-facing observability dashboard bundle from JSONL metrics streams.
    ObservabilityDashboard {
        /// One or more JSONL metric/evidence inputs.
        #[arg(long = "input", required = true, num_args = 1..)]
        input: Vec<PathBuf>,
        /// JSON summary output path.
        #[arg(
            long,
            default_value = "target/conformance/observability_dashboard.current.v1.json"
        )]
        output: PathBuf,
        /// Prometheus exposition output path.
        #[arg(
            long,
            default_value = "target/conformance/observability_dashboard.prom"
        )]
        prometheus_output: PathBuf,
        /// StatsD line protocol output path.
        #[arg(
            long,
            default_value = "target/conformance/observability_dashboard.statsd"
        )]
        statsd_output: PathBuf,
        /// Grafana dashboard template output path.
        #[arg(
            long,
            default_value = "target/conformance/observability_dashboard.grafana.json"
        )]
        grafana_output: PathBuf,
        /// Prometheus alert-rules output path.
        #[arg(
            long,
            default_value = "target/conformance/observability_dashboard.alerts.yaml"
        )]
        alerts_output: PathBuf,
    },
    /// Capture exporter-driven observability JSONL inputs and build the dashboard bundle.
    ObservabilityCapture {
        /// Output directory for raw JSONL inputs and rendered dashboard artifacts.
        #[arg(long, default_value = "target/conformance/observability_capture")]
        out_dir: PathBuf,
        /// Bead id recorded in exported JSONL rows.
        #[arg(long, default_value = "bd-282v")]
        bead_id: String,
        /// Scenario/run id recorded in exported JSONL rows.
        #[arg(long, default_value = "capture")]
        run_id: String,
        /// Runtime mode to export (`strict`, `hardened`, or `off`).
        #[arg(long, default_value = "hardened")]
        mode: String,
        /// Seed deterministic sample activity before exporting so bundle generation
        /// can be verified end-to-end without hand-crafted JSON rows.
        #[arg(long)]
        seed_sample: bool,
    },
    /// Execute manifest-driven shadow runs against host glibc vs FrankenLibC.
    ShadowRun {
        /// Shadow-run manifest JSON path.
        #[arg(long)]
        manifest: PathBuf,
        /// Workspace root used as the command cwd.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// Output directory for per-scenario artifacts.
        #[arg(long, default_value = "target/conformance/shadow_run")]
        out_dir: PathBuf,
        /// JSON report output path.
        #[arg(long, default_value = "target/conformance/shadow_run.current.v1.json")]
        report: PathBuf,
        /// Structured JSONL output path.
        #[arg(long, default_value = "target/conformance/shadow_run.log.jsonl")]
        log: PathBuf,
        /// Artifact-index JSON output path.
        #[arg(
            long,
            default_value = "target/conformance/shadow_run.artifacts.v1.json"
        )]
        artifact_index: PathBuf,
        /// FrankenLibC interpose library to preload for candidate runs.
        #[arg(long, default_value = "target/release/libfrankenlibc_abi.so")]
        lib_path: PathBuf,
        /// Reference label recorded in reports.
        #[arg(long, default_value = "glibc")]
        reference: String,
        /// Runtime mode to evaluate (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Per-run timeout in milliseconds.
        #[arg(long, default_value_t = 5_000)]
        timeout_ms: u64,
        /// Disable syscall-trace capture even when `strace` is available.
        #[arg(long)]
        no_syscall_trace: bool,
        /// Return non-zero when any scenario diverges or errors.
        #[arg(long)]
        fail_on_mismatch: bool,
    },
    /// Execute declarative fault-injection scenarios with reusable tooling.
    FaultInject {
        /// Fault-injection manifest path (YAML or JSON).
        #[arg(long)]
        manifest: PathBuf,
        /// Optional single scenario id to run.
        #[arg(long)]
        scenario: Option<String>,
        /// Output directory for fault-injection artifacts.
        #[arg(long, default_value = "target/conformance/fault_injection")]
        out_dir: PathBuf,
        /// JSON report output path.
        #[arg(
            long,
            default_value = "target/conformance/fault_injection.current.v1.json"
        )]
        report: PathBuf,
        /// Structured JSONL output path.
        #[arg(long, default_value = "target/conformance/fault_injection.log.jsonl")]
        log: PathBuf,
        /// Artifact-index JSON output path.
        #[arg(
            long,
            default_value = "target/conformance/fault_injection.artifacts.v1.json"
        )]
        artifact_index: PathBuf,
        /// Runtime mode to evaluate (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Return non-zero when any scenario fails its expected classification.
        #[arg(long)]
        fail_on_mismatch: bool,
    },
    /// Generate differential conformance matrix (host vs implementation).
    ConformanceMatrix {
        /// Directory containing fixture JSON files.
        #[arg(long)]
        fixture: PathBuf,
        /// Output JSON path for matrix artifact.
        #[arg(
            long,
            default_value = "target/conformance/conformance_matrix.current.v1.json"
        )]
        output: PathBuf,
        /// Structured JSONL output path for conformance logging events.
        #[arg(
            long,
            default_value = "target/conformance/conformance_matrix.log.jsonl"
        )]
        log: PathBuf,
        /// Mode to evaluate (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Logical campaign identifier used in trace ids.
        #[arg(long, default_value = "franken_shadow")]
        campaign: String,
        /// Run each fixture case in a child process to isolate crashes/timeouts.
        #[arg(long)]
        isolate: bool,
        /// Per-case timeout used when `--isolate` is enabled.
        #[arg(long, default_value_t = 5_000)]
        case_timeout_ms: u64,
        /// Performance budget in milliseconds used for WARN near-violation checks (>80%).
        #[arg(long, default_value_t = 5_000)]
        perf_budget_ms: u64,
        /// Return non-zero when any case fails or errors.
        #[arg(long)]
        fail_on_mismatch: bool,
    },
    /// Internal subprocess entrypoint for isolated conformance-matrix case execution.
    #[command(hide = true)]
    ConformanceMatrixCase {
        /// Fixture function name to execute.
        #[arg(long)]
        function: String,
        /// Runtime mode for the case (`strict` or `hardened`).
        #[arg(long)]
        mode: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture {
            input,
            output,
            family,
        } => {
            eprintln!(
                "Capturing family='{family}' from {} into {}",
                input.display(),
                output.display()
            );
            std::fs::create_dir_all(&output)?;
            let captured = frankenlibc_harness::capture::capture_family_fixtures(&input, &family)
                .map_err(|err| format!("capture failed: {err}"))?;

            let mut refreshed_total = 0usize;
            let mut skipped_total = 0usize;
            let mut warning_total = 0usize;

            for artifact in captured {
                let path = output.join(&artifact.file_name);
                let body = artifact
                    .fixture_set
                    .to_json()
                    .map_err(|err| format!("failed serializing {}: {err}", artifact.file_name))?;
                std::fs::write(&path, body)?;

                refreshed_total += artifact.stats.refreshed_cases;
                skipped_total += artifact.stats.skipped_cases;
                warning_total += artifact.stats.warnings.len();

                eprintln!(
                    "wrote {} (cases={}, refreshed={}, skipped={})",
                    path.display(),
                    artifact.stats.total_cases,
                    artifact.stats.refreshed_cases,
                    artifact.stats.skipped_cases
                );
                for warning in artifact.stats.warnings {
                    eprintln!("capture warning: {warning}");
                }
            }

            eprintln!(
                "Capture complete: refreshed_cases={}, skipped_cases={}, warnings={}",
                refreshed_total, skipped_total, warning_total
            );
        }
        Command::Verify {
            fixture,
            report,
            timestamp,
        } => {
            eprintln!("Verifying against fixtures in {}", fixture.display());
            let mut fixture_sets = Vec::new();
            let mut fixture_paths: Vec<PathBuf> = std::fs::read_dir(&fixture)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            fixture_paths.sort();

            for path in fixture_paths {
                match frankenlibc_harness::FixtureSet::from_file(&path) {
                    Ok(set) => fixture_sets.push(set),
                    Err(err) => eprintln!("Skipping {}: {}", path.display(), err),
                }
            }
            if fixture_sets.is_empty() {
                return Err(format!("No fixture JSON files found in {}", fixture.display()).into());
            }

            #[cfg(feature = "asupersync-tooling")]
            let (mut results, suite) = {
                let run = frankenlibc_harness::asupersync_orchestrator::run_fixture_verification(
                    "fixture-verify",
                    &fixture_sets,
                );
                (run.verification_results, run.suite)
            };

            #[cfg(not(feature = "asupersync-tooling"))]
            let mut results = {
                let strict_runner =
                    frankenlibc_harness::TestRunner::new("fixture-verify", "strict");
                let hardened_runner =
                    frankenlibc_harness::TestRunner::new("fixture-verify", "hardened");

                let mut results = Vec::new();
                for set in &fixture_sets {
                    results.extend(strict_runner.run(set));
                    results.extend(hardened_runner.run(set));
                }
                results
            };

            // Stabilize report ordering for reproducible golden-output hashing.
            results.sort_by(|a, b| {
                a.family
                    .cmp(&b.family)
                    .then_with(|| a.symbol.cmp(&b.symbol))
                    .then_with(|| a.mode.cmp(&b.mode))
                    .then_with(|| a.case_name.cmp(&b.case_name))
                    .then_with(|| a.spec_section.cmp(&b.spec_section))
                    .then_with(|| a.expected.cmp(&b.expected))
                    .then_with(|| a.actual.cmp(&b.actual))
                    .then_with(|| a.passed.cmp(&b.passed))
            });

            let summary = frankenlibc_harness::verify::VerificationSummary::from_results(results);
            let report_doc = frankenlibc_harness::ConformanceReport {
                title: String::from("frankenlibc Conformance Report"),
                mode: String::from("strict+hardened"),
                timestamp: timestamp
                    .unwrap_or_else(|| format!("{:?}", std::time::SystemTime::now())),
                summary,
            };

            eprintln!(
                "Verification complete: total={}, passed={}, failed={}",
                report_doc.summary.total, report_doc.summary.passed, report_doc.summary.failed
            );

            if let Some(report_path) = report {
                eprintln!("Writing report to {}", report_path.display());
                std::fs::write(&report_path, report_doc.to_markdown())?;
                let json_path = report_path.with_extension("json");
                std::fs::write(&json_path, report_doc.to_json())?;

                #[cfg(feature = "asupersync-tooling")]
                {
                    let suite_path = report_path.with_extension("suite.json");
                    asupersync_conformance::write_json_report(&suite, &suite_path)?;
                    eprintln!("Wrote suite report to {}", suite_path.display());
                }
            }

            if !report_doc.summary.all_passed() {
                return Err("Conformance verification failed".into());
            }
        }
        Command::Traceability {
            support_matrix,
            fixture,
            conformance_matrix,
            c_fixture_spec,
            output_md,
            output_json,
        } => {
            let report = frankenlibc_harness::report::PosixObligationMatrixReport::from_paths(
                &support_matrix,
                &fixture,
                &conformance_matrix,
                &c_fixture_spec,
            )
            .map_err(|err| format!("failed generating POSIX obligation report: {err}"))?;
            let matrix =
                frankenlibc_harness::traceability::TraceabilityMatrix::from_posix_obligation_report(
                    &report,
                );
            if let Some(parent) = output_md.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if let Some(parent) = output_json.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output_md, matrix.to_markdown())?;
            std::fs::write(&output_json, matrix.to_json())?;
            eprintln!(
                "Traceability written to {} and {}",
                output_md.display(),
                output_json.display()
            );
        }
        Command::RealityReport {
            support_matrix,
            output,
        } => {
            let report =
                frankenlibc_harness::RealityReport::from_support_matrix_path(&support_matrix)
                    .map_err(|err| format!("failed generating reality report: {err}"))?;
            let body = report.to_json();
            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, body)?;
                eprintln!("Wrote reality report to {}", path.display());
            } else {
                print!("{body}");
            }
        }
        Command::PosixConformanceReport {
            support_matrix,
            fixture,
            conformance_matrix,
            output,
        } => {
            let report = frankenlibc_harness::report::PosixConformanceReport::from_paths(
                &support_matrix,
                &fixture,
                &conformance_matrix,
            )
            .map_err(|err| format!("failed generating POSIX conformance report: {err}"))?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, report.to_json())?;
            eprintln!(
                "Wrote POSIX conformance report to {} (eligible_symbols={}, symbols_with_cases={})",
                output.display(),
                report.summary.eligible_symbols,
                report.summary.symbols_with_cases
            );
        }
        Command::PosixObligationReport {
            support_matrix,
            fixture,
            conformance_matrix,
            c_fixture_spec,
            output,
        } => {
            let report = frankenlibc_harness::report::PosixObligationMatrixReport::from_paths(
                &support_matrix,
                &fixture,
                &conformance_matrix,
                &c_fixture_spec,
            )
            .map_err(|err| format!("failed generating POSIX obligation report: {err}"))?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, report.to_json())?;
            eprintln!(
                "Wrote POSIX obligation report to {} (obligations={}, gaps={})",
                output.display(),
                report.summary.total_obligations,
                report.gaps.len()
            );
        }
        Command::ErrnoEdgeReport {
            support_matrix,
            fixture,
            conformance_matrix,
            output,
        } => {
            let report = frankenlibc_harness::report::ErrnoEdgeCaseReport::from_paths(
                &support_matrix,
                &fixture,
                &conformance_matrix,
            )
            .map_err(|err| format!("failed generating errno edge report: {err}"))?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, report.to_json())?;
            eprintln!(
                "Wrote errno edge report to {} (rows={}, failing_edge_cases={})",
                output.display(),
                report.rows.len(),
                report.summary.failing_edge_cases
            );
        }
        Command::VerifyMembrane {
            mode,
            output,
            log,
            campaign,
            fail_on_mismatch,
        } => {
            let mode =
                frankenlibc_harness::healing_oracle::HealingOracleMode::from_str_loose(&mode)
                    .ok_or_else(|| {
                        format!("Unsupported mode '{mode}', expected strict|hardened|both")
                    })?;

            let suite = frankenlibc_harness::healing_oracle::HealingOracleSuite::canonical();
            let report = frankenlibc_harness::healing_oracle::build_healing_oracle_report(
                &suite, mode, &campaign,
            );
            let body = serde_json::to_string_pretty(&report)?;
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, body)?;
            emit_healing_oracle_logs(&log, &output, &report)?;

            eprintln!(
                "Healing oracle complete: total={}, passed={}, failed={} -> {} (log: {})",
                report.summary.total_cases,
                report.summary.passed,
                report.summary.failed,
                output.display(),
                log.display()
            );

            if fail_on_mismatch && !report.all_passed() {
                return Err(
                    format!("Healing oracle mismatch: failed={}", report.summary.failed).into(),
                );
            }
        }
        Command::EvidenceCompliance {
            workspace_root,
            log,
            artifact_index,
            output,
        } => {
            let report = frankenlibc_harness::evidence_compliance::validate_evidence_bundle(
                &workspace_root,
                &log,
                &artifact_index,
            );
            let triage = evidence_report_to_triage_json(&report, &log, &artifact_index);
            let body = serde_json::to_string_pretty(&triage)?;

            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, body)?;
            } else {
                print!("{body}");
            }

            if !report.ok {
                return Err(format!(
                    "Evidence compliance failed: {} violation(s)",
                    report.violations.len()
                )
                .into());
            }
        }
        Command::ExplainabilityWorkbench {
            log,
            artifact_index,
            trace_id,
            scenario_id,
            format,
            output,
            ansi,
            width,
        } => {
            let report = frankenlibc_harness::explainability_workbench::build_report(
                &log,
                artifact_index.as_deref(),
                trace_id.as_deref(),
                scenario_id.as_deref(),
            )?;

            let out = match format.to_ascii_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&report)?,
                "plain" => frankenlibc_harness::explainability_workbench::render_plain(&report),
                "ftui" => {
                    #[cfg(feature = "frankentui-ui")]
                    {
                        frankenlibc_harness::explainability_workbench::render_ftui(
                            &report, ansi, width,
                        )
                    }

                    #[cfg(not(feature = "frankentui-ui"))]
                    {
                        let _ = ansi;
                        let _ = width;
                        eprintln!("note: enable `frankentui-ui` feature for ftui rendering");
                        frankenlibc_harness::explainability_workbench::render_plain(&report)
                    }
                }
                other => {
                    return Err(
                        format!("Unsupported format '{other}', expected json|plain|ftui").into(),
                    );
                }
            };

            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, out)?;
            } else {
                print!("{out}");
            }
        }
        Command::DecodeEvidence {
            input,
            epoch_id,
            format,
            output,
            ansi,
            width,
        } => {
            let report =
                frankenlibc_harness::evidence_decode::decode_evidence_file(&input, epoch_id)?;

            let out = match format.to_ascii_lowercase().as_str() {
                "json" => serde_json::to_string_pretty(&report)?,
                "plain" => frankenlibc_harness::evidence_decode_render::render_plain(&report),
                "ftui" => {
                    #[cfg(feature = "frankentui-ui")]
                    {
                        frankenlibc_harness::evidence_decode_render::render_ftui(
                            &report, ansi, width,
                        )
                    }

                    #[cfg(not(feature = "frankentui-ui"))]
                    {
                        let _ = ansi;
                        let _ = width;
                        eprintln!("note: enable `frankentui-ui` feature for ftui rendering");
                        frankenlibc_harness::evidence_decode_render::render_plain(&report)
                    }
                }
                other => {
                    return Err(
                        format!("Unsupported format '{other}', expected json|plain|ftui").into(),
                    );
                }
            };

            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, out)?;
            } else {
                print!("{out}");
            }
        }
        Command::SnapshotKernel {
            output,
            mode,
            seed,
            steps,
        } => {
            let seed = parse_seed(&seed)?;
            let mode = frankenlibc_harness::kernel_snapshot::SnapshotMode::from_str_loose(&mode)
                .ok_or_else(|| {
                    format!("Unsupported mode '{mode}', expected strict|hardened|both")
                })?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let fixture = frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture(
                seed, steps, mode,
            );
            let body = serde_json::to_string_pretty(&fixture)?;
            std::fs::write(&output, body)?;
            eprintln!("Wrote kernel snapshot fixture to {}", output.display());
        }
        Command::DiffKernelSnapshot {
            golden,
            current,
            mode,
            all,
            ansi,
            width,
        } => {
            let golden_body = std::fs::read_to_string(&golden)?;
            let golden_fixture: frankenlibc_harness::kernel_snapshot::RuntimeKernelSnapshotFixtureV1 =
                serde_json::from_str(&golden_body)?;

            let current_fixture: frankenlibc_harness::kernel_snapshot::RuntimeKernelSnapshotFixtureV1 =
                if current.exists() {
                    let current_body = std::fs::read_to_string(&current)?;
                    serde_json::from_str(&current_body)?
                } else {
                    eprintln!(
                        "Current fixture not found at {}; generating from golden scenario (seed={}, steps={})",
                        current.display(),
                        golden_fixture.scenario.seed,
                        golden_fixture.scenario.steps
                    );
                    frankenlibc_harness::kernel_snapshot::build_kernel_snapshot_fixture(
                        golden_fixture.scenario.seed,
                        golden_fixture.scenario.steps,
                        frankenlibc_harness::kernel_snapshot::SnapshotMode::Both,
                    )
                };

            let mode = frankenlibc_harness::snapshot_diff::DiffMode::from_str_loose(&mode)
                .ok_or_else(|| format!("Unsupported mode '{mode}', expected strict|hardened"))?;

            let report = frankenlibc_harness::snapshot_diff::diff_kernel_snapshots(
                &golden_fixture,
                &current_fixture,
                mode,
                all,
            )?;

            #[cfg(not(feature = "frankentui-ui"))]
            let _ = width;

            #[cfg(feature = "frankentui-ui")]
            let out = frankenlibc_harness::snapshot_diff::render_ftui(&report, ansi, width);

            #[cfg(not(feature = "frankentui-ui"))]
            let out = {
                if ansi {
                    eprintln!("note: enable `frankentui-ui` feature for ANSI rendering");
                }
                frankenlibc_harness::snapshot_diff::render_plain(&report)
            };

            print!("{out}");
        }
        Command::KernelRegressionReport {
            output,
            seed,
            steps,
            warmup_iters,
            samples,
            iters,
            trend_stride,
        } => {
            // NOTE: mode is process-immutable (cached from env). To avoid cross-contamination,
            // spawn two subprocesses with different FRANKENLIBC_MODE values.
            let exe = std::env::current_exe()?;
            let seed_num = parse_seed(&seed)?;
            let cfg = KernelRegressionCliConfig {
                seed: seed_num,
                steps,
                warmup_iters,
                samples,
                iters,
                trend_stride,
            };

            let strict = run_kernel_mode_subprocess(&exe, "strict", cfg)?;
            let hardened = run_kernel_mode_subprocess(&exe, "hardened", cfg)?;

            let report = frankenlibc_harness::kernel_regression_report::KernelRegressionReport {
                strict,
                hardened,
            };
            let md =
                frankenlibc_harness::kernel_regression_report::render_regression_markdown(&report);
            let json = serde_json::to_string_pretty(&report)?;

            if let Some(path) = output {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, md)?;
                std::fs::write(path.with_extension("json"), json)?;
            } else {
                print!("{md}");
            }
        }
        Command::KernelRegressionMode {
            mode,
            seed,
            steps,
            warmup_iters,
            samples,
            iters,
            trend_stride,
        } => {
            use frankenlibc_membrane::config::SafetyLevel;

            let expected = match mode.to_ascii_lowercase().as_str() {
                "strict" => SafetyLevel::Strict,
                "hardened" => SafetyLevel::Hardened,
                other => {
                    return Err(
                        format!("Unsupported mode '{other}', expected strict|hardened").into(),
                    );
                }
            };
            let seed_num = parse_seed(&seed)?;

            let cfg = frankenlibc_harness::kernel_regression_report::ModeRunConfig {
                seed: seed_num,
                steps,
                microbench: frankenlibc_harness::kernel_regression_report::MicrobenchConfig {
                    warmup_iters,
                    sample_count: samples,
                    sample_iters: iters,
                },
                trend_stride,
            };

            let metrics =
                frankenlibc_harness::kernel_regression_report::collect_mode_metrics(expected, cfg)
                    .map_err(|e| format!("kernel regression mode run failed: {e}"))?;

            let body = serde_json::to_string_pretty(&metrics)?;
            print!("{body}");
        }
        Command::RuntimeMathLinkageProofs {
            workspace_root,
            log,
            report,
        } => {
            let rep = frankenlibc_harness::runtime_math_linkage_proofs::run_and_write(
                &workspace_root,
                &log,
                &report,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "runtime_math linkage proofs FAILED: {} module(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: runtime_math linkage proofs passed for {} modules (log: {}, report: {})",
                rep.summary.total_modules,
                log.display(),
                report.display()
            );
        }
        Command::RuntimeMathHjiViabilityProofs {
            workspace_root,
            log,
            report,
        } => {
            let rep = frankenlibc_harness::runtime_math_hji_viability_proofs::run_and_write(
                &workspace_root,
                &log,
                &report,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "runtime_math HJI viability proofs FAILED: {} check(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: runtime_math HJI viability proofs passed for {} checks (log: {}, report: {})",
                rep.summary.checks,
                log.display(),
                report.display()
            );
        }
        Command::RuntimeMathCpomdpFeasibilityProofs {
            workspace_root,
            log,
            report,
            feasibility_artifact,
            sensitivity_artifact,
        } => {
            let rep = frankenlibc_harness::runtime_math_cpomdp_feasibility_proofs::run_and_write(
                &workspace_root,
                &log,
                &report,
                &feasibility_artifact,
                &sensitivity_artifact,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "runtime_math CPOMDP feasibility proofs FAILED: {} check(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: runtime_math CPOMDP feasibility proofs passed for {} checks (log: {}, report: {})",
                rep.summary.checks,
                log.display(),
                report.display()
            );
        }
        Command::RuntimeMathDeterminismProofs {
            workspace_root,
            log,
            report,
        } => {
            let rep = frankenlibc_harness::runtime_math_determinism_proofs::run_and_write(
                &workspace_root,
                &log,
                &report,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "runtime_math determinism proofs FAILED: {} mode(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: runtime_math determinism proofs passed for {} modes (log: {}, report: {})",
                rep.summary.modes,
                log.display(),
                report.display()
            );
        }
        Command::RuntimeMathDivergenceBounds {
            workspace_root,
            log,
            report,
        } => {
            let rep = frankenlibc_harness::runtime_math_divergence_bounds::run_and_write(
                &workspace_root,
                &log,
                &report,
            )?;
            if rep.summary.failed != 0 || rep.summary.violations != 0 {
                return Err(std::io::Error::other(format!(
                    "runtime_math divergence bounds FAILED: {} case(s) failed, {} violation(s) (report: {})",
                    rep.summary.failed,
                    rep.summary.violations,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: runtime_math divergence bounds passed for {} cases (log: {}, report: {})",
                rep.summary.total_cases,
                log.display(),
                report.display()
            );
        }
        Command::ProofBinderProofs {
            workspace_root,
            log,
            report,
            validator_report,
        } => {
            let rep = frankenlibc_harness::proof_binder_proofs::run_and_write(
                &workspace_root,
                &log,
                &report,
                &validator_report,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "proof binder proofs FAILED: {} check(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: proof binder proofs passed for {} checks (log: {}, report: {}, validator: {})",
                rep.summary.checks,
                log.display(),
                report.display(),
                validator_report.display()
            );
        }
        Command::ProofChainE2e {
            workspace_root,
            log,
            report,
            binder_log,
            binder_report,
            validator_report,
            cross_report,
        } => {
            let rep = frankenlibc_harness::proof_chain_e2e::run_and_write(
                &workspace_root,
                &log,
                &report,
                &binder_log,
                &binder_report,
                &validator_report,
                &cross_report,
            )?;
            if rep.summary.failed != 0 {
                return Err(std::io::Error::other(format!(
                    "proof chain e2e FAILED: {} check(s) failed (report: {})",
                    rep.summary.failed,
                    report.display()
                ))
                .into());
            }
            eprintln!(
                "OK: proof chain e2e passed for {} checks (log: {}, report: {}, binder report: {}, cross report: {})",
                rep.summary.checks,
                log.display(),
                report.display(),
                binder_report.display(),
                cross_report.display()
            );
        }
        Command::ObservabilityDashboard {
            input,
            output,
            prometheus_output,
            statsd_output,
            grafana_output,
            alerts_output,
        } => {
            let report = frankenlibc_harness::observability_dashboard::write_bundle(
                &input,
                &output,
                &prometheus_output,
                &statsd_output,
                &grafana_output,
                &alerts_output,
            )
            .map_err(std::io::Error::other)?;
            eprintln!(
                "Observability dashboard complete: total_rows={}, invalid_rows={} -> {} (prometheus: {}, statsd: {}, grafana: {}, alerts: {})",
                report.summary.total_rows,
                report.summary.invalid_rows,
                output.display(),
                prometheus_output.display(),
                statsd_output.display(),
                grafana_output.display(),
                alerts_output.display()
            );
        }
        Command::ObservabilityCapture {
            out_dir,
            bead_id,
            run_id,
            mode,
            seed_sample,
        } => {
            let bundle = frankenlibc_harness::observability_dashboard::capture_bundle(
                &out_dir,
                &bead_id,
                &run_id,
                &mode,
                seed_sample,
            )
            .map_err(std::io::Error::other)?;
            eprintln!(
                "Observability capture complete: inputs={} total_rows={} invalid_rows={} -> {} (prometheus: {}, statsd: {}, grafana: {}, alerts: {})",
                bundle.input_paths.len(),
                bundle.report.summary.total_rows,
                bundle.report.summary.invalid_rows,
                bundle.output.display(),
                bundle.prometheus_output.display(),
                bundle.statsd_output.display(),
                bundle.grafana_output.display(),
                bundle.alerts_output.display()
            );
        }
        Command::ShadowRun {
            manifest,
            workspace_root,
            out_dir,
            report,
            log,
            artifact_index,
            lib_path,
            reference,
            mode,
            timeout_ms,
            no_syscall_trace,
            fail_on_mismatch,
        } => {
            let manifest_doc = ShadowRunManifest::from_path(&manifest)?;
            let modes = shadow_run_modes(&mode)
                .map_err(|err| format!("Unsupported mode '{mode}': {err}"))?;
            let mut config = ShadowRunConfig::new(
                workspace_root,
                out_dir,
                lib_path,
                Duration::from_millis(timeout_ms.max(1)),
            );
            config.report_path = Some(report.clone());
            config.log_path = Some(log.clone());
            config.artifact_index_path = Some(artifact_index.clone());
            config.reference_label = reference;
            config.capture_syscall_traces = !no_syscall_trace;
            config.run_id = manifest_doc.manifest_id.clone();
            config.manifest_ref = Some(manifest.to_string_lossy().into_owned());

            let shadow_report = frankenlibc_harness::shadow_run::run_shadow_manifest_with_executor(
                &manifest_doc,
                &modes,
                &config,
                &mut ProcessShadowExecutor,
            )?;
            eprintln!(
                "Shadow run complete: total={}, passed={}, diverged={}, skipped={}, errors={} -> {} (log: {})",
                shadow_report.summary.total_runs,
                shadow_report.summary.passed,
                shadow_report.summary.diverged,
                shadow_report.summary.skipped,
                shadow_report.summary.errors,
                report.display(),
                log.display()
            );

            if fail_on_mismatch
                && (shadow_report.summary.diverged > 0 || shadow_report.summary.errors > 0)
            {
                return Err(format!(
                    "Shadow run mismatch: diverged={}, errors={}",
                    shadow_report.summary.diverged, shadow_report.summary.errors
                )
                .into());
            }
        }
        Command::FaultInject {
            manifest,
            scenario,
            out_dir,
            report,
            log,
            artifact_index,
            mode,
            fail_on_mismatch,
        } => {
            let manifest_doc =
                frankenlibc_harness::fault_injection::FaultManifest::from_path(&manifest)?;
            let modes = shadow_run_modes(&mode)
                .map_err(|err| format!("Unsupported mode '{mode}': {err}"))?;
            let mut config = frankenlibc_harness::fault_injection::FaultRunConfig::new(out_dir);
            config.report_path = report.clone();
            config.log_path = log.clone();
            config.artifact_index_path = artifact_index.clone();
            config.run_id = manifest_doc.manifest_id.clone();
            config.manifest_ref = Some(manifest.to_string_lossy().into_owned());

            let fault_report =
                frankenlibc_harness::fault_injection::run_manifest_with_default_executor(
                    &manifest_doc,
                    scenario.as_deref(),
                    &modes,
                    &config,
                )?;
            eprintln!(
                "Fault injection complete: scenarios={}, total_cases={}, passed={}, failed={} -> {} (log: {}, artifacts: {})",
                fault_report.summary.scenario_count,
                fault_report.summary.total_cases,
                fault_report.summary.passed,
                fault_report.summary.failed,
                report.display(),
                log.display(),
                artifact_index.display()
            );

            if fail_on_mismatch && fault_report.summary.failed > 0 {
                return Err(format!(
                    "Fault injection mismatch: failed={}, false_negatives={}",
                    fault_report.summary.failed, fault_report.summary.false_negatives
                )
                .into());
            }
        }
        Command::ConformanceMatrix {
            fixture,
            output,
            log,
            mode,
            campaign,
            isolate,
            case_timeout_ms,
            perf_budget_ms,
            fail_on_mismatch,
        } => {
            let fixture_sets = load_fixture_sets(&fixture)?;
            if fixture_sets.is_empty() {
                return Err(format!("No fixture JSON files found in {}", fixture.display()).into());
            }
            let previous_matrix = load_previous_matrix_if_present(&output);

            let mode = frankenlibc_harness::conformance_matrix::MatrixMode::from_str_loose(&mode)
                .ok_or_else(|| {
                format!("Unsupported mode '{mode}', expected strict|hardened|both")
            })?;

            let matrix = if isolate {
                let exe = stable_conformance_case_runner(&std::env::current_exe()?, &output)?;
                let timeout = Duration::from_millis(case_timeout_ms.max(1));
                frankenlibc_harness::conformance_matrix::build_conformance_matrix_with_executor(
                    &fixture_sets,
                    mode,
                    &campaign,
                    |function, inputs, active_mode| match run_conformance_case_subprocess(
                        &exe,
                        function,
                        inputs,
                        active_mode,
                        timeout,
                    ) {
                        Ok(run) => CaseExecution::Completed(run),
                        Err(MatrixCaseSubprocessError::Timeout(err)) => CaseExecution::Timeout(err),
                        Err(MatrixCaseSubprocessError::Crash(err)) => CaseExecution::Crash(err),
                        Err(MatrixCaseSubprocessError::Error(err)) => CaseExecution::Error(err),
                    },
                )
            } else {
                frankenlibc_harness::conformance_matrix::build_conformance_matrix(
                    &fixture_sets,
                    mode,
                    &campaign,
                )
            };
            let body = serde_json::to_string_pretty(&matrix)?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, body)?;
            emit_conformance_matrix_logs(
                &log,
                &output,
                &campaign,
                &matrix,
                previous_matrix.as_ref(),
                perf_budget_ms.max(1),
            )?;

            eprintln!(
                "Conformance matrix complete: total={}, passed={}, failed={}, errors={} -> {} (log: {})",
                matrix.summary.total_cases,
                matrix.summary.passed,
                matrix.summary.failed,
                matrix.summary.errors,
                output.display(),
                log.display()
            );

            if fail_on_mismatch && !matrix.all_passed() {
                return Err(format!(
                    "Conformance matrix mismatch: failed={}, errors={}",
                    matrix.summary.failed, matrix.summary.errors
                )
                .into());
            }
        }
        Command::ConformanceMatrixCase { function, mode } => {
            let mut stdin_buf = String::new();
            std::io::stdin().read_to_string(&mut stdin_buf)?;
            let inputs: serde_json::Value = serde_json::from_str(&stdin_buf)
                .map_err(|err| format!("invalid case inputs json: {err}"))?;

            if function == "__harness_test_timeout" {
                std::thread::sleep(Duration::from_secs(30));
            }
            if function == "__harness_test_crash" {
                std::process::abort();
            }

            let envelope =
                match frankenlibc_fixture_exec::execute_fixture_case(&function, &inputs, &mode) {
                    Ok(run) => MatrixCaseEnvelope::ok(run),
                    Err(err) => MatrixCaseEnvelope::error(err),
                };
            let payload = serde_json::to_vec(&envelope)?;
            std::io::stdout().write_all(&payload)?;
            std::io::stdout().flush()?;
            // This command is intentionally subprocess-only. Replacing the
            // current process image skips the crashing fixture-exec teardown
            // path after the result has already been flushed to stdout.
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;

                let exec_err = ProcCommand::new("/bin/true").exec();
                return Err(
                    format!("failed to exec /bin/true after case output: {exec_err}").into(),
                );
            }
        }
    }

    Ok(())
}

fn shadow_run_modes(raw: &str) -> Result<Vec<String>, String> {
    match raw.to_ascii_lowercase().as_str() {
        "strict" => Ok(vec!["strict".to_string()]),
        "hardened" => Ok(vec!["hardened".to_string()]),
        "both" => Ok(vec!["strict".to_string(), "hardened".to_string()]),
        other => Err(format!("expected strict|hardened|both, got {other}")),
    }
}

#[derive(Debug, Clone, Copy)]
struct KernelRegressionCliConfig {
    seed: u64,
    steps: u32,
    warmup_iters: u64,
    samples: usize,
    iters: u64,
    trend_stride: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct MatrixCaseEnvelope {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<frankenlibc_fixture_exec::DifferentialExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl MatrixCaseEnvelope {
    fn ok(run: frankenlibc_fixture_exec::DifferentialExecution) -> Self {
        Self {
            kind: "ok".to_string(),
            run: Some(run),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            kind: "error".to_string(),
            run: None,
            error: Some(error),
        }
    }
}

#[derive(Debug)]
enum MatrixCaseSubprocessError {
    Timeout(String),
    Crash(String),
    Error(String),
}

fn stable_conformance_case_runner(
    current_exe: &Path,
    output: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let runner_dir = output.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(runner_dir)?;
    let runner = runner_dir.join(format!(
        "conformance-matrix-case-runner-{}.bin",
        std::process::id()
    ));
    match std::fs::copy(current_exe, &runner) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(target_os = "linux")]
            {
                let proc_exe = Path::new("/proc/self/exe");
                std::fs::copy(proc_exe, &runner).map_err(|proc_err| {
                    format!(
                        "copy current executable from {} failed: {err}; /proc/self/exe fallback failed: {proc_err}",
                        current_exe.display()
                    )
                })?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                return Err(format!(
                    "copy current executable from {} failed: {err}",
                    current_exe.display()
                )
                .into());
            }
        }
        Err(err) => {
            return Err(format!(
                "copy current executable from {} failed: {err}",
                current_exe.display()
            )
            .into());
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(&runner)?.permissions();
        permissions.set_mode(permissions.mode() | 0o700);
        std::fs::set_permissions(&runner, permissions)?;
    }

    Ok(runner)
}

fn run_conformance_case_subprocess(
    exe: &std::path::Path,
    function: &str,
    inputs: &serde_json::Value,
    mode: &str,
    timeout: Duration,
) -> Result<frankenlibc_fixture_exec::DifferentialExecution, MatrixCaseSubprocessError> {
    let mut child = ProcCommand::new(exe)
        .arg("conformance-matrix-case")
        .arg("--function")
        .arg(function)
        .arg("--mode")
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| MatrixCaseSubprocessError::Error(format!("spawn failed: {err}")))?;

    let payload = serde_json::to_vec(inputs).map_err(|err| {
        MatrixCaseSubprocessError::Error(format!("serialize inputs failed: {err}"))
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&payload).map_err(|err| {
            MatrixCaseSubprocessError::Error(format!("stdin write failed: {err}"))
        })?;
    }

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(MatrixCaseSubprocessError::Timeout(format!(
                        "case exceeded {}ms",
                        timeout.as_millis()
                    )));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => {
                return Err(MatrixCaseSubprocessError::Error(format!(
                    "try_wait failed: {err}"
                )));
            }
        }
    };

    let mut stdout = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout).map_err(|err| {
            MatrixCaseSubprocessError::Error(format!("stdout read failed: {err}"))
        })?;
    }
    let mut stderr = Vec::new();
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut stderr)
            .map_err(|e| MatrixCaseSubprocessError::Error(format!("stderr read failed: {e}")))?;
    }
    let stderr_text = String::from_utf8_lossy(&stderr).trim().to_string();

    if !status.success() {
        #[cfg(unix)]
        if let Some(signal) = status.signal() {
            return Err(MatrixCaseSubprocessError::Crash(format!(
                "signal={signal} stderr={stderr_text}"
            )));
        }
        return Err(MatrixCaseSubprocessError::Crash(format!(
            "exit_code={} stderr={}",
            status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr_text
        )));
    }

    let envelope: MatrixCaseEnvelope = serde_json::from_slice(&stdout).map_err(|err| {
        MatrixCaseSubprocessError::Error(format!(
            "invalid subprocess payload: {err}; stdout={}",
            String::from_utf8_lossy(&stdout)
        ))
    })?;
    match envelope.kind.as_str() {
        "ok" => envelope
            .run
            .ok_or_else(|| MatrixCaseSubprocessError::Error("missing run payload".to_string())),
        "error" => Err(MatrixCaseSubprocessError::Error(
            envelope
                .error
                .unwrap_or_else(|| "missing error payload".to_string()),
        )),
        other => Err(MatrixCaseSubprocessError::Error(format!(
            "unknown envelope kind: {other}"
        ))),
    }
}

fn run_kernel_mode_subprocess(
    exe: &std::path::Path,
    mode: &str,
    cfg: KernelRegressionCliConfig,
) -> Result<
    frankenlibc_harness::kernel_regression_report::KernelModeMetrics,
    Box<dyn std::error::Error>,
> {
    let output = ProcCommand::new(exe)
        .arg("kernel-regression-mode")
        .arg("--mode")
        .arg(mode)
        .arg("--seed")
        .arg(format!("0x{:X}", cfg.seed))
        .arg("--steps")
        .arg(cfg.steps.to_string())
        .arg("--warmup-iters")
        .arg(cfg.warmup_iters.to_string())
        .arg("--samples")
        .arg(cfg.samples.to_string())
        .arg("--iters")
        .arg(cfg.iters.to_string())
        .arg("--trend-stride")
        .arg(cfg.trend_stride.to_string())
        .env("FRANKENLIBC_MODE", mode)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("kernel-regression-mode failed for mode={mode}: {stderr}").into());
    }

    let metrics: frankenlibc_harness::kernel_regression_report::KernelModeMetrics =
        serde_json::from_slice(&output.stdout)?;
    Ok(metrics)
}

fn expected_fields_for_violation(
    v: &frankenlibc_harness::evidence_compliance::EvidenceViolation,
) -> Vec<String> {
    match v.code.as_str() {
        "log.schema_violation" => {
            if let Some(hint) = &v.remediation_hint
                && let Some(start) = hint.find("field '")
            {
                let rem = &hint[start + 7..];
                if let Some(end) = rem.find('\'') {
                    let field = &rem[..end];
                    if !field.trim().is_empty() {
                        return vec![field.to_string()];
                    }
                }
            }
            Vec::new()
        }
        "failure_event.missing_artifact_refs" => vec!["artifact_refs".to_string()],
        "failure_artifact_ref.missing" => vec!["artifact_refs".to_string()],
        "failure_artifact_ref.not_indexed" => {
            vec![
                "artifact_refs".to_string(),
                "artifact_index.artifacts".to_string(),
            ]
        }
        "artifact_index.bad_version" => vec!["index_version".to_string()],
        "artifact_index.invalid_json" => vec![
            "index_version".to_string(),
            "run_id".to_string(),
            "bead_id".to_string(),
            "artifacts".to_string(),
        ],
        "artifact_index.missing" => vec!["artifact_index".to_string()],
        "log.missing" => vec![
            "timestamp".to_string(),
            "trace_id".to_string(),
            "level".to_string(),
            "event".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn evidence_report_to_triage_json(
    report: &frankenlibc_harness::evidence_compliance::EvidenceComplianceReport,
    log_path: &PathBuf,
    artifact_index: &PathBuf,
) -> serde_json::Value {
    let violations: Vec<serde_json::Value> = report
        .violations
        .iter()
        .map(|v| {
            let offending_event = v
                .trace_id
                .clone()
                .or_else(|| v.line_number.map(|line| format!("line:{line}")))
                .or_else(|| v.path.clone())
                .unwrap_or_else(|| "unknown".to_string());

            serde_json::json!({
                "violation_code": v.code,
                "offending_event": offending_event,
                "expected_fields": expected_fields_for_violation(v),
                "remediation_hint": v.remediation_hint,
                "artifact_pointer": v.path,
                "line_number": v.line_number,
                "message": v.message,
            })
        })
        .collect();

    serde_json::json!({
        "ok": report.ok,
        "violation_count": report.violations.len(),
        "log_path": log_path,
        "artifact_index_path": artifact_index,
        "violations": violations
    })
}

fn load_previous_matrix_if_present(path: &Path) -> Option<ConformanceMatrixReport> {
    if !path.exists() {
        return None;
    }

    let previous_body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(err) => {
            eprintln!(
                "WARN: unable to read previous conformance matrix '{}' for regression checks: {err}",
                path.display()
            );
            return None;
        }
    };

    match serde_json::from_str::<ConformanceMatrixReport>(&previous_body) {
        Ok(report) => Some(report),
        Err(err) => {
            eprintln!(
                "WARN: unable to parse previous conformance matrix '{}' for regression checks: {err}",
                path.display()
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct DurationStats {
    samples: usize,
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
    mean_ms: f64,
    max_ms: u64,
}

fn duration_stats(samples: &[u64]) -> Option<DurationStats> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let sum: u128 = sorted.iter().map(|value| u128::from(*value)).sum();
    let mean_ms = (sum as f64) / (sorted.len() as f64);
    Some(DurationStats {
        samples: sorted.len(),
        p50_ms: percentile_sorted_ms(&sorted, 50, 100),
        p95_ms: percentile_sorted_ms(&sorted, 95, 100),
        p99_ms: percentile_sorted_ms(&sorted, 99, 100),
        mean_ms,
        max_ms: *sorted.last().unwrap_or(&0),
    })
}

fn percentile_sorted_ms(sorted: &[u64], numerator: u64, denominator: u64) -> u64 {
    debug_assert!(!sorted.is_empty());
    debug_assert!(denominator > 0);
    let span = u128::try_from(sorted.len().saturating_sub(1)).unwrap_or(u128::MAX);
    let idx = span
        .saturating_mul(u128::from(numerator))
        .saturating_add(u128::from(denominator / 2))
        .saturating_div(u128::from(denominator));
    let idx = usize::try_from(idx)
        .unwrap_or(usize::MAX)
        .min(sorted.len().saturating_sub(1));
    sorted[idx]
}

fn previous_pass_map(previous: Option<&ConformanceMatrixReport>) -> BTreeMap<String, bool> {
    let mut prior = BTreeMap::new();
    if let Some(report) = previous {
        for case in &report.cases {
            prior.insert(case.trace_id.clone(), case.passed);
        }
    }
    prior
}

fn case_outcome(case: &frankenlibc_harness::conformance_matrix::ConformanceCaseRow) -> Outcome {
    match case.status.as_str() {
        "pass" => Outcome::Pass,
        "error" => Outcome::Error,
        "timeout" => Outcome::Timeout,
        "crash" => Outcome::Error,
        _ => {
            if case.passed {
                Outcome::Pass
            } else {
                Outcome::Fail
            }
        }
    }
}

fn sanitize_trace_component(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

fn emit_conformance_matrix_logs(
    log_path: &Path,
    matrix_output_path: &Path,
    campaign: &str,
    matrix: &ConformanceMatrixReport,
    previous: Option<&ConformanceMatrixReport>,
    perf_budget_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let run_id = format!("{}_matrix", sanitize_trace_component(campaign));
    let mut emitter = LogEmitter::to_file(log_path, CONFORMANCE_LOG_BEAD_ID, &run_id)?;
    let prior = previous_pass_map(previous);

    let matrix_artifact = matrix_output_path.display().to_string();
    let log_artifact = log_path.display().to_string();
    let artifact_refs = vec![matrix_artifact.clone(), log_artifact.clone()];

    let mut duration_by_symbol: BTreeMap<(String, String), Vec<u64>> = BTreeMap::new();

    for case in &matrix.cases {
        let duration_ms = case.duration_ms.unwrap_or(0);
        let latency_ns = duration_ms.saturating_mul(1_000_000);
        if let Some(sample) = case.duration_ms {
            duration_by_symbol
                .entry((case.symbol.clone(), case.mode.clone()))
                .or_default()
                .push(sample);
        }

        emitter.emit_entry(
            LogEntry::new(
                case.trace_id.clone(),
                LogLevel::Trace,
                "conformance.fixture_execution",
            )
            .with_stream(StreamKind::Conformance)
            .with_gate(CONFORMANCE_LOG_GATE)
            .with_mode(case.mode.clone())
            .with_api(case.family.clone(), case.symbol.clone())
            .with_outcome(case_outcome(case))
            .with_errno(0)
            .with_latency_ns(latency_ns)
            .with_duration_ms(duration_ms)
            .with_healing_action("none")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "case_name": case.case_name,
                "spec_section": case.spec_section,
                "status": case.status,
                "diff_offset": case.diff_offset,
                "decision_path": "conformance->fixture_execution"
            })),
        )?;

        emitter.emit_entry(
            LogEntry::new(
                case.trace_id.clone(),
                LogLevel::Debug,
                "conformance.shadow_run_divergence",
            )
            .with_stream(StreamKind::Conformance)
            .with_gate(CONFORMANCE_LOG_GATE)
            .with_mode(case.mode.clone())
            .with_api(case.family.clone(), case.symbol.clone())
            .with_outcome(case_outcome(case))
            .with_errno(0)
            .with_latency_ns(latency_ns)
            .with_healing_action("none")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "host_output": case.host_output,
                "actual_output": case.actual_output,
                "expected_output": case.expected_output,
                "host_parity": case.host_parity,
                "note": case.note,
                "decision_path": "conformance->shadow_compare"
            })),
        )?;

        if duration_ms.saturating_mul(100)
            >= perf_budget_ms.saturating_mul(CONFORMANCE_WARN_BUDGET_PERCENT)
        {
            emitter.emit_entry(
                LogEntry::new(
                    case.trace_id.clone(),
                    LogLevel::Warn,
                    "conformance.performance_budget_near_violation",
                )
                .with_stream(StreamKind::Conformance)
                .with_gate(CONFORMANCE_LOG_GATE)
                .with_mode(case.mode.clone())
                .with_api(case.family.clone(), case.symbol.clone())
                .with_outcome(case_outcome(case))
                .with_errno(0)
                .with_latency_ns(latency_ns)
                .with_duration_ms(duration_ms)
                .with_healing_action("none")
                .with_artifacts(artifact_refs.clone())
                .with_details(serde_json::json!({
                    "duration_ms": duration_ms,
                    "budget_ms": perf_budget_ms,
                    "budget_percent": if perf_budget_ms == 0 { 0.0 } else { (duration_ms as f64 * 100.0) / perf_budget_ms as f64 },
                    "warn_threshold_percent": CONFORMANCE_WARN_BUDGET_PERCENT,
                    "decision_path": "conformance->perf_budget_guard"
                })),
            )?;
        }

        if prior.get(&case.trace_id).copied().unwrap_or(false) && !case.passed {
            emitter.emit_entry(
                LogEntry::new(
                    case.trace_id.clone(),
                    LogLevel::Error,
                    "conformance.regression_detected",
                )
                .with_stream(StreamKind::Conformance)
                .with_gate(CONFORMANCE_LOG_GATE)
                .with_mode(case.mode.clone())
                .with_api(case.family.clone(), case.symbol.clone())
                .with_outcome(Outcome::Fail)
                .with_errno(0)
                .with_latency_ns(latency_ns)
                .with_healing_action("none")
                .with_artifacts(artifact_refs.clone())
                .with_details(serde_json::json!({
                    "previous_status": "pass",
                    "current_status": case.status,
                    "current_passed": case.passed,
                    "diff_offset": case.diff_offset,
                    "decision_path": "conformance->regression_detector"
                })),
            )?;
        }
    }

    let summary_trace_id = format!(
        "{}::conformance::summary",
        sanitize_trace_component(campaign)
    );
    emitter.emit_entry(
        LogEntry::new(
            summary_trace_id,
            LogLevel::Info,
            "conformance.fixture_summary",
        )
        .with_stream(StreamKind::Conformance)
        .with_gate(CONFORMANCE_LOG_GATE)
        .with_mode(matrix.mode.clone())
        .with_api("conformance", "fixture_summary")
        .with_outcome(if matrix.all_passed() {
            Outcome::Pass
        } else {
            Outcome::Fail
        })
        .with_errno(0)
        .with_healing_action("none")
        .with_artifacts(artifact_refs.clone())
        .with_details(serde_json::json!({
            "campaign": matrix.campaign,
            "total_cases": matrix.summary.total_cases,
            "passed": matrix.summary.passed,
            "failed": matrix.summary.failed,
            "errors": matrix.summary.errors,
            "pass_rate_percent": matrix.summary.pass_rate_percent,
            "decision_path": "conformance->summary"
        })),
    )?;

    for row in &matrix.symbol_matrix {
        let key = (row.symbol.clone(), row.mode.clone());
        let stats = duration_by_symbol
            .get(&key)
            .and_then(|samples| duration_stats(samples));
        let duration_details = stats.unwrap_or_default();

        let benchmark_trace_id = format!(
            "{}::benchmark::{}::{}",
            sanitize_trace_component(campaign),
            sanitize_trace_component(&row.symbol),
            sanitize_trace_component(&row.mode),
        );
        emitter.emit_entry(
            LogEntry::new(
                benchmark_trace_id.clone(),
                LogLevel::Info,
                "conformance.benchmark_result",
            )
            .with_stream(StreamKind::Conformance)
            .with_gate(CONFORMANCE_LOG_GATE)
            .with_mode(row.mode.clone())
            .with_api("conformance", row.symbol.clone())
            .with_outcome(if row.failed == 0 && row.errors == 0 {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_errno(0)
            .with_healing_action("none")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "samples": duration_details.samples,
                "p50_ms": duration_details.p50_ms,
                "p95_ms": duration_details.p95_ms,
                "p99_ms": duration_details.p99_ms,
                "mean_ms": duration_details.mean_ms,
                "max_ms": duration_details.max_ms,
                "budget_ms": perf_budget_ms,
                "total": row.total,
                "passed": row.passed,
                "failed": row.failed,
                "errors": row.errors,
                "pass_rate_percent": row.pass_rate_percent,
                "decision_path": "conformance->benchmark_summary"
            })),
        )?;

        if duration_details.samples > 0
            && duration_details.p95_ms.saturating_mul(100)
                >= perf_budget_ms.saturating_mul(CONFORMANCE_WARN_BUDGET_PERCENT)
        {
            emitter.emit_entry(
                LogEntry::new(
                    benchmark_trace_id,
                    LogLevel::Warn,
                    "conformance.performance_budget_near_violation",
                )
                .with_stream(StreamKind::Conformance)
                .with_gate(CONFORMANCE_LOG_GATE)
                .with_mode(row.mode.clone())
                .with_api("conformance", row.symbol.clone())
                .with_outcome(if row.failed == 0 && row.errors == 0 {
                    Outcome::Pass
                } else {
                    Outcome::Fail
                })
                .with_errno(0)
                .with_healing_action("none")
                .with_artifacts(artifact_refs.clone())
                .with_details(serde_json::json!({
                    "p95_ms": duration_details.p95_ms,
                    "budget_ms": perf_budget_ms,
                    "warn_threshold_percent": CONFORMANCE_WARN_BUDGET_PERCENT,
                    "decision_path": "conformance->benchmark_budget_guard"
                })),
            )?;
        }
    }

    emitter.flush()?;
    Ok(())
}

fn emit_healing_oracle_logs(
    log_path: &Path,
    report_output_path: &Path,
    report: &HealingOracleReport,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let run_id = format!(
        "{}_{}",
        sanitize_trace_component(&report.campaign),
        sanitize_trace_component(&report.mode)
    );
    let mut emitter = LogEmitter::to_file(log_path, &report.bead, &run_id)?;
    let report_artifact = report_output_path.display().to_string();
    let log_artifact = log_path.display().to_string();
    let artifact_refs = vec![report_artifact, log_artifact];

    for row in &report.cases {
        let outcome = if row.status == "pass" {
            Outcome::Pass
        } else {
            Outcome::Fail
        };
        let level = if row.status == "pass" {
            LogLevel::Info
        } else {
            LogLevel::Error
        };

        emitter.emit_entry(
            LogEntry::new(row.trace_id.clone(), level, "healing_oracle.case_result")
                .with_stream(StreamKind::Conformance)
                .with_gate(HEALING_LOG_GATE)
                .with_mode(row.mode.clone())
                .with_api(row.api_family.clone(), row.symbol.clone())
                .with_outcome(outcome)
                .with_errno(0)
                .with_latency_ns(0)
                .with_healing_action(row.observed_action.clone())
                .with_artifacts(artifact_refs.clone())
                .with_details(serde_json::json!({
                    "case_id": row.case_id,
                    "condition": row.condition,
                    "expected_action": row.expected_action,
                    "observed_action": row.observed_action,
                    "detected": row.detected,
                    "repaired": row.repaired,
                    "posix_valid": row.posix_valid,
                    "evidence_logged": row.evidence_logged,
                    "decision_path": "healing_oracle->case_result"
                })),
        )?;
    }

    let summary_trace = format!(
        "{}::healing_oracle::summary",
        sanitize_trace_component(&report.campaign)
    );
    emitter.emit_entry(
        LogEntry::new(summary_trace, LogLevel::Info, "healing_oracle.summary")
            .with_stream(StreamKind::Conformance)
            .with_gate(HEALING_LOG_GATE)
            .with_mode(report.mode.clone())
            .with_api("membrane", "healing_oracle")
            .with_outcome(if report.all_passed() {
                Outcome::Pass
            } else {
                Outcome::Fail
            })
            .with_errno(0)
            .with_latency_ns(0)
            .with_healing_action("none")
            .with_artifacts(artifact_refs)
            .with_details(serde_json::json!({
                "total_cases": report.summary.total_cases,
                "passed": report.summary.passed,
                "failed": report.summary.failed,
                "detected": report.summary.detected,
                "repaired": report.summary.repaired,
                "posix_valid": report.summary.posix_valid,
                "evidence_logged": report.summary.evidence_logged,
                "pass_rate_percent": report.summary.pass_rate_percent,
                "decision_path": "healing_oracle->summary"
            })),
    )?;

    emitter.flush()?;
    Ok(())
}

fn parse_seed(raw: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = raw.trim();
    let seed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let hex = hex.replace('_', "");
        u64::from_str_radix(&hex, 16)?
    } else {
        let dec = s.replace('_', "");
        dec.parse::<u64>()?
    };
    Ok(seed)
}

fn load_fixture_sets(
    dir: &std::path::Path,
) -> Result<Vec<frankenlibc_harness::FixtureSet>, Box<dyn std::error::Error>> {
    let mut fixture_sets = Vec::new();
    let mut fixture_paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    fixture_paths.sort();

    for path in fixture_paths {
        match frankenlibc_harness::FixtureSet::from_file(&path) {
            Ok(set) => fixture_sets.push(set),
            Err(err) => eprintln!("Skipping {}: {}", path.display(), err),
        }
    }

    Ok(fixture_sets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenlibc_harness::conformance_matrix::{
        ConformanceCaseRow, ConformanceMatrixSummary, SymbolMatrixRow,
    };

    fn sample_case(
        trace_id: &str,
        status: &str,
        passed: bool,
        duration_ms: u64,
    ) -> ConformanceCaseRow {
        ConformanceCaseRow {
            trace_id: trace_id.to_string(),
            family: "string".to_string(),
            symbol: "strlen".to_string(),
            mode: "strict".to_string(),
            case_name: "case-1".to_string(),
            spec_section: "POSIX".to_string(),
            input_hex: "00".to_string(),
            expected_output: "1".to_string(),
            actual_output: if passed { "1" } else { "2" }.to_string(),
            host_output: Some("1".to_string()),
            host_parity: Some(passed),
            note: None,
            status: status.to_string(),
            passed,
            error: None,
            diff_offset: if passed { None } else { Some(0) },
            duration_ms: Some(duration_ms),
        }
    }

    fn sample_report(cases: Vec<ConformanceCaseRow>) -> ConformanceMatrixReport {
        ConformanceMatrixReport {
            schema_version: "v1".to_string(),
            bead: "bd-l93x.2".to_string(),
            generated_at_utc: "deterministic:test".to_string(),
            campaign: "test_campaign".to_string(),
            mode: "strict".to_string(),
            total_fixture_sets: 1,
            summary: ConformanceMatrixSummary {
                total_cases: u64::try_from(cases.len()).unwrap_or(u64::MAX),
                passed: u64::try_from(cases.iter().filter(|case| case.passed).count())
                    .unwrap_or(u64::MAX),
                failed: u64::try_from(cases.iter().filter(|case| !case.passed).count())
                    .unwrap_or(u64::MAX),
                errors: 0,
                pass_rate_percent: 50.0,
            },
            symbol_matrix: vec![SymbolMatrixRow {
                symbol: "strlen".to_string(),
                mode: "strict".to_string(),
                total: 1,
                passed: 0,
                failed: 1,
                errors: 0,
                pass_rate_percent: 0.0,
            }],
            cases,
        }
    }

    #[test]
    fn duration_stats_computes_quantiles() {
        let stats = duration_stats(&[10, 30, 20, 40, 50]).expect("stats");
        assert_eq!(stats.samples, 5);
        assert_eq!(stats.p50_ms, 30);
        assert_eq!(stats.p95_ms, 50);
        assert_eq!(stats.p99_ms, 50);
        assert_eq!(stats.max_ms, 50);
        assert!((stats.mean_ms - 30.0).abs() < f64::EPSILON);
    }

    #[test]
    fn previous_pass_map_retains_trace_status() {
        let report = sample_report(vec![
            sample_case("trace::1", "pass", true, 10),
            sample_case("trace::2", "fail", false, 10),
        ]);
        let prior = previous_pass_map(Some(&report));
        assert_eq!(prior.get("trace::1"), Some(&true));
        assert_eq!(prior.get("trace::2"), Some(&false));
    }

    #[test]
    fn shadow_run_modes_expands_both() {
        assert_eq!(
            shadow_run_modes("both").expect("mode"),
            vec!["strict".to_string(), "hardened".to_string()]
        );
        assert!(shadow_run_modes("invalid").is_err());
    }

    #[test]
    fn shadow_run_cli_accepts_manifest_and_defaults() {
        let cli = Cli::try_parse_from(["harness", "shadow-run", "--manifest", "shadow.json"])
            .expect("cli parses");

        match cli.command {
            Command::ShadowRun {
                manifest,
                report,
                log,
                artifact_index,
                lib_path,
                mode,
                timeout_ms,
                no_syscall_trace,
                fail_on_mismatch,
                ..
            } => {
                assert_eq!(manifest, PathBuf::from("shadow.json"));
                assert_eq!(
                    report,
                    PathBuf::from("target/conformance/shadow_run.current.v1.json")
                );
                assert_eq!(
                    log,
                    PathBuf::from("target/conformance/shadow_run.log.jsonl")
                );
                assert_eq!(
                    artifact_index,
                    PathBuf::from("target/conformance/shadow_run.artifacts.v1.json")
                );
                assert_eq!(
                    lib_path,
                    PathBuf::from("target/release/libfrankenlibc_abi.so")
                );
                assert_eq!(mode, "both");
                assert_eq!(timeout_ms, 5_000);
                assert!(!no_syscall_trace);
                assert!(!fail_on_mismatch);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn fault_inject_cli_accepts_manifest_and_defaults() {
        let cli = Cli::try_parse_from(["harness", "fault-inject", "--manifest", "fault.yaml"])
            .expect("cli parses");

        match cli.command {
            Command::FaultInject {
                manifest,
                scenario,
                report,
                log,
                artifact_index,
                mode,
                fail_on_mismatch,
                ..
            } => {
                assert_eq!(manifest, PathBuf::from("fault.yaml"));
                assert!(scenario.is_none());
                assert_eq!(
                    report,
                    PathBuf::from("target/conformance/fault_injection.current.v1.json")
                );
                assert_eq!(
                    log,
                    PathBuf::from("target/conformance/fault_injection.log.jsonl")
                );
                assert_eq!(
                    artifact_index,
                    PathBuf::from("target/conformance/fault_injection.artifacts.v1.json")
                );
                assert_eq!(mode, "both");
                assert!(!fail_on_mismatch);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn emits_required_conformance_log_levels_and_regression_events() {
        let tmp = std::env::temp_dir();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        );
        let matrix_path = tmp.join(format!("frankenlibc-conformance-matrix-{suffix}.json"));
        let log_path = tmp.join(format!("frankenlibc-conformance-log-{suffix}.jsonl"));

        std::fs::write(&matrix_path, "{}").expect("matrix artifact");

        let previous = sample_report(vec![sample_case(
            "test_campaign::string::strlen::strict::case-1",
            "pass",
            true,
            60,
        )]);
        let current = sample_report(vec![sample_case(
            "test_campaign::string::strlen::strict::case-1",
            "fail",
            false,
            90,
        )]);

        emit_conformance_matrix_logs(
            &log_path,
            &matrix_path,
            "test_campaign",
            &current,
            Some(&previous),
            100,
        )
        .expect("emit log");

        let body = std::fs::read_to_string(&log_path).expect("read log");
        assert!(
            body.contains("\"event\":\"conformance.fixture_execution\"")
                && body.contains("\"level\":\"trace\"")
        );
        assert!(
            body.contains("\"event\":\"conformance.shadow_run_divergence\"")
                && body.contains("\"level\":\"debug\"")
        );
        assert!(
            body.contains("\"event\":\"conformance.fixture_summary\"")
                && body.contains("\"level\":\"info\"")
        );
        assert!(
            body.contains("\"event\":\"conformance.benchmark_result\"")
                && body.contains("\"level\":\"info\"")
        );
        assert!(
            body.contains("\"event\":\"conformance.performance_budget_near_violation\"")
                && body.contains("\"level\":\"warn\"")
        );
        assert!(
            body.contains("\"event\":\"conformance.regression_detected\"")
                && body.contains("\"level\":\"error\"")
        );
    }
}
