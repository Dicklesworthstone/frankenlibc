//! CLI entrypoint for frankenlibc conformance harness.

use std::collections::{BTreeMap, BTreeSet};
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
        /// Run each fixture case in a child process so crash/abort cases become report rows.
        #[arg(long)]
        isolate: bool,
        /// Per-case timeout used when `--isolate` is enabled.
        #[arg(long, default_value_t = 5000)]
        case_timeout_ms: u64,
        /// Write reports even when some fixture rows fail.
        #[arg(long)]
        allow_failures: bool,
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
    /// Consume a TraceRow JSONL file (bd-yhvim input shape) and
    /// emit a single MinimizedTrace summary as JSONL.
    DecisionTraceMinimize {
        /// Input JSONL path. Each line: a TraceRow object with
        /// schema_version, scenario, api_family, symbol,
        /// decision_path, input_class, mode_strict_decision,
        /// mode_hardened_decision, source_commit, artifact_refs[].
        #[arg(long)]
        input: PathBuf,
        /// Output JSONL path: one MinimizedTrace summary record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Probe asupersync Lab availability (bd-qfbhc). Emits a single
    /// LabAvailability JSONL record. By default the detector reads
    /// process env (`FRANKENLIBC_ASUPERSYNC_AVAILABLE`, `PATH`) and
    /// the canonical `/dp/asupersync` directory. Override via flags.
    AsupersyncDetect {
        /// Override the value of `FRANKENLIBC_ASUPERSYNC_AVAILABLE`.
        /// When omitted, the detector reads the process env.
        #[arg(long)]
        override_var: Option<String>,
        /// Override the asupersync install directory probed in
        /// branch 2. Default: `/dp/asupersync`.
        #[arg(long)]
        asupersync_dir: Option<PathBuf>,
        /// Override `PATH` entries for branch 3 binary discovery.
        /// When omitted, splits the process `PATH`. Pass one
        /// colon-separated value.
        #[arg(long, value_delimiter = ':')]
        path_search_paths: Vec<PathBuf>,
        /// Output JSONL path: one LabAvailability record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Stress the production `EvidenceRingBuffer<CAP>` past
    /// capacity (bd-9nyo2) and emit a single RealRingReport as JSONL.
    /// CAP is selected by the `--cap` flag (one of 32, 128, 1024).
    EvidenceRingStress {
        /// Deterministic payload-byte seed: writes `(seed ^ i) as u8`.
        #[arg(long, default_value_t = 0xc0ffee_u64)]
        seed: u64,
        /// Number of CAPs to push (must be >= 2).
        #[arg(long, default_value_t = 4_u64)]
        multiple: u64,
        /// EvidenceRingBuffer capacity. One of 32, 128, 1024.
        #[arg(long, default_value_t = 32_usize)]
        cap: usize,
        /// 40-char hex SHA stamped on the report.
        #[arg(long)]
        source_commit: String,
        /// Output JSONL path: one RealRingReport record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Drive a paired-lane live measurement (bd-juvqm.3 / bd-8b70o /
    /// bd-vmp2v) and emit JSONL with one LiveMeasurementRow per lane
    /// plus a single P99Delta record. Uses
    /// `system_fingerprint::environment_fingerprint` (bd-6epxt) by
    /// default; `FRANKENLIBC_ENV_FINGERPRINT` honored end-to-end.
    LiveMeasurement {
        /// Logical profile id stamped on every LiveMeasurementRow.
        #[arg(long, default_value = "default-fp")]
        profile_id: String,
        /// Number of timed reads per lane (must be >= 1000 for p999).
        #[arg(long, default_value_t = 5_000)]
        n: u64,
        /// PCG32 seed used for the lane driver and tail_stats bootstrap.
        #[arg(long, default_value_t = 0xc0ffee_u64)]
        seed: u64,
        /// 40-char hex SHA stamped on every LiveMeasurementRow.
        #[arg(long)]
        source_commit: String,
        /// Optional environment fingerprint override; when omitted,
        /// the detector picks up `FRANKENLIBC_ENV_FINGERPRINT` or
        /// reads `/proc/cpuinfo` + `/proc/sys/kernel/osrelease`.
        #[arg(long)]
        environment_fingerprint: Option<String>,
        /// Output JSONL path. Three records emitted in order:
        /// conservative LiveMeasurementRow, seqlock LiveMeasurementRow,
        /// then P99Delta with kind="p99_delta".
        #[arg(long)]
        output: PathBuf,
    },
    /// Compute deterministic tail statistics for a JSON sample array.
    /// Emits one tail_stats_report JSONL record with p50/p95/p99/p999,
    /// p99 bootstrap CI, sufficiency flags, and overload classification.
    TailStats {
        /// Input JSON path: an array of finite numeric samples.
        #[arg(long)]
        samples_json: PathBuf,
        /// PCG32 seed used by tail_stats::compute for p99 bootstrap CI.
        #[arg(long)]
        seed: u64,
        /// Output JSONL path: one tail_stats_report record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a live-measurement p99_delta JSONL row against a
    /// budget via `tail_stats::validate_p99_delta_against_budget`.
    /// Emits one p99_delta_validation JSONL record and exits non-zero
    /// when the row is malformed or the delta fails the budget gate.
    ValidateP99Delta {
        /// Input JSONL path: exactly one p99_delta record.
        #[arg(long)]
        jsonl: PathBuf,
        /// Maximum allowed p99 delta in nanoseconds.
        #[arg(long)]
        allowed_budget_ns: u64,
        /// Maximum allowed p99 amplification ratio.
        #[arg(long)]
        amplification_threshold: f64,
        /// Output JSONL path: one p99_delta_validation record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Compute the alien-CS contention score + per-concept breakdown via
    /// `frankenlibc_membrane::alien_cs_metrics::compute_contention_score`
    /// and `compute_contention_breakdown`. Each diagnostic struct is
    /// optional; pass JSON file path(s) to include that concept.
    ComputeContentionScore {
        /// Optional JSON path to a SeqLockDiagnostics object with fields
        /// {reads, cache_hits, cache_misses, writes, contention_events,
        /// pending_writers, hit_ratio}.
        #[arg(long)]
        seqlock_diag: Option<PathBuf>,
        /// Optional JSON path to an EbrDiagnostics object with fields
        /// {global_epoch, active_threads, pinned_threads, total_retired,
        /// total_reclaimed, pending_per_epoch: [u, u, u]}.
        #[arg(long)]
        ebr_diag: Option<PathBuf>,
        /// Optional JSON path to a FlatCombinerDiagnostics object with
        /// fields {total_ops, total_passes, max_batch_size, avg_batch_size,
        /// active_slots, total_slots}.
        #[arg(long)]
        fc_diag: Option<PathBuf>,
        /// Output JSONL path: one contention_score record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Pack a 7-stage membrane check ordering via
    /// `frankenlibc_membrane::check_oracle::{pack_ordering, unpack_ordering}`.
    ///
    /// Stage names are `null`, `tls-cache`, `bloom`, `arena`, `fingerprint`,
    /// `canary`, and `bounds`. Pass seven repeated `--stage <name>` flags or
    /// one or more comma-separated `--stage` values.
    PackCheckOrdering {
        /// Validation stage name. Repeat seven times or pass comma-separated names.
        #[arg(long = "stage", required = true, num_args = 1..)]
        stages: Vec<String>,
    },
    /// Convert a Unix-days timestamp (days since 1970-01-01) into a civil
    /// (year, month, day) tuple via
    /// `frankenlibc_membrane::util::civil_date_from_unix_days`
    /// (Howard Hinnant's loopless algorithm).
    CivilDateFromUnixDays {
        /// Days since 1970-01-01 (may be negative). Use `--unix-days=-N`
        /// for negative inputs.
        #[arg(long)]
        unix_days: i64,
        /// Output JSONL path: one civil_date record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Map a Gröbner canonical root-cause class id (0..=7) to a deterministic
    /// healing action via
    /// `frankenlibc_membrane::heal::recommended_healing_for_canonical_class`.
    /// Output `action` is the kebab-case variant name.
    RecommendHealingForCanonicalClass {
        /// Canonical class id from grobner::CANONICAL_CLASS_* constants.
        #[arg(long)]
        class_id: u8,
        /// Output JSONL path: one recommended_healing record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Convert a sparse-recovery boolean support vector over the six latent
    /// causes into a compact Grobner canonical class id via
    /// `frankenlibc_membrane::grobner::canonical_class_from_support`.
    /// Compute deterministic SHA-256 over a D x D Gram matrix plus
    /// monomial_degree + barrier_budget_milli via
    /// `frankenlibc_membrane::runtime_math::sos_barrier::compute_certificate_hash`.
    /// D inferred from the outer JSON array length; supports D in 2..=8.
    ComputeCertificateHash {
        /// Path to JSON 2D array of i64 values forming the D x D Gram matrix.
        #[arg(long)]
        gram_matrix: PathBuf,
        /// Monomial degree (u32) of the SOS quadratic form.
        #[arg(long)]
        monomial_degree: u32,
        /// Barrier budget in milli-units (i64). Use --barrier-budget-milli=<N>
        /// for negative values.
        #[arg(long)]
        barrier_budget_milli: i64,
        /// Output JSONL path: one certificate_hash record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate ALL repair payloads for an epoch via
    /// `frankenlibc_membrane::runtime_math::evidence::generate_repair_payloads_v1`.
    /// Iterates esi from k_source..k_source+R-1 where R =
    /// derive_repair_symbol_count_v1(k_source, overhead_percent).
    GenerateRepairPayloads {
        /// Epoch seed used by the per-repair schedule.
        #[arg(long)]
        epoch_seed: u64,
        /// Binary input path with K concatenated 128-byte source symbols.
        #[arg(long)]
        source_payloads: PathBuf,
        /// Repair overhead percent (e.g. 25 = 25% redundancy over k_source).
        #[arg(long)]
        overhead_percent: u16,
        /// Output JSONL path: R per-symbol records + final summary record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Encode a single XOR repair symbol via
    /// `frankenlibc_membrane::runtime_math::evidence::encode_xor_repair_payload_v1`.
    /// Source payloads are read from a binary file containing K concatenated
    /// 128-byte (EVIDENCE_SYMBOL_SIZE_T) symbols.
    EncodeXorRepairPayload {
        /// Epoch seed used by derive_repair_schedule_v1 to pick source indices.
        #[arg(long)]
        epoch_seed: u64,
        /// Binary input path. Must contain a multiple of 128 bytes.
        #[arg(long)]
        source_payloads: PathBuf,
        /// Repair ESI (must be >= K = number of source symbols).
        #[arg(long)]
        repair_esi: u16,
        /// Output JSONL path: one xor_repair_payload record (hex payload + schedule).
        #[arg(long)]
        output: PathBuf,
    },
    CanonicalClassFromSupport {
        /// Active latent cause C0: temporal/provenance.
        #[arg(long)]
        c0_temporal: bool,
        /// Active latent cause C1: tail-latency/congestion.
        #[arg(long)]
        c1_congestion: bool,
        /// Active latent cause C2: topological/path-complexity.
        #[arg(long)]
        c2_topological: bool,
        /// Active latent cause C3: transition/regime shift.
        #[arg(long)]
        c3_regime: bool,
        /// Active latent cause C4: numeric/floating exceptional.
        #[arg(long)]
        c4_numeric: bool,
        /// Active latent cause C5: resource admissibility.
        #[arg(long)]
        c5_admissibility: bool,
        /// Output JSONL path: one canonical_class_from_support record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Iterate a JSONL file of runtime_evidence.decision.v1 rows and
    /// validate each via
    /// `frankenlibc_membrane::runtime_math::evidence::validate_runtime_evidence_row_v1`.
    /// Emits one per-row `evidence_row_validation` record plus a final
    /// `evidence_row_validation_summary` record.
    ValidateRuntimeEvidenceRows {
        /// Input JSONL path (one runtime_evidence row per line).
        #[arg(long)]
        jsonl: PathBuf,
        /// Output JSONL path: per-row validation records + final summary.
        #[arg(long)]
        output: PathBuf,
    },
    /// Look up the design-kernel cost in nanoseconds for a named runtime
    /// probe via `frankenlibc_membrane::runtime_math::design::probe_cost_ns`.
    /// Probe enum has 17 members (spectral..coupling).
    ProbeCostNs {
        /// Probe name (kebab-case): spectral, rough-path, persistence,
        /// anytime, cvar, bridge, large-deviations, hji, mean-field,
        /// padic, symplectic, higher-topos, commitment-audit, changepoint,
        /// conformal, loss-minimizer, coupling.
        #[arg(long)]
        probe: String,
        /// Output JSONL path: one probe_cost_ns record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Certify a candidate SIMD string-kernel implementation against the
    /// scalar reference via
    /// `frankenlibc_membrane::runtime_math::clifford::certify_simd_string_operation`.
    /// Emits a Clifford-algebra equivalence certificate including
    /// grade-2/parity energy and rejection rationale on failure.
    CertifySimdStringOp {
        /// String operation: memcpy | memcmp | strlen.
        #[arg(long)]
        operation: String,
        /// Candidate ISA: scalar | sse4.2 | avx2 | neon.
        #[arg(long)]
        candidate_isa: String,
        /// Source operand address (usize).
        #[arg(long, default_value_t = 0usize)]
        src_addr: usize,
        /// Destination operand address (usize).
        #[arg(long, default_value_t = 0usize)]
        dst_addr: usize,
        /// Operand length in bytes.
        #[arg(long, default_value_t = 0usize)]
        len: usize,
        /// Whether the operation is allowed to operate on overlapping
        /// source/destination regions.
        #[arg(long, default_value_t = false)]
        overlap: bool,
        /// Output JSONL path: one simd_string_certificate record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Reduce a u128 monomial/signature bitset mask to normal form using a
    /// table of (lhs, rhs) rewrite rules, via
    /// `frankenlibc_membrane::grobner::reduce_mask_with_limit`.
    /// The rule set must be confluent + terminating (e.g. extracted from a
    /// Gröbner basis); the step limit is a safety belt.
    ReduceMask {
        /// Input monomial mask as a u128 decimal integer.
        #[arg(long)]
        mask: u128,
        /// Path to a JSON file containing the rewrite rules as
        /// `[{ "lhs": <u128>, "rhs": <u128> }, ...]` (decimal integers).
        #[arg(long)]
        rules: PathBuf,
        /// Maximum number of successful rewrites permitted before bailing.
        /// Defaults to grobner::DEFAULT_STEP_LIMIT (1024).
        #[arg(long, default_value_t = 1024u32)]
        step_limit: u32,
        /// Output JSONL path: one reduce_mask record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Compute the memory-pressure ppm composition pipeline via
    /// `frankenlibc_membrane::runtime_math::sos_barrier::depth_to_arena_utilization_ppm`
    /// (depth -> ppm) and
    /// `frankenlibc_membrane::runtime_math::sos_barrier::compose_memory_pressure_ppm`
    /// (depth + EWMA pressure + raw pressure -> composed ppm).
    ComputeMemoryPressurePpm {
        /// Quarantine ring depth (entries).
        #[arg(long)]
        depth: u32,
        /// EWMA pressure score in milli-units (0..100_000).
        #[arg(long)]
        pressure_score_milli: u64,
        /// Raw pressure score in milli-units (0..100_000) used to detect
        /// sudden bursts not yet captured by EWMA lag.
        #[arg(long)]
        pressure_raw_score_milli: u64,
        /// Output JSONL path: one memory_pressure_ppm record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate the quarantine-depth admissibility barrier (Invariant A)
    /// via `frankenlibc_membrane::runtime_math::sos_barrier::evaluate_quarantine_barrier`.
    /// Returns barrier value in milli-units; positive => certified safe,
    /// negative => violation.
    EvaluateQuarantineBarrier {
        /// Quarantine ring depth (entries).
        #[arg(long)]
        depth: u32,
        /// Concurrent free-rate / arena owner contention indicator.
        #[arg(long)]
        contention: u32,
        /// Adverse-event rate (0..1_000_000 ppm).
        #[arg(long)]
        adverse_ppm: u32,
        /// Latency dual variable from PrimalDualController (-128..128).
        #[arg(long)]
        lambda_latency: i64,
        /// Output JSONL path: one quarantine_barrier record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate the pointer-provenance admissibility barrier (Invariant B)
    /// via `frankenlibc_membrane::runtime_math::sos_barrier::evaluate_provenance_barrier`.
    /// Positive headroom => certified safe; negative => violation.
    EvaluateProvenanceBarrier {
        /// Risk upper bound (0..1_000_000 ppm).
        #[arg(long)]
        risk_ppm: u32,
        /// Validation depth: 0 = Fast, 1_000_000 = Full.
        #[arg(long)]
        validation_depth_ppm: u32,
        /// Bloom false-positive rate (0..1_000_000 ppm).
        #[arg(long)]
        bloom_fp_rate_ppm: u32,
        /// arena_used / arena_capacity (0..1_000_000 ppm).
        #[arg(long)]
        arena_pressure_ppm: u32,
        /// Output JSONL path: one provenance_barrier record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate the size-class admissibility barrier certificate via
    /// `frankenlibc_membrane::runtime_math::sos_barrier::evaluate_size_class_barrier`.
    /// Positive headroom => certified safe; negative => violation.
    EvaluateSizeClassBarrier {
        /// Caller-requested allocation size in bytes.
        #[arg(long)]
        requested_size: usize,
        /// Size-class bytes selected by the allocator mapping.
        #[arg(long)]
        mapped_class_size: usize,
        /// Whether `mapped_class_size` belongs to the active
        /// allocator size-class table.
        #[arg(long, default_value_t = false)]
        class_membership_valid: bool,
        /// Output JSONL path: one size_class_barrier record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate the thread-safety barrier certificate via
    /// `frankenlibc_membrane::runtime_math::sos_barrier::evaluate_thread_safety_barrier`.
    /// Positive headroom => certified safe; negative => violation.
    EvaluateThreadSafetyBarrier {
        /// Concurrent threads touching allocator paths.
        #[arg(long)]
        thread_count: u32,
        /// Concurrent writers observed for a single arena free-list
        /// critical section.
        #[arg(long)]
        concurrent_writers: u32,
        /// True when ownership checks disagree.
        #[arg(long, default_value_t = false)]
        arena_owner_conflict: bool,
        /// Normalized skew between expected/observed free-list
        /// generation progress (0..1_000_000).
        #[arg(long)]
        free_list_skew_ppm: u32,
        /// Normalized lag between expected/observed allocation
        /// epochs (0..1_000_000).
        #[arg(long)]
        allocation_epoch_lag_ppm: u32,
        /// Output JSONL path: one thread_safety_barrier record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Evaluate the allocator-fragmentation barrier certificate via
    /// `frankenlibc_membrane::runtime_math::sos_barrier::evaluate_fragmentation_barrier`.
    /// Positive headroom => certified safe; negative => violation.
    EvaluateFragmentationBarrier {
        /// Observed allocator alloc-like events.
        #[arg(long)]
        allocation_count: u32,
        /// Observed allocator free-like events.
        #[arg(long)]
        free_count: u32,
        /// Normalized size-class dispersion (0..1_000_000).
        #[arg(long)]
        size_class_dispersion_ppm: u32,
        /// Normalized arena utilization (0..1_000_000).
        #[arg(long)]
        arena_utilization_ppm: u32,
        /// Output JSONL path: one fragmentation_barrier record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Discretize a runtime control decision's continuous state onto
    /// a single u32 row index into the Policy Compaction Profile
    /// Table, via the pipeline
    /// `policy_table::{risk_bucket_v1, budget_bucket_v1,
    /// consistency_bucket_v1, key_v1_index}`. Emits one
    /// policy_key JSONL record with every intermediate bucket plus
    /// the final key_index.
    DerivePolicyKey {
        /// Safety level: strict | hardened | off.
        #[arg(long)]
        mode: String,
        /// ApiFamily enum name: PointerValidation | Allocator |
        /// StringMemory | Stdio | Threading | Resolver | MathFenv |
        /// Loader | Stdlib | Ctype | Time | Signal | IoFd | Socket |
        /// Locale | Termios | Inet | Process | VirtualMemory | Poll.
        #[arg(long)]
        family: String,
        /// Risk in parts per million (0..=1_000_000).
        #[arg(long)]
        risk_ppm: u32,
        /// Fast-path over budget flag.
        #[arg(long, default_value_t = false)]
        fast_over_budget: bool,
        /// Full-pipeline over budget flag.
        #[arg(long, default_value_t = false)]
        full_over_budget: bool,
        /// Pareto-exhausted flag.
        #[arg(long, default_value_t = false)]
        pareto_exhausted: bool,
        /// Consistency-fault count.
        #[arg(long, default_value_t = 0_u64)]
        consistency_faults: u64,
        /// Output JSONL path: one policy_key record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Derive a deterministic repair schedule for a single repair
    /// symbol via
    /// `frankenlibc_membrane::runtime_math::evidence::derive_repair_schedule_v1`.
    /// Emits one JSONL record carrying the degree + selected indices.
    DeriveRepairSchedule {
        /// Epoch seed used to derive the schedule.
        #[arg(long)]
        epoch_seed: u64,
        /// Number of source symbols K_source.
        #[arg(long)]
        k_source: u16,
        /// Repair symbol ESI (encoding symbol id).
        #[arg(long)]
        repair_esi: u16,
        /// Output JSONL path: one repair_schedule record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Decode a raw 128-byte v1 decision payload via
    /// `frankenlibc_membrane::runtime_math::evidence::decode_decision_payload_v1`
    /// and emit one structured JSONL record describing the payload.
    /// Exits non-zero on decode failure.
    DecodeDecisionPayload {
        /// Path to the 128-byte raw payload file.
        #[arg(long)]
        payload: PathBuf,
        /// Output JSONL path: one decision_payload_decode record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a Policy Compaction Profile Table (.pcpt) artifact via
    /// `frankenlibc_membrane::runtime_math::policy_table::verify_pcpt`.
    /// Checks magic, schema_version, hash alg, key/cell spec ids,
    /// table length, hashes, and per-cell invariants. Emits one
    /// pcpt_verification JSONL record; exits non-zero on rejection.
    VerifyPcpt {
        /// Path to the .pcpt artifact.
        #[arg(long)]
        pcpt: PathBuf,
        /// Output JSONL path: one pcpt_verification record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Load the canonical evidence rows from disk, build a
    /// deterministic Dossier, and emit both a JSONL summary record
    /// and the markdown render. Exposes
    /// `explain_dossier::{load_dossier_inputs_from_disk, build_dossier,
    /// render_markdown}` as a standalone CLI for CI.
    ExplainDossier {
        /// Workspace root that contains the canonical evidence
        /// artifacts. Default: current directory.
        #[arg(long, default_value = ".")]
        workspace_root: PathBuf,
        /// 40-char hex SHA every evidence row must match.
        #[arg(long)]
        expected_commit: String,
        /// Output path for the rendered markdown dossier.
        #[arg(long)]
        output_markdown: PathBuf,
        /// Output JSONL path: one dossier record.
        #[arg(long)]
        output_jsonl: PathBuf,
    },
    /// Compute repair-symbol sizing + maximum tolerated loss fraction
    /// via `frankenlibc_membrane::runtime_math::evidence::
    /// {derive_repair_symbol_count_v1, loss_fraction_max_ppm_v1}`
    /// (bd-1es / bd-3a9). Pure numeric helpers; emits one JSONL
    /// record describing the repair sizing for given inputs.
    DeriveRepairMath {
        /// Source symbol count K_source (u16).
        #[arg(long)]
        k_source: u16,
        /// Overhead percent (u16). R = max(slack_decode,
        /// ceil(K_source * overhead_percent / 100)).
        #[arg(long)]
        overhead_percent: u16,
        /// Output JSONL path: one repair_math record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Render a text diff between two files via
    /// `harness::diff::render_diff`. Useful for surfacing
    /// expected-vs-actual divergences from CI without compiling.
    /// Output is unstructured plain text (the diff itself).
    RenderDiff {
        /// Path to the expected text file.
        #[arg(long)]
        expected: PathBuf,
        /// Path to the actual text file.
        #[arg(long)]
        actual: PathBuf,
        /// Output path for the rendered diff. When the files are
        /// identical the literal marker "[identical]" is written.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a stdio_evidence JSONL artifact against the
    /// StdioEvidenceRow schema (bd-9chy.4) via
    /// `stdio_evidence::parse_stdio_evidence_file`. Iterates every
    /// row and reports parse failures + unsupported schema versions
    /// in one structured summary JSONL record. Exits non-zero when
    /// any error is encountered.
    ValidateStdioEvidence {
        /// Path to the stdio_evidence JSONL artifact.
        #[arg(long)]
        jsonl: PathBuf,
        /// Output JSONL path: one stdio_evidence_validation record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a structured log JSONL artifact against the canonical
    /// LogEntry schema via `structured_log::validate_log_file`.
    /// Emits one JSONL record describing the outcome; exits non-zero
    /// when any row fails validation or the input cannot be read.
    ValidateStructuredLog {
        /// Path to the structured log JSONL artifact.
        #[arg(long)]
        jsonl: PathBuf,
        /// Output JSONL path: one structured_log_validation record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Parse a setjmp_semantics_contract.v1.json document and run
    /// its intrinsic-consistency checks via
    /// `setjmp_contract::{parse_contract_str, validate_intrinsic}`.
    /// Emits one JSONL record describing the outcome; exits non-zero
    /// when parsing fails or intrinsic checks return errors.
    ValidateSetjmpContract {
        /// Path to the setjmp_semantics_contract.v1.json document
        /// to validate (default: tests/conformance/setjmp_semantics_contract.v1.json).
        #[arg(
            long,
            default_value = "tests/conformance/setjmp_semantics_contract.v1.json"
        )]
        contract: PathBuf,
        /// Output JSONL path: one setjmp_contract_validation record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a runtime_evidence.decision.v1 JSONL log against the
    /// canonical membrane schema + replay-specific invariants
    /// (freshness, monotone timestamps, valid decision transitions,
    /// repair evidence, gate expectations) via
    /// `runtime_evidence_verifier::verify_runtime_evidence_jsonl`.
    VerifyRuntimeEvidence {
        /// Path to the runtime evidence JSONL log to verify.
        #[arg(long)]
        jsonl: PathBuf,
        /// 40-char hex SHA every row must match.
        #[arg(long)]
        expected_source_commit: String,
        /// Optional path to a JSON file containing an array of
        /// expectation objects: [{"symbol":"x","runtime_mode":"y",
        /// "decision_action":"Allow","denied":false}, ...].
        #[arg(long)]
        expectations: Option<PathBuf>,
        /// When set, an unexpected Deny decision is flagged as a
        /// failure (default: unexpected denials are tolerated).
        #[arg(long, default_value_t = false)]
        deny_unexpected_denials: bool,
        /// Output JSONL path: one verifier_report record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Drive `concurrency_model_check::check_seqlock` against a given
    /// write_count to exhaustively enumerate all interleavings of the
    /// writer's publication steps and one reader's read attempt,
    /// asserting seqlock invariants. Cap write_count at a small bound
    /// (state-space is 2^(3W+4)).
    SeqlockModelCheck {
        /// Number of writer publications to enumerate. Must be in
        /// [1, 4] — beyond 4, the schedule space (2^16) blows up.
        #[arg(long, default_value_t = 2_u32)]
        write_count: u32,
        /// Output JSONL path: one seqlock_model_report record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Drive `read_mostly_fast_path_prototype::isomorphism_witness`
    /// against an explicit write history and emit a JSONL report
    /// asserting that the conservative and seqlock lanes observed
    /// identical value sequences. This is the deterministic isomorphism
    /// proof for the read_mostly fast path, exposed as a CLI so CI can
    /// run it without linking to the crate.
    LaneIsomorphism {
        /// Initial value written to both lanes before any writes.
        #[arg(long, default_value_t = 0_u32)]
        initial: u32,
        /// Comma-separated u32 write history applied to both lanes.
        #[arg(long, default_value = "1,2,3,4")]
        writes: String,
        /// Number of reads drained from each lane between writes.
        #[arg(long, default_value_t = 4_usize)]
        reads_per_phase: usize,
        /// Output JSONL path: one isomorphism_report record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Dump this binary's compile-time tooling contract as one JSONL
    /// record, exposing
    /// `explainability_workbench::tooling_contract` so CI workflows
    /// can verify the deployed binary was built with the expected
    /// feature flags (asupersync-tooling, frankentui-ui) without
    /// linking to the Rust crate.
    ToolingContract {
        /// Output JSONL path: one tooling_contract record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a ReplayRecord JSONL row and classify the outcome
    /// against an observed-outputs JSONL list, exposing
    /// `asupersync_lab_replay::{validate_replay, classify_outcome}`
    /// (bd-juvqm.15) as a standalone CLI. Asupersync availability is
    /// probed via `detect_asupersync_available` with default process
    /// env, optionally overridden by `--override-var`.
    ReplayClassify {
        /// Input JSONL path: exactly one line carrying a ReplayRecord
        /// object (schema_version, trace_class, virtual_time_seed,
        /// schedule_decisions[], replay_inputs[], expected_outputs[],
        /// artifact_refs[], source_commit).
        #[arg(long)]
        input: PathBuf,
        /// Observed-outputs JSONL path: one line `{"observed_outputs":[...]}`.
        #[arg(long)]
        observed: PathBuf,
        /// Override `FRANKENLIBC_ASUPERSYNC_AVAILABLE` for the
        /// availability probe. When omitted, the detector reads the
        /// process env.
        #[arg(long)]
        override_var: Option<String>,
        /// Output JSONL path: one replay_outcome record.
        #[arg(long)]
        output: PathBuf,
    },
    /// Expose `system_fingerprint::{detect_components,
    /// environment_fingerprint, from_components,
    /// validate_environment_fingerprint}` (bd-6epxt) as a standalone
    /// CLI. Two modes:
    ///
    /// 1. Detect mode (default): emit one JSONL record describing the
    ///    host environment fingerprint and its components. Honors the
    ///    `FRANKENLIBC_ENV_FINGERPRINT` env override end-to-end.
    /// 2. Validate mode (`--validate <STRING>`): parse the supplied
    ///    string via `validate_environment_fingerprint`, emit one
    ///    JSONL record carrying ok=true|false plus either components
    ///    or a structured error string. Fails closed without panic.
    EnvFingerprint {
        /// Validate a supplied fingerprint string instead of detecting.
        /// When set the subcommand emits a record with
        /// kind="environment_fingerprint_validation".
        #[arg(long)]
        validate: Option<String>,
        /// Output JSONL path. Exactly one record is written.
        #[arg(long)]
        output: PathBuf,
    },
}

type TailStatsCliError = (String, String);

fn tail_stats_cli_error(kind: &str, message: impl Into<String>) -> TailStatsCliError {
    (kind.to_string(), message.into())
}

fn read_tail_stats_samples(path: &Path) -> Result<Vec<f64>, TailStatsCliError> {
    let body =
        std::fs::read_to_string(path).map_err(|e| tail_stats_cli_error("io", e.to_string()))?;
    let value = serde_json::from_str::<serde_json::Value>(&body)
        .map_err(|e| tail_stats_cli_error("json", e.to_string()))?;
    let samples = value
        .as_array()
        .ok_or_else(|| tail_stats_cli_error("root", "expected JSON sample array"))?;
    samples
        .iter()
        .enumerate()
        .map(|(idx, sample)| {
            let n = sample.as_f64().ok_or_else(|| {
                tail_stats_cli_error(
                    "invalid_sample",
                    format!("sample[{idx}] must be a finite JSON number"),
                )
            })?;
            if n.is_finite() {
                Ok(n)
            } else {
                Err(tail_stats_cli_error(
                    "non_finite_sample",
                    format!("sample[{idx}] must be finite"),
                ))
            }
        })
        .collect()
}

fn tail_stats_error_kind(err: frankenlibc_harness::tail_stats::TailStatsError) -> &'static str {
    match err {
        frankenlibc_harness::tail_stats::TailStatsError::Empty => "empty",
        frankenlibc_harness::tail_stats::TailStatsError::NonFiniteSample => "non_finite_sample",
        frankenlibc_harness::tail_stats::TailStatsError::InvalidQuantile => "invalid_quantile",
    }
}

type P99DeltaCliError = (String, String);

fn p99_delta_cli_error(kind: &str, message: impl Into<String>) -> P99DeltaCliError {
    (kind.to_string(), message.into())
}

fn required_p99_delta_number(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<f64, P99DeltaCliError> {
    let n = obj
        .get(field)
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| {
            p99_delta_cli_error(
                "invalid_number",
                format!("{field} must be a finite JSON number"),
            )
        })?;
    if n.is_finite() {
        Ok(n)
    } else {
        Err(p99_delta_cli_error(
            "invalid_number",
            format!("{field} must be finite"),
        ))
    }
}

fn required_p99_delta_bool(
    obj: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<bool, P99DeltaCliError> {
    obj.get(field)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| p99_delta_cli_error("invalid_bool", format!("{field} must be a bool")))
}

fn parse_p99_delta_value(
    value: &serde_json::Value,
) -> Result<frankenlibc_harness::tail_stats::P99Delta, P99DeltaCliError> {
    let obj = value
        .as_object()
        .ok_or_else(|| p99_delta_cli_error("root", "expected p99_delta JSON object".to_string()))?;
    if obj.get("kind").and_then(serde_json::Value::as_str) != Some("p99_delta") {
        return Err(p99_delta_cli_error(
            "wrong_kind",
            "record kind must be p99_delta",
        ));
    }
    Ok(frankenlibc_harness::tail_stats::P99Delta {
        p99_delta_ns: required_p99_delta_number(obj, "p99_delta_ns")?,
        ci_disjoint: required_p99_delta_bool(obj, "ci_disjoint")?,
        amplification_ratio: required_p99_delta_number(obj, "amplification_ratio")?,
        sufficient_samples: required_p99_delta_bool(obj, "sufficient_samples")?,
    })
}

fn read_p99_delta_jsonl(path: &Path) -> Result<serde_json::Value, P99DeltaCliError> {
    let body =
        std::fs::read_to_string(path).map_err(|e| p99_delta_cli_error("io", e.to_string()))?;
    let lines = body
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() != 1 {
        return Err(p99_delta_cli_error(
            "record_count",
            format!(
                "expected exactly one non-empty JSONL record; got {}",
                lines.len()
            ),
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(lines[0])
        .map_err(|e| p99_delta_cli_error("json", e.to_string()))?;
    Ok(value)
}

fn p99_delta_validator_error_kind(
    err: &frankenlibc_harness::tail_stats::P99DeltaError,
) -> &'static str {
    match err {
        frankenlibc_harness::tail_stats::P99DeltaError::OverBudget => "over_budget",
        frankenlibc_harness::tail_stats::P99DeltaError::AmplificationAboveThreshold => {
            "amplification_above_threshold"
        }
        frankenlibc_harness::tail_stats::P99DeltaError::InsufficientSamples => {
            "insufficient_samples"
        }
        frankenlibc_harness::tail_stats::P99DeltaError::CiIndistinguishableButOverBudget => {
            "ci_indistinguishable_but_over_budget"
        }
    }
}

fn check_stage_name(stage: frankenlibc_membrane::check_oracle::CheckStage) -> &'static str {
    use frankenlibc_membrane::check_oracle::CheckStage;
    match stage {
        CheckStage::Null => "null",
        CheckStage::TlsCache => "tls-cache",
        CheckStage::Bloom => "bloom",
        CheckStage::Arena => "arena",
        CheckStage::Fingerprint => "fingerprint",
        CheckStage::Canary => "canary",
        CheckStage::Bounds => "bounds",
    }
}

fn parse_check_stage_name(
    name: &str,
) -> Result<frankenlibc_membrane::check_oracle::CheckStage, String> {
    use frankenlibc_membrane::check_oracle::CheckStage;
    match name {
        "null" => Ok(CheckStage::Null),
        "tls-cache" => Ok(CheckStage::TlsCache),
        "bloom" => Ok(CheckStage::Bloom),
        "arena" => Ok(CheckStage::Arena),
        "fingerprint" => Ok(CheckStage::Fingerprint),
        "canary" => Ok(CheckStage::Canary),
        "bounds" => Ok(CheckStage::Bounds),
        _ => Err(format!(
            "unknown check stage {name:?}; expected one of null,tls-cache,bloom,arena,fingerprint,canary,bounds"
        )),
    }
}

fn parse_check_ordering(
    stage_args: &[String],
) -> Result<
    [frankenlibc_membrane::check_oracle::CheckStage;
        frankenlibc_membrane::check_oracle::NUM_STAGES],
    String,
> {
    use frankenlibc_membrane::check_oracle::{CheckStage, NUM_STAGES};

    let names = stage_args
        .iter()
        .flat_map(|arg| arg.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    if names.len() != NUM_STAGES {
        return Err(format!(
            "pack-check-ordering requires exactly {NUM_STAGES} stages; got {}",
            names.len()
        ));
    }

    let mut ordering = [CheckStage::Null; NUM_STAGES];
    let mut seen = [false; NUM_STAGES];
    for (idx, name) in names.iter().enumerate() {
        let stage = parse_check_stage_name(name)?;
        let stage_idx = stage as usize;
        if seen[stage_idx] {
            return Err(format!(
                "duplicate check stage {name:?}; ordering must be a permutation"
            ));
        }
        seen[stage_idx] = true;
        ordering[idx] = stage;
    }

    if let Some(missing_idx) = seen.iter().position(|stage_seen| !stage_seen) {
        return Err(format!(
            "missing check stage {:?}; ordering must be a permutation",
            check_stage_name(CheckStage::from_u8(missing_idx as u8))
        ));
    }

    Ok(ordering)
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
            isolate,
            case_timeout_ms,
            allow_failures,
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
                if isolate {
                    let output_hint = report
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("target/conformance/fixture_verify.md"));
                    let exe =
                        stable_conformance_case_runner(&std::env::current_exe()?, &output_hint)?;
                    let timeout = Duration::from_millis(case_timeout_ms.max(1));
                    let run = run_fixture_verification_isolated(
                        "fixture-verify",
                        &fixture_sets,
                        &exe,
                        timeout,
                    );
                    (run.verification_results, run.suite)
                } else {
                    let run =
                        frankenlibc_harness::asupersync_orchestrator::run_fixture_verification(
                            "fixture-verify",
                            &fixture_sets,
                        );
                    (run.verification_results, run.suite)
                }
            };

            #[cfg(not(feature = "asupersync-tooling"))]
            let mut results = {
                if isolate {
                    let output_hint = report
                        .clone()
                        .unwrap_or_else(|| PathBuf::from("target/conformance/fixture_verify.md"));
                    let exe =
                        stable_conformance_case_runner(&std::env::current_exe()?, &output_hint)?;
                    let timeout = Duration::from_millis(case_timeout_ms.max(1));
                    run_fixture_verification_isolated(
                        "fixture-verify",
                        &fixture_sets,
                        &exe,
                        timeout,
                    )
                    .verification_results
                } else {
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
                }
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

            if !allow_failures && !report_doc.summary.all_passed() {
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
                isolate,
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
                // Use a deterministic abnormal exit instead of abort(3).
                // On hosts that route core dumps through a helper, abort can
                // linger long enough for the parent timeout to win the race,
                // which tests host core-dump policy rather than crash-row
                // classification.
                std::process::exit(134);
            }

            let startup_frankenlibc_mode = std::env::var("FRANKENLIBC_MODE").ok();
            let envelope =
                match frankenlibc_fixture_exec::execute_fixture_case(&function, &inputs, &mode) {
                    Ok(run) => MatrixCaseEnvelope::ok(run),
                    Err(err) => MatrixCaseEnvelope::error(err),
                }
                .with_startup_mode_evidence(&mode, startup_frankenlibc_mode);
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
        Command::DecisionTraceMinimize { input, output } => {
            use frankenlibc_harness::decision_trace_minimizer::{
                TraceRow, minimize, serialize_minimized_trace_jsonl,
            };
            let body = std::fs::read_to_string(&input)
                .map_err(|e| format!("read --input {}: {e}", input.display()))?;
            let mut rows: Vec<TraceRow> = Vec::new();
            for (i, line) in body
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .enumerate()
            {
                let v: serde_json::Value = serde_json::from_str(line)
                    .map_err(|e| format!("--input line {} not JSON: {e}", i + 1))?;
                let required_string = |k: &str| -> Result<String, String> {
                    v.get(k)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                        .ok_or_else(|| format!("--input line {} missing string field `{k}`", i + 1))
                };
                let artifact_refs = v
                    .get("artifact_refs")
                    .and_then(serde_json::Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                rows.push(TraceRow {
                    schema_version: required_string("schema_version")?,
                    scenario: required_string("scenario")?,
                    api_family: required_string("api_family")?,
                    symbol: required_string("symbol")?,
                    decision_path: required_string("decision_path")?,
                    input_class: required_string("input_class")?,
                    mode_strict_decision: required_string("mode_strict_decision")?,
                    mode_hardened_decision: required_string("mode_hardened_decision")?,
                    source_commit: required_string("source_commit")?,
                    artifact_refs,
                });
            }
            if rows.is_empty() {
                return Err("--input contained zero TraceRow records".into());
            }
            let minimized = minimize(&rows).map_err(|e| format!("minimize: {e}"))?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut serialized = serialize_minimized_trace_jsonl(&minimized);
            if !serialized.ends_with('\n') {
                serialized.push('\n');
            }
            std::fs::write(&output, serialized)?;
            eprintln!(
                "decision-trace-minimize: read {} TraceRow records → wrote 1 MinimizedTrace JSONL record to {}",
                rows.len(),
                output.display()
            );
        }
        Command::AsupersyncDetect {
            override_var,
            asupersync_dir,
            path_search_paths,
            output,
        } => {
            use frankenlibc_harness::asupersync_lab_replay::{
                DetectionEnv, detect_asupersync_available,
            };
            let mut env = DetectionEnv::from_process_env();
            if let Some(v) = override_var {
                env.override_var = Some(v);
            }
            if let Some(p) = asupersync_dir {
                env.asupersync_dir = p;
            }
            if !path_search_paths.is_empty() {
                env.path_search_paths = path_search_paths;
            }
            let availability = detect_asupersync_available(&env);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let record = serde_json::json!({
                "kind": "lab_availability",
                "available": availability.available,
                "version": availability.version,
                "path": availability.path.as_ref().map(|p| p.display().to_string()),
                "detection_reason": availability.detection_reason,
            });
            let mut body = record.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "asupersync-detect: reason={} available={} → wrote 1 JSONL record to {}",
                availability.detection_reason,
                availability.available,
                output.display()
            );
        }
        Command::EvidenceRingStress {
            seed,
            multiple,
            cap,
            source_commit,
            output,
        } => {
            use frankenlibc_harness::evidence_ring_backpressure::{
                run_real_ring_stress, serialize_real_ring_report_jsonl,
            };
            let sha_ok =
                source_commit.len() == 40 && source_commit.chars().all(|c| c.is_ascii_hexdigit());
            if !sha_ok {
                return Err(format!(
                    "--source-commit must be a 40-char ascii-hex SHA; got {source_commit:?}"
                )
                .into());
            }
            if multiple < 2 {
                return Err(format!(
                    "--multiple must be >= 2 (the ring needs at least two CAPs of pushes to evict); got {multiple}"
                )
                .into());
            }
            // CAP must be a const generic — dispatch on the supported set.
            let report = match cap {
                32 => run_real_ring_stress::<32>(seed, multiple, &source_commit),
                128 => run_real_ring_stress::<128>(seed, multiple, &source_commit),
                1024 => run_real_ring_stress::<1024>(seed, multiple, &source_commit),
                other => {
                    return Err(format!("--cap must be one of 32, 128, 1024; got {other}").into());
                }
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut body = serialize_real_ring_report_jsonl(&report);
            if !body.ends_with('\n') {
                body.push('\n');
            }
            std::fs::write(&output, body)?;
            eprintln!(
                "evidence-ring-stress: cap={cap} multiple={multiple} → wrote 1 RealRingReport JSONL record to {}",
                output.display()
            );
        }
        Command::LiveMeasurement {
            profile_id,
            n,
            seed,
            source_commit,
            environment_fingerprint,
            output,
        } => {
            use frankenlibc_harness::read_mostly_fast_path_prototype::{
                run_live_measurement_pair_with_p99_delta,
                run_live_measurement_pair_with_p99_delta_and_detected_fingerprint,
            };
            // SHA validation mirrors validate_live_measurement so a
            // bad commit is rejected before doing 5_000+ timed reads.
            let sha_ok =
                source_commit.len() == 40 && source_commit.chars().all(|c| c.is_ascii_hexdigit());
            if !sha_ok {
                return Err(format!(
                    "--source-commit must be a 40-char ascii-hex SHA; got {source_commit:?}"
                )
                .into());
            }
            let (pair, delta) = if let Some(fp) = environment_fingerprint {
                run_live_measurement_pair_with_p99_delta(&profile_id, n, seed, &fp, &source_commit)
            } else {
                run_live_measurement_pair_with_p99_delta_and_detected_fingerprint(
                    &profile_id,
                    n,
                    seed,
                    &source_commit,
                )
            }
            .map_err(|err| format!("live measurement failed: {err:?}"))?;

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = String::new();
            for (kind, row) in [
                ("live_measurement_row", &pair.conservative),
                ("live_measurement_row", &pair.seqlock),
            ] {
                let line = serde_json::json!({
                    "kind": kind,
                    "lane_id": row.lane_id,
                    "profile_id": row.profile_id,
                    "source_commit": row.source_commit,
                    "environment_fingerprint": row.environment_fingerprint,
                    "p99_ns": row.p99_ns,
                    "p999_ns": row.p999_ns,
                    "throughput_ops_per_sec": row.throughput_ops_per_sec,
                    "n": row.n,
                    "seed": row.seed,
                });
                out.push_str(&line.to_string());
                out.push('\n');
            }
            let delta_line = serde_json::json!({
                "kind": "p99_delta",
                "profile_id": profile_id,
                "p99_delta_ns": delta.p99_delta_ns,
                "ci_disjoint": delta.ci_disjoint,
                "amplification_ratio": delta.amplification_ratio,
                "sufficient_samples": delta.sufficient_samples,
            });
            out.push_str(&delta_line.to_string());
            out.push('\n');
            std::fs::write(&output, out)?;
            eprintln!(
                "live-measurement: wrote 3 JSONL records (2 LiveMeasurementRow + 1 P99Delta) to {}",
                output.display()
            );
        }
        Command::TailStats {
            samples_json,
            seed,
            output,
        } => {
            use frankenlibc_harness::tail_stats::compute;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }

            let (sample_count, stats, error): (
                Option<usize>,
                Option<frankenlibc_harness::tail_stats::TailStats>,
                Option<TailStatsCliError>,
            ) = match read_tail_stats_samples(&samples_json) {
                Err(e) => (None, None, Some(e)),
                Ok(samples) => {
                    let sample_count = Some(samples.len());
                    match compute(&samples, seed) {
                        Ok(stats) => (sample_count, Some(stats), None),
                        Err(err) => (
                            sample_count,
                            None,
                            Some((tail_stats_error_kind(err).to_string(), err.to_string())),
                        ),
                    }
                }
            };

            let ok = error.is_none();
            let (error_kind, message) = error
                .map(|(kind, message)| {
                    (
                        serde_json::Value::String(kind),
                        serde_json::Value::String(message),
                    )
                })
                .unwrap_or((serde_json::Value::Null, serde_json::Value::Null));
            let line = if let Some(stats) = stats {
                serde_json::json!({
                    "kind": "tail_stats_report",
                    "input": samples_json.display().to_string(),
                    "ok": ok,
                    "error_kind": error_kind,
                    "message": message,
                    "n": stats.n,
                    "sample_count": sample_count,
                    "p50": stats.p50,
                    "p95": stats.p95,
                    "p99": stats.p99,
                    "p999": stats.p999,
                    "p99_ci_low": stats.p99_ci_low,
                    "p99_ci_high": stats.p99_ci_high,
                    "sufficient_for_p99": stats.sufficient_for_p99,
                    "sufficient_for_p999": stats.sufficient_for_p999,
                    "overloaded_host": stats.overloaded_host,
                    "seed": stats.seed,
                    "bootstrap_iters": stats.bootstrap_iters,
                })
            } else {
                serde_json::json!({
                    "kind": "tail_stats_report",
                    "input": samples_json.display().to_string(),
                    "ok": ok,
                    "error_kind": error_kind,
                    "message": message,
                    "n": serde_json::Value::Null,
                    "sample_count": sample_count,
                    "p50": serde_json::Value::Null,
                    "p95": serde_json::Value::Null,
                    "p99": serde_json::Value::Null,
                    "p999": serde_json::Value::Null,
                    "p99_ci_low": serde_json::Value::Null,
                    "p99_ci_high": serde_json::Value::Null,
                    "sufficient_for_p99": serde_json::Value::Null,
                    "sufficient_for_p999": serde_json::Value::Null,
                    "overloaded_host": serde_json::Value::Null,
                    "seed": seed,
                    "bootstrap_iters": serde_json::Value::Null,
                })
            };
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "tail-stats: ok={ok} wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "tail-stats: rejected {} - see {}",
                    samples_json.display(),
                    output.display()
                )
                .into());
            }
        }
        Command::ValidateP99Delta {
            jsonl,
            allowed_budget_ns,
            amplification_threshold,
            output,
        } => {
            use frankenlibc_harness::tail_stats::validate_p99_delta_against_budget;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }

            let (delta_value, error) =
                if !amplification_threshold.is_finite() || amplification_threshold <= 0.0 {
                    (
                        serde_json::Value::Null,
                        Some(p99_delta_cli_error(
                            "invalid_amplification_threshold",
                            "--amplification-threshold must be finite and > 0",
                        )),
                    )
                } else {
                    match read_p99_delta_jsonl(&jsonl) {
                        Err(e) => (serde_json::Value::Null, Some(e)),
                        Ok(value) => {
                            let error = match parse_p99_delta_value(&value) {
                                Err(e) => Some(e),
                                Ok(delta) => validate_p99_delta_against_budget(
                                    &delta,
                                    allowed_budget_ns,
                                    amplification_threshold,
                                )
                                .err()
                                .map(|err| {
                                    (
                                        p99_delta_validator_error_kind(&err).to_string(),
                                        err.to_string(),
                                    )
                                }),
                            };
                            (value, error)
                        }
                    }
                };

            let ok = error.is_none();
            let (error_kind, message) = error
                .map(|(kind, message)| {
                    (
                        serde_json::Value::String(kind),
                        serde_json::Value::String(message),
                    )
                })
                .unwrap_or((serde_json::Value::Null, serde_json::Value::Null));
            let line = serde_json::json!({
                "kind": "p99_delta_validation",
                "input": jsonl.display().to_string(),
                "allowed_budget_ns": allowed_budget_ns,
                "amplification_threshold": amplification_threshold,
                "ok": ok,
                "error_kind": error_kind,
                "message": message,
                "delta": delta_value,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "validate-p99-delta: ok={ok} wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "validate-p99-delta: rejected {} - see {}",
                    jsonl.display(),
                    output.display()
                )
                .into());
            }
        }
        Command::ComputeContentionScore {
            seqlock_diag,
            ebr_diag,
            fc_diag,
            output,
        } => {
            use frankenlibc_membrane::alien_cs_metrics::{
                compute_contention_breakdown, compute_contention_score,
            };
            use frankenlibc_membrane::ebr::EbrDiagnostics;
            use frankenlibc_membrane::flat_combining::FlatCombinerDiagnostics;
            use frankenlibc_membrane::seqlock::SeqLockDiagnostics;
            fn load_value(p: &Path) -> Result<serde_json::Value, String> {
                let body =
                    std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display()))?;
                serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", p.display()))
            }
            fn u64_or_zero(v: &serde_json::Value, k: &str) -> u64 {
                v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0)
            }
            fn usize_or_zero(v: &serde_json::Value, k: &str) -> usize {
                v.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0) as usize
            }
            fn f64_or_zero(v: &serde_json::Value, k: &str) -> f64 {
                v.get(k).and_then(serde_json::Value::as_f64).unwrap_or(0.0)
            }
            let seqlock: Option<SeqLockDiagnostics> = match &seqlock_diag {
                Some(p) => {
                    let v = load_value(p)?;
                    Some(SeqLockDiagnostics {
                        reads: u64_or_zero(&v, "reads"),
                        cache_hits: u64_or_zero(&v, "cache_hits"),
                        cache_misses: u64_or_zero(&v, "cache_misses"),
                        writes: u64_or_zero(&v, "writes"),
                        contention_events: u64_or_zero(&v, "contention_events"),
                        pending_writers: u64_or_zero(&v, "pending_writers"),
                        hit_ratio: f64_or_zero(&v, "hit_ratio"),
                    })
                }
                None => None,
            };
            let ebr: Option<EbrDiagnostics> = match &ebr_diag {
                Some(p) => {
                    let v = load_value(p)?;
                    let pe = v
                        .get("pending_per_epoch")
                        .and_then(serde_json::Value::as_array);
                    let pending_per_epoch = if let Some(arr) = pe {
                        let mut out = [0usize; 3];
                        for (i, slot) in out.iter_mut().enumerate().take(arr.len().min(3)) {
                            *slot = arr[i].as_u64().unwrap_or(0) as usize;
                        }
                        out
                    } else {
                        [0usize; 3]
                    };
                    Some(EbrDiagnostics {
                        global_epoch: u64_or_zero(&v, "global_epoch"),
                        active_threads: usize_or_zero(&v, "active_threads"),
                        pinned_threads: usize_or_zero(&v, "pinned_threads"),
                        total_retired: u64_or_zero(&v, "total_retired"),
                        total_reclaimed: u64_or_zero(&v, "total_reclaimed"),
                        pending_per_epoch,
                    })
                }
                None => None,
            };
            let fc: Option<FlatCombinerDiagnostics> = match &fc_diag {
                Some(p) => {
                    let v = load_value(p)?;
                    Some(FlatCombinerDiagnostics {
                        total_ops: u64_or_zero(&v, "total_ops"),
                        total_passes: u64_or_zero(&v, "total_passes"),
                        max_batch_size: u64_or_zero(&v, "max_batch_size"),
                        avg_batch_size: f64_or_zero(&v, "avg_batch_size"),
                        active_slots: usize_or_zero(&v, "active_slots"),
                        total_slots: usize_or_zero(&v, "total_slots"),
                    })
                }
                None => None,
            };
            let breakdown =
                compute_contention_breakdown(seqlock.as_ref(), ebr.as_ref(), fc.as_ref());
            let score = compute_contention_score(seqlock.as_ref(), ebr.as_ref(), fc.as_ref());
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "contention_score",
                "score": score,
                "breakdown": {
                    "seqlock_cache_miss_ratio": breakdown.seqlock_cache_miss_ratio,
                    "seqlock_contention_per_write": breakdown.seqlock_contention_per_write,
                    "ebr_pinned_fraction": breakdown.ebr_pinned_fraction,
                    "flat_combining_ops_per_pass": breakdown.flat_combining_ops_per_pass,
                    "flat_combining_efficiency_loss": breakdown.flat_combining_efficiency_loss,
                },
                "concepts_present": {
                    "seqlock": seqlock.is_some(),
                    "ebr": ebr.is_some(),
                    "flat_combining": fc.is_some(),
                },
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!("compute-contention-score: score={score:.6}");
        }
        Command::PackCheckOrdering { stages } => {
            use frankenlibc_membrane::check_oracle::{pack_ordering, unpack_ordering};

            let ordering = parse_check_ordering(&stages)?;
            let packed = pack_ordering(&ordering);
            let unpacked = unpack_ordering(packed);
            let stage_names = ordering
                .iter()
                .copied()
                .map(check_stage_name)
                .collect::<Vec<_>>();
            let unpacked_stage_names = unpacked
                .iter()
                .copied()
                .map(check_stage_name)
                .collect::<Vec<_>>();
            let line = serde_json::json!({
                "kind": "check_ordering_pack",
                "stages": stage_names,
                "packed_u64": packed,
                "packed_hex": format!("0x{packed:016x}"),
                "unpacked_round_trip": unpacked_stage_names,
                "round_trip_ok": ordering == unpacked,
            });
            println!("{line}");
        }
        Command::CivilDateFromUnixDays { unix_days, output } => {
            use frankenlibc_membrane::util::civil_date_from_unix_days;
            let (year, month, day) = civil_date_from_unix_days(unix_days);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "civil_date",
                "unix_days": unix_days,
                "year": year,
                "month": month,
                "day": day,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "civil-date-from-unix-days: unix_days={unix_days} -> {year:04}-{month:02}-{day:02}"
            );
        }
        Command::RecommendHealingForCanonicalClass { class_id, output } => {
            use frankenlibc_membrane::grobner::{
                CANONICAL_CLASS_ADMISSIBILITY, CANONICAL_CLASS_COMPOUND,
                CANONICAL_CLASS_CONGESTION, CANONICAL_CLASS_NONE, CANONICAL_CLASS_NUMERIC,
                CANONICAL_CLASS_REGIME, CANONICAL_CLASS_TEMPORAL, CANONICAL_CLASS_TOPOLOGICAL,
            };
            use frankenlibc_membrane::heal::{
                HealingAction, recommended_healing_for_canonical_class,
            };
            let class_label = match class_id {
                x if x == CANONICAL_CLASS_NONE => "none",
                x if x == CANONICAL_CLASS_TEMPORAL => "temporal",
                x if x == CANONICAL_CLASS_CONGESTION => "congestion",
                x if x == CANONICAL_CLASS_TOPOLOGICAL => "topological",
                x if x == CANONICAL_CLASS_REGIME => "regime",
                x if x == CANONICAL_CLASS_NUMERIC => "numeric",
                x if x == CANONICAL_CLASS_ADMISSIBILITY => "admissibility",
                x if x == CANONICAL_CLASS_COMPOUND => "compound",
                _ => "out_of_range_compound_fallback",
            };
            let action = recommended_healing_for_canonical_class(class_id);
            let (action_label, action_args): (&str, serde_json::Value) = match action {
                HealingAction::None => ("none", serde_json::Value::Null),
                HealingAction::ClampSize { requested, clamped } => (
                    "clamp-size",
                    serde_json::json!({"requested": requested, "clamped": clamped}),
                ),
                HealingAction::TruncateWithNull {
                    requested,
                    truncated,
                } => (
                    "truncate-with-null",
                    serde_json::json!({"requested": requested, "truncated": truncated}),
                ),
                HealingAction::IgnoreDoubleFree => ("ignore-double-free", serde_json::Value::Null),
                HealingAction::IgnoreForeignFree => {
                    ("ignore-foreign-free", serde_json::Value::Null)
                }
                HealingAction::ReallocAsMalloc { size } => {
                    ("realloc-as-malloc", serde_json::json!({"size": size}))
                }
                HealingAction::ReturnSafeDefault => {
                    ("return-safe-default", serde_json::Value::Null)
                }
                HealingAction::UpgradeToSafeVariant => {
                    ("upgrade-to-safe-variant", serde_json::Value::Null)
                }
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "recommended_healing",
                "class_id": class_id,
                "class_label": class_label,
                "action": action_label,
                "action_args": action_args,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "recommend-healing-for-canonical-class: class_id={class_id} ({class_label}) -> action={action_label}"
            );
        }
        Command::ComputeCertificateHash {
            gram_matrix,
            monomial_degree,
            barrier_budget_milli,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::compute_certificate_hash;
            let body = std::fs::read_to_string(&gram_matrix)
                .map_err(|e| format!("read {}: {e}", gram_matrix.display()))?;
            let parsed: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| format!("parse: {e}"))?;
            let outer = parsed
                .as_array()
                .ok_or_else(|| "gram_matrix root must be a JSON array".to_string())?;
            let dim = outer.len();
            if !(2..=8).contains(&dim) {
                return Err(
                    format!("unsupported gram_matrix dim {dim}; supported D in 2..=8").into(),
                );
            }
            let mut flat: Vec<i64> = Vec::with_capacity(dim * dim);
            for (i, row) in outer.iter().enumerate() {
                let row_arr = row
                    .as_array()
                    .ok_or_else(|| format!("gram_matrix row {i} must be a JSON array"))?;
                if row_arr.len() != dim {
                    return Err(format!(
                        "gram_matrix row {i} has length {}, expected {dim}",
                        row_arr.len()
                    )
                    .into());
                }
                for (j, cell) in row_arr.iter().enumerate() {
                    let v = cell
                        .as_i64()
                        .ok_or_else(|| format!("gram_matrix[{i}][{j}] must be an i64 integer"))?;
                    flat.push(v);
                }
            }
            fn to_matrix<const D: usize>(flat: &[i64]) -> [[i64; D]; D] {
                let mut out = [[0i64; D]; D];
                for i in 0..D {
                    for j in 0..D {
                        out[i][j] = flat[i * D + j];
                    }
                }
                out
            }
            let digest: [u8; 32] = match dim {
                2 => compute_certificate_hash::<2>(
                    &to_matrix::<2>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                3 => compute_certificate_hash::<3>(
                    &to_matrix::<3>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                4 => compute_certificate_hash::<4>(
                    &to_matrix::<4>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                5 => compute_certificate_hash::<5>(
                    &to_matrix::<5>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                6 => compute_certificate_hash::<6>(
                    &to_matrix::<6>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                7 => compute_certificate_hash::<7>(
                    &to_matrix::<7>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                8 => compute_certificate_hash::<8>(
                    &to_matrix::<8>(&flat),
                    monomial_degree,
                    barrier_budget_milli,
                ),
                _ => unreachable!("dim already bounds-checked"),
            };
            let hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "certificate_hash",
                "dim": dim,
                "monomial_degree": monomial_degree,
                "barrier_budget_milli": barrier_budget_milli,
                "hash_hex": hash_hex,
            });
            let mut out_body = line.to_string();
            out_body.push('\n');
            std::fs::write(&output, out_body)?;
            eprintln!(
                "compute-certificate-hash: dim={dim} monomial_degree={monomial_degree} budget_milli={barrier_budget_milli} -> hash={hash_hex}"
            );
        }
        Command::GenerateRepairPayloads {
            epoch_seed,
            source_payloads,
            overhead_percent,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::evidence::{
                EVIDENCE_SYMBOL_SIZE_T, generate_repair_payloads_v1,
            };
            let body = std::fs::read(&source_payloads)
                .map_err(|e| format!("read {}: {e}", source_payloads.display()))?;
            if !body.len().is_multiple_of(EVIDENCE_SYMBOL_SIZE_T) {
                return Err(format!(
                    "source_payloads length {} is not a multiple of {EVIDENCE_SYMBOL_SIZE_T}",
                    body.len()
                )
                .into());
            }
            let k = body.len() / EVIDENCE_SYMBOL_SIZE_T;
            if k == 0 {
                return Err("source_payloads must contain at least one 128-byte symbol".into());
            }
            let k_u16 = u16::try_from(k).map_err(|_| format!("k_source={k} exceeds u16::MAX"))?;
            let mut payloads: Vec<[u8; EVIDENCE_SYMBOL_SIZE_T]> = Vec::with_capacity(k);
            for i in 0..k {
                let start = i * EVIDENCE_SYMBOL_SIZE_T;
                let mut arr = [0u8; EVIDENCE_SYMBOL_SIZE_T];
                arr.copy_from_slice(&body[start..start + EVIDENCE_SYMBOL_SIZE_T]);
                payloads.push(arr);
            }
            let repairs = generate_repair_payloads_v1(epoch_seed, &payloads, overhead_percent);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut out_body = String::new();
            let mut esis: Vec<u16> = Vec::with_capacity(repairs.len());
            for (esi, payload) in &repairs {
                let payload_hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
                let rec = serde_json::json!({
                    "kind": "repair_payload",
                    "epoch_seed": epoch_seed,
                    "k_source": k_u16,
                    "overhead_percent": overhead_percent,
                    "repair_count": repairs.len(),
                    "esi": *esi,
                    "payload_hex": payload_hex,
                });
                out_body.push_str(&rec.to_string());
                out_body.push('\n');
                esis.push(*esi);
            }
            let summary = serde_json::json!({
                "kind": "repair_payload_summary",
                "epoch_seed": epoch_seed,
                "k_source": k_u16,
                "overhead_percent": overhead_percent,
                "repair_count": repairs.len(),
                "esis": esis,
            });
            out_body.push_str(&summary.to_string());
            out_body.push('\n');
            std::fs::write(&output, out_body)?;
            eprintln!(
                "generate-repair-payloads: epoch_seed={epoch_seed} k_source={k_u16} overhead_percent={overhead_percent} repair_count={}",
                repairs.len()
            );
        }
        Command::EncodeXorRepairPayload {
            epoch_seed,
            source_payloads,
            repair_esi,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::evidence::{
                EVIDENCE_SYMBOL_SIZE_T, derive_repair_schedule_v1, encode_xor_repair_payload_v1,
            };
            let body = std::fs::read(&source_payloads)
                .map_err(|e| format!("read {}: {e}", source_payloads.display()))?;
            if body.len() % EVIDENCE_SYMBOL_SIZE_T != 0 {
                return Err(format!(
                    "source_payloads length {} is not a multiple of {EVIDENCE_SYMBOL_SIZE_T}",
                    body.len()
                )
                .into());
            }
            let k = body.len() / EVIDENCE_SYMBOL_SIZE_T;
            if k == 0 {
                return Err("source_payloads must contain at least one 128-byte symbol".into());
            }
            let k_u16 = u16::try_from(k).map_err(|_| format!("k_source={k} exceeds u16::MAX"))?;
            if repair_esi < k_u16 {
                return Err(format!("repair_esi={repair_esi} must be >= k_source={k_u16}").into());
            }
            let mut payloads: Vec<[u8; EVIDENCE_SYMBOL_SIZE_T]> = Vec::with_capacity(k);
            for i in 0..k {
                let start = i * EVIDENCE_SYMBOL_SIZE_T;
                let mut arr = [0u8; EVIDENCE_SYMBOL_SIZE_T];
                arr.copy_from_slice(&body[start..start + EVIDENCE_SYMBOL_SIZE_T]);
                payloads.push(arr);
            }
            let sched = derive_repair_schedule_v1(epoch_seed, k_u16, repair_esi);
            let schedule_indices: Vec<u16> = sched.indices().to_vec();
            let payload = encode_xor_repair_payload_v1(epoch_seed, &payloads, repair_esi);
            let payload_hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "xor_repair_payload",
                "epoch_seed": epoch_seed,
                "k_source": k_u16,
                "repair_esi": repair_esi,
                "schedule_indices": schedule_indices,
                "payload_hex": payload_hex,
            });
            let mut out_body = line.to_string();
            out_body.push('\n');
            std::fs::write(&output, out_body)?;
            eprintln!(
                "encode-xor-repair-payload: epoch_seed={epoch_seed} k_source={k_u16} repair_esi={repair_esi} schedule_len={}",
                schedule_indices.len()
            );
        }
        Command::CanonicalClassFromSupport {
            c0_temporal,
            c1_congestion,
            c2_topological,
            c3_regime,
            c4_numeric,
            c5_admissibility,
            output,
        } => {
            use frankenlibc_membrane::grobner::{
                CANONICAL_CLASS_ADMISSIBILITY, CANONICAL_CLASS_COMPOUND,
                CANONICAL_CLASS_CONGESTION, CANONICAL_CLASS_NONE, CANONICAL_CLASS_NUMERIC,
                CANONICAL_CLASS_REGIME, CANONICAL_CLASS_TEMPORAL, CANONICAL_CLASS_TOPOLOGICAL,
                canonical_class_from_support,
            };
            let active = [
                c0_temporal,
                c1_congestion,
                c2_topological,
                c3_regime,
                c4_numeric,
                c5_admissibility,
            ];
            let class_id = canonical_class_from_support(&active);
            let class_label = match class_id {
                x if x == CANONICAL_CLASS_NONE => "none",
                x if x == CANONICAL_CLASS_TEMPORAL => "temporal",
                x if x == CANONICAL_CLASS_CONGESTION => "congestion",
                x if x == CANONICAL_CLASS_TOPOLOGICAL => "topological",
                x if x == CANONICAL_CLASS_REGIME => "regime",
                x if x == CANONICAL_CLASS_NUMERIC => "numeric",
                x if x == CANONICAL_CLASS_ADMISSIBILITY => "admissibility",
                x if x == CANONICAL_CLASS_COMPOUND => "compound",
                _ => "unknown",
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "canonical_class_from_support",
                "active": active,
                "class_id": class_id,
                "class_label": class_label,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "canonical-class-from-support: active={active:?} -> class_id={class_id} ({class_label})"
            );
        }
        Command::ValidateRuntimeEvidenceRows { jsonl, output } => {
            use frankenlibc_membrane::runtime_math::evidence::{
                RuntimeEvidenceRowValidationError, validate_runtime_evidence_row_v1,
            };
            let body = std::fs::read_to_string(&jsonl)
                .map_err(|e| format!("read {}: {e}", jsonl.display()))?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut out_body = String::new();
            let mut total: u64 = 0;
            let mut valid_count: u64 = 0;
            let mut invalid_count: u64 = 0;
            for (idx, line) in body.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                total += 1;
                let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
                    Ok(v) => v,
                    Err(e) => {
                        invalid_count += 1;
                        let rec = serde_json::json!({
                            "kind": "evidence_row_validation",
                            "row_index": idx,
                            "valid": false,
                            "error_kind": "json_parse_error",
                            "error_field": null,
                            "parse_error": e.to_string(),
                        });
                        out_body.push_str(&rec.to_string());
                        out_body.push('\n');
                        continue;
                    }
                };
                let (valid, error_kind, error_field) =
                    match validate_runtime_evidence_row_v1(&parsed) {
                        Ok(()) => {
                            valid_count += 1;
                            (true, None, None)
                        }
                        Err(err) => {
                            invalid_count += 1;
                            let (kind, field) = match err {
                                RuntimeEvidenceRowValidationError::NotObject => {
                                    ("not_object", None)
                                }
                                RuntimeEvidenceRowValidationError::MissingRequiredField(f) => {
                                    ("missing_required_field", Some(f))
                                }
                                RuntimeEvidenceRowValidationError::WrongType(f) => {
                                    ("wrong_type", Some(f))
                                }
                                RuntimeEvidenceRowValidationError::EmptyString(f) => {
                                    ("empty_string", Some(f))
                                }
                                RuntimeEvidenceRowValidationError::EmptyArtifactRefs => {
                                    ("empty_artifact_refs", None)
                                }
                                RuntimeEvidenceRowValidationError::UnexpectedValue(f) => {
                                    ("unexpected_value", Some(f))
                                }
                            };
                            (false, Some(kind), field)
                        }
                    };
                let rec = serde_json::json!({
                    "kind": "evidence_row_validation",
                    "row_index": idx,
                    "valid": valid,
                    "error_kind": error_kind,
                    "error_field": error_field,
                });
                out_body.push_str(&rec.to_string());
                out_body.push('\n');
            }
            let summary = serde_json::json!({
                "kind": "evidence_row_validation_summary",
                "total": total,
                "valid": valid_count,
                "invalid": invalid_count,
            });
            out_body.push_str(&summary.to_string());
            out_body.push('\n');
            std::fs::write(&output, out_body)?;
            eprintln!(
                "validate-runtime-evidence-rows: total={total} valid={valid_count} invalid={invalid_count}"
            );
        }
        Command::ProbeCostNs { probe, output } => {
            use frankenlibc_membrane::runtime_math::design::{Probe, probe_cost_ns};
            let p = match probe.as_str() {
                "spectral" => Probe::Spectral,
                "rough-path" => Probe::RoughPath,
                "persistence" => Probe::Persistence,
                "anytime" => Probe::Anytime,
                "cvar" => Probe::Cvar,
                "bridge" => Probe::Bridge,
                "large-deviations" => Probe::LargeDeviations,
                "hji" => Probe::Hji,
                "mean-field" => Probe::MeanField,
                "padic" => Probe::Padic,
                "symplectic" => Probe::Symplectic,
                "higher-topos" => Probe::HigherTopos,
                "commitment-audit" => Probe::CommitmentAudit,
                "changepoint" => Probe::Changepoint,
                "conformal" => Probe::Conformal,
                "loss-minimizer" => Probe::LossMinimizer,
                "coupling" => Probe::Coupling,
                other => return Err(format!("unknown probe: {other}").into()),
            };
            let cost = probe_cost_ns(p);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "probe_cost_ns",
                "probe": probe,
                "cost_ns": cost,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!("probe-cost-ns: probe={probe} -> cost_ns={cost}");
        }
        Command::CertifySimdStringOp {
            operation,
            candidate_isa,
            src_addr,
            dst_addr,
            len,
            overlap,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::clifford::{
                CliffordState, SimdIsa, SimdStringOperation, certify_simd_string_operation,
            };
            let op = match operation.as_str() {
                "memcpy" => SimdStringOperation::Memcpy,
                "memcmp" => SimdStringOperation::Memcmp,
                "strlen" => SimdStringOperation::Strlen,
                other => {
                    return Err(format!("unknown operation: {other}").into());
                }
            };
            let isa = match candidate_isa.as_str() {
                "scalar" | "portable" => SimdIsa::Scalar,
                "sse4.2" | "sse42" => SimdIsa::Sse42,
                "avx2" => SimdIsa::Avx2,
                "neon" => SimdIsa::Neon,
                other => {
                    return Err(format!("unknown candidate_isa: {other}").into());
                }
            };
            let cert = certify_simd_string_operation(op, isa, src_addr, dst_addr, len, overlap);
            let state_label = match cert.state {
                CliffordState::Calibrating => "calibrating",
                CliffordState::Aligned => "aligned",
                CliffordState::MisalignmentDrift => "misalignment_drift",
                CliffordState::OverlapViolation => "overlap_violation",
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "simd_string_certificate",
                "operation": operation,
                "candidate_isa": candidate_isa,
                "architecture": cert.architecture,
                "lane_bytes": cert.lane_bytes,
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "len": len,
                "overlap": overlap,
                "equivalent": cert.equivalent,
                "state": state_label,
                "grade2_energy": cert.grade2_energy,
                "parity_imbalance": cert.parity_imbalance,
                "overlap_fraction": cert.overlap_fraction,
                "rationale": cert.rationale,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "certify-simd-string-op: op={operation} isa={candidate_isa} src={src_addr} dst={dst_addr} len={len} overlap={overlap} -> equivalent={} state={state_label}",
                cert.equivalent
            );
        }
        Command::ReduceMask {
            mask,
            rules,
            step_limit,
            output,
        } => {
            use frankenlibc_membrane::grobner::{
                MonomialMask, ReduceError, ReductionRule, reduce_mask_with_limit,
            };
            let body = std::fs::read_to_string(&rules)
                .map_err(|e| format!("read rules {}: {e}", rules.display()))?;
            #[derive(serde::Deserialize)]
            struct RuleJson {
                lhs: MonomialMask,
                rhs: MonomialMask,
            }
            let parsed: Vec<RuleJson> =
                serde_json::from_str(&body).map_err(|e| format!("parse rules: {e}"))?;
            let rule_count = parsed.len();
            let rule_table: Vec<ReductionRule> = parsed
                .into_iter()
                .map(|r| ReductionRule {
                    lhs: r.lhs,
                    rhs: r.rhs,
                })
                .collect();
            let (reduced_mask, steps, reached_fixpoint, error) =
                match reduce_mask_with_limit(mask, &rule_table, step_limit) {
                    Ok((m, stats)) => (m, stats.steps, stats.reached_fixpoint, None),
                    Err(ReduceError::StepLimitExceeded { steps }) => {
                        (mask, steps, false, Some("step_limit_exceeded"))
                    }
                };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "reduce_mask",
                "input_mask": mask.to_string(),
                "rule_count": rule_count,
                "step_limit": step_limit,
                "reduced_mask": reduced_mask.to_string(),
                "steps": steps,
                "reached_fixpoint": reached_fixpoint,
                "error": error,
            });
            let mut out_body = line.to_string();
            out_body.push('\n');
            std::fs::write(&output, out_body)?;
            eprintln!(
                "reduce-mask: input_mask={mask} rule_count={rule_count} step_limit={step_limit} -> reduced_mask={reduced_mask} steps={steps} fixpoint={reached_fixpoint} error={error:?}"
            );
        }
        Command::ComputeMemoryPressurePpm {
            depth,
            pressure_score_milli,
            pressure_raw_score_milli,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::{
                compose_memory_pressure_ppm, depth_to_arena_utilization_ppm,
            };
            let depth_ppm = depth_to_arena_utilization_ppm(depth);
            let composed_ppm =
                compose_memory_pressure_ppm(depth, pressure_score_milli, pressure_raw_score_milli);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "memory_pressure_ppm",
                "depth": depth,
                "pressure_score_milli": pressure_score_milli,
                "pressure_raw_score_milli": pressure_raw_score_milli,
                "depth_arena_utilization_ppm": depth_ppm,
                "composed_pressure_ppm": composed_ppm,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "compute-memory-pressure-ppm: depth={depth} score_milli={pressure_score_milli} raw_milli={pressure_raw_score_milli} -> depth_ppm={depth_ppm} composed_ppm={composed_ppm}"
            );
        }
        Command::EvaluateQuarantineBarrier {
            depth,
            contention,
            adverse_ppm,
            lambda_latency,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_quarantine_barrier;
            let headroom =
                evaluate_quarantine_barrier(depth, contention, adverse_ppm, lambda_latency);
            let safe = headroom >= 0;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "quarantine_barrier",
                "depth": depth,
                "contention": contention,
                "adverse_ppm": adverse_ppm,
                "lambda_latency": lambda_latency,
                "headroom": headroom,
                "safe": safe,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "evaluate-quarantine-barrier: depth={depth} contention={contention} adverse_ppm={adverse_ppm} lambda_latency={lambda_latency} -> headroom={headroom} safe={safe}"
            );
        }
        Command::EvaluateProvenanceBarrier {
            risk_ppm,
            validation_depth_ppm,
            bloom_fp_rate_ppm,
            arena_pressure_ppm,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_provenance_barrier;
            let headroom = evaluate_provenance_barrier(
                risk_ppm,
                validation_depth_ppm,
                bloom_fp_rate_ppm,
                arena_pressure_ppm,
            );
            let safe = headroom >= 0;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "provenance_barrier",
                "risk_ppm": risk_ppm,
                "validation_depth_ppm": validation_depth_ppm,
                "bloom_fp_rate_ppm": bloom_fp_rate_ppm,
                "arena_pressure_ppm": arena_pressure_ppm,
                "headroom": headroom,
                "safe": safe,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "evaluate-provenance-barrier: risk_ppm={risk_ppm} depth_ppm={validation_depth_ppm} bloom_fp_ppm={bloom_fp_rate_ppm} arena_ppm={arena_pressure_ppm} -> headroom={headroom} safe={safe}"
            );
        }
        Command::EvaluateSizeClassBarrier {
            requested_size,
            mapped_class_size,
            class_membership_valid,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_size_class_barrier;
            let headroom = evaluate_size_class_barrier(
                requested_size,
                mapped_class_size,
                class_membership_valid,
            );
            let safe = headroom >= 0;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "size_class_barrier",
                "requested_size": requested_size,
                "mapped_class_size": mapped_class_size,
                "class_membership_valid": class_membership_valid,
                "headroom": headroom,
                "safe": safe,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "evaluate-size-class-barrier: requested={requested_size} mapped={mapped_class_size} membership_valid={class_membership_valid} → headroom={headroom} safe={safe}"
            );
        }
        Command::EvaluateThreadSafetyBarrier {
            thread_count,
            concurrent_writers,
            arena_owner_conflict,
            free_list_skew_ppm,
            allocation_epoch_lag_ppm,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_thread_safety_barrier;
            let headroom = evaluate_thread_safety_barrier(
                thread_count,
                concurrent_writers,
                arena_owner_conflict,
                free_list_skew_ppm,
                allocation_epoch_lag_ppm,
            );
            let safe = headroom >= 0;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "thread_safety_barrier",
                "thread_count": thread_count,
                "concurrent_writers": concurrent_writers,
                "arena_owner_conflict": arena_owner_conflict,
                "free_list_skew_ppm": free_list_skew_ppm,
                "allocation_epoch_lag_ppm": allocation_epoch_lag_ppm,
                "headroom": headroom,
                "safe": safe,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "evaluate-thread-safety-barrier: threads={thread_count} writers={concurrent_writers} conflict={arena_owner_conflict} skew_ppm={free_list_skew_ppm} epoch_lag_ppm={allocation_epoch_lag_ppm} → headroom={headroom} safe={safe}"
            );
        }
        Command::EvaluateFragmentationBarrier {
            allocation_count,
            free_count,
            size_class_dispersion_ppm,
            arena_utilization_ppm,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::sos_barrier::evaluate_fragmentation_barrier;
            let headroom = evaluate_fragmentation_barrier(
                allocation_count,
                free_count,
                size_class_dispersion_ppm,
                arena_utilization_ppm,
            );
            let safe = headroom >= 0;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "fragmentation_barrier",
                "allocation_count": allocation_count,
                "free_count": free_count,
                "size_class_dispersion_ppm": size_class_dispersion_ppm,
                "arena_utilization_ppm": arena_utilization_ppm,
                "headroom": headroom,
                "safe": safe,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "evaluate-fragmentation-barrier: alloc={allocation_count} free={free_count} size_class_ppm={size_class_dispersion_ppm} arena_ppm={arena_utilization_ppm} → headroom={headroom} safe={safe}"
            );
        }
        Command::DerivePolicyKey {
            mode,
            family,
            risk_ppm,
            fast_over_budget,
            full_over_budget,
            pareto_exhausted,
            consistency_faults,
            output,
        } => {
            use frankenlibc_membrane::config::SafetyLevel;
            use frankenlibc_membrane::runtime_math::ApiFamily;
            use frankenlibc_membrane::runtime_math::policy_table::{
                budget_bucket_v1, consistency_bucket_v1, key_v1_index, risk_bucket_v1,
            };
            let safety_level = match mode.to_ascii_lowercase().as_str() {
                "strict" => SafetyLevel::Strict,
                "hardened" => SafetyLevel::Hardened,
                "off" => SafetyLevel::Off,
                _ => {
                    return Err(format!("--mode must be strict|hardened|off; got {mode:?}").into());
                }
            };
            let api_family = match family.as_str() {
                "PointerValidation" => ApiFamily::PointerValidation,
                "Allocator" => ApiFamily::Allocator,
                "StringMemory" => ApiFamily::StringMemory,
                "Stdio" => ApiFamily::Stdio,
                "Threading" => ApiFamily::Threading,
                "Resolver" => ApiFamily::Resolver,
                "MathFenv" => ApiFamily::MathFenv,
                "Loader" => ApiFamily::Loader,
                "Stdlib" => ApiFamily::Stdlib,
                "Ctype" => ApiFamily::Ctype,
                "Time" => ApiFamily::Time,
                "Signal" => ApiFamily::Signal,
                "IoFd" => ApiFamily::IoFd,
                "Socket" => ApiFamily::Socket,
                "Locale" => ApiFamily::Locale,
                "Termios" => ApiFamily::Termios,
                "Inet" => ApiFamily::Inet,
                "Process" => ApiFamily::Process,
                "VirtualMemory" => ApiFamily::VirtualMemory,
                "Poll" => ApiFamily::Poll,
                _ => return Err(format!("--family unknown ApiFamily: {family:?}").into()),
            };
            let risk_bucket = risk_bucket_v1(risk_ppm);
            let budget_bucket =
                budget_bucket_v1(fast_over_budget, full_over_budget, pareto_exhausted);
            let consistency_bucket = consistency_bucket_v1(consistency_faults);
            let key_index = key_v1_index(
                safety_level,
                api_family,
                risk_bucket,
                budget_bucket,
                consistency_bucket,
            );
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "policy_key",
                "mode": mode,
                "family": family,
                "risk_ppm": risk_ppm,
                "fast_over_budget": fast_over_budget,
                "full_over_budget": full_over_budget,
                "pareto_exhausted": pareto_exhausted,
                "consistency_faults": consistency_faults,
                "risk_bucket": risk_bucket,
                "budget_bucket": budget_bucket,
                "consistency_bucket": consistency_bucket,
                "key_index": key_index,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "derive-policy-key: mode={mode} family={family} → risk_bucket={risk_bucket} budget_bucket={budget_bucket} consistency_bucket={consistency_bucket} key_index={key_index}"
            );
        }
        Command::DeriveRepairSchedule {
            epoch_seed,
            k_source,
            repair_esi,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::evidence::derive_repair_schedule_v1;
            let schedule = derive_repair_schedule_v1(epoch_seed, k_source, repair_esi);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let indices: Vec<u16> = schedule.indices().to_vec();
            let line = serde_json::json!({
                "kind": "repair_schedule",
                "epoch_seed": epoch_seed,
                "k_source": k_source,
                "repair_esi": repair_esi,
                "degree": schedule.degree(),
                "indices": indices,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "derive-repair-schedule: epoch_seed={epoch_seed} k_source={k_source} repair_esi={repair_esi} → degree={} indices={:?}",
                schedule.degree(),
                indices
            );
        }
        Command::DecodeDecisionPayload { payload, output } => {
            use frankenlibc_membrane::runtime_math::evidence::{
                EVIDENCE_SYMBOL_SIZE_T, decode_decision_payload_v1,
            };
            let bytes = std::fs::read(&payload)
                .map_err(|e| format!("read --payload {}: {e}", payload.display()))?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let (line, ok) = if bytes.len() != EVIDENCE_SYMBOL_SIZE_T {
                (
                    serde_json::json!({
                        "kind": "decision_payload_decode",
                        "input": payload.display().to_string(),
                        "ok": false,
                        "error": format!(
                            "payload size {} != {EVIDENCE_SYMBOL_SIZE_T}",
                            bytes.len()
                        ),
                    }),
                    false,
                )
            } else {
                let mut arr = [0u8; EVIDENCE_SYMBOL_SIZE_T];
                arr.copy_from_slice(&bytes);
                match decode_decision_payload_v1(&arr) {
                    Ok(decoded) => {
                        let loss = decoded.loss_evidence.as_ref().map(|le| {
                            serde_json::json!({
                                "posterior_adverse_ppm": le.posterior_adverse_ppm,
                                "selected_action": le.selected_action,
                                "competing_action": le.competing_action,
                                "selected_expected_loss_milli": le.selected_expected_loss_milli,
                                "competing_expected_loss_milli": le.competing_expected_loss_milli,
                            })
                        });
                        (
                            serde_json::json!({
                                "kind": "decision_payload_decode",
                                "input": payload.display().to_string(),
                                "ok": true,
                                "mode": decoded.mode,
                                "addr_hint": decoded.addr_hint,
                                "requested_bytes": decoded.requested_bytes,
                                "is_write": decoded.is_write,
                                "bloom_negative": decoded.bloom_negative,
                                "contention_hint": decoded.contention_hint,
                                "policy_id": decoded.policy_id,
                                "risk_upper_bound_ppm": decoded.risk_upper_bound_ppm,
                                "estimated_cost_ns": decoded.estimated_cost_ns,
                                "adverse": decoded.adverse,
                                "healing_action": format!("{:?}", decoded.healing_action),
                                "loss_evidence": loss,
                            }),
                            true,
                        )
                    }
                    Err(err) => (
                        serde_json::json!({
                            "kind": "decision_payload_decode",
                            "input": payload.display().to_string(),
                            "ok": false,
                            "error": format!("{err:?}"),
                        }),
                        false,
                    ),
                }
            };
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "decode-decision-payload: ok={ok} → wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "decode-decision-payload: rejected {} — see {}",
                    payload.display(),
                    output.display()
                )
                .into());
            }
        }
        Command::VerifyPcpt { pcpt, output } => {
            use frankenlibc_membrane::runtime_math::policy_table::verify_pcpt;
            let bytes =
                std::fs::read(&pcpt).map_err(|e| format!("read --pcpt {}: {e}", pcpt.display()))?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let (line, ok) = match verify_pcpt(&bytes) {
                Ok(verified) => {
                    let s = verified.summary();
                    (
                        serde_json::json!({
                            "kind": "pcpt_verification",
                            "input": pcpt.display().to_string(),
                            "ok": true,
                            "schema_version": s.schema_version,
                            "hash_alg": format!("{:?}", s.hash_alg),
                            "key_spec_id": s.key_spec_id,
                            "cell_spec_id": s.cell_spec_id,
                            "table_len": s.table_len,
                            "table_hash_hex": s.table_hash_hex,
                            "meta_hash_hex": s.meta_hash_hex,
                            "generator_build_info": s.generator_build_info,
                            "offline_proof_digest_hex": s.offline_proof_digest_hex,
                            "invariant_manifest": s.invariant_manifest,
                        }),
                        true,
                    )
                }
                Err(err) => (
                    serde_json::json!({
                        "kind": "pcpt_verification",
                        "input": pcpt.display().to_string(),
                        "ok": false,
                        "error": format!("{err:?}"),
                    }),
                    false,
                ),
            };
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "verify-pcpt: ok={ok} → wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "verify-pcpt: rejected {} — see {}",
                    pcpt.display(),
                    output.display()
                )
                .into());
            }
        }
        Command::ExplainDossier {
            workspace_root,
            expected_commit,
            output_markdown,
            output_jsonl,
        } => {
            use frankenlibc_harness::explain_dossier::{
                build_dossier, load_dossier_inputs_from_disk, render_markdown,
            };
            if expected_commit.len() != 40
                || !expected_commit.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(format!(
                    "--expected-commit must be a 40-char ascii-hex SHA; got {expected_commit:?}"
                )
                .into());
            }
            let inputs = load_dossier_inputs_from_disk(&workspace_root, &expected_commit)
                .map_err(|err| format!("load_dossier_inputs_from_disk: {err:?}"))?;
            let dossier = build_dossier(&inputs, &expected_commit)
                .map_err(|err| format!("build_dossier: {err:?}"))?;
            for p in [&output_markdown, &output_jsonl] {
                if let Some(parent) = p.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let markdown = render_markdown(&dossier);
            std::fs::write(&output_markdown, &markdown)?;
            let evidence_rows_json: Vec<serde_json::Value> = dossier
                .evidence_rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "kind": r.kind,
                        "summary": r.summary,
                        "artifact_refs": r.artifact_refs,
                        "source_commit": r.source_commit,
                    })
                })
                .collect();
            let line = serde_json::json!({
                "kind": "dossier",
                "schema_version": dossier.schema_version,
                "source_commit": dossier.source_commit,
                "practical_recommendation": dossier.practical_recommendation,
                "replacement_level": dossier.replacement_level,
                "first_failing_blocker": dossier.first_failing_blocker,
                "top_decision_terms": dossier.top_decision_terms,
                "strict_hardened_divergence_signature": dossier.strict_hardened_divergence_signature,
                "next_diagnostic_command": dossier.next_diagnostic_command,
                "support_taxonomy_claim": dossier.support_taxonomy_claim,
                "evidence_rows": evidence_rows_json,
                "all_artifact_refs": dossier.all_artifact_refs,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output_jsonl, body)?;
            eprintln!(
                "explain-dossier: wrote markdown ({} bytes) to {} and 1 JSONL record to {}",
                markdown.len(),
                output_markdown.display(),
                output_jsonl.display()
            );
        }
        Command::DeriveRepairMath {
            k_source,
            overhead_percent,
            output,
        } => {
            use frankenlibc_membrane::runtime_math::evidence::{
                SLACK_DECODE_V1, derive_repair_symbol_count_v1, loss_fraction_max_ppm_v1,
            };
            let r_repair = derive_repair_symbol_count_v1(k_source, overhead_percent);
            let loss_fraction_max_ppm = loss_fraction_max_ppm_v1(k_source, r_repair);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "repair_math",
                "k_source": k_source,
                "overhead_percent": overhead_percent,
                "r_repair": r_repair,
                "loss_fraction_max_ppm": loss_fraction_max_ppm,
                "slack_decode": SLACK_DECODE_V1,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "derive-repair-math: k_source={k_source} overhead_percent={overhead_percent} → r_repair={r_repair} loss_fraction_max_ppm={loss_fraction_max_ppm}"
            );
        }
        Command::RenderDiff {
            expected,
            actual,
            output,
        } => {
            use frankenlibc_harness::diff::render_diff;
            let exp = std::fs::read_to_string(&expected)
                .map_err(|e| format!("read --expected {}: {e}", expected.display()))?;
            let act = std::fs::read_to_string(&actual)
                .map_err(|e| format!("read --actual {}: {e}", actual.display()))?;
            let rendered = render_diff(&exp, &act);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&output, &rendered)?;
            eprintln!(
                "render-diff: wrote {} bytes to {}",
                rendered.len(),
                output.display()
            );
        }
        Command::ValidateStdioEvidence { jsonl, output } => {
            use frankenlibc_harness::stdio_evidence::{ParseError, parse_stdio_evidence_file};
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let mut total_rows: u64 = 0;
            let mut errors: Vec<serde_json::Value> = Vec::new();
            match parse_stdio_evidence_file(&jsonl) {
                Ok(iter) => {
                    for item in iter {
                        match item {
                            Ok(_row) => total_rows += 1,
                            Err(ParseError::Io(e)) => errors.push(serde_json::json!({
                                "line": 0,
                                "kind": "io",
                                "detail": e.to_string(),
                            })),
                            Err(ParseError::Json { line, error }) => {
                                errors.push(serde_json::json!({
                                    "line": line,
                                    "kind": "json",
                                    "detail": error.to_string(),
                                }))
                            }
                            Err(ParseError::UnsupportedVersion { line, version }) => {
                                errors.push(serde_json::json!({
                                    "line": line,
                                    "kind": "unsupported_version",
                                    "detail": format!("schema version {version} is not supported"),
                                }))
                            }
                        }
                    }
                }
                Err(e) => errors.push(serde_json::json!({
                    "line": 0,
                    "kind": "io",
                    "detail": e.to_string(),
                })),
            }
            let ok = errors.is_empty();
            let line = serde_json::json!({
                "kind": "stdio_evidence_validation",
                "input": jsonl.display().to_string(),
                "total_rows": total_rows,
                "ok": ok,
                "errors": errors,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "validate-stdio-evidence: total_rows={total_rows} ok={ok} → wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "validate-stdio-evidence: {} error(s) — see {}",
                    errors.len(),
                    output.display()
                )
                .into());
            }
        }
        Command::ValidateStructuredLog { jsonl, output } => {
            use frankenlibc_harness::structured_log::validate_log_file;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }

            let (total_lines, errors) = match validate_log_file(&jsonl) {
                Ok((total_lines, validation_errors)) => {
                    let errors = validation_errors
                        .into_iter()
                        .map(|err| {
                            serde_json::json!({
                                "line_number": err.line_number,
                                "field": err.field,
                                "message": err.message,
                            })
                        })
                        .collect::<Vec<_>>();
                    (total_lines, errors)
                }
                Err(e) => (
                    0,
                    vec![serde_json::json!({
                        "line_number": 0,
                        "field": "<io>",
                        "message": e.to_string(),
                    })],
                ),
            };

            let ok = errors.is_empty();
            let line = serde_json::json!({
                "kind": "structured_log_validation",
                "input": jsonl.display().to_string(),
                "total_lines": total_lines,
                "ok": ok,
                "errors": errors,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "validate-structured-log: total_lines={total_lines} ok={ok} wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "validate-structured-log: rejected {} with {} error(s) - see {}",
                    jsonl.display(),
                    errors.len(),
                    output.display()
                )
                .into());
            }
        }
        Command::ValidateSetjmpContract { contract, output } => {
            use frankenlibc_harness::setjmp_contract::parse_contract_str;
            let body = std::fs::read_to_string(&contract)
                .map_err(|e| format!("read --contract {}: {e}", contract.display()))?;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let (line, ok) = match parse_contract_str(&body) {
                Err(parse_error) => (
                    serde_json::json!({
                        "kind": "setjmp_contract_validation",
                        "input": contract.display().to_string(),
                        "ok": false,
                        "parse_error": parse_error,
                        "intrinsic_errors": serde_json::Value::Array(Vec::new()),
                    }),
                    false,
                ),
                Ok(parsed) => match parsed.validate_intrinsic() {
                    Ok(()) => (
                        serde_json::json!({
                            "kind": "setjmp_contract_validation",
                            "input": contract.display().to_string(),
                            "ok": true,
                            "intrinsic_errors": serde_json::Value::Array(Vec::new()),
                        }),
                        true,
                    ),
                    Err(errs) => (
                        serde_json::json!({
                            "kind": "setjmp_contract_validation",
                            "input": contract.display().to_string(),
                            "ok": false,
                            "intrinsic_errors": errs,
                        }),
                        false,
                    ),
                },
            };
            let mut serialized = line.to_string();
            serialized.push('\n');
            std::fs::write(&output, serialized)?;
            eprintln!(
                "validate-setjmp-contract: ok={ok} → wrote 1 JSONL record to {}",
                output.display()
            );
            if !ok {
                return Err(format!(
                    "validate-setjmp-contract: rejected {} — see {}",
                    contract.display(),
                    output.display()
                )
                .into());
            }
        }
        Command::VerifyRuntimeEvidence {
            jsonl,
            expected_source_commit,
            expectations,
            deny_unexpected_denials,
            output,
        } => {
            use frankenlibc_harness::runtime_evidence_verifier::{
                RuntimeEvidenceExpectation, RuntimeEvidenceVerifierConfig,
                verify_runtime_evidence_jsonl,
            };
            if expected_source_commit.is_empty() {
                return Err("--expected-source-commit must not be empty".into());
            }
            let mut config = RuntimeEvidenceVerifierConfig::new(&expected_source_commit);
            if deny_unexpected_denials {
                config = config.deny_unexpected_denials();
            }
            if let Some(path) = expectations {
                let body = std::fs::read_to_string(&path)
                    .map_err(|e| format!("read --expectations {}: {e}", path.display()))?;
                let v: serde_json::Value = serde_json::from_str(&body)
                    .map_err(|e| format!("--expectations not JSON: {e}"))?;
                let arr = v
                    .as_array()
                    .ok_or_else(|| "--expectations must be a JSON array".to_string())?;
                for (i, row) in arr.iter().enumerate() {
                    let symbol = row
                        .get("symbol")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            format!("--expectations[{i}] missing string field `symbol`")
                        })?;
                    let runtime_mode = row
                        .get("runtime_mode")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            format!("--expectations[{i}] missing string field `runtime_mode`")
                        })?;
                    let decision_action = row
                        .get("decision_action")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            format!("--expectations[{i}] missing string field `decision_action`")
                        })?;
                    let denied = row
                        .get("denied")
                        .and_then(serde_json::Value::as_bool)
                        .ok_or_else(|| {
                            format!("--expectations[{i}] missing bool field `denied`")
                        })?;
                    config = config.with_expectation(RuntimeEvidenceExpectation::new(
                        symbol,
                        runtime_mode,
                        decision_action,
                        denied,
                    ));
                }
            }
            let jsonl_body = std::fs::read_to_string(&jsonl)
                .map_err(|e| format!("read --jsonl {}: {e}", jsonl.display()))?;
            let report = verify_runtime_evidence_jsonl(&jsonl_body, &config);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let serialized = serde_json::to_string(&report)
                .map_err(|e| format!("serialize verifier report: {e}"))?;
            let mut body = serialized;
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "verify-runtime-evidence: status={} total_rows={} failure_count={}",
                report.status, report.total_rows, report.failure_count
            );
            if !report.passed() {
                return Err(format!(
                    "verify-runtime-evidence: {} failure(s) — see {}",
                    report.failure_count,
                    output.display()
                )
                .into());
            }
        }
        Command::SeqlockModelCheck {
            write_count,
            output,
        } => {
            use frankenlibc_harness::concurrency_model_check::{InvariantViolation, check_seqlock};
            const WRITE_COUNT_CAP: u32 = 4;
            if write_count == 0 {
                return Err("--write-count must be > 0".into());
            }
            if write_count > WRITE_COUNT_CAP {
                return Err(format!(
                    "--write-count must be <= {WRITE_COUNT_CAP}; got {write_count}"
                )
                .into());
            }
            let report = check_seqlock(write_count);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let violations_json: Vec<serde_json::Value> = report
                .invariant_violations
                .iter()
                .map(|v| match v {
                    InvariantViolation::StaleReadAccepted {
                        read_val,
                        published,
                        schedule,
                    } => serde_json::json!({
                        "kind": "stale_read_accepted",
                        "read_val": read_val,
                        "published": published,
                        "schedule": schedule,
                    }),
                    InvariantViolation::StableReadAtOddVersion { ver, schedule } => {
                        serde_json::json!({
                            "kind": "stable_read_at_odd_version",
                            "ver": ver,
                            "schedule": schedule,
                        })
                    }
                    InvariantViolation::RetryCountNonMonotone {
                        observed,
                        prior,
                        schedule,
                    } => serde_json::json!({
                        "kind": "retry_count_non_monotone",
                        "observed": observed,
                        "prior": prior,
                        "schedule": schedule,
                    }),
                    InvariantViolation::MissedWriterPublication {
                        published,
                        schedule,
                    } => serde_json::json!({
                        "kind": "missed_writer_publication",
                        "published": published,
                        "schedule": schedule,
                    }),
                })
                .collect();
            let line = serde_json::json!({
                "kind": "seqlock_model_report",
                "write_count": write_count,
                "schedules_explored": report.schedules_explored,
                "stable_outcomes": report.stable_outcomes,
                "retry_outcomes": report.retry_outcomes,
                "invariant_violation_count": report.invariant_violations.len(),
                "invariant_violations": violations_json,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "seqlock-model-check: wrote 1 seqlock_model_report JSONL record to {} (schedules_explored={} violations={})",
                output.display(),
                report.schedules_explored,
                report.invariant_violations.len()
            );
        }
        Command::LaneIsomorphism {
            initial,
            writes,
            reads_per_phase,
            output,
        } => {
            use frankenlibc_harness::read_mostly_fast_path_prototype::isomorphism_witness;
            let parsed_writes: Vec<u32> = writes
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<u32>()
                        .map_err(|e| format!("--writes contains non-u32 token `{s}`: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if parsed_writes.is_empty() {
                return Err("--writes must contain at least one u32 token".into());
            }
            if reads_per_phase == 0 {
                return Err("--reads-per-phase must be > 0".into());
            }
            let report = isomorphism_witness(initial, &parsed_writes, reads_per_phase);
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = serde_json::json!({
                "kind": "isomorphism_report",
                "initial": initial,
                "writes": parsed_writes,
                "reads_per_phase": reads_per_phase,
                "conservative_outcomes": report.conservative_outcomes,
                "seqlock_outcomes": report.seqlock_outcomes,
                "outcomes_identical": report.outcomes_identical,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "lane-isomorphism: wrote 1 isomorphism_report JSONL record to {} (outcomes_identical={})",
                output.display(),
                report.outcomes_identical
            );
        }
        Command::ToolingContract { output } => {
            use frankenlibc_harness::explainability_workbench::tooling_contract;
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let tc = tooling_contract();
            let line = serde_json::json!({
                "kind": "tooling_contract",
                "has_asupersync_dependency": tc.has_asupersync_dependency,
                "asupersync_feature_present": tc.asupersync_feature_present,
                "default_enables_asupersync_tooling": tc.default_enables_asupersync_tooling,
                "asupersync_tooling_enabled": tc.asupersync_tooling_enabled,
                "frankentui_feature_present": tc.frankentui_feature_present,
                "frankentui_dependency_set_complete": tc.frankentui_dependency_set_complete,
                "frankentui_ui_enabled": tc.frankentui_ui_enabled,
            });
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "tooling-contract: wrote 1 JSONL record to {}",
                output.display()
            );
        }
        Command::ReplayClassify {
            input,
            observed,
            override_var,
            output,
        } => {
            use frankenlibc_harness::asupersync_lab_replay::{
                DetectionEnv, ReplayOutcome, ReplayRecord, classify_outcome,
                detect_asupersync_available, validate_replay,
            };
            let record_body = std::fs::read_to_string(&input)
                .map_err(|e| format!("read --input {}: {e}", input.display()))?;
            let record_line = record_body
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .ok_or_else(|| "--input contained zero ReplayRecord rows".to_string())?;
            let v: serde_json::Value =
                serde_json::from_str(record_line).map_err(|e| format!("--input not JSON: {e}"))?;
            let required_string = |k: &str| -> Result<String, String> {
                v.get(k)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("--input missing string field `{k}`"))
            };
            let required_u64 = |k: &str| -> Result<u64, String> {
                v.get(k)
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| format!("--input missing u64 field `{k}`"))
            };
            let string_array = |k: &str| -> Result<Vec<String>, String> {
                v.get(k)
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| format!("--input missing array field `{k}`"))?
                    .iter()
                    .map(|x| {
                        x.as_str().map(str::to_string).ok_or_else(|| {
                            format!("--input field `{k}` must be an array of strings")
                        })
                    })
                    .collect()
            };
            let record = ReplayRecord {
                schema_version: required_string("schema_version")?,
                trace_class: required_string("trace_class")?,
                virtual_time_seed: required_u64("virtual_time_seed")?,
                schedule_decisions: string_array("schedule_decisions")?,
                replay_inputs: string_array("replay_inputs")?,
                expected_outputs: string_array("expected_outputs")?,
                artifact_refs: string_array("artifact_refs")?,
                source_commit: required_string("source_commit")?,
            };
            validate_replay(&record).map_err(|e| format!("validate_replay: {e}"))?;

            let observed_body = std::fs::read_to_string(&observed)
                .map_err(|e| format!("read --observed {}: {e}", observed.display()))?;
            let observed_line = observed_body
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .ok_or_else(|| "--observed contained zero rows".to_string())?;
            let ov: serde_json::Value = serde_json::from_str(observed_line)
                .map_err(|e| format!("--observed not JSON: {e}"))?;
            let observed_outputs: Vec<String> = ov
                .get("observed_outputs")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| "--observed missing array field `observed_outputs`".to_string())?
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| "`observed_outputs` must be an array of strings".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;

            let mut env = DetectionEnv::from_process_env();
            if let Some(ov) = override_var {
                env.override_var = Some(ov);
            }
            let availability = detect_asupersync_available(&env);
            let outcome =
                classify_outcome(&record, availability.available, observed_outputs.as_slice());

            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = match outcome {
                ReplayOutcome::Pass => serde_json::json!({
                    "kind": "replay_outcome",
                    "outcome": "pass",
                    "asupersync_available": availability.available,
                    "detection_reason": availability.detection_reason,
                    "trace_class": record.trace_class,
                    "source_commit": record.source_commit,
                }),
                ReplayOutcome::CodeFailure { signature } => serde_json::json!({
                    "kind": "replay_outcome",
                    "outcome": "code_failure",
                    "signature": signature,
                    "asupersync_available": availability.available,
                    "detection_reason": availability.detection_reason,
                    "trace_class": record.trace_class,
                    "source_commit": record.source_commit,
                }),
                ReplayOutcome::ToolFailure { reason } => serde_json::json!({
                    "kind": "replay_outcome",
                    "outcome": "tool_failure",
                    "reason": reason,
                    "asupersync_available": availability.available,
                    "detection_reason": availability.detection_reason,
                    "trace_class": record.trace_class,
                    "source_commit": record.source_commit,
                }),
            };
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "replay-classify: wrote 1 replay_outcome JSONL record to {}",
                output.display()
            );
        }
        Command::EnvFingerprint { validate, output } => {
            use frankenlibc_harness::system_fingerprint::{
                detect_components, environment_fingerprint, validate_environment_fingerprint,
            };
            if let Some(parent) = output.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            let line = match validate {
                None => {
                    let components = detect_components();
                    let fingerprint = environment_fingerprint();
                    serde_json::json!({
                        "kind": "environment_fingerprint",
                        "fingerprint": fingerprint,
                        "os": components.os,
                        "arch": components.arch,
                        "cpus": components.cpus,
                        "kernel_release": components.kernel_release,
                        "source": "detected",
                    })
                }
                Some(input) => match validate_environment_fingerprint(&input) {
                    Ok(components) => serde_json::json!({
                        "kind": "environment_fingerprint_validation",
                        "input": input,
                        "ok": true,
                        "os": components.os,
                        "arch": components.arch,
                        "cpus": components.cpus,
                        "kernel_release": components.kernel_release,
                    }),
                    Err(err) => serde_json::json!({
                        "kind": "environment_fingerprint_validation",
                        "input": input,
                        "ok": false,
                        "error": err.to_string(),
                    }),
                },
            };
            let mut body = line.to_string();
            body.push('\n');
            std::fs::write(&output, body)?;
            eprintln!(
                "env-fingerprint: wrote 1 JSONL record to {}",
                output.display()
            );
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
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_runtime_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_frankenlibc_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    startup_mode_matches: Option<bool>,
}

impl MatrixCaseEnvelope {
    fn ok(run: frankenlibc_fixture_exec::DifferentialExecution) -> Self {
        Self {
            kind: "ok".to_string(),
            run: Some(run),
            error: None,
            startup_runtime_mode: None,
            startup_frankenlibc_mode: None,
            startup_mode_matches: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            kind: "error".to_string(),
            run: None,
            error: Some(error),
            startup_runtime_mode: None,
            startup_frankenlibc_mode: None,
            startup_mode_matches: None,
        }
    }

    fn with_startup_mode_evidence(
        mut self,
        expected_mode: &str,
        frankenlibc_mode: Option<String>,
    ) -> Self {
        let observed = frankenlibc_mode.unwrap_or_else(|| "<unset>".to_string());
        self.startup_runtime_mode = Some(expected_mode.to_string());
        self.startup_mode_matches = Some(observed == expected_mode);
        self.startup_frankenlibc_mode = Some(observed);
        self
    }
}

#[derive(Debug)]
enum MatrixCaseSubprocessError {
    Timeout(String),
    Crash(String),
    Error(String),
}

struct IsolatedFixtureVerificationRun {
    verification_results: Vec<frankenlibc_harness::verify::VerificationResult>,
    #[cfg(feature = "asupersync-tooling")]
    suite: asupersync_conformance::SuiteResult,
}

fn run_fixture_verification_isolated(
    campaign: &str,
    fixture_sets: &[frankenlibc_harness::FixtureSet],
    exe: &Path,
    timeout: Duration,
) -> IsolatedFixtureVerificationRun {
    let mut verification_results = Vec::new();
    #[cfg(feature = "asupersync-tooling")]
    let mut suite =
        asupersync_conformance::SuiteResult::new(format!("frankenlibc-harness:{campaign}"));

    let suite_start = Instant::now();
    let mut sets: Vec<&frankenlibc_harness::FixtureSet> = fixture_sets.iter().collect();
    sets.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.captured_at.cmp(&b.captured_at))
            .then_with(|| a.version.cmp(&b.version))
    });

    for set in sets {
        let mut cases: Vec<&frankenlibc_harness::FixtureCase> = set.cases.iter().collect();
        cases.sort_by(|a, b| {
            a.function
                .cmp(&b.function)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.mode.cmp(&b.mode))
        });

        for case in cases {
            for exec_mode in verify_case_execution_modes(&case.mode) {
                let start = Instant::now();
                let execution = match run_conformance_case_subprocess(
                    exe,
                    &case.function,
                    &case.inputs,
                    &exec_mode,
                    timeout,
                ) {
                    Ok(run) => CaseExecution::Completed(run),
                    Err(MatrixCaseSubprocessError::Timeout(err)) => CaseExecution::Timeout(err),
                    Err(MatrixCaseSubprocessError::Crash(err)) => CaseExecution::Crash(err),
                    Err(MatrixCaseSubprocessError::Error(err)) => CaseExecution::Error(err),
                };
                let duration_ms = start.elapsed().as_millis() as u64;
                let result =
                    verify_result_from_case_execution(campaign, set, case, &exec_mode, execution);

                #[cfg(feature = "asupersync-tooling")]
                {
                    use asupersync_conformance::{
                        SuiteTestResult, TestCategory, TestResult as SuiteTestResultStatus,
                    };

                    let mut status = if result.passed {
                        SuiteTestResultStatus::passed()
                    } else {
                        SuiteTestResultStatus::failed(
                            result.diff.clone().unwrap_or_else(|| result.actual.clone()),
                        )
                    };
                    status.duration_ms = Some(duration_ms);
                    if result.passed {
                        suite.passed += 1;
                    } else {
                        suite.failed += 1;
                    }
                    suite.results.push(SuiteTestResult {
                        test_id: result.trace_id.clone(),
                        test_name: result.case_name.clone(),
                        category: TestCategory::IO,
                        expected: result.expected.clone(),
                        result: status,
                        events: Vec::new(),
                    });
                }

                verification_results.push(result);
            }
        }
    }

    #[cfg(feature = "asupersync-tooling")]
    {
        suite.total = suite.results.len();
        suite.duration_ms = suite_start.elapsed().as_millis() as u64;
        IsolatedFixtureVerificationRun {
            verification_results,
            suite,
        }
    }
    #[cfg(not(feature = "asupersync-tooling"))]
    {
        let _ = suite_start;
        IsolatedFixtureVerificationRun {
            verification_results,
        }
    }
}

fn verify_case_execution_modes(mode: &str) -> Vec<String> {
    if mode.eq_ignore_ascii_case("both") {
        return vec![String::from("strict"), String::from("hardened")];
    }
    vec![mode.to_string()]
}

fn verify_result_from_case_execution(
    campaign: &str,
    set: &frankenlibc_harness::FixtureSet,
    case: &frankenlibc_harness::FixtureCase,
    exec_mode: &str,
    execution: CaseExecution,
) -> frankenlibc_harness::verify::VerificationResult {
    let display_case_name = if case.mode.eq_ignore_ascii_case("both") {
        format!("{} [{}]", case.name, exec_mode)
    } else {
        case.name.clone()
    };
    let trace_id = format!(
        "{campaign}::{family}::{symbol}::{mode}::{case_name}",
        family = set.family,
        symbol = case.function,
        mode = exec_mode,
        case_name = case.name
    );

    match execution {
        CaseExecution::Completed(run) => {
            let mut notes = Vec::new();
            if exec_mode.eq_ignore_ascii_case("strict") && !run.host_parity {
                notes.push(format!(
                    "strict host parity mismatch: host={}, impl={}",
                    frankenlibc_harness::verify::report_note_output(&run.host_output),
                    frankenlibc_harness::verify::report_note_output(&run.impl_output)
                ));
            }
            if let Some(note) = run.note.clone() {
                notes.push(note);
            }
            let match_kind = frankenlibc_harness::verify::expected_output_match(
                &case.expected_output,
                &run.impl_output,
            );
            if let Some(kind) = match_kind
                && let Some(note) = frankenlibc_harness::verify::expected_output_match_note(kind)
            {
                notes.push(note.to_string());
            }
            let host_match_kind = frankenlibc_harness::verify::expected_output_match(
                &case.expected_output,
                &run.host_output,
            );
            let report_host_output = frankenlibc_harness::verify::report_actual_output(
                &case.expected_output,
                &frankenlibc_harness::verify::report_note_output(&run.host_output),
                host_match_kind,
            );

            let diff = if match_kind.is_none() {
                Some(frankenlibc_harness::diff::render_diff(
                    &case.expected_output,
                    &run.impl_output,
                ))
            } else if notes.is_empty() {
                None
            } else {
                Some(notes.join("\n"))
            };

            frankenlibc_harness::verify::VerificationResult {
                trace_id,
                campaign: campaign.to_string(),
                family: set.family.clone(),
                symbol: case.function.clone(),
                mode: exec_mode.to_string(),
                case_name: display_case_name,
                spec_section: case.spec_section.clone(),
                passed: match_kind.is_some(),
                expected: case.expected_output.clone(),
                actual: frankenlibc_harness::verify::report_actual_output(
                    &case.expected_output,
                    &run.impl_output,
                    match_kind,
                ),
                host_output: Some(report_host_output),
                host_parity: Some(run.host_parity),
                diff,
            }
        }
        CaseExecution::Error(err) => verify_synthetic_failure(
            campaign,
            set,
            case,
            exec_mode,
            display_case_name,
            trace_id,
            format!("unsupported:{err}"),
        ),
        CaseExecution::Timeout(err) => verify_synthetic_failure(
            campaign,
            set,
            case,
            exec_mode,
            display_case_name,
            trace_id,
            format!("timeout:{err}"),
        ),
        CaseExecution::Crash(err) => verify_synthetic_failure(
            campaign,
            set,
            case,
            exec_mode,
            display_case_name,
            trace_id,
            format!("crash:{err}"),
        ),
    }
}

fn verify_synthetic_failure(
    campaign: &str,
    set: &frankenlibc_harness::FixtureSet,
    case: &frankenlibc_harness::FixtureCase,
    exec_mode: &str,
    display_case_name: String,
    trace_id: String,
    actual: String,
) -> frankenlibc_harness::verify::VerificationResult {
    frankenlibc_harness::verify::VerificationResult {
        trace_id,
        campaign: campaign.to_string(),
        family: set.family.clone(),
        symbol: case.function.clone(),
        mode: exec_mode.to_string(),
        case_name: display_case_name,
        spec_section: case.spec_section.clone(),
        passed: false,
        expected: case.expected_output.clone(),
        actual: actual.clone(),
        host_output: None,
        host_parity: None,
        diff: Some(frankenlibc_harness::diff::render_diff(
            &case.expected_output,
            &actual,
        )),
    }
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
        .env("FRANKENLIBC_MODE", mode)
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
    let observed_mode = envelope
        .startup_frankenlibc_mode
        .clone()
        .unwrap_or_else(|| "<missing>".to_string());
    if envelope.startup_mode_matches != Some(true) {
        return Err(MatrixCaseSubprocessError::Error(format!(
            "runtime_mode_startup_mismatch: expected FRANKENLIBC_MODE={mode}, child observed {observed_mode}"
        )));
    }
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
    isolate: bool,
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
    let mut startup_modes: BTreeSet<String> =
        matrix.cases.iter().map(|case| case.mode.clone()).collect();
    if startup_modes.is_empty() {
        startup_modes.insert(matrix.mode.clone());
    }

    for active_mode in startup_modes {
        let startup_trace_id = format!(
            "{}::runtime-mode-startup::{}",
            sanitize_trace_component(campaign),
            sanitize_trace_component(&active_mode)
        );
        emitter.emit_entry(
            LogEntry::new(
                startup_trace_id,
                LogLevel::Info,
                "conformance.runtime_mode_startup",
            )
            .with_stream(StreamKind::Conformance)
            .with_gate(CONFORMANCE_LOG_GATE)
            .with_mode(active_mode.as_str())
            .with_api("conformance", "runtime_mode_startup")
            .with_outcome(Outcome::Pass)
            .with_errno(0)
            .with_healing_action("none")
            .with_artifacts(artifact_refs.clone())
            .with_details(serde_json::json!({
                "campaign": matrix.campaign,
                "env_key": "FRANKENLIBC_MODE",
                "expected_runtime_mode": active_mode,
                "process_immutable": true,
                "subprocess_isolated": isolate,
                "mode_source": if isolate { "child_process_env" } else { "in_process_mode_argument" },
                "mismatch_behavior": if isolate {
                    "runtime_mode_startup_mismatch"
                } else {
                    "unsupported CLI modes fail before execution"
                },
                "ambient_tz_dependency": false,
                "ambient_tz_policy": "not read for FRANKENLIBC_MODE selection",
                "decision_path": "conformance->runtime_mode_startup"
            })),
        )?;
    }

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

    fn parse_cli_on_expanded_stack<const N: usize>(args: [&'static str; N]) -> Cli {
        // The derived clap graph is large enough to overflow the test harness
        // worker stack on some builders while the process main stack is fine.
        std::thread::Builder::new()
            .name("harness-cli-parse".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(args).expect("cli parses"))
            .expect("spawn cli parser thread")
            .join()
            .expect("cli parser thread")
    }

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
        let cli =
            parse_cli_on_expanded_stack(["harness", "shadow-run", "--manifest", "shadow.json"]);

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
        let cli =
            parse_cli_on_expanded_stack(["harness", "fault-inject", "--manifest", "fault.yaml"]);

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
            true,
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
            body.contains("\"event\":\"conformance.runtime_mode_startup\"")
                && body.contains("\"mismatch_behavior\":\"runtime_mode_startup_mismatch\"")
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
