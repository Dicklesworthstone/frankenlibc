//! Report generation for conformance results.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::conformance_matrix::{ConformanceCaseRow, ConformanceMatrixReport};
use crate::verify::VerificationSummary;
use crate::{FixtureCase, FixtureSet};

/// A conformance report combining verification and traceability data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Report title.
    pub title: String,
    /// Runtime mode tested (strict or hardened).
    pub mode: String,
    /// Timestamp (UTC).
    pub timestamp: String,
    /// Verification summary.
    pub summary: VerificationSummary,
}

impl ConformanceReport {
    /// Render the report as markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n\n", self.title));
        out.push_str(&format!("- Mode: {}\n", self.mode));
        out.push_str(&format!("- Timestamp: {}\n", self.timestamp));
        out.push_str(&format!("- Total: {}\n", self.summary.total));
        out.push_str(&format!("- Passed: {}\n", self.summary.passed));
        out.push_str(&format!("- Failed: {}\n\n", self.summary.failed));

        out.push_str("| Trace | Family | Symbol | Mode | Case | Spec | Status |\n");
        out.push_str("|-------|--------|--------|------|------|------|--------|\n");
        for r in &self.summary.results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                r.trace_id, r.family, r.symbol, r.mode, r.case_name, r.spec_section, status
            ));
        }
        out
    }

    /// Render the report as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

/// Missing-link diagnostic for decision traceability aggregation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionTraceFinding {
    pub trace_id: String,
    pub symbol: Option<String>,
    pub reason: String,
}

/// Aggregated explainability report over JSONL structured logs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionTraceReport {
    pub total_events: usize,
    pub decision_events: usize,
    pub explainable_decision_events: usize,
    pub missing_explainability: usize,
    pub findings: Vec<DecisionTraceFinding>,
}

impl DecisionTraceReport {
    /// Build an explainability report from JSONL content.
    #[must_use]
    pub fn from_jsonl_str(jsonl: &str) -> Self {
        let mut report = Self {
            total_events: 0,
            decision_events: 0,
            explainable_decision_events: 0,
            missing_explainability: 0,
            findings: Vec::new(),
        };

        for (line_no, raw) in jsonl.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            report.total_events += 1;

            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(err) => {
                    report.missing_explainability += 1;
                    report.findings.push(DecisionTraceFinding {
                        trace_id: "<invalid-json>".to_string(),
                        symbol: None,
                        reason: format!("line {} invalid JSON: {}", line_no + 1, err),
                    });
                    continue;
                }
            };

            let Some(obj) = value.as_object() else {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id: "<invalid-object>".to_string(),
                    symbol: None,
                    reason: format!("line {} is not a JSON object", line_no + 1),
                });
                continue;
            };

            let is_runtime_decision_event = obj
                .get("event")
                .and_then(|v| v.as_str())
                .is_some_and(|e| e == "runtime_decision");
            if !is_runtime_decision_event {
                continue;
            }
            report.decision_events += 1;

            let trace_id = obj
                .get("trace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("<missing-trace-id>")
                .to_string();
            let symbol = obj
                .get("symbol")
                .and_then(|v| v.as_str())
                .map(ToString::to_string);

            if obj.get("decision").is_none() {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id,
                    symbol,
                    reason: "missing fields: decision".to_string(),
                });
                continue;
            }

            let mut missing = Vec::new();
            if obj
                .get("trace_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("trace_id");
            }
            if obj
                .get("symbol")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("symbol");
            }
            if obj
                .get("span_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("span_id");
            }
            if obj
                .get("controller_id")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("controller_id");
            }
            if obj
                .get("decision_action")
                .and_then(|v| v.as_str())
                .is_none_or(str::is_empty)
            {
                missing.push("decision_action");
            }
            if !obj
                .get("risk_inputs")
                .is_some_and(serde_json::Value::is_object)
            {
                missing.push("risk_inputs");
            }

            if missing.is_empty() {
                report.explainable_decision_events += 1;
            } else {
                report.missing_explainability += 1;
                report.findings.push(DecisionTraceFinding {
                    trace_id,
                    symbol,
                    reason: format!("missing fields: {}", missing.join(", ")),
                });
            }
        }

        report
    }

    /// True when every decision event has complete explainability context.
    #[must_use]
    pub const fn fully_explainable(&self) -> bool {
        self.missing_explainability == 0
    }
}

/// Taxonomy count summary derived from support matrix symbols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityCounts {
    pub implemented: u64,
    pub raw_syscall: u64,
    pub wraps_host_libc: u64,
    pub glibc_call_through: u64,
    pub stub: u64,
}

const REALITY_REPORT_SCHEMA_VERSION: &str = "v1";

/// Machine-readable single source-of-truth report for docs reality tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub total_exported: u64,
    pub counts: RealityCounts,
    pub stubs: Vec<String>,
}

impl RealityReport {
    /// Build report from support_matrix JSON bytes.
    pub fn from_support_matrix_json_str(json: &str) -> Result<Self, String> {
        let matrix: serde_json::Value = serde_json::from_str(json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;

        let generated_at_utc = matrix["generated_at_utc"]
            .as_str()
            .ok_or("missing generated_at_utc in support matrix")?
            .to_string();
        let total_exported = matrix["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;

        let symbols = matrix["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;
        let symbol_count = u64::try_from(symbols.len())
            .map_err(|_| "support matrix symbols[] length does not fit u64".to_string())?;
        if symbol_count != total_exported {
            return Err(format!(
                "support matrix total_exported ({total_exported}) does not match symbols[] length ({symbol_count})"
            ));
        }

        let mut stubs = Vec::new();
        let mut implemented = 0u64;
        let mut raw_syscall = 0u64;
        let mut wraps_host_libc = 0u64;
        let mut glibc_call_through = 0u64;
        let mut stub = 0u64;

        for sym in symbols {
            let status = sym["status"].as_str().ok_or("symbol missing status")?;
            let symbol_name = sym["symbol"].as_str().ok_or("symbol missing symbol name")?;
            match status {
                "Implemented" => implemented += 1,
                "RawSyscall" => raw_syscall += 1,
                "WrapsHostLibc" => wraps_host_libc += 1,
                "GlibcCallThrough" => glibc_call_through += 1,
                "Stub" => {
                    stub += 1;
                    stubs.push(symbol_name.to_string());
                }
                _ => {
                    return Err(format!(
                        "unknown support status '{status}' for symbol '{symbol_name}'"
                    ));
                }
            }
        }

        stubs.sort();

        let computed_total =
            implemented + raw_syscall + wraps_host_libc + glibc_call_through + stub;
        if computed_total != total_exported {
            return Err(format!(
                "support matrix status totals ({computed_total}) do not match total_exported ({total_exported})"
            ));
        }

        Ok(Self {
            schema_version: REALITY_REPORT_SCHEMA_VERSION.to_string(),
            generated_at_utc,
            total_exported,
            counts: RealityCounts {
                implemented,
                raw_syscall,
                wraps_host_libc,
                glibc_call_through,
                stub,
            },
            stubs,
        })
    }

    /// Build report from support_matrix file on disk.
    pub fn from_support_matrix_path(path: &Path) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|err| format!("failed reading support matrix '{}': {err}", path.display()))?;
        Self::from_support_matrix_json_str(&json)
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

/// Per-category fixture-case counts used for POSIX conformance coverage quality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PosixCaseCategoryCounts {
    pub normal: u64,
    pub boundary: u64,
    pub error: u64,
    pub other: u64,
}

impl PosixCaseCategoryCounts {
    #[must_use]
    pub const fn all_core_categories_present(&self) -> bool {
        self.normal > 0 && self.boundary > 0 && self.error > 0
    }

    #[must_use]
    pub const fn total(&self) -> u64 {
        self.normal + self.boundary + self.error + self.other
    }
}

/// Execution-status counts from conformance matrix rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PosixExecutionCounts {
    pub total: u64,
    pub pass: u64,
    pub fail: u64,
    pub error: u64,
    pub timeout: u64,
    pub crash: u64,
}

impl PosixExecutionCounts {
    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.fail > 0 || self.error > 0 || self.timeout > 0 || self.crash > 0
    }
}

/// Per-symbol POSIX conformance coverage row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixSymbolCoverageRow {
    pub symbol: String,
    pub status: String,
    pub module: String,
    pub case_count: u64,
    pub strict_cases: u64,
    pub hardened_cases: u64,
    pub has_errno_case: bool,
    pub spec_sections: Vec<String>,
    pub categories: PosixCaseCategoryCounts,
    pub execution: PosixExecutionCounts,
    pub quality_flags: Vec<String>,
}

/// Summary section for POSIX conformance coverage report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixConformanceSummary {
    pub total_exported: u64,
    pub eligible_symbols: u64,
    pub symbols_with_cases: u64,
    pub symbols_with_all_core_categories: u64,
    pub symbols_with_errno_case: u64,
    pub symbols_with_missing_spec_traceability: u64,
    pub symbols_with_execution_failures: u64,
    pub total_fixture_cases: u64,
    pub total_execution_cases: u64,
}

/// Machine-readable report for bd-18qq.7 POSIX conformance campaign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixConformanceReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub summary: PosixConformanceSummary,
    pub symbols: Vec<PosixSymbolCoverageRow>,
}

#[derive(Debug, Default)]
struct FixtureSymbolAggregate {
    case_count: u64,
    strict_cases: u64,
    hardened_cases: u64,
    has_errno_case: bool,
    spec_sections: BTreeSet<String>,
    categories: PosixCaseCategoryCounts,
}

impl PosixConformanceReport {
    /// Build report from on-disk support matrix + fixture directory + conformance matrix.
    pub fn from_paths(
        support_matrix_path: &Path,
        fixture_dir: &Path,
        conformance_matrix_path: &Path,
    ) -> Result<Self, String> {
        let support_matrix_json = std::fs::read_to_string(support_matrix_path).map_err(|err| {
            format!(
                "failed reading support matrix '{}': {err}",
                support_matrix_path.display()
            )
        })?;
        let conformance_matrix_json =
            std::fs::read_to_string(conformance_matrix_path).map_err(|err| {
                format!(
                    "failed reading conformance matrix '{}': {err}",
                    conformance_matrix_path.display()
                )
            })?;
        let fixture_sets = load_fixture_sets_from_dir(fixture_dir)?;
        Self::from_inputs(
            &support_matrix_json,
            &fixture_sets,
            &conformance_matrix_json,
        )
    }

    /// Build report from parsed fixture sets and raw JSON blobs.
    pub fn from_inputs(
        support_matrix_json: &str,
        fixture_sets: &[FixtureSet],
        conformance_matrix_json: &str,
    ) -> Result<Self, String> {
        let support_value: serde_json::Value = serde_json::from_str(support_matrix_json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;
        let generated_at_utc = support_value["generated_at_utc"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let total_exported = support_value["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;
        let support_symbols = support_value["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;

        let mut eligible_symbols: Vec<(String, String, String)> = Vec::new();
        for symbol_row in support_symbols {
            let symbol = symbol_row["symbol"]
                .as_str()
                .ok_or("support matrix symbol row missing symbol")?;
            let status = symbol_row["status"]
                .as_str()
                .ok_or("support matrix symbol row missing status")?;
            let module = symbol_row["module"].as_str().unwrap_or("unknown");
            if status == "Implemented" || status == "RawSyscall" {
                eligible_symbols.push((symbol.to_string(), status.to_string(), module.to_string()));
            }
        }
        eligible_symbols.sort_by(|a, b| a.0.cmp(&b.0));

        let mut fixture_by_symbol: BTreeMap<String, FixtureSymbolAggregate> = BTreeMap::new();
        for fixture_set in fixture_sets {
            for case in &fixture_set.cases {
                let agg = fixture_by_symbol.entry(case.function.clone()).or_default();
                agg.case_count = agg.case_count.saturating_add(1);
                if case.mode.eq_ignore_ascii_case("strict")
                    || case.mode.eq_ignore_ascii_case("both")
                {
                    agg.strict_cases = agg.strict_cases.saturating_add(1);
                }
                if case.mode.eq_ignore_ascii_case("hardened")
                    || case.mode.eq_ignore_ascii_case("both")
                {
                    agg.hardened_cases = agg.hardened_cases.saturating_add(1);
                }
                if case.expected_errno != 0 {
                    agg.has_errno_case = true;
                }
                let spec_section = case.spec_section.trim();
                if !spec_section.is_empty() {
                    agg.spec_sections.insert(spec_section.to_string());
                }
                match classify_posix_case(case) {
                    PosixCaseClass::Normal => {
                        agg.categories.normal = agg.categories.normal.saturating_add(1)
                    }
                    PosixCaseClass::Boundary => {
                        agg.categories.boundary = agg.categories.boundary.saturating_add(1)
                    }
                    PosixCaseClass::Error => {
                        agg.categories.error = agg.categories.error.saturating_add(1)
                    }
                    PosixCaseClass::Other => {
                        agg.categories.other = agg.categories.other.saturating_add(1)
                    }
                }
            }
        }

        let matrix: ConformanceMatrixReport = serde_json::from_str(conformance_matrix_json)
            .map_err(|err| format!("invalid conformance matrix JSON: {err}"))?;
        let mut execution_by_symbol: BTreeMap<String, PosixExecutionCounts> = BTreeMap::new();
        for case in &matrix.cases {
            let counts = execution_by_symbol.entry(case.symbol.clone()).or_default();
            counts.total = counts.total.saturating_add(1);
            match case.status.as_str() {
                "pass" => counts.pass = counts.pass.saturating_add(1),
                "fail" => counts.fail = counts.fail.saturating_add(1),
                "error" => counts.error = counts.error.saturating_add(1),
                "timeout" => counts.timeout = counts.timeout.saturating_add(1),
                "crash" => counts.crash = counts.crash.saturating_add(1),
                _ => {}
            }
        }

        let mut rows = Vec::with_capacity(eligible_symbols.len());
        for (symbol, status, module) in eligible_symbols {
            let fixture = fixture_by_symbol.remove(&symbol).unwrap_or_default();
            let execution = execution_by_symbol.remove(&symbol).unwrap_or_default();
            let spec_sections: Vec<String> = fixture.spec_sections.into_iter().collect();

            let mut quality_flags = Vec::new();
            if fixture.case_count == 0 {
                quality_flags.push(String::from("missing_fixture_cases"));
            }
            if fixture.strict_cases == 0 {
                quality_flags.push(String::from("missing_strict_case"));
            }
            if fixture.hardened_cases == 0 {
                quality_flags.push(String::from("missing_hardened_case"));
            }
            if fixture.categories.normal == 0 {
                quality_flags.push(String::from("missing_normal_case"));
            }
            if fixture.categories.boundary == 0 {
                quality_flags.push(String::from("missing_boundary_case"));
            }
            if fixture.categories.error == 0 {
                quality_flags.push(String::from("missing_error_case"));
            }
            if !fixture.has_errno_case {
                quality_flags.push(String::from("missing_errno_case"));
            }
            if spec_sections.is_empty() {
                quality_flags.push(String::from("missing_spec_traceability"));
            }
            if execution.has_failures() {
                quality_flags.push(String::from("execution_failures_present"));
            }

            rows.push(PosixSymbolCoverageRow {
                symbol,
                status,
                module,
                case_count: fixture.case_count,
                strict_cases: fixture.strict_cases,
                hardened_cases: fixture.hardened_cases,
                has_errno_case: fixture.has_errno_case,
                spec_sections,
                categories: fixture.categories,
                execution,
                quality_flags,
            });
        }

        rows.sort_by(|a, b| a.symbol.cmp(&b.symbol));

        let eligible_symbols =
            u64::try_from(rows.len()).map_err(|_| "eligible symbol count overflow".to_string())?;
        let symbols_with_cases =
            u64::try_from(rows.iter().filter(|row| row.case_count > 0).count()).unwrap_or(0);
        let symbols_with_all_core_categories = u64::try_from(
            rows.iter()
                .filter(|row| row.categories.all_core_categories_present())
                .count(),
        )
        .unwrap_or(0);
        let symbols_with_errno_case =
            u64::try_from(rows.iter().filter(|row| row.has_errno_case).count()).unwrap_or(0);
        let symbols_with_missing_spec_traceability = u64::try_from(
            rows.iter()
                .filter(|row| row.spec_sections.is_empty())
                .count(),
        )
        .unwrap_or(0);
        let symbols_with_execution_failures = u64::try_from(
            rows.iter()
                .filter(|row| row.execution.has_failures())
                .count(),
        )
        .unwrap_or(0);
        let total_fixture_cases = rows
            .iter()
            .fold(0u64, |acc, row| acc.saturating_add(row.case_count));
        let total_execution_cases = rows
            .iter()
            .fold(0u64, |acc, row| acc.saturating_add(row.execution.total));

        Ok(Self {
            schema_version: "v1".to_string(),
            bead: "bd-18qq.7".to_string(),
            generated_at_utc,
            summary: PosixConformanceSummary {
                total_exported,
                eligible_symbols,
                symbols_with_cases,
                symbols_with_all_core_categories,
                symbols_with_errno_case,
                symbols_with_missing_spec_traceability,
                symbols_with_execution_failures,
                total_fixture_cases,
                total_execution_cases,
            },
            symbols: rows,
        })
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

/// Summary section for POSIX obligation traceability coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixObligationSummary {
    pub total_exported: u64,
    pub tracked_symbols: u64,
    pub total_obligations: u64,
    pub covered_obligations: u64,
    pub mapped_without_execution: u64,
    pub obligations_with_execution_failures: u64,
    pub error_condition_obligations: u64,
    pub async_concurrency_obligations: u64,
    pub symbols_missing_any_mapping: u64,
    pub symbols_missing_execution_evidence: u64,
    pub symbols_missing_error_conditions: u64,
    pub symbols_missing_async_concurrency: u64,
}

/// Per-obligation traceability row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixObligationRow {
    pub obligation_id: String,
    pub posix_ref: String,
    pub symbol: String,
    pub symbol_family: String,
    pub owner: String,
    pub support_status: String,
    pub coverage_state: String,
    pub obligation_kinds: Vec<String>,
    pub modes: Vec<String>,
    pub test_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub execution: PosixExecutionCounts,
}

/// Explicit gap row for symbols that lack obligation coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixObligationGapRow {
    pub symbol: String,
    pub symbol_family: String,
    pub owner: String,
    pub support_status: String,
    pub mapped_posix_refs: Vec<String>,
    pub test_refs: Vec<String>,
    pub gap_reasons: Vec<String>,
}

/// Machine-readable report for bd-2tq.4 POSIX obligation mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PosixObligationMatrixReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub summary: PosixObligationSummary,
    pub obligations: Vec<PosixObligationRow>,
    pub gaps: Vec<PosixObligationGapRow>,
}

/// Summary section for bd-2tq.5 errno/edge-case prioritization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrnoEdgeCaseSummary {
    pub tracked_symbols: u64,
    pub total_edge_cases: u64,
    pub errno_cases: u64,
    pub covered_edge_cases: u64,
    pub failing_edge_cases: u64,
    pub execution_error_cases: u64,
    pub missing_execution_cases: u64,
    pub symbols_with_failures: u64,
}

/// One errno/edge-case differential row with an actionable triage template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrnoEdgeCaseRow {
    pub priority_score: u64,
    pub trace_id: String,
    pub symbol: String,
    pub symbol_family: String,
    pub owner: String,
    pub support_status: String,
    pub runtime_mode: String,
    pub case_id: String,
    pub spec_section: String,
    pub edge_class: String,
    pub expected_output: String,
    pub actual_output: Option<String>,
    pub host_output: Option<String>,
    pub expected_errno: i32,
    pub actual_errno: Option<i32>,
    pub status: String,
    pub failure_kind: String,
    pub diff_ref: String,
    pub artifact_refs: Vec<String>,
    pub triage_steps: Vec<String>,
}

/// Machine-readable report for bd-2tq.5 errno + edge-case conformance expansion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrnoEdgeCaseReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub summary: ErrnoEdgeCaseSummary,
    pub rows: Vec<ErrnoEdgeCaseRow>,
}

#[derive(Debug, Clone)]
struct FixtureCatalogEntry {
    source: String,
    set: FixtureSet,
}

#[derive(Debug, Clone)]
struct SupportSymbolMetadata {
    status: String,
    module: String,
    family: String,
}

#[derive(Debug, Clone, Default)]
struct PosixObligationAggregate {
    symbol_family: String,
    owner: String,
    support_status: String,
    obligation_kinds: BTreeSet<String>,
    modes: BTreeSet<String>,
    test_refs: BTreeSet<String>,
    artifact_refs: BTreeSet<String>,
    execution: PosixExecutionCounts,
}

#[derive(Debug, Deserialize, Default)]
struct CFixtureSpec {
    #[serde(default)]
    fixtures: Vec<CFixturePack>,
}

#[derive(Debug, Deserialize, Default)]
struct CFixturePack {
    id: String,
    source: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    covered_symbols: Vec<String>,
    #[serde(default)]
    covered_modules: Vec<String>,
    #[serde(default)]
    spec_traceability: CFixtureTraceability,
    #[serde(default)]
    mode_expectations: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct CFixtureTraceability {
    #[serde(default)]
    posix: Vec<String>,
}

impl PosixObligationMatrixReport {
    /// Build report from on-disk support matrix + fixture directory + conformance matrix + C fixture spec.
    pub fn from_paths(
        support_matrix_path: &Path,
        fixture_dir: &Path,
        conformance_matrix_path: &Path,
        c_fixture_spec_path: &Path,
    ) -> Result<Self, String> {
        let support_matrix_json = std::fs::read_to_string(support_matrix_path).map_err(|err| {
            format!(
                "failed reading support matrix '{}': {err}",
                support_matrix_path.display()
            )
        })?;
        let conformance_matrix_json =
            std::fs::read_to_string(conformance_matrix_path).map_err(|err| {
                format!(
                    "failed reading conformance matrix '{}': {err}",
                    conformance_matrix_path.display()
                )
            })?;
        let c_fixture_spec_json = std::fs::read_to_string(c_fixture_spec_path).map_err(|err| {
            format!(
                "failed reading C fixture spec '{}': {err}",
                c_fixture_spec_path.display()
            )
        })?;
        let fixture_catalog = load_fixture_catalog_from_dir(fixture_dir)?;
        Self::from_fixture_catalog_inputs(
            &support_matrix_json,
            &fixture_catalog,
            &conformance_matrix_json,
            &c_fixture_spec_json,
        )
    }

    /// Build report from parsed fixture sets and raw JSON blobs.
    pub fn from_inputs(
        support_matrix_json: &str,
        fixture_sets: &[FixtureSet],
        conformance_matrix_json: &str,
        c_fixture_spec_json: &str,
    ) -> Result<Self, String> {
        let fixture_catalog = fixture_sets
            .iter()
            .map(|set| FixtureCatalogEntry {
                source: format!("tests/conformance/fixtures/{}.json", set.family),
                set: set.clone(),
            })
            .collect::<Vec<_>>();
        Self::from_fixture_catalog_inputs(
            support_matrix_json,
            &fixture_catalog,
            conformance_matrix_json,
            c_fixture_spec_json,
        )
    }

    fn from_fixture_catalog_inputs(
        support_matrix_json: &str,
        fixture_catalog: &[FixtureCatalogEntry],
        conformance_matrix_json: &str,
        c_fixture_spec_json: &str,
    ) -> Result<Self, String> {
        let support_value: serde_json::Value = serde_json::from_str(support_matrix_json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;
        let generated_at_utc = support_value["generated_at_utc"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let total_exported = support_value["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;
        let support_symbols = support_value["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;

        let mut tracked_symbols = BTreeMap::new();
        for symbol_row in support_symbols {
            let symbol = symbol_row["symbol"]
                .as_str()
                .ok_or("support matrix symbol row missing symbol")?;
            let status = symbol_row["status"]
                .as_str()
                .ok_or("support matrix symbol row missing status")?;
            if !status_tracks_posix_obligations(status) {
                continue;
            }

            let module = symbol_row["module"].as_str().unwrap_or("unknown");
            tracked_symbols.insert(
                symbol.to_string(),
                SupportSymbolMetadata {
                    status: status.to_string(),
                    module: module.to_string(),
                    family: derive_family_from_module(module),
                },
            );
        }

        let mut obligations: BTreeMap<(String, String), PosixObligationAggregate> = BTreeMap::new();
        let mut matrix_case_lookup: BTreeMap<(String, String, String), (String, String)> =
            BTreeMap::new();

        for entry in fixture_catalog {
            for case in &entry.set.cases {
                let posix_ref = normalize_obligation_ref(&case.spec_section);
                if !is_posix_ref(&posix_ref) {
                    continue;
                }

                let symbol = case.function.clone();
                let key = (symbol.clone(), posix_ref.clone());
                let support_meta = tracked_symbols.get(&symbol);
                let aggregate = obligations.entry(key.clone()).or_default();
                if aggregate.symbol_family.is_empty() {
                    aggregate.symbol_family = if !entry.set.family.trim().is_empty() {
                        entry.set.family.clone()
                    } else {
                        support_meta
                            .map(|meta| meta.family.clone())
                            .unwrap_or_else(|| "unknown".to_string())
                    };
                }
                if aggregate.owner.is_empty() {
                    aggregate.owner = support_meta
                        .map(|meta| meta.module.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                }
                if aggregate.support_status.is_empty() {
                    aggregate.support_status = support_meta
                        .map(|meta| meta.status.clone())
                        .unwrap_or_else(|| "Untracked".to_string());
                }

                aggregate.obligation_kinds.extend(classify_obligation_kinds(
                    &[
                        &entry.set.family,
                        &case.function,
                        &case.name,
                        &case.spec_section,
                        &case.inputs.to_string(),
                    ],
                    case.expected_errno,
                ));
                for mode in expand_modes(&case.mode) {
                    aggregate.modes.insert(mode.clone());
                    let test_ref =
                        format!("fixture::{}::{}::{}", entry.set.family, case.name, mode);
                    aggregate.test_refs.insert(test_ref);
                    matrix_case_lookup.insert(
                        (symbol.clone(), case.name.clone(), mode.clone()),
                        key.clone(),
                    );
                    matrix_case_lookup.insert(
                        (
                            symbol.clone(),
                            format!("{} [{}]", case.name, mode),
                            mode.clone(),
                        ),
                        key.clone(),
                    );
                }
                aggregate.artifact_refs.insert(entry.source.clone());
            }
        }

        let c_fixture_spec: CFixtureSpec = serde_json::from_str(c_fixture_spec_json)
            .map_err(|err| format!("invalid C fixture spec JSON: {err}"))?;
        for fixture in &c_fixture_spec.fixtures {
            for posix_ref_raw in &fixture.spec_traceability.posix {
                let posix_ref = normalize_obligation_ref(posix_ref_raw);
                if !is_posix_ref(&posix_ref) {
                    continue;
                }

                for symbol in &fixture.covered_symbols {
                    let key = (symbol.clone(), posix_ref.clone());
                    let support_meta = tracked_symbols.get(symbol);
                    let aggregate = obligations.entry(key).or_default();
                    if aggregate.symbol_family.is_empty() {
                        aggregate.symbol_family = support_meta
                            .map(|meta| meta.family.clone())
                            .or_else(|| {
                                fixture
                                    .covered_modules
                                    .first()
                                    .map(|module| derive_family_from_module(module))
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                    }
                    if aggregate.owner.is_empty() {
                        aggregate.owner = support_meta
                            .map(|meta| meta.module.clone())
                            .or_else(|| fixture.covered_modules.first().cloned())
                            .unwrap_or_else(|| "unknown".to_string());
                    }
                    if aggregate.support_status.is_empty() {
                        aggregate.support_status = support_meta
                            .map(|meta| meta.status.clone())
                            .unwrap_or_else(|| "Untracked".to_string());
                    }

                    aggregate.obligation_kinds.extend(classify_obligation_kinds(
                        &[&fixture.id, &fixture.description, posix_ref_raw],
                        0,
                    ));

                    if fixture.mode_expectations.is_empty() {
                        aggregate
                            .test_refs
                            .insert(format!("c_fixture::{}", fixture.id));
                    } else {
                        for mode in fixture.mode_expectations.keys() {
                            let mode = mode.to_ascii_lowercase();
                            aggregate.modes.extend(expand_modes(&mode));
                            aggregate
                                .test_refs
                                .insert(format!("c_fixture::{}::{}", fixture.id, mode));
                        }
                    }
                    aggregate.artifact_refs.insert(fixture.source.clone());
                    aggregate
                        .artifact_refs
                        .insert(String::from("tests/conformance/c_fixture_spec.json"));
                }
            }
        }

        let matrix: ConformanceMatrixReport = serde_json::from_str(conformance_matrix_json)
            .map_err(|err| format!("invalid conformance matrix JSON: {err}"))?;
        let mut c_fixture_obligations_by_symbol_mode: BTreeMap<
            (String, String),
            Vec<(String, String)>,
        > = BTreeMap::new();
        for (obligation_key, aggregate) in &obligations {
            if !aggregate
                .test_refs
                .iter()
                .all(|test_ref| test_ref.starts_with("c_fixture::"))
            {
                continue;
            }

            for mode in &aggregate.modes {
                c_fixture_obligations_by_symbol_mode
                    .entry((obligation_key.0.clone(), mode.clone()))
                    .or_default()
                    .push(obligation_key.clone());
            }
        }
        for case in &matrix.cases {
            let lookup_key = (
                case.symbol.clone(),
                case.case_name.clone(),
                case.mode.to_ascii_lowercase(),
            );
            let fallback_key = (case.symbol.clone(), case.mode.to_ascii_lowercase());
            if let Some(obligation_key) = matrix_case_lookup.get(&lookup_key) {
                if let Some(aggregate) = obligations.get_mut(obligation_key) {
                    record_posix_execution(&mut aggregate.execution, &case.status);
                }
                if let Some(obligation_keys) =
                    c_fixture_obligations_by_symbol_mode.get(&fallback_key)
                {
                    for c_fixture_obligation_key in obligation_keys {
                        if c_fixture_obligation_key == obligation_key {
                            continue;
                        }
                        if let Some(aggregate) = obligations.get_mut(c_fixture_obligation_key) {
                            record_posix_execution(&mut aggregate.execution, &case.status);
                            aggregate.test_refs.insert(format!(
                                "conformance_matrix::{}::{}::{}",
                                case.symbol, case.case_name, case.mode
                            ));
                            aggregate.artifact_refs.insert(String::from(
                                "tests/conformance/conformance_matrix.v1.json",
                            ));
                        }
                    }
                }
                continue;
            }

            let Some(obligation_keys) = c_fixture_obligations_by_symbol_mode.get(&fallback_key)
            else {
                continue;
            };
            for obligation_key in obligation_keys {
                if let Some(aggregate) = obligations.get_mut(obligation_key) {
                    record_posix_execution(&mut aggregate.execution, &case.status);
                    aggregate.test_refs.insert(format!(
                        "conformance_matrix::{}::{}::{}",
                        case.symbol, case.case_name, case.mode
                    ));
                    aggregate
                        .artifact_refs
                        .insert(String::from("tests/conformance/conformance_matrix.v1.json"));
                }
            }
        }

        let mut obligation_rows = obligations
            .into_iter()
            .map(|((symbol, posix_ref), aggregate)| PosixObligationRow {
                obligation_id: format!("{}::{}", symbol, obligation_ref_slug(&posix_ref)),
                posix_ref,
                symbol,
                symbol_family: aggregate.symbol_family,
                owner: aggregate.owner,
                support_status: aggregate.support_status,
                coverage_state: classify_obligation_coverage_state(&aggregate.execution)
                    .to_string(),
                obligation_kinds: aggregate.obligation_kinds.into_iter().collect(),
                modes: aggregate.modes.into_iter().collect(),
                test_refs: aggregate.test_refs.into_iter().collect(),
                artifact_refs: aggregate.artifact_refs.into_iter().collect(),
                execution: aggregate.execution,
            })
            .collect::<Vec<_>>();
        obligation_rows.sort_by(|a, b| {
            a.symbol
                .cmp(&b.symbol)
                .then_with(|| a.posix_ref.cmp(&b.posix_ref))
        });

        let mut gaps = Vec::new();
        for (symbol, meta) in &tracked_symbols {
            let symbol_rows = obligation_rows
                .iter()
                .filter(|row| row.symbol == *symbol)
                .collect::<Vec<_>>();
            let mut gap_reasons = Vec::new();
            if symbol_rows.is_empty() {
                gap_reasons.push(String::from("missing_test_mapping"));
                gap_reasons.push(String::from("missing_posix_traceability"));
            } else {
                if symbol_rows.iter().all(|row| row.execution.total == 0) {
                    gap_reasons.push(String::from("missing_execution_evidence"));
                }
                if symbol_rows.iter().all(|row| {
                    !row.obligation_kinds
                        .iter()
                        .any(|kind| kind == "error_condition")
                }) {
                    gap_reasons.push(String::from("missing_error_condition_obligation"));
                }
                if async_concurrency_candidate_for_symbol(symbol, &meta.family, &meta.module)
                    && symbol_rows.iter().all(|row| {
                        !row.obligation_kinds
                            .iter()
                            .any(|kind| kind == "async_concurrency")
                    })
                {
                    gap_reasons.push(String::from("missing_async_concurrency_obligation"));
                }
            }

            if gap_reasons.is_empty() {
                continue;
            }

            gaps.push(PosixObligationGapRow {
                symbol: symbol.clone(),
                symbol_family: meta.family.clone(),
                owner: meta.module.clone(),
                support_status: meta.status.clone(),
                mapped_posix_refs: symbol_rows
                    .iter()
                    .map(|row| row.posix_ref.clone())
                    .collect(),
                test_refs: symbol_rows
                    .iter()
                    .flat_map(|row| row.test_refs.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                gap_reasons,
            });
        }
        gaps.sort_by(|a, b| a.symbol.cmp(&b.symbol));

        let total_obligations = u64::try_from(obligation_rows.len())
            .map_err(|_| "obligation count overflow".to_string())?;
        let tracked_symbols_count = u64::try_from(tracked_symbols.len())
            .map_err(|_| "tracked symbol count overflow".to_string())?;
        let covered_obligations = u64::try_from(
            obligation_rows
                .iter()
                .filter(|row| row.coverage_state == "covered")
                .count(),
        )
        .unwrap_or(0);
        let mapped_without_execution = u64::try_from(
            obligation_rows
                .iter()
                .filter(|row| row.coverage_state == "mapped_without_execution")
                .count(),
        )
        .unwrap_or(0);
        let obligations_with_execution_failures = u64::try_from(
            obligation_rows
                .iter()
                .filter(|row| row.coverage_state == "execution_failures")
                .count(),
        )
        .unwrap_or(0);
        let error_condition_obligations = u64::try_from(
            obligation_rows
                .iter()
                .filter(|row| {
                    row.obligation_kinds
                        .iter()
                        .any(|kind| kind == "error_condition")
                })
                .count(),
        )
        .unwrap_or(0);
        let async_concurrency_obligations = u64::try_from(
            obligation_rows
                .iter()
                .filter(|row| {
                    row.obligation_kinds
                        .iter()
                        .any(|kind| kind == "async_concurrency")
                })
                .count(),
        )
        .unwrap_or(0);
        let symbols_missing_any_mapping = u64::try_from(
            gaps.iter()
                .filter(|gap| {
                    gap.gap_reasons
                        .iter()
                        .any(|reason| reason == "missing_test_mapping")
                })
                .count(),
        )
        .unwrap_or(0);
        let symbols_missing_execution_evidence = u64::try_from(
            gaps.iter()
                .filter(|gap| {
                    gap.gap_reasons
                        .iter()
                        .any(|reason| reason == "missing_execution_evidence")
                })
                .count(),
        )
        .unwrap_or(0);
        let symbols_missing_error_conditions = u64::try_from(
            gaps.iter()
                .filter(|gap| {
                    gap.gap_reasons
                        .iter()
                        .any(|reason| reason == "missing_error_condition_obligation")
                })
                .count(),
        )
        .unwrap_or(0);
        let symbols_missing_async_concurrency = u64::try_from(
            gaps.iter()
                .filter(|gap| {
                    gap.gap_reasons
                        .iter()
                        .any(|reason| reason == "missing_async_concurrency_obligation")
                })
                .count(),
        )
        .unwrap_or(0);

        Ok(Self {
            schema_version: "v1".to_string(),
            bead: "bd-2tq.4".to_string(),
            generated_at_utc,
            summary: PosixObligationSummary {
                total_exported,
                tracked_symbols: tracked_symbols_count,
                total_obligations,
                covered_obligations,
                mapped_without_execution,
                obligations_with_execution_failures,
                error_condition_obligations,
                async_concurrency_obligations,
                symbols_missing_any_mapping,
                symbols_missing_execution_evidence,
                symbols_missing_error_conditions,
                symbols_missing_async_concurrency,
            },
            obligations: obligation_rows,
            gaps,
        })
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

impl ErrnoEdgeCaseReport {
    /// Build report from on-disk support matrix + fixture directory + conformance matrix.
    pub fn from_paths(
        support_matrix_path: &Path,
        fixture_dir: &Path,
        conformance_matrix_path: &Path,
    ) -> Result<Self, String> {
        let support_matrix_json = std::fs::read_to_string(support_matrix_path).map_err(|err| {
            format!(
                "failed reading support matrix '{}': {err}",
                support_matrix_path.display()
            )
        })?;
        let conformance_matrix_json =
            std::fs::read_to_string(conformance_matrix_path).map_err(|err| {
                format!(
                    "failed reading conformance matrix '{}': {err}",
                    conformance_matrix_path.display()
                )
            })?;
        let fixture_catalog = load_fixture_catalog_from_dir(fixture_dir)?;
        Self::from_fixture_catalog_inputs(
            &support_matrix_json,
            &fixture_catalog,
            &conformance_matrix_json,
        )
    }

    /// Build report from parsed fixture sets and raw JSON blobs.
    pub fn from_inputs(
        support_matrix_json: &str,
        fixture_sets: &[FixtureSet],
        conformance_matrix_json: &str,
    ) -> Result<Self, String> {
        let fixture_catalog = fixture_sets
            .iter()
            .map(|set| FixtureCatalogEntry {
                source: format!("tests/conformance/fixtures/{}.json", set.family),
                set: set.clone(),
            })
            .collect::<Vec<_>>();
        Self::from_fixture_catalog_inputs(
            support_matrix_json,
            &fixture_catalog,
            conformance_matrix_json,
        )
    }

    fn from_fixture_catalog_inputs(
        support_matrix_json: &str,
        fixture_catalog: &[FixtureCatalogEntry],
        conformance_matrix_json: &str,
    ) -> Result<Self, String> {
        let support_value: serde_json::Value = serde_json::from_str(support_matrix_json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;
        let generated_at_utc = support_value["generated_at_utc"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let support_symbols = support_value["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;

        let mut tracked_symbols = BTreeMap::new();
        for symbol_row in support_symbols {
            let symbol = symbol_row["symbol"]
                .as_str()
                .ok_or("support matrix symbol row missing symbol")?;
            let status = symbol_row["status"]
                .as_str()
                .ok_or("support matrix symbol row missing status")?;
            if !status_tracks_posix_obligations(status) {
                continue;
            }

            let module = symbol_row["module"].as_str().unwrap_or("unknown");
            tracked_symbols.insert(
                symbol.to_string(),
                SupportSymbolMetadata {
                    status: status.to_string(),
                    module: module.to_string(),
                    family: derive_family_from_module(module),
                },
            );
        }

        let matrix: ConformanceMatrixReport = serde_json::from_str(conformance_matrix_json)
            .map_err(|err| format!("invalid conformance matrix JSON: {err}"))?;
        let mut matrix_rows = BTreeMap::new();
        for row in &matrix.cases {
            matrix_rows.insert(
                (
                    row.symbol.clone(),
                    row.case_name.clone(),
                    row.mode.to_ascii_lowercase(),
                ),
                row.clone(),
            );
        }

        let mut symbol_failure_counts: BTreeMap<String, u64> = BTreeMap::new();
        for entry in fixture_catalog {
            for case in &entry.set.cases {
                if !is_errno_or_edge_case(case) {
                    continue;
                }
                for mode in expand_modes(&case.mode) {
                    let case_name = expected_conformance_case_name(case, &mode);
                    let status = matrix_rows
                        .get(&(case.function.clone(), case_name, mode.clone()))
                        .map(|row| row.status.as_str())
                        .unwrap_or("missing_execution");
                    if status != "pass" {
                        *symbol_failure_counts
                            .entry(case.function.clone())
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        let mut rows = Vec::new();
        for entry in fixture_catalog {
            for case in &entry.set.cases {
                if !is_errno_or_edge_case(case) {
                    continue;
                }

                let support_meta = tracked_symbols.get(&case.function);
                let symbol_family = if !entry.set.family.trim().is_empty() {
                    entry.set.family.clone()
                } else {
                    support_meta
                        .map(|meta| meta.family.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                };
                let owner = support_meta
                    .map(|meta| meta.module.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                let support_status = support_meta
                    .map(|meta| meta.status.clone())
                    .unwrap_or_else(|| "Untracked".to_string());
                let edge_class = classify_errno_edge_class(case).to_string();

                for mode in expand_modes(&case.mode) {
                    let case_name = expected_conformance_case_name(case, &mode);
                    let matrix_row =
                        matrix_rows.get(&(case.function.clone(), case_name.clone(), mode.clone()));
                    let status = matrix_row
                        .map(|row| row.status.clone())
                        .unwrap_or_else(|| "missing_execution".to_string());
                    let actual_output = matrix_row.map(|row| row.actual_output.clone());
                    let host_output = matrix_row.and_then(|row| row.host_output.clone());
                    let actual_errno = matrix_row.and_then(|row| {
                        parse_errno_value(&row.actual_output)
                            .or_else(|| row.error.as_deref().and_then(parse_errno_value))
                    });
                    let failure_kind = classify_errno_edge_failure_kind(
                        case.expected_errno,
                        &status,
                        matrix_row,
                        actual_errno,
                    );
                    let diff_ref = matrix_row
                        .map(|row| format!("conformance_matrix::trace_id::{}", row.trace_id))
                        .unwrap_or_else(|| {
                            format!(
                                "conformance_matrix::missing::{}::{}::{}",
                                case.function, case_name, mode
                            )
                        });
                    let priority_score = symbol_failure_counts
                        .get(&case.function)
                        .copied()
                        .unwrap_or(0)
                        .saturating_mul(100)
                        .saturating_add(errno_edge_status_weight(&status))
                        .saturating_add(if case.expected_errno != 0 { 20 } else { 0 })
                        .saturating_add(match edge_class.as_str() {
                            "error_condition" => 10,
                            "boundary" => 5,
                            _ => 0,
                        })
                        .saturating_add(match support_status.as_str() {
                            "RawSyscall" => 10,
                            "WrapsHostLibc" => 5,
                            "GlibcCallThrough" => 5,
                            _ => 0,
                        });

                    rows.push(ErrnoEdgeCaseRow {
                        priority_score,
                        trace_id: matrix_row
                            .map(|row| row.trace_id.clone())
                            .unwrap_or_else(|| {
                                format!("missing::{}::{}::{}", case.function, mode, case.name)
                            }),
                        symbol: case.function.clone(),
                        symbol_family: symbol_family.clone(),
                        owner: owner.clone(),
                        support_status: support_status.clone(),
                        runtime_mode: mode.clone(),
                        case_id: case_name.clone(),
                        spec_section: case.spec_section.clone(),
                        edge_class: edge_class.clone(),
                        expected_output: case.expected_output.clone(),
                        actual_output,
                        host_output,
                        expected_errno: case.expected_errno,
                        actual_errno,
                        status: status.clone(),
                        failure_kind: failure_kind.clone(),
                        diff_ref: diff_ref.clone(),
                        artifact_refs: vec![
                            entry.source.clone(),
                            String::from("tests/conformance/conformance_matrix.v1.json"),
                        ],
                        triage_steps: build_errno_edge_triage_steps(
                            case,
                            &failure_kind,
                            &diff_ref,
                            matrix_row,
                        ),
                    });
                }
            }
        }

        rows.sort_by(|a, b| {
            b.priority_score
                .cmp(&a.priority_score)
                .then_with(|| a.symbol.cmp(&b.symbol))
                .then_with(|| a.case_id.cmp(&b.case_id))
                .then_with(|| a.runtime_mode.cmp(&b.runtime_mode))
        });

        let tracked_symbols_count = u64::try_from(tracked_symbols.len())
            .map_err(|_| "tracked symbol count overflow".to_string())?;
        let total_edge_cases =
            u64::try_from(rows.len()).map_err(|_| "errno/edge row count overflow".to_string())?;
        let errno_cases =
            u64::try_from(rows.iter().filter(|row| row.expected_errno != 0).count()).unwrap_or(0);
        let covered_edge_cases =
            u64::try_from(rows.iter().filter(|row| row.status == "pass").count()).unwrap_or(0);
        let failing_edge_cases =
            u64::try_from(rows.iter().filter(|row| row.status != "pass").count()).unwrap_or(0);
        let execution_error_cases = u64::try_from(
            rows.iter()
                .filter(|row| matches!(row.status.as_str(), "error" | "timeout" | "crash"))
                .count(),
        )
        .unwrap_or(0);
        let missing_execution_cases = u64::try_from(
            rows.iter()
                .filter(|row| row.status == "missing_execution")
                .count(),
        )
        .unwrap_or(0);
        let symbols_with_failures = u64::try_from(
            rows.iter()
                .filter(|row| row.status != "pass")
                .map(|row| row.symbol.clone())
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .unwrap_or(0);

        Ok(Self {
            schema_version: "v1".to_string(),
            bead: "bd-2tq.5".to_string(),
            generated_at_utc,
            summary: ErrnoEdgeCaseSummary {
                tracked_symbols: tracked_symbols_count,
                total_edge_cases,
                errno_cases,
                covered_edge_cases,
                failing_edge_cases,
                execution_error_cases,
                missing_execution_cases,
                symbols_with_failures,
            },
            rows,
        })
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

fn classify_obligation_coverage_state(execution: &PosixExecutionCounts) -> &'static str {
    if execution.total == 0 {
        "mapped_without_execution"
    } else if execution.has_failures() {
        "execution_failures"
    } else {
        "covered"
    }
}

fn record_posix_execution(execution: &mut PosixExecutionCounts, status: &str) {
    execution.total = execution.total.saturating_add(1);
    match status {
        "pass" => execution.pass = execution.pass.saturating_add(1),
        "fail" => execution.fail = execution.fail.saturating_add(1),
        "error" => execution.error = execution.error.saturating_add(1),
        "timeout" => execution.timeout = execution.timeout.saturating_add(1),
        "crash" => execution.crash = execution.crash.saturating_add(1),
        _ => {}
    }
}

fn status_tracks_posix_obligations(status: &str) -> bool {
    matches!(
        status,
        "Implemented" | "RawSyscall" | "WrapsHostLibc" | "GlibcCallThrough"
    )
}

fn derive_family_from_module(module: &str) -> String {
    module.strip_suffix("_abi").unwrap_or(module).to_string()
}

fn normalize_obligation_ref(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_posix_ref(spec_ref: &str) -> bool {
    spec_ref.to_ascii_lowercase().contains("posix")
}

fn obligation_ref_slug(spec_ref: &str) -> String {
    let mut slug = String::new();
    let mut last_was_sep = false;
    for ch in spec_ref.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            slug.push(normalized);
            last_was_sep = false;
        } else if !last_was_sep {
            slug.push('_');
            last_was_sep = true;
        }
    }
    slug.trim_matches('_').to_string()
}

fn is_errno_or_edge_case(case: &FixtureCase) -> bool {
    case.expected_errno != 0 || !matches!(classify_posix_case(case), PosixCaseClass::Normal)
}

fn classify_errno_edge_class(case: &FixtureCase) -> &'static str {
    if case.expected_errno != 0 {
        return "error_condition";
    }

    match classify_posix_case(case) {
        PosixCaseClass::Normal => "normal",
        PosixCaseClass::Boundary => "boundary",
        PosixCaseClass::Error => "error_condition",
        PosixCaseClass::Other => "other_edge",
    }
}

fn expected_conformance_case_name(case: &FixtureCase, mode: &str) -> String {
    if case.mode.eq_ignore_ascii_case("both") {
        format!("{} [{}]", case.name, mode)
    } else {
        case.name.clone()
    }
}

fn parse_errno_value(raw: &str) -> Option<i32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(value) = trimmed.parse::<i32>()
        && value >= 0
    {
        return Some(value);
    }

    [
        ("EPERM", 1),
        ("ENOENT", 2),
        ("ESRCH", 3),
        ("EINTR", 4),
        ("EIO", 5),
        ("EBADF", 9),
        ("EAGAIN", 11),
        ("ENOMEM", 12),
        ("EACCES", 13),
        ("EFAULT", 14),
        ("EBUSY", 16),
        ("EINVAL", 22),
        ("ENFILE", 23),
        ("EMFILE", 24),
        ("ENOTTY", 25),
        ("EPIPE", 32),
        ("ERANGE", 34),
        ("EDEADLK", 35),
        ("ENOSYS", 38),
        ("ENOTSOCK", 88),
        ("EDESTADDRREQ", 89),
        ("EMSGSIZE", 90),
        ("EPROTOTYPE", 91),
        ("ENOPROTOOPT", 92),
        ("EPROTONOSUPPORT", 93),
        ("EAFNOSUPPORT", 97),
        ("EADDRINUSE", 98),
        ("EADDRNOTAVAIL", 99),
        ("ENETDOWN", 100),
        ("ENETUNREACH", 101),
        ("ECONNABORTED", 103),
        ("ECONNRESET", 104),
        ("ENOBUFS", 105),
        ("EISCONN", 106),
        ("ENOTCONN", 107),
        ("ETIMEDOUT", 110),
        ("ECONNREFUSED", 111),
    ]
    .iter()
    .find_map(|(name, value)| trimmed.contains(name).then_some(*value))
}

fn errno_edge_status_weight(status: &str) -> u64 {
    match status {
        "error" => 80,
        "timeout" | "crash" => 70,
        "fail" => 60,
        "missing_execution" => 50,
        _ => 0,
    }
}

fn classify_errno_edge_failure_kind(
    expected_errno: i32,
    status: &str,
    matrix_row: Option<&ConformanceCaseRow>,
    actual_errno: Option<i32>,
) -> String {
    match status {
        "pass" => String::from("covered"),
        "missing_execution" => String::from("missing_execution"),
        "timeout" => String::from("timeout"),
        "crash" => String::from("crash"),
        "error" => {
            if matrix_row
                .and_then(|row| row.error.as_deref())
                .is_some_and(|err| err.contains("unsupported function"))
            {
                String::from("unsupported_function")
            } else if matrix_row
                .and_then(|row| row.error.as_deref())
                .is_some_and(|err| err.contains("missing "))
            {
                String::from("input_schema_mismatch")
            } else {
                String::from("execution_error")
            }
        }
        "fail" => {
            if expected_errno != 0 && actual_errno != Some(expected_errno) {
                String::from("errno_mismatch")
            } else {
                String::from("output_mismatch")
            }
        }
        _ => String::from("unknown"),
    }
}

fn build_errno_edge_triage_steps(
    case: &FixtureCase,
    failure_kind: &str,
    diff_ref: &str,
    matrix_row: Option<&ConformanceCaseRow>,
) -> Vec<String> {
    let mut steps = vec![format!(
        "Inspect fixture '{}' for '{}' and compare it against {}.",
        case.name, case.function, diff_ref
    )];

    match failure_kind {
        "unsupported_function" => steps.push(format!(
            "Add '{}' to frankenlibc_conformance::execute_fixture_case or narrow the fixture until the harness can execute it deterministically.",
            case.function
        )),
        "input_schema_mismatch" => steps.push(format!(
            "Align the fixture input schema for '{}' with the executor decoder before rerunning the differential case.",
            case.function
        )),
        "errno_mismatch" => steps.push(format!(
            "Check errno propagation/reset behavior for '{}' and verify the failing path preserves errno {}.",
            case.function, case.expected_errno
        )),
        "output_mismatch" => steps.push(format!(
            "Diff expected vs actual output for '{}' and inspect strict/hardened repair behavior on this edge path.",
            case.function
        )),
        "missing_execution" => steps.push(format!(
            "Regenerate the conformance matrix or add missing execution wiring so '{}' runs for this scenario.",
            case.function
        )),
        "timeout" | "crash" => steps.push(format!(
            "Reproduce '{}' in isolation and capture a minimized replay for the failing edge case.",
            case.function
        )),
        _ => {}
    }

    if let Some(row) = matrix_row
        && let Some(error) = &row.error
    {
        steps.push(format!("Recorded execution error: {error}"));
    }

    steps
}

fn classify_obligation_kinds(text_fragments: &[&str], expected_errno: i32) -> BTreeSet<String> {
    let mut kinds = BTreeSet::from([String::from("functional")]);
    let combined = text_fragments
        .iter()
        .map(|text| text.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");

    if expected_errno != 0
        || [
            "errno",
            "error",
            "invalid",
            "fault",
            "efault",
            "einval",
            "eperm",
            "ebusy",
            "eagain",
            "range",
            "adversarial",
            "denied",
        ]
        .iter()
        .any(|marker| combined.contains(marker))
    {
        kinds.insert(String::from("error_condition"));
    }

    if [
        "pthread",
        "thread",
        "mutex",
        "cond",
        "rwlock",
        "signal",
        "sig",
        "setjmp",
        "longjmp",
        "concurrent",
        "concurrency",
        "spawn",
        "exec",
        "cancel",
        "poll",
        "select",
        "fork",
    ]
    .iter()
    .any(|marker| combined.contains(marker))
    {
        kinds.insert(String::from("async_concurrency"));
    }

    kinds
}

fn async_concurrency_candidate_for_symbol(symbol: &str, family: &str, owner: &str) -> bool {
    let combined = format!("{symbol}\n{family}\n{owner}").to_ascii_lowercase();
    [
        "pthread", "thread", "mutex", "cond", "rwlock", "signal", "sig", "setjmp", "spawn", "exec",
        "poll", "select", "fork",
    ]
    .iter()
    .any(|marker| combined.contains(marker))
}

fn expand_modes(raw: &str) -> Vec<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "both" => vec![String::from("hardened"), String::from("strict")],
        "hardened" => vec![String::from("hardened")],
        "strict" => vec![String::from("strict")],
        other => vec![other.to_string()],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PosixCaseClass {
    Normal,
    Boundary,
    Error,
    Other,
}

fn classify_posix_case(case: &FixtureCase) -> PosixCaseClass {
    if case.expected_errno != 0 {
        return PosixCaseClass::Error;
    }

    let mut haystack = String::new();
    haystack.push_str(&case.name.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.spec_section.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.expected_output.to_ascii_lowercase());
    haystack.push('\n');
    haystack.push_str(&case.inputs.to_string().to_ascii_lowercase());

    let has_boundary_marker = [
        "boundary",
        "bound",
        "limit",
        "max",
        "min",
        "overflow",
        "underflow",
        "size_max",
        "long_max",
        "int_max",
        "empty",
        "zero",
        "null",
        "eof",
    ]
    .iter()
    .any(|marker| haystack.contains(marker));
    if has_boundary_marker {
        return PosixCaseClass::Boundary;
    }

    let has_error_marker = [
        "invalid",
        "error",
        "errno",
        "efault",
        "einval",
        "failed",
        "denied",
        "uaf",
        "double_free",
    ]
    .iter()
    .any(|marker| haystack.contains(marker));
    if has_error_marker {
        return PosixCaseClass::Error;
    }

    if haystack.contains("normal") || haystack.contains("happy_path") || haystack.contains("basic")
    {
        return PosixCaseClass::Normal;
    }

    PosixCaseClass::Other
}

fn stable_artifact_source_path(path: &Path) -> String {
    if path.is_relative() {
        return path.to_string_lossy().to_string();
    }

    if let Ok(current_dir) = std::env::current_dir()
        && let Ok(relative) = path.strip_prefix(&current_dir)
    {
        return relative.to_string_lossy().to_string();
    }

    path.to_string_lossy().to_string()
}

fn load_fixture_catalog_from_dir(fixture_dir: &Path) -> Result<Vec<FixtureCatalogEntry>, String> {
    let mut fixture_paths: Vec<_> = std::fs::read_dir(fixture_dir)
        .map_err(|err| {
            format!(
                "failed reading fixture dir '{}': {err}",
                fixture_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    fixture_paths.sort();

    let mut entries = Vec::new();
    for path in fixture_paths {
        if let Ok(set) = FixtureSet::from_file(&path) {
            entries.push(FixtureCatalogEntry {
                source: stable_artifact_source_path(&path),
                set,
            });
        }
    }

    if entries.is_empty() {
        return Err(format!(
            "no fixture sets could be parsed from '{}'",
            fixture_dir.display()
        ));
    }

    Ok(entries)
}

fn load_fixture_sets_from_dir(fixture_dir: &Path) -> Result<Vec<FixtureSet>, String> {
    let entries = load_fixture_catalog_from_dir(fixture_dir)?;
    let mut sets = Vec::with_capacity(entries.len());
    for entry in entries {
        sets.push(entry.set);
    }

    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::{
        DecisionTraceReport, ErrnoEdgeCaseReport, PosixCaseCategoryCounts, PosixConformanceReport,
        PosixObligationMatrixReport, RealityCounts, RealityReport,
    };
    use crate::FixtureSet;

    fn sample_matrix(symbol_rows: &str, total_exported: u64) -> String {
        format!(
            r#"{{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": {total_exported},
  "symbols": [
{symbol_rows}
  ]
}}"#
        )
    }

    #[test]
    fn parses_valid_support_matrix() {
        let json = sample_matrix(
            r#"    { "symbol": "zeta", "status": "Stub" },
    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "beta", "status": "RawSyscall" },
    { "symbol": "gamma", "status": "GlibcCallThrough" },
    { "symbol": "delta", "status": "WrapsHostLibc" },
    { "symbol": "eta", "status": "Stub" }"#,
            6,
        );
        let report = RealityReport::from_support_matrix_json_str(&json).unwrap();

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.generated_at_utc, "2026-02-11T03:14:20Z");
        assert_eq!(report.total_exported, 6);
        assert_eq!(
            report.counts,
            RealityCounts {
                implemented: 1,
                raw_syscall: 1,
                wraps_host_libc: 1,
                glibc_call_through: 1,
                stub: 2
            }
        );
        assert_eq!(report.stubs, vec!["eta".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn rejects_unknown_status() {
        let json = sample_matrix(
            r#"    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "omega", "status": "Experimental" }"#,
            2,
        );

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("unknown support status"));
        assert!(err.contains("Experimental"));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": 1,
  "symbols": [
    { "status": "Implemented" }
  ]
}"#;

        let err = RealityReport::from_support_matrix_json_str(json).unwrap_err();
        assert!(err.contains("symbol missing symbol name"));
    }

    #[test]
    fn rejects_total_export_mismatch() {
        let json = sample_matrix(r#"    { "symbol": "alpha", "status": "Implemented" }"#, 2);

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("does not match symbols[] length"));
    }

    #[test]
    fn decision_trace_report_flags_missing_explainability() {
        let jsonl = r#"{"timestamp":"2026-02-12T00:00:00Z","trace_id":"bd-33p.2::run::001","level":"error","event":"runtime_decision","decision":"Deny","symbol":"malloc","controller_id":"runtime_math_kernel.v1","decision_action":"Deny"}"#;
        let report = DecisionTraceReport::from_jsonl_str(jsonl);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.decision_events, 1);
        assert_eq!(report.explainable_decision_events, 0);
        assert_eq!(report.missing_explainability, 1);
        assert!(!report.fully_explainable());
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].reason.contains("risk_inputs"));
    }

    #[test]
    fn decision_trace_report_accepts_complete_decision_chain() {
        let jsonl = r#"{"timestamp":"2026-02-12T00:00:00Z","trace_id":"bd-33p.2::run::002","span_id":"abi::malloc::decision::0000000000000001","parent_span_id":"abi::malloc::entry::0000000000000001","level":"info","event":"runtime_decision","symbol":"malloc","decision":"FullValidate","controller_id":"runtime_math_kernel.v1","decision_action":"FullValidate","risk_inputs":{"requested_bytes":128,"bloom_negative":false}}"#;
        let report = DecisionTraceReport::from_jsonl_str(jsonl);
        assert_eq!(report.total_events, 1);
        assert_eq!(report.decision_events, 1);
        assert_eq!(report.explainable_decision_events, 1);
        assert_eq!(report.missing_explainability, 0);
        assert!(report.fully_explainable());
        assert!(report.findings.is_empty());
    }

    fn sample_fixture_set() -> FixtureSet {
        FixtureSet::from_json(
            r#"{
  "version":"v1",
  "family":"string",
  "captured_at":"2026-02-26T00:00:00Z",
  "cases":[
    {
      "name":"normal_strlen",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen",
      "inputs":{"s":"abc"},
      "expected_output":"3",
      "expected_errno":0,
      "mode":"strict"
    },
    {
      "name":"boundary_strlen_size_max",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen boundary",
      "inputs":{"s":"a"},
      "expected_output":"1",
      "expected_errno":0,
      "mode":"hardened"
    },
    {
      "name":"error_strlen_efault",
      "function":"strlen",
      "spec_section":"POSIX.1-2024 strlen errno",
      "inputs":{"s":null},
      "expected_output":"0",
      "expected_errno":14,
      "mode":"both"
    }
  ]
}"#,
        )
        .expect("fixture set should parse")
    }

    fn sample_c_fixture_spec() -> &'static str {
        r#"{
  "schema_version": 1,
  "fixtures": [
    {
      "id": "fixture_pthread",
      "source": "tests/integration/fixture_pthread.c",
      "description": "Concurrent pthread create/join lifecycle fixture",
      "covered_symbols": ["pthread_create"],
      "covered_modules": ["pthread_abi"],
      "spec_traceability": {
        "posix": ["POSIX.1-2017 pthread create/join lifecycle under concurrent execution"]
      },
      "mode_expectations": {
        "strict": {"expected_exit": 0},
        "hardened": {"expected_exit": 0}
      }
    }
  ]
}"#
    }

    fn sample_errno_edge_fixture_sets() -> Vec<FixtureSet> {
        vec![
            FixtureSet::from_json(
                r#"{
  "version":"v1",
  "family":"socket_ops",
  "captured_at":"2026-03-01T00:00:00Z",
  "cases":[
    {
      "name":"error_bind_invalid_fd",
      "function":"bind",
      "spec_section":"POSIX.1-2024 bind error",
      "inputs":{"fd":-1,"addrlen":16},
      "expected_output":"-1",
      "expected_errno":9,
      "mode":"both"
    },
    {
      "name":"boundary_bind_zero_length",
      "function":"bind",
      "spec_section":"POSIX.1-2024 bind boundary",
      "inputs":{"fd":3,"addrlen":0},
      "expected_output":"0",
      "expected_errno":0,
      "mode":"strict"
    }
  ]
}"#,
            )
            .expect("socket errno fixture set should parse"),
            FixtureSet::from_json(
                r#"{
  "version":"v1",
  "family":"pthread_cond",
  "captured_at":"2026-03-01T00:00:00Z",
  "cases":[
    {
      "name":"error_pthread_cond_init_invalid_attr",
      "function":"pthread_cond_init",
      "spec_section":"POSIX.1-2024 pthread_cond_init error",
      "inputs":{"cond":"0x1","attr":"invalid"},
      "expected_output":"-1",
      "expected_errno":22,
      "mode":"strict"
    }
  ]
}"#,
            )
            .expect("pthread errno fixture set should parse"),
        ]
    }

    #[test]
    fn posix_conformance_report_builds_from_inputs() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "total_exported":2,
  "symbols":[
    {"symbol":"strlen","status":"Implemented","module":"string_abi"},
    {"symbol":"malloc","status":"RawSyscall","module":"malloc_abi"}
  ]
}"#;
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "campaign":"test",
  "mode":"both",
  "total_fixture_sets":1,
  "summary":{"total_cases":3,"passed":2,"failed":1,"errors":0,"pass_rate_percent":66.7},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"t1","family":"string","symbol":"strlen","mode":"strict","case_name":"normal_strlen","spec_section":"POSIX","input_hex":"","expected_output":"3","actual_output":"3","host_output":"3","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t2","family":"string","symbol":"strlen","mode":"hardened","case_name":"boundary_strlen_size_max","spec_section":"POSIX","input_hex":"","expected_output":"1","actual_output":"1","host_output":"1","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t3","family":"string","symbol":"strlen","mode":"strict","case_name":"error_strlen_efault","spec_section":"POSIX","input_hex":"","expected_output":"0","actual_output":"-1","host_output":"-1","host_parity":false,"note":null,"status":"fail","passed":false,"error":null,"diff_offset":0}
  ]
}"#;

        let fixture_set = sample_fixture_set();
        let report =
            PosixConformanceReport::from_inputs(support_matrix, &[fixture_set], conformance_matrix)
                .expect("report should build");

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.bead, "bd-18qq.7");
        assert_eq!(report.summary.total_exported, 2);
        assert_eq!(report.summary.eligible_symbols, 2);
        assert_eq!(report.summary.symbols_with_cases, 1);
        assert_eq!(report.summary.symbols_with_all_core_categories, 1);

        let strlen_row = report
            .symbols
            .iter()
            .find(|row| row.symbol == "strlen")
            .expect("strlen row");
        assert!(strlen_row.has_errno_case);
        assert_eq!(
            strlen_row.categories,
            PosixCaseCategoryCounts {
                normal: 1,
                boundary: 1,
                error: 1,
                other: 0
            }
        );
        assert!(strlen_row.execution.has_failures());
        assert!(
            strlen_row
                .quality_flags
                .contains(&"execution_failures_present".to_string())
        );

        let malloc_row = report
            .symbols
            .iter()
            .find(|row| row.symbol == "malloc")
            .expect("malloc row");
        assert_eq!(malloc_row.case_count, 0);
        assert!(
            malloc_row
                .quality_flags
                .contains(&"missing_fixture_cases".to_string())
        );
    }

    #[test]
    fn posix_obligation_matrix_report_builds_rows_and_gaps() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "total_exported":3,
  "symbols":[
    {"symbol":"strlen","status":"Implemented","module":"string_abi"},
    {"symbol":"pthread_create","status":"Implemented","module":"pthread_abi"},
    {"symbol":"malloc","status":"RawSyscall","module":"malloc_abi"}
  ]
}"#;
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "campaign":"test",
  "mode":"both",
  "total_fixture_sets":1,
  "summary":{"total_cases":3,"passed":2,"failed":1,"errors":0,"pass_rate_percent":66.7},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"t1","family":"string","symbol":"strlen","mode":"strict","case_name":"normal_strlen","spec_section":"POSIX","input_hex":"","expected_output":"3","actual_output":"3","host_output":"3","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t2","family":"string","symbol":"strlen","mode":"hardened","case_name":"boundary_strlen_size_max","spec_section":"POSIX","input_hex":"","expected_output":"1","actual_output":"1","host_output":"1","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"t3","family":"string","symbol":"strlen","mode":"strict","case_name":"error_strlen_efault","spec_section":"POSIX","input_hex":"","expected_output":"0","actual_output":"-1","host_output":"-1","host_parity":false,"note":null,"status":"fail","passed":false,"error":null,"diff_offset":0}
  ]
}"#;

        let report = PosixObligationMatrixReport::from_inputs(
            support_matrix,
            &[sample_fixture_set()],
            conformance_matrix,
            sample_c_fixture_spec(),
        )
        .expect("report should build");

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.bead, "bd-2tq.4");
        assert_eq!(report.summary.tracked_symbols, 3);
        assert!(report.summary.total_obligations >= 2);
        assert_eq!(report.summary.symbols_missing_any_mapping, 1);

        let strlen_error = report
            .obligations
            .iter()
            .find(|row| row.symbol == "strlen" && row.posix_ref.contains("errno"))
            .expect("strlen errno obligation");
        assert_eq!(strlen_error.coverage_state, "execution_failures");
        assert!(
            strlen_error
                .obligation_kinds
                .contains(&"error_condition".to_string())
        );
        assert!(
            strlen_error
                .test_refs
                .iter()
                .any(|test_ref| test_ref.contains("error_strlen_efault"))
        );

        let pthread_row = report
            .obligations
            .iter()
            .find(|row| row.symbol == "pthread_create")
            .expect("pthread_create obligation");
        assert_eq!(pthread_row.coverage_state, "mapped_without_execution");
        assert!(
            pthread_row
                .obligation_kinds
                .contains(&"async_concurrency".to_string())
        );
        assert!(
            pthread_row
                .artifact_refs
                .contains(&"tests/integration/fixture_pthread.c".to_string())
        );

        let malloc_gap = report
            .gaps
            .iter()
            .find(|gap| gap.symbol == "malloc")
            .expect("malloc gap");
        assert!(
            malloc_gap
                .gap_reasons
                .contains(&"missing_test_mapping".to_string())
        );

        let pthread_gap = report
            .gaps
            .iter()
            .find(|gap| gap.symbol == "pthread_create")
            .expect("pthread gap");
        assert!(
            pthread_gap
                .gap_reasons
                .contains(&"missing_execution_evidence".to_string())
        );
    }

    #[test]
    fn posix_obligation_matrix_credits_symbol_execution_for_c_fixture_posix_rows() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "total_exported":1,
  "symbols":[
    {"symbol":"cos","status":"Implemented","module":"math_abi"}
  ]
}"#;
        let fixture_set = FixtureSet::from_json(
            r#"{
  "version":"v1",
  "family":"math",
  "captured_at":"2026-02-26T00:00:00Z",
  "cases":[
    {
      "name":"cos_zero",
      "function":"cos",
      "spec_section":"C11 7.12.4.5 cos",
      "inputs":{"x":0.0},
      "expected_output":"1.0",
      "expected_errno":0,
      "mode":"both"
    }
  ]
}"#,
        )
        .expect("fixture set should parse");
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "campaign":"test",
  "mode":"both",
  "total_fixture_sets":1,
  "summary":{"total_cases":2,"passed":2,"failed":0,"errors":0,"pass_rate_percent":100.0},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"cos-strict","family":"math","symbol":"cos","mode":"strict","case_name":"cos_zero [strict]","spec_section":"C11 7.12.4.5 cos","input_hex":"","expected_output":"1.0","actual_output":"1.0","host_output":"1.0","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"cos-hardened","family":"math","symbol":"cos","mode":"hardened","case_name":"cos_zero [hardened]","spec_section":"C11 7.12.4.5 cos","input_hex":"","expected_output":"1.0","actual_output":"1.0","host_output":"1.0","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null}
  ]
}"#;
        let c_fixture_spec = r#"{
  "schema_version":1,
  "fixtures":[
    {
      "id":"fixture_math",
      "source":"tests/integration/fixture_math.c",
      "description":"Floating-point math fixture",
      "covered_symbols":["cos"],
      "covered_modules":["math_abi"],
      "spec_traceability":{
        "posix":["POSIX.1-2017 <math.h>: cos contract"]
      },
      "mode_expectations":{
        "strict":{"expected_exit":0},
        "hardened":{"expected_exit":0}
      }
    }
  ]
}"#;

        let report = PosixObligationMatrixReport::from_inputs(
            support_matrix,
            &[fixture_set],
            conformance_matrix,
            c_fixture_spec,
        )
        .expect("report should build");

        let cos_row = report
            .obligations
            .iter()
            .find(|row| row.symbol == "cos")
            .expect("cos obligation row");
        assert_eq!(cos_row.coverage_state, "covered");
        assert_eq!(cos_row.execution.total, 2);
        assert_eq!(cos_row.execution.pass, 2);
        assert!(
            cos_row
                .test_refs
                .iter()
                .any(|test_ref| test_ref.starts_with("conformance_matrix::cos::"))
        );
        assert!(report.gaps.iter().all(|gap| {
            gap.symbol != "cos"
                || !gap
                    .gap_reasons
                    .contains(&"missing_execution_evidence".to_string())
        }));
    }

    #[test]
    fn posix_obligation_matrix_also_credits_c_fixture_aggregate_when_direct_row_matches() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "total_exported":1,
  "symbols":[
    {"symbol":"isalpha","status":"Implemented","module":"ctype_abi"}
  ]
}"#;
        let fixture_set = FixtureSet::from_json(
            r#"{
  "version":"v1",
  "family":"ctype",
  "captured_at":"2026-02-26T00:00:00Z",
  "cases":[
    {
      "name":"isalpha_letter_A",
      "function":"isalpha",
      "spec_section":"POSIX.1-2017 isalpha",
      "inputs":{"c":65},
      "expected_output":"1",
      "expected_errno":0,
      "mode":"both"
    }
  ]
}"#,
        )
        .expect("fixture set should parse");
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-02-26T00:00:00Z",
  "campaign":"test",
  "mode":"both",
  "total_fixture_sets":1,
  "summary":{"total_cases":2,"passed":2,"failed":0,"errors":0,"pass_rate_percent":100.0},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"isalpha-strict","family":"ctype","symbol":"isalpha","mode":"strict","case_name":"isalpha_letter_A [strict]","spec_section":"POSIX.1-2017 isalpha","input_hex":"","expected_output":"1","actual_output":"1","host_output":"1","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"isalpha-hardened","family":"ctype","symbol":"isalpha","mode":"hardened","case_name":"isalpha_letter_A [hardened]","spec_section":"POSIX.1-2017 isalpha","input_hex":"","expected_output":"1","actual_output":"1","host_output":"1","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null}
  ]
}"#;
        let c_fixture_spec = r#"{
  "schema_version":1,
  "fixtures":[
    {
      "id":"fixture_ctype",
      "source":"tests/integration/fixture_ctype.c",
      "description":"ctype aggregate fixture",
      "covered_symbols":["isalpha"],
      "covered_modules":["ctype_abi"],
      "spec_traceability":{
        "posix":["POSIX.1-2017 <ctype.h>: isalpha/isupper/islower/isdigit/isxdigit/isspace/isprint/ispunct/isalnum and tolower/toupper behavior"]
      },
      "mode_expectations":{
        "strict":{"expected_exit":0},
        "hardened":{"expected_exit":0}
      }
    }
  ]
}"#;

        let report = PosixObligationMatrixReport::from_inputs(
            support_matrix,
            &[fixture_set],
            conformance_matrix,
            c_fixture_spec,
        )
        .expect("report should build");

        let aggregate_row = report
            .obligations
            .iter()
            .find(|row| row.symbol == "isalpha" && row.posix_ref.contains("<ctype.h>"))
            .expect("aggregate ctype obligation row");
        assert_eq!(aggregate_row.coverage_state, "covered");
        assert_eq!(aggregate_row.execution.total, 2);
        assert_eq!(aggregate_row.execution.pass, 2);
        assert!(
            aggregate_row
                .test_refs
                .iter()
                .any(|test_ref| test_ref.starts_with("conformance_matrix::isalpha::"))
        );

        let direct_row = report
            .obligations
            .iter()
            .find(|row| row.symbol == "isalpha" && row.posix_ref == "POSIX.1-2017 isalpha")
            .expect("direct isalpha obligation row");
        assert_eq!(direct_row.coverage_state, "covered");
        assert_eq!(direct_row.execution.total, 2);
    }

    #[test]
    fn errno_edge_case_report_prioritizes_failures_and_parses_errno() {
        let support_matrix = r#"{
  "generated_at_utc":"2026-03-01T00:00:00Z",
  "total_exported":3,
  "symbols":[
    {"symbol":"bind","status":"Implemented","module":"socket_abi"},
    {"symbol":"pthread_cond_init","status":"RawSyscall","module":"pthread_abi"},
    {"symbol":"malloc","status":"Stub","module":"malloc_abi"}
  ]
}"#;
        let conformance_matrix = r#"{
  "schema_version":"v1",
  "bead":"bd-l93x.2",
  "generated_at_utc":"2026-03-01T00:00:00Z",
  "campaign":"errno-edge",
  "mode":"both",
  "total_fixture_sets":2,
  "summary":{"total_cases":4,"passed":1,"failed":1,"errors":2,"pass_rate_percent":25.0},
  "symbol_matrix":[],
  "cases":[
    {"trace_id":"edge-bind-strict","family":"socket_ops","symbol":"bind","mode":"strict","case_name":"error_bind_invalid_fd [strict]","spec_section":"POSIX","input_hex":"","expected_output":"-1","actual_output":"-1 EINVAL","host_output":"-1 EBADF","host_parity":false,"note":null,"status":"fail","passed":false,"error":null,"diff_offset":0},
    {"trace_id":"edge-bind-hardened","family":"socket_ops","symbol":"bind","mode":"hardened","case_name":"error_bind_invalid_fd [hardened]","spec_section":"POSIX","input_hex":"","expected_output":"-1","actual_output":"","host_output":null,"host_parity":null,"note":null,"status":"error","passed":false,"error":"missing sockaddr field for bind","diff_offset":null},
    {"trace_id":"edge-bind-boundary","family":"socket_ops","symbol":"bind","mode":"strict","case_name":"boundary_bind_zero_length","spec_section":"POSIX","input_hex":"","expected_output":"0","actual_output":"0","host_output":"0","host_parity":true,"note":null,"status":"pass","passed":true,"error":null,"diff_offset":null},
    {"trace_id":"edge-pthread","family":"pthread_cond","symbol":"pthread_cond_init","mode":"strict","case_name":"error_pthread_cond_init_invalid_attr","spec_section":"POSIX","input_hex":"","expected_output":"-1","actual_output":"","host_output":null,"host_parity":null,"note":null,"status":"error","passed":false,"error":"unsupported function: pthread_cond_init","diff_offset":null}
  ]
}"#;

        let report = ErrnoEdgeCaseReport::from_inputs(
            support_matrix,
            &sample_errno_edge_fixture_sets(),
            conformance_matrix,
        )
        .expect("errno edge report should build");

        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.bead, "bd-2tq.5");
        assert_eq!(report.summary.tracked_symbols, 2);
        assert_eq!(report.summary.total_edge_cases, 4);
        assert_eq!(report.summary.errno_cases, 3);
        assert_eq!(report.summary.covered_edge_cases, 1);
        assert_eq!(report.summary.failing_edge_cases, 3);
        assert_eq!(report.summary.execution_error_cases, 2);
        assert_eq!(report.summary.missing_execution_cases, 0);
        assert_eq!(report.summary.symbols_with_failures, 2);

        assert_eq!(report.rows[0].trace_id, "edge-bind-hardened");
        assert_eq!(report.rows[0].failure_kind, "input_schema_mismatch");

        let bind_strict = report
            .rows
            .iter()
            .find(|row| row.trace_id == "edge-bind-strict")
            .expect("bind strict row");
        assert_eq!(bind_strict.actual_errno, Some(22));
        assert_eq!(bind_strict.failure_kind, "errno_mismatch");
        assert_eq!(bind_strict.case_id, "error_bind_invalid_fd [strict]");
        assert!(bind_strict.diff_ref.contains("edge-bind-strict"));
        assert!(
            bind_strict
                .triage_steps
                .iter()
                .any(|step| step.contains("errno 9"))
        );
        assert_eq!(
            bind_strict.artifact_refs,
            vec![
                "tests/conformance/fixtures/socket_ops.json".to_string(),
                "tests/conformance/conformance_matrix.v1.json".to_string(),
            ]
        );

        let pthread_row = report
            .rows
            .iter()
            .find(|row| row.trace_id == "edge-pthread")
            .expect("pthread row");
        assert_eq!(pthread_row.support_status, "RawSyscall");
        assert_eq!(pthread_row.failure_kind, "unsupported_function");
        assert_eq!(pthread_row.actual_errno, None);

        let boundary_row = report
            .rows
            .iter()
            .find(|row| row.trace_id == "edge-bind-boundary")
            .expect("boundary row");
        assert_eq!(boundary_row.edge_class, "boundary");
        assert_eq!(boundary_row.status, "pass");
        assert_eq!(boundary_row.failure_kind, "covered");
    }
}
