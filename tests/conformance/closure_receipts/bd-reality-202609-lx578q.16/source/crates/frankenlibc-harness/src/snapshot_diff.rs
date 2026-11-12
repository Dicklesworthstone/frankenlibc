//! Deterministic diff rendering for runtime_math `RuntimeKernelSnapshot` fixtures.
//!
//! Goal: make snapshot drift obvious and reviewable (side-by-side fields + thresholds),
//! and optionally render through FrankentUI for a stable, readable CLI "UI".

use std::collections::{BTreeMap, BTreeSet};

use frankenlibc_membrane::runtime_math::RuntimeKernelSnapshot;
use serde_json::Value;

use crate::kernel_snapshot::{ModeSnapshotV1, RuntimeKernelSnapshotFixtureV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffMode {
    Strict,
    Hardened,
}

impl DiffMode {
    #[must_use]
    pub fn from_str_loose(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "hardened" => Some(Self::Hardened),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Hardened => "hardened",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    Same,
    Changed,
    Alert,
}

#[derive(Debug, Clone)]
pub struct DiffRow {
    pub field: String,
    pub golden: String,
    pub current: String,
    pub delta: Option<f64>,
    pub status: DiffStatus,
}

#[derive(Debug, Clone)]
pub struct SnapshotDiffReport {
    pub mode: DiffMode,
    pub scenario_id: String,
    pub rows: Vec<DiffRow>,
}

const KEY_FIELDS: &[&str] = &[
    "schema_version",
    "decisions",
    "consistency_faults",
    "full_validation_trigger_ppm",
    "repair_trigger_ppm",
    "sampled_risk_bonus_ppm",
    "pareto_cumulative_regret_milli",
    "pareto_cap_enforcements",
    "pareto_exhausted_families",
    "quarantine_depth",
    "tropical_full_wcl_ns",
    "spectral_edge_ratio",
    "spectral_phase_transition",
    "anytime_max_e_value",
    "anytime_alarmed_families",
    "cvar_max_robust_ns",
    "cvar_alarmed_families",
    "bridge_transport_distance",
    "bridge_transitioning",
    "ld_elevated_families",
    "ld_max_anomaly_count",
    "hji_safety_value",
    "hji_breached",
];

pub fn diff_kernel_snapshots(
    golden: &RuntimeKernelSnapshotFixtureV1,
    current: &RuntimeKernelSnapshotFixtureV1,
    mode: DiffMode,
    all_fields: bool,
) -> Result<SnapshotDiffReport, String> {
    let golden_snap = snapshot_for_mode(golden, mode)
        .ok_or_else(|| format!("golden fixture missing mode {}", mode.as_str()))?;
    let current_snap = snapshot_for_mode(current, mode)
        .ok_or_else(|| format!("current fixture missing mode {}", mode.as_str()))?;

    let golden_map = snapshot_field_map(&golden_snap.snapshot);
    let current_map = snapshot_field_map(&current_snap.snapshot);

    let fields: Vec<String> = if all_fields {
        let mut all = BTreeSet::<String>::new();
        all.extend(golden_map.keys().cloned());
        all.extend(current_map.keys().cloned());
        all.into_iter().collect()
    } else {
        KEY_FIELDS.iter().map(|s| (*s).to_string()).collect()
    };

    let mut rows = Vec::new();
    for field in fields {
        let g = golden_map
            .get(&field)
            .cloned()
            .unwrap_or_else(|| String::from("<missing>"));
        let c = current_map
            .get(&field)
            .cloned()
            .unwrap_or_else(|| String::from("<missing>"));

        let (delta, status) = classify_delta(&field, &g, &c);
        rows.push(DiffRow {
            field,
            golden: g,
            current: c,
            delta,
            status,
        });
    }

    Ok(SnapshotDiffReport {
        mode,
        scenario_id: golden.scenario.id.clone(),
        rows,
    })
}

fn snapshot_for_mode(
    fixture: &RuntimeKernelSnapshotFixtureV1,
    mode: DiffMode,
) -> Option<&ModeSnapshotV1> {
    match mode {
        DiffMode::Strict => fixture.strict.as_ref(),
        DiffMode::Hardened => fixture.hardened.as_ref(),
    }
}

fn snapshot_field_map(snapshot: &RuntimeKernelSnapshot) -> BTreeMap<String, String> {
    let encoded = serde_json::to_value(snapshot).expect("RuntimeKernelSnapshot must serialize");
    let object = encoded
        .as_object()
        .expect("RuntimeKernelSnapshot must serialize as a JSON object");

    let mut out = BTreeMap::new();
    for (field, value) in object {
        out.insert(field.clone(), render_value(value));
    }
    out
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Null => String::from("null"),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).expect("snapshot value must serialize")
        }
    }
}

fn classify_delta(field: &str, golden: &str, current: &str) -> (Option<f64>, DiffStatus) {
    if golden == current {
        return (None, DiffStatus::Same);
    }

    let g = parse_number(golden);
    let c = parse_number(current);
    let delta = g.zip(c).map(|(g, c)| c - g);

    let Some(delta) = delta else {
        return (None, DiffStatus::Changed);
    };

    let threshold = threshold_for(field);
    if threshold.is_some_and(|t| delta.abs() >= t) {
        return (Some(delta), DiffStatus::Alert);
    }

    (Some(delta), DiffStatus::Changed)
}

fn parse_number(raw: &str) -> Option<f64> {
    let s = raw.trim().trim_end_matches(',');
    if s == "true" {
        return Some(1.0);
    }
    if s == "false" {
        return Some(0.0);
    }
    s.parse::<f64>().ok()
}

fn threshold_for(field: &str) -> Option<f64> {
    // Heuristic thresholds for "highlight beyond" in the UI.
    //
    // These are intentionally conservative; they are not a hard gate.
    match field {
        "full_validation_trigger_ppm" | "repair_trigger_ppm" | "sampled_risk_bonus_ppm" => {
            Some(10_000.0)
        }
        "pareto_cumulative_regret_milli" => Some(1_000.0),
        "quarantine_depth" => Some(64.0),
        "tropical_full_wcl_ns" => Some(10.0),
        "spectral_edge_ratio" => Some(0.25),
        "anytime_max_e_value" => Some(1.0),
        "bridge_transport_distance" => Some(0.5),
        "hji_safety_value" => Some(0.5),
        _ => None,
    }
}

#[must_use]
pub fn render_plain(report: &SnapshotDiffReport) -> String {
    let mut out = String::new();
    use std::fmt::Write as _;

    let w_field: usize = 32;
    let w_val: usize = 22;
    let w_delta: usize = 14;
    let w_status: usize = 8;

    writeln!(
        out,
        "runtime_math snapshot diff (mode={}, scenario={})",
        report.mode.as_str(),
        report.scenario_id
    )
    .ok();

    writeln!(
        out,
        "{:<w_field$} {:<w_val$} {:<w_val$} {:<w_delta$} {:<w_status$}",
        "field", "golden", "current", "delta", "status",
    )
    .ok();

    writeln!(
        out,
        "{}",
        "-".repeat(w_field + w_val + w_val + w_delta + w_status + 4)
    )
    .ok();

    for row in &report.rows {
        let delta = row
            .delta
            .map(|d| format!("{d:+.6}"))
            .unwrap_or_else(String::new);
        let status = match row.status {
            DiffStatus::Same => "OK",
            DiffStatus::Changed => "CHG",
            DiffStatus::Alert => "ALERT",
        };

        writeln!(
            out,
            "{:<w_field$} {:<w_val$} {:<w_val$} {:<w_delta$} {:<w_status$}",
            truncate(&row.field, w_field),
            truncate(&row.golden, w_val),
            truncate(&row.current, w_val),
            truncate(&delta, w_delta),
            status,
        )
        .ok();
    }

    out
}

fn truncate(s: &str, width: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    if width <= 3 {
        return s[..width].to_string();
    }
    format!("{}...", &s[..(width - 3)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenlibc_membrane::{RuntimeMathKernel, SafetyLevel};

    fn fixture_with_snapshot(snapshot: RuntimeKernelSnapshot) -> RuntimeKernelSnapshotFixtureV1 {
        RuntimeKernelSnapshotFixtureV1 {
            version: String::from("v1"),
            scenario: crate::kernel_snapshot::KernelSnapshotScenarioV1 {
                id: String::from("snapshot-diff-test"),
                seed: 0,
                steps: 1,
                families: vec![String::from("allocator")],
            },
            strict: Some(ModeSnapshotV1 {
                mode: String::from("strict"),
                snapshot,
            }),
            hardened: None,
        }
    }

    #[test]
    fn snapshot_field_map_preserves_scalar_and_array_values() {
        let kernel = RuntimeMathKernel::new();
        let snapshot = kernel.snapshot(SafetyLevel::Strict);
        let fields = snapshot_field_map(&snapshot);

        assert_eq!(
            fields.get("schema_version"),
            Some(&snapshot.schema_version.to_string())
        );
        assert_eq!(
            fields.get("policy_action_dist"),
            Some(&serde_json::to_string(&snapshot.policy_action_dist).expect("array serializes"))
        );
    }

    #[test]
    fn diff_kernel_snapshots_uses_structured_snapshot_payloads() {
        let kernel = RuntimeMathKernel::new();
        let golden_snapshot = kernel.snapshot(SafetyLevel::Strict);
        let mut current_snapshot = golden_snapshot;
        current_snapshot.full_validation_trigger_ppm += 25_000;

        let golden = fixture_with_snapshot(golden_snapshot);
        let current = fixture_with_snapshot(current_snapshot);
        let report =
            diff_kernel_snapshots(&golden, &current, DiffMode::Strict, false).expect("diff works");

        let row = report
            .rows
            .iter()
            .find(|row| row.field == "full_validation_trigger_ppm")
            .expect("key field should be present");
        assert_eq!(row.status, DiffStatus::Alert);
        assert_eq!(row.delta, Some(25_000.0));
    }
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn render_ftui_buffer(report: &SnapshotDiffReport, width: u16) -> ftui_render::buffer::Buffer {
    use ftui_core::geometry::Rect;
    use ftui_layout::Constraint;
    use ftui_render::cell::PackedRgba;
    use ftui_render::frame::Frame;
    use ftui_render::grapheme_pool::GraphemePool;
    use ftui_style::Style;
    use ftui_widgets::Widget;
    use ftui_widgets::block::Block;
    use ftui_widgets::borders::{BorderType, Borders};
    use ftui_widgets::table::{Row, Table};

    let height = (report.rows.len() as u16).saturating_add(4);
    let mut pool = GraphemePool::new();
    let mut frame = Frame::new(width, height, &mut pool);

    let header =
        Row::new(["field", "golden", "current", "delta", "status"]).style(Style::new().bold());

    let rows: Vec<Row> = report
        .rows
        .iter()
        .map(|row| {
            let delta = row.delta.map(|d| format!("{d:+.6}")).unwrap_or_default();
            let status = match row.status {
                DiffStatus::Same => "OK",
                DiffStatus::Changed => "CHG",
                DiffStatus::Alert => "ALERT",
            };

            let style = match row.status {
                DiffStatus::Same => Style::new(),
                DiffStatus::Changed => Style::new().fg(PackedRgba::rgb(255, 255, 0)),
                DiffStatus::Alert => Style::new().fg(PackedRgba::RED).bold(),
            };

            Row::new([
                row.field.as_str(),
                row.golden.as_str(),
                row.current.as_str(),
                delta.as_str(),
                status,
            ])
            .style(style)
        })
        .collect();

    let block_title = format!(
        " runtime_math snapshot diff (mode={}, scenario={}) ",
        report.mode.as_str(),
        report.scenario_id
    );
    let table = Table::new(
        rows,
        [
            Constraint::Fixed(30),
            Constraint::Fixed(22),
            Constraint::Fixed(22),
            Constraint::Fixed(14),
            Constraint::Fixed(10),
        ],
    )
    .header(header)
    .block(
        Block::new()
            .title(&block_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    )
    .column_spacing(1);

    let area = Rect::from_size(width, height);
    table.render(area, &mut frame);
    frame.buffer
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn render_ftui(report: &SnapshotDiffReport, ansi: bool, width: u16) -> String {
    let buffer = render_ftui_buffer(report, width);
    if ansi {
        ftui_harness::buffer_to_ansi(&buffer)
    } else {
        ftui_harness::buffer_to_text(&buffer)
    }
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn compute_ftui_snapshot_checksum(report: &SnapshotDiffReport, width: u16) -> String {
    let buffer = render_ftui_buffer(report, width);
    ftui_harness::golden::compute_buffer_checksum(&buffer)
}

#[cfg(feature = "frankentui-ui")]
#[must_use]
pub fn compare_ftui_snapshots(
    frame_id: u32,
    expected: &SnapshotDiffReport,
    actual: &SnapshotDiffReport,
    width: u16,
) -> ftui_harness::frame_comparison::ComparisonResult {
    let expected_buf = render_ftui_buffer(expected, width);
    let actual_buf = render_ftui_buffer(actual, width);
    ftui_harness::frame_comparison::FrameComparator::new().compare_buffers(
        frame_id,
        &expected_buf,
        &actual_buf,
    )
}
