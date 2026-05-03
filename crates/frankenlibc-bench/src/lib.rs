//! Benchmark support for FrankenLibC.
//!
//! Individual Criterion entrypoints live in `benches/`. This library keeps
//! the benchmark artifact/report plumbing testable from ordinary unit tests.

use std::collections::BTreeMap;
use std::fs::{File, create_dir_all};
use std::io::{self, Write};
use std::path::Path;

pub const METADATA_BENCH_SCHEMA_VERSION: &str = "v1";
pub const METADATA_BENCH_BEAD_ID: &str = "bd-3aof.3";
pub const GLIBC_BASELINE_SCHEMA_VERSION: &str = "v1";
pub const GLIBC_BASELINE_BEAD_ID: &str = "bd-bp8fl.8.3";

/// Concrete implementation under comparison for metadata-read benchmarks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetadataImplementation {
    Rcu,
    Mutex,
}

impl MetadataImplementation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rcu => "rcu",
            Self::Mutex => "mutex",
        }
    }
}

/// Metadata workload family exercised by the RCU-vs-mutex benchmark matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MetadataOperation {
    ThreadMetadata,
    SizeClassLookup,
    TlsCacheLookup,
}

impl MetadataOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ThreadMetadata => "thread_metadata",
            Self::SizeClassLookup => "size_class_lookup",
            Self::TlsCacheLookup => "tls_cache_lookup",
        }
    }
}

/// One measured configuration from the metadata benchmark matrix.
#[derive(Debug, Clone)]
pub struct MetadataBenchRecord {
    pub implementation: MetadataImplementation,
    pub operation: MetadataOperation,
    pub read_ratio_pct: u8,
    pub thread_count: usize,
    pub total_ops: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub throughput_ops_s: f64,
    pub p50_ns_op: f64,
    pub p95_ns_op: f64,
    pub p99_ns_op: f64,
    pub cv_pct: f64,
    pub sample_count: usize,
}

/// Break-even point for one operation/thread-count slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataBreakEven {
    pub operation: MetadataOperation,
    pub thread_count: usize,
    pub break_even_read_ratio_pct: Option<u8>,
}

/// Percentile helper for a sorted sample set.
#[must_use]
pub fn percentile_sorted(samples: &[u64], percentile: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&percentile));
    if samples.is_empty() {
        return 0.0;
    }
    let idx = ((samples.len() - 1) as f64 * percentile).round() as usize;
    samples[idx.min(samples.len() - 1)] as f64
}

/// Coefficient of variation in percent for the provided samples.
#[must_use]
pub fn coefficient_of_variation_pct(samples: &[u64]) -> f64 {
    if samples.len() <= 1 {
        return 0.0;
    }
    let mean = samples.iter().map(|&value| value as f64).sum::<f64>() / samples.len() as f64;
    if mean <= f64::EPSILON {
        return 0.0;
    }
    let variance = samples
        .iter()
        .map(|&value| {
            let delta = value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    variance.sqrt() / mean * 100.0
}

/// Summarize latency samples into p50/p95/p99/CV.
#[must_use]
pub fn summarize_latency_samples(samples: &[u64]) -> (f64, f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    (
        percentile_sorted(&sorted, 0.50),
        percentile_sorted(&sorted, 0.95),
        percentile_sorted(&sorted, 0.99),
        coefficient_of_variation_pct(&sorted),
    )
}

/// Build the read-ratio threshold where RCU first beats mutex throughput.
#[must_use]
pub fn build_break_even_summary(records: &[MetadataBenchRecord]) -> Vec<MetadataBreakEven> {
    let mut grouped =
        BTreeMap::<(MetadataOperation, usize), BTreeMap<u8, (Option<f64>, Option<f64>)>>::new();

    for record in records {
        let entry = grouped
            .entry((record.operation, record.thread_count))
            .or_default()
            .entry(record.read_ratio_pct)
            .or_default();

        match record.implementation {
            MetadataImplementation::Rcu => entry.0 = Some(record.throughput_ops_s),
            MetadataImplementation::Mutex => entry.1 = Some(record.throughput_ops_s),
        }
    }

    grouped
        .into_iter()
        .map(|((operation, thread_count), ratios)| {
            let break_even_read_ratio_pct =
                ratios
                    .into_iter()
                    .find_map(|(read_ratio_pct, pair)| match pair {
                        (Some(rcu), Some(mutex)) if rcu >= mutex => Some(read_ratio_pct),
                        _ => None,
                    });

            MetadataBreakEven {
                operation,
                thread_count,
                break_even_read_ratio_pct,
            }
        })
        .collect()
}

#[must_use]
pub fn metadata_bench_json(
    records: &[MetadataBenchRecord],
    break_even: &[MetadataBreakEven],
) -> String {
    let mut body = format!(
        "{{\n  \"schema_version\": \"{}\",\n  \"bead_id\": \"{}\",\n  \"record_count\": {},\n  \"break_even_count\": {},\n  \"records\": [\n",
        METADATA_BENCH_SCHEMA_VERSION,
        METADATA_BENCH_BEAD_ID,
        records.len(),
        break_even.len()
    );
    for (idx, record) in records.iter().enumerate() {
        let comma = if idx + 1 == records.len() { "" } else { "," };
        body.push_str(&format!(
            "    {{\"implementation\":\"{}\",\"operation\":\"{}\",\"read_ratio_pct\":{},\"thread_count\":{},\"total_ops\":{},\"read_ops\":{},\"write_ops\":{},\"throughput_ops_s\":{:.3},\"p50_ns_op\":{:.3},\"p95_ns_op\":{:.3},\"p99_ns_op\":{:.3},\"cv_pct\":{:.3},\"sample_count\":{}}}{}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.total_ops,
            record.read_ops,
            record.write_ops,
            record.throughput_ops_s,
            record.p50_ns_op,
            record.p95_ns_op,
            record.p99_ns_op,
            record.cv_pct,
            record.sample_count,
            comma
        ));
    }
    body.push_str("  ],\n  \"break_even\": [\n");
    for (idx, summary) in break_even.iter().enumerate() {
        let comma = if idx + 1 == break_even.len() { "" } else { "," };
        let threshold = summary
            .break_even_read_ratio_pct
            .map_or(String::from("null"), |value| value.to_string());
        body.push_str(&format!(
            "    {{\"operation\":\"{}\",\"thread_count\":{},\"break_even_read_ratio_pct\":{}}}{}\n",
            summary.operation.as_str(),
            summary.thread_count,
            threshold,
            comma
        ));
    }
    body.push_str("  ]\n}\n");
    body
}

#[must_use]
pub fn throughput_dat(records: &[MetadataBenchRecord]) -> String {
    let mut body =
        String::from("# impl operation read_ratio_pct thread_count throughput_ops_s total_ops\n");
    for record in records {
        body.push_str(&format!(
            "{} {} {} {} {:.3} {}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.throughput_ops_s,
            record.total_ops
        ));
    }
    body
}

#[must_use]
pub fn latency_dat(records: &[MetadataBenchRecord]) -> String {
    let mut body = String::from(
        "# impl operation read_ratio_pct thread_count p50_ns p95_ns p99_ns cv_pct sample_count\n",
    );
    for record in records {
        body.push_str(&format!(
            "{} {} {} {} {:.3} {:.3} {:.3} {:.3} {}\n",
            record.implementation.as_str(),
            record.operation.as_str(),
            record.read_ratio_pct,
            record.thread_count,
            record.p50_ns_op,
            record.p95_ns_op,
            record.p99_ns_op,
            record.cv_pct,
            record.sample_count
        ));
    }
    body
}

#[must_use]
pub fn break_even_dat(summary: &[MetadataBreakEven]) -> String {
    let mut body = String::from("# operation thread_count break_even_read_ratio_pct\n");
    for record in summary {
        let threshold = record.break_even_read_ratio_pct.unwrap_or(0);
        body.push_str(&format!(
            "{} {} {}\n",
            record.operation.as_str(),
            record.thread_count,
            threshold
        ));
    }
    body
}

fn svg_shell(title: &str, subtitle: &str, rows: &[String]) -> String {
    let height = 140 + rows.len().saturating_mul(22);
    let mut body = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1280\" height=\"{height}\" viewBox=\"0 0 1280 {height}\">\n\
<rect width=\"1280\" height=\"{height}\" fill=\"#f8fafc\"/>\n\
<text x=\"32\" y=\"40\" font-family=\"monospace\" font-size=\"26\" fill=\"#0f172a\">{title}</text>\n\
<text x=\"32\" y=\"68\" font-family=\"monospace\" font-size=\"14\" fill=\"#334155\">{subtitle}</text>\n"
    );

    for (idx, row) in rows.iter().enumerate() {
        let y = 102 + idx * 22;
        body.push_str(&format!(
            "<text x=\"32\" y=\"{y}\" font-family=\"monospace\" font-size=\"13\" fill=\"#1e293b\">{row}</text>\n"
        ));
    }
    body.push_str("</svg>\n");
    body
}

#[must_use]
pub fn throughput_svg(records: &[MetadataBenchRecord]) -> String {
    let rows = records
        .iter()
        .map(|record| {
            format!(
                "{} {} ratio={} threads={} ops/s={:.3}",
                record.implementation.as_str(),
                record.operation.as_str(),
                record.read_ratio_pct,
                record.thread_count,
                record.throughput_ops_s
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU vs Mutex Metadata Throughput",
        "One row per implementation/operation/read-ratio/thread-count sample.",
        &rows,
    )
}

#[must_use]
pub fn latency_svg(records: &[MetadataBenchRecord]) -> String {
    let rows = records
        .iter()
        .map(|record| {
            format!(
                "{} {} ratio={} threads={} p50={:.3}ns p95={:.3}ns p99={:.3}ns cv={:.3}%",
                record.implementation.as_str(),
                record.operation.as_str(),
                record.read_ratio_pct,
                record.thread_count,
                record.p50_ns_op,
                record.p95_ns_op,
                record.p99_ns_op,
                record.cv_pct
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU vs Mutex Metadata Latency Percentiles",
        "Per-configuration latency summary used by the artifact gate.",
        &rows,
    )
}

#[must_use]
pub fn break_even_svg(summary: &[MetadataBreakEven]) -> String {
    let rows = summary
        .iter()
        .map(|record| {
            format!(
                "{} threads={} break_even_read_ratio={}",
                record.operation.as_str(),
                record.thread_count,
                record
                    .break_even_read_ratio_pct
                    .map_or(String::from("none"), |ratio| format!("{ratio}%"))
            )
        })
        .collect::<Vec<_>>();
    svg_shell(
        "RCU Break-even Read Ratio by Thread Count",
        "Lowest read ratio where RCU throughput meets or beats mutex throughput.",
        &rows,
    )
}

#[must_use]
pub fn throughput_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "throughput_vs_threads.svg"
set title "RCU vs Mutex Metadata Throughput"
set xlabel "Threads"
set ylabel "Ops/s"
set key left top
set grid
plot "throughput_vs_threads.dat" using 4:5 with linespoints title "all configurations"
"#
}

#[must_use]
pub fn latency_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "latency_percentiles.svg"
set title "RCU vs Mutex Metadata Latency Percentiles"
set xlabel "Threads"
set ylabel "ns/op"
set key left top
set grid
plot \
  "latency_percentiles.dat" using 4:5 with linespoints title "p50", \
  "latency_percentiles.dat" using 4:6 with linespoints title "p95", \
  "latency_percentiles.dat" using 4:7 with linespoints title "p99"
"#
}

#[must_use]
pub fn break_even_gnuplot_script() -> &'static str {
    r#"set terminal svg size 1280,720 dynamic enhanced
set output "break_even_ratio.svg"
set title "RCU Break-even Read Ratio by Thread Count"
set xlabel "Threads"
set ylabel "Read ratio (%)"
set yrange [0:100]
set key left top
set grid
plot "break_even.dat" using 2:3 with linespoints title "break-even read ratio"
"#
}

/// Write the full metadata benchmark artifact bundle into `out_dir`.
pub fn write_metadata_bench_artifacts(
    records: &[MetadataBenchRecord],
    out_dir: &Path,
) -> io::Result<Vec<MetadataBreakEven>> {
    create_dir_all(out_dir)?;
    let break_even = build_break_even_summary(records);

    write_file(
        &out_dir.join("metadata_benchmark_report.v1.json"),
        &metadata_bench_json(records, &break_even),
    )?;
    write_file(
        &out_dir.join("throughput_vs_threads.dat"),
        &throughput_dat(records),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.dat"),
        &latency_dat(records),
    )?;
    write_file(
        &out_dir.join("break_even.dat"),
        &break_even_dat(&break_even),
    )?;
    write_file(
        &out_dir.join("throughput_vs_threads.gp"),
        throughput_gnuplot_script(),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.gp"),
        latency_gnuplot_script(),
    )?;
    write_file(&out_dir.join("break_even.gp"), break_even_gnuplot_script())?;
    write_file(
        &out_dir.join("throughput_vs_threads.svg"),
        &throughput_svg(records),
    )?;
    write_file(
        &out_dir.join("latency_percentiles.svg"),
        &latency_svg(records),
    )?;
    write_file(
        &out_dir.join("break_even_ratio.svg"),
        &break_even_svg(&break_even),
    )?;

    Ok(break_even)
}

fn write_file(path: &Path, body: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(body.as_bytes())
}

/// One profile row comparing a FrankenLibC hot path with an explicit host glibc baseline.
#[derive(Debug, Clone, PartialEq)]
pub struct GlibcBaselineRecord {
    pub profile_id: String,
    pub api_family: String,
    pub symbol: String,
    pub workload: String,
    pub runtime_mode: String,
    pub replacement_level: String,
    pub profile_tool: String,
    pub sample_count: usize,
    pub frankenlibc_ns_op: f64,
    pub host_glibc_ns_op: f64,
    pub hotness_score: f64,
    pub baseline_artifact: String,
    pub parity_proof_ref: String,
    pub source_commit: String,
    pub target_dir: String,
    pub generated_at_unix: u64,
}

/// Validate that a committed glibc-baseline report is current enough to support claims.
///
/// The caller supplies the expected source commit and the oldest acceptable
/// generation timestamp, so tests and gates can reject stale copied reports.
pub fn validate_glibc_baseline_records(
    records: &[GlibcBaselineRecord],
    expected_source_commit: &str,
    min_generated_at_unix: u64,
) -> Result<(), String> {
    if records.is_empty() {
        return Err(String::from("profile record set is empty"));
    }

    for record in records {
        if record.source_commit != expected_source_commit {
            return Err(format!(
                "{} source_commit mismatch: expected {}, actual {}",
                record.profile_id, expected_source_commit, record.source_commit
            ));
        }
        if record.generated_at_unix < min_generated_at_unix {
            return Err(format!("{} profile is stale", record.profile_id));
        }
        if record.parity_proof_ref.trim().is_empty() {
            return Err(format!("{} missing parity_proof_ref", record.profile_id));
        }
        if record.baseline_artifact.trim().is_empty() {
            return Err(format!("{} missing baseline_artifact", record.profile_id));
        }
        if record.sample_count == 0 {
            return Err(format!("{} has zero samples", record.profile_id));
        }
        if !record.hotness_score.is_finite()
            || !record.frankenlibc_ns_op.is_finite()
            || !record.host_glibc_ns_op.is_finite()
        {
            return Err(format!("{} contains non-finite metric", record.profile_id));
        }
    }

    Ok(())
}

/// Rank profile records by optimization priority, with stable tie-breaks for reproducibility.
#[must_use]
pub fn rank_glibc_baseline_records(records: &[GlibcBaselineRecord]) -> Vec<GlibcBaselineRecord> {
    let mut ranked = records.to_vec();
    ranked.sort_by(|left, right| {
        right
            .hotness_score
            .partial_cmp(&left.hotness_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.api_family.cmp(&right.api_family))
            .then_with(|| left.symbol.cmp(&right.symbol))
            .then_with(|| left.profile_id.cmp(&right.profile_id))
    });
    ranked
}

#[must_use]
pub fn glibc_baseline_markdown(records: &[GlibcBaselineRecord]) -> String {
    let ranked = rank_glibc_baseline_records(records);
    let mut body = format!(
        "# Host glibc baseline profile\n\nSchema: `{}`  \nBead: `{}`\n\n",
        GLIBC_BASELINE_SCHEMA_VERSION, GLIBC_BASELINE_BEAD_ID
    );
    body.push_str("| Rank | Profile | API family | Symbol | Workload | FL ns/op | glibc ns/op | Ratio | Hotness | Samples | Parity proof |\n");
    body.push_str("|---:|---|---|---|---|---:|---:|---:|---:|---:|---|\n");
    for (idx, record) in ranked.iter().enumerate() {
        let ratio = if record.host_glibc_ns_op <= f64::EPSILON {
            0.0
        } else {
            record.frankenlibc_ns_op / record.host_glibc_ns_op
        };
        body.push_str(&format!(
            "| {} | `{}` | `{}` | `{}` | {} | {:.3} | {:.3} | {:.2}x | {:.3} | {} | {} |\n",
            idx + 1,
            record.profile_id,
            record.api_family,
            record.symbol,
            record.workload,
            record.frankenlibc_ns_op,
            record.host_glibc_ns_op,
            ratio,
            record.hotness_score,
            record.sample_count,
            record.parity_proof_ref
        ));
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Vec<MetadataBenchRecord> {
        vec![
            MetadataBenchRecord {
                implementation: MetadataImplementation::Rcu,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 50,
                thread_count: 8,
                total_ops: 100,
                read_ops: 50,
                write_ops: 50,
                throughput_ops_s: 1200.0,
                p50_ns_op: 10.0,
                p95_ns_op: 20.0,
                p99_ns_op: 30.0,
                cv_pct: 1.0,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Mutex,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 50,
                thread_count: 8,
                total_ops: 100,
                read_ops: 50,
                write_ops: 50,
                throughput_ops_s: 1100.0,
                p50_ns_op: 11.0,
                p95_ns_op: 21.0,
                p99_ns_op: 31.0,
                cv_pct: 2.0,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Rcu,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 90,
                thread_count: 8,
                total_ops: 100,
                read_ops: 90,
                write_ops: 10,
                throughput_ops_s: 1500.0,
                p50_ns_op: 8.0,
                p95_ns_op: 16.0,
                p99_ns_op: 24.0,
                cv_pct: 1.5,
                sample_count: 16,
            },
            MetadataBenchRecord {
                implementation: MetadataImplementation::Mutex,
                operation: MetadataOperation::ThreadMetadata,
                read_ratio_pct: 90,
                thread_count: 8,
                total_ops: 100,
                read_ops: 90,
                write_ops: 10,
                throughput_ops_s: 1400.0,
                p50_ns_op: 9.0,
                p95_ns_op: 17.0,
                p99_ns_op: 25.0,
                cv_pct: 2.5,
                sample_count: 16,
            },
        ]
    }

    #[test]
    fn summarize_latency_samples_reports_percentiles_and_cv() {
        let (p50, p95, p99, cv) = summarize_latency_samples(&[10, 20, 30, 40, 50]);
        assert_eq!(p50, 30.0);
        assert_eq!(p95, 50.0);
        assert_eq!(p99, 50.0);
        assert!(cv > 0.0);
    }

    #[test]
    fn break_even_summary_prefers_lowest_ratio_that_wins() {
        let summary = build_break_even_summary(&sample_records());
        assert_eq!(
            summary,
            vec![MetadataBreakEven {
                operation: MetadataOperation::ThreadMetadata,
                thread_count: 8,
                break_even_read_ratio_pct: Some(50),
            }]
        );
    }

    #[test]
    fn json_and_plot_scripts_reference_expected_sections() {
        let summary = build_break_even_summary(&sample_records());
        let json = metadata_bench_json(&sample_records(), &summary);
        assert!(json.contains(METADATA_BENCH_SCHEMA_VERSION));
        assert!(json.contains(METADATA_BENCH_BEAD_ID));
        assert!(json.contains("\"records\""));
        assert!(json.contains("\"break_even\""));
        assert!(throughput_svg(&sample_records()).contains("<svg"));
        assert!(latency_svg(&sample_records()).contains("<svg"));
        assert!(break_even_svg(&summary).contains("<svg"));
        assert!(throughput_gnuplot_script().contains("set terminal svg"));
        assert!(latency_gnuplot_script().contains("latency_percentiles.svg"));
        assert!(break_even_gnuplot_script().contains("break_even_ratio.svg"));
    }

    fn sample_glibc_records() -> Vec<GlibcBaselineRecord> {
        vec![
            GlibcBaselineRecord {
                profile_id: String::from("strlen_4096"),
                api_family: String::from("string"),
                symbol: String::from("strlen"),
                workload: String::from("4096 byte nul-terminated scan"),
                runtime_mode: String::from("strict"),
                replacement_level: String::from("L0"),
                profile_tool: String::from("criterion"),
                sample_count: 12,
                frankenlibc_ns_op: 120.0,
                host_glibc_ns_op: 24.0,
                hotness_score: 5.0,
                baseline_artifact: String::from("artifacts/perf/glibc-baseline.md"),
                parity_proof_ref: String::from("tests/conformance/fixtures/string_ops"),
                source_commit: String::from("abc123"),
                target_dir: String::from("/tmp/target"),
                generated_at_unix: 1_777_000_000,
            },
            GlibcBaselineRecord {
                profile_id: String::from("memcpy_4096"),
                api_family: String::from("string"),
                symbol: String::from("memcpy"),
                workload: String::from("4096 byte copy"),
                runtime_mode: String::from("strict"),
                replacement_level: String::from("L0"),
                profile_tool: String::from("criterion"),
                sample_count: 12,
                frankenlibc_ns_op: 48.0,
                host_glibc_ns_op: 24.0,
                hotness_score: 2.0,
                baseline_artifact: String::from("artifacts/perf/glibc-baseline.md"),
                parity_proof_ref: String::from("tests/conformance/fixtures/string_memory_full"),
                source_commit: String::from("abc123"),
                target_dir: String::from("/tmp/target"),
                generated_at_unix: 1_777_000_000,
            },
        ]
    }

    #[test]
    fn glibc_baseline_ranking_is_deterministic() {
        let ranked = rank_glibc_baseline_records(&sample_glibc_records());
        assert_eq!(ranked[0].profile_id, "strlen_4096");
        assert_eq!(ranked[1].profile_id, "memcpy_4096");
    }

    #[test]
    fn glibc_baseline_validation_rejects_stale_source_commit() {
        let err = validate_glibc_baseline_records(&sample_glibc_records(), "def456", 1)
            .expect_err("source commit mismatch should be rejected");
        assert!(err.contains("source_commit mismatch"));
    }

    #[test]
    fn glibc_baseline_validation_requires_parity_proof() {
        let mut records = sample_glibc_records();
        records[0].parity_proof_ref.clear();
        let err = validate_glibc_baseline_records(&records, "abc123", 1)
            .expect_err("missing parity proof should be rejected");
        assert!(err.contains("missing parity_proof_ref"));
    }

    #[test]
    fn glibc_baseline_markdown_contains_required_columns() {
        let report = glibc_baseline_markdown(&sample_glibc_records());
        assert!(report.contains(GLIBC_BASELINE_BEAD_ID));
        assert!(report.contains("| Rank | Profile | API family | Symbol |"));
        assert!(report.contains("`strlen_4096`"));
        assert!(report.contains("tests/conformance/fixtures/string_ops"));
    }
}
