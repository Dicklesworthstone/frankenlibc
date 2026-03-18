//! Atomic counters for membrane observability.
//!
//! All counters use relaxed ordering — they are advisory/diagnostic,
//! not synchronization primitives.

use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, TraceId};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global membrane operation counters.
pub struct MembraneMetrics {
    /// Total pointer validations performed.
    pub validations: AtomicU64,
    /// Validations resolved from TLS cache (fast path).
    pub tls_cache_hits: AtomicU64,
    /// TLS cache misses requiring full pipeline.
    pub tls_cache_misses: AtomicU64,
    /// Bloom filter true positives (pointer is ours).
    pub bloom_hits: AtomicU64,
    /// Bloom filter negatives (pointer is not ours).
    pub bloom_misses: AtomicU64,
    /// Successful arena lookups.
    pub arena_lookups: AtomicU64,
    /// Fingerprint validation passes.
    pub fingerprint_passes: AtomicU64,
    /// Fingerprint validation failures (corruption detected).
    pub fingerprint_failures: AtomicU64,
    /// Canary check passes.
    pub canary_passes: AtomicU64,
    /// Canary check failures (buffer overflow detected).
    pub canary_failures: AtomicU64,
    /// Total healing actions applied.
    pub heals: AtomicU64,
    /// Double-free attempts silently ignored.
    pub double_frees_healed: AtomicU64,
    /// Foreign-free attempts silently ignored.
    pub foreign_frees_healed: AtomicU64,
    /// Size clamps applied.
    pub size_clamps: AtomicU64,
}

impl MembraneMetrics {
    /// Create a new zeroed metrics instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            validations: AtomicU64::new(0),
            tls_cache_hits: AtomicU64::new(0),
            tls_cache_misses: AtomicU64::new(0),
            bloom_hits: AtomicU64::new(0),
            bloom_misses: AtomicU64::new(0),
            arena_lookups: AtomicU64::new(0),
            fingerprint_passes: AtomicU64::new(0),
            fingerprint_failures: AtomicU64::new(0),
            canary_passes: AtomicU64::new(0),
            canary_failures: AtomicU64::new(0),
            heals: AtomicU64::new(0),
            double_frees_healed: AtomicU64::new(0),
            foreign_frees_healed: AtomicU64::new(0),
            size_clamps: AtomicU64::new(0),
        }
    }

    /// Increment a counter by 1.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a counter value.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Snapshot all counters into a displayable summary.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            validations: Self::get(&self.validations),
            tls_cache_hits: Self::get(&self.tls_cache_hits),
            tls_cache_misses: Self::get(&self.tls_cache_misses),
            bloom_hits: Self::get(&self.bloom_hits),
            bloom_misses: Self::get(&self.bloom_misses),
            arena_lookups: Self::get(&self.arena_lookups),
            fingerprint_passes: Self::get(&self.fingerprint_passes),
            fingerprint_failures: Self::get(&self.fingerprint_failures),
            canary_passes: Self::get(&self.canary_passes),
            canary_failures: Self::get(&self.canary_failures),
            heals: Self::get(&self.heals),
            double_frees_healed: Self::get(&self.double_frees_healed),
            foreign_frees_healed: Self::get(&self.foreign_frees_healed),
            size_clamps: Self::get(&self.size_clamps),
        }
    }

    /// Export the current metrics snapshot as a single deterministic JSONL row.
    #[must_use]
    pub fn export_snapshot_jsonl(
        &self,
        bead_id: &str,
        run_id: &str,
        mode: &str,
        api_family: &str,
        symbol: &str,
    ) -> String {
        self.snapshot()
            .export_jsonl(bead_id, run_id, mode, api_family, symbol)
    }
}

impl Default for MembraneMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of all membrane counters.
#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub validations: u64,
    pub tls_cache_hits: u64,
    pub tls_cache_misses: u64,
    pub bloom_hits: u64,
    pub bloom_misses: u64,
    pub arena_lookups: u64,
    pub fingerprint_passes: u64,
    pub fingerprint_failures: u64,
    pub canary_passes: u64,
    pub canary_failures: u64,
    pub heals: u64,
    pub double_frees_healed: u64,
    pub foreign_frees_healed: u64,
    pub size_clamps: u64,
}

impl MetricsSnapshot {
    /// Ratio of TLS cache hits to all TLS cache lookups.
    #[must_use]
    pub fn tls_cache_hit_rate(&self) -> f64 {
        ratio(
            self.tls_cache_hits,
            self.tls_cache_hits + self.tls_cache_misses,
        )
    }

    /// Ratio of bloom hits to all bloom checks.
    #[must_use]
    pub fn bloom_hit_rate(&self) -> f64 {
        ratio(self.bloom_hits, self.bloom_hits + self.bloom_misses)
    }

    /// Export a single aggregate metrics snapshot row as deterministic JSONL.
    #[must_use]
    pub fn export_jsonl(
        &self,
        bead_id: &str,
        run_id: &str,
        mode: &str,
        api_family: &str,
        symbol: &str,
    ) -> String {
        let bead = sanitize_trace_component(bead_id);
        let run = sanitize_trace_component(run_id);
        let mode = sanitize_trace_component(mode);
        let api_family = sanitize_trace_component(api_family);
        let symbol = sanitize_trace_component(symbol);
        let timestamp = now_utc_iso_like();
        let decision_id = DecisionId::from_raw(1);
        let trace_id = membrane_scope_trace_id("membrane::metrics", &bead, &run);
        let mut out = String::with_capacity(768);
        let _ = writeln!(
            &mut out,
            "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{}\",\"bead_id\":\"{bead}\",\"scenario_id\":\"{run}\",\"decision_id\":{},\"schema_version\":\"{}\",\"level\":\"info\",\"event\":\"membrane_metrics_snapshot\",\"controller_id\":\"membrane_metrics.v1\",\"mode\":\"{mode}\",\"api_family\":\"{api_family}\",\"symbol\":\"{symbol}\",\"decision_path\":\"tsm::metrics::snapshot\",\"decision_action\":\"observe\",\"outcome\":\"snapshot\",\"healing_action\":null,\"errno\":0,\"latency_ns\":0,\"metrics\":{{\"validations\":{},\"tls_cache_hits\":{},\"tls_cache_misses\":{},\"tls_cache_hit_rate\":{},\"bloom_hits\":{},\"bloom_misses\":{},\"bloom_hit_rate\":{},\"arena_lookups\":{},\"fingerprint_passes\":{},\"fingerprint_failures\":{},\"canary_passes\":{},\"canary_failures\":{},\"heals\":{},\"double_frees_healed\":{},\"foreign_frees_healed\":{},\"size_clamps\":{}}},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/metrics.rs\"]}}",
            trace_id.as_str(),
            decision_id.as_u64(),
            MEMBRANE_SCHEMA_VERSION,
            self.validations,
            self.tls_cache_hits,
            self.tls_cache_misses,
            self.tls_cache_hit_rate(),
            self.bloom_hits,
            self.bloom_misses,
            self.bloom_hit_rate(),
            self.arena_lookups,
            self.fingerprint_passes,
            self.fingerprint_failures,
            self.canary_passes,
            self.canary_failures,
            self.heals,
            self.double_frees_healed,
            self.foreign_frees_healed,
            self.size_clamps,
        );
        out
    }
}

/// Global metrics instance.
static GLOBAL_METRICS: MembraneMetrics = MembraneMetrics::new();

/// Access the global metrics singleton.
#[must_use]
pub fn global_metrics() -> &'static MembraneMetrics {
    &GLOBAL_METRICS
}

fn membrane_scope_trace_id(scope: &'static str, bead_id: &str, run_id: &str) -> TraceId {
    TraceId::new(format!("{scope}::{bead_id}::{run_id}"))
}

fn sanitize_trace_component(component: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        String::from("unknown")
    } else {
        sanitized
    }
}

fn now_utc_iso_like() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:09}Z", now.as_secs(), now.subsec_nanos())
}

const fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = MembraneMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.validations, 0);
        assert_eq!(snap.heals, 0);
    }

    #[test]
    fn increment_works() {
        let m = MembraneMetrics::new();
        MembraneMetrics::inc(&m.validations);
        MembraneMetrics::inc(&m.validations);
        MembraneMetrics::inc(&m.heals);
        let snap = m.snapshot();
        assert_eq!(snap.validations, 2);
        assert_eq!(snap.heals, 1);
    }

    #[test]
    fn snapshot_rates_are_derived_from_counters() {
        let snapshot = MetricsSnapshot {
            validations: 10,
            tls_cache_hits: 3,
            tls_cache_misses: 1,
            bloom_hits: 6,
            bloom_misses: 2,
            arena_lookups: 5,
            fingerprint_passes: 4,
            fingerprint_failures: 1,
            canary_passes: 7,
            canary_failures: 1,
            heals: 2,
            double_frees_healed: 1,
            foreign_frees_healed: 1,
            size_clamps: 0,
        };

        assert_eq!(snapshot.tls_cache_hit_rate(), 0.75);
        assert_eq!(snapshot.bloom_hit_rate(), 0.75);
    }

    #[test]
    fn snapshot_export_jsonl_includes_required_fields() {
        let snapshot = MetricsSnapshot {
            validations: 11,
            tls_cache_hits: 7,
            tls_cache_misses: 4,
            bloom_hits: 5,
            bloom_misses: 5,
            arena_lookups: 4,
            fingerprint_passes: 3,
            fingerprint_failures: 1,
            canary_passes: 2,
            canary_failures: 1,
            heals: 6,
            double_frees_healed: 2,
            foreign_frees_healed: 1,
            size_clamps: 3,
        };

        let jsonl = snapshot.export_jsonl(
            "bd-32e",
            "strict run/1",
            "strict",
            "pointer_validation",
            "membrane::ptr_validator::validate",
        );
        let row: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("metrics JSONL row should parse");

        assert_eq!(row["bead_id"], "bd-32e");
        assert_eq!(row["scenario_id"], "strict_run_1");
        assert_eq!(row["mode"], "strict");
        assert_eq!(row["api_family"], "pointer_validation");
        assert_eq!(row["symbol"], "membrane__ptr_validator__validate");
        assert_eq!(row["event"], "membrane_metrics_snapshot");
        assert_eq!(row["decision_path"], "tsm::metrics::snapshot");
        assert_eq!(row["outcome"], "snapshot");
        assert_eq!(
            row["artifact_refs"][0],
            "crates/frankenlibc-membrane/src/metrics.rs"
        );
        assert_eq!(row["metrics"]["validations"], 11);
        assert_eq!(row["metrics"]["heals"], 6);
        assert_eq!(row["metrics"]["tls_cache_hit_rate"], 7.0 / 11.0);
    }

    #[test]
    fn snapshot_export_sanitizes_empty_or_non_identifier_components() {
        let snapshot = MembraneMetrics::new().snapshot();
        let jsonl = snapshot.export_jsonl("", "bad run/id", "hard mode", "api/family", "");
        let row: serde_json::Value =
            serde_json::from_str(jsonl.trim()).expect("metrics JSONL row should parse");

        assert_eq!(row["bead_id"], "unknown");
        assert_eq!(row["scenario_id"], "bad_run_id");
        assert_eq!(row["mode"], "hard_mode");
        assert_eq!(row["api_family"], "api_family");
        assert_eq!(row["symbol"], "unknown");
        assert_eq!(row["trace_id"], "membrane::metrics::unknown::bad_run_id");
    }
}
