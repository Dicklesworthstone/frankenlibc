//! Unified metrics and observation for Alien CS concurrency primitives.
//!
//! Aggregates diagnostics from RCU, SeqLock, EBR, and Flat Combining into
//! a single snapshot for observability. Provides contention tracking and
//! structured metric emission without requiring an external logging framework.
//!
//! # Design rationale
//!
//! The membrane crate operates at `#![deny(unsafe_code)]` and has no logging
//! dependency. Instead of adding one, this module provides a structured
//! `AlienCsSnapshot` that callers can serialize, log, or forward to OTLP
//! as appropriate for their context.

use crate::ebr::EbrDiagnostics;
use crate::flat_combining::FlatCombinerDiagnostics;
use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, TraceId};
use crate::seqlock::SeqLockDiagnostics;
use crate::util::now_utc_iso_like;
use std::fmt::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// ──────────────── Global Metric Ring ────────────────

/// Default capacity for the global alien CS metric ring.
const GLOBAL_RING_CAPACITY: usize = 4096;

static GLOBAL_ALIEN_CS_RING: OnceLock<MetricRing> = OnceLock::new();

/// Access the global alien CS metric ring.
///
/// This is the shared emission target for all concurrency primitives.
/// Zero-overhead when no consumer reads the ring.
pub fn global_alien_cs_ring() -> &'static MetricRing {
    GLOBAL_ALIEN_CS_RING.get_or_init(|| MetricRing::new(GLOBAL_RING_CAPACITY))
}

/// Emit a metric event to the global alien CS ring.
///
/// This is the hot-path emission point. The only cost when no
/// consumer is attached is a single atomic increment + lock acquisition
/// on the ring's internal mutex.
#[inline]
pub fn emit_alien_cs_event(kind: MetricEventKind, value: u64, concept: &'static str) {
    global_alien_cs_ring().emit(kind, value, concept);
}

/// Unified diagnostics snapshot across all four Alien CS concepts.
#[derive(Debug, Clone)]
pub struct AlienCsSnapshot {
    /// Timestamp when this snapshot was captured (monotonic).
    pub captured_at_ns: u64,
    /// SeqLock metrics (if a SeqLock is being observed).
    pub seqlock: Option<SeqLockDiagnostics>,
    /// EBR metrics (if an EbrCollector is being observed).
    pub ebr: Option<EbrDiagnostics>,
    /// Flat Combining metrics (if a FlatCombiner is being observed).
    pub flat_combining: Option<FlatCombinerDiagnostics>,
    /// RCU metrics.
    pub rcu: Option<RcuMetrics>,
    /// Aggregate contention score (higher = more contention observed).
    pub contention_score: f64,
}

/// RCU-specific metrics (RcuCell doesn't have built-in diagnostics).
#[derive(Debug, Clone)]
pub struct RcuMetrics {
    /// Current epoch.
    pub epoch: u64,
    /// Number of readers currently active.
    pub reader_count: usize,
}

/// Export-time context for Alien CS structured logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlienCsLogContext {
    /// Bead/work item identifier for trace correlation.
    pub bead_id: String,
    /// Deterministic scenario/run identifier.
    pub run_id: String,
    /// Runtime mode (`strict`/`hardened`).
    pub mode: String,
    /// Symbol namespace to associate with the exported rows.
    pub symbol: String,
}

impl AlienCsLogContext {
    /// Build a sanitized export context.
    #[must_use]
    pub fn new(bead_id: &str, run_id: &str, mode: &str, symbol: &str) -> Self {
        Self {
            bead_id: sanitize_trace_component(bead_id),
            run_id: sanitize_trace_component(run_id),
            mode: sanitize_trace_component(mode),
            symbol: sanitize_trace_component(symbol),
        }
    }

    /// Preserve the legacy `export_jsonl` behavior with an explicit strict-mode default.
    #[must_use]
    pub fn strict_defaults(bead_id: &str, run_id: &str) -> Self {
        Self::new(bead_id, run_id, "strict", "alien_cs")
    }
}

/// Derived contention metrics used in aggregate snapshot exports.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AlienCsContentionBreakdown {
    /// Fraction of reads that had to refresh the cached snapshot.
    pub seqlock_cache_miss_ratio: f64,
    /// Writer wait events per committed write.
    pub seqlock_contention_per_write: f64,
    /// Fraction of active EBR threads currently pinned.
    pub ebr_pinned_fraction: f64,
    /// Average flat-combining operations completed per pass.
    pub flat_combining_ops_per_pass: f64,
    /// Inverse batching efficiency (higher means more contention).
    pub flat_combining_efficiency_loss: f64,
}

/// Metric event kinds for structured emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricEventKind {
    /// SeqLock cache miss (reader had to refresh).
    SeqLockCacheMiss,
    /// SeqLock write contention (writer waited for lock).
    SeqLockContention,
    /// EBR epoch advanced.
    EbrEpochAdvance,
    /// EBR items reclaimed.
    EbrReclaim,
    /// EBR grace period delayed (pinned threads blocking advance).
    EbrGracePeriodDelay,
    /// Flat Combining pass executed.
    FcCombiningPass,
    /// RCU update applied.
    RcuUpdate,
    /// RCU reader refreshed.
    RcuReaderRefresh,
}

impl MetricEventKind {
    const fn concept_event_name(self) -> &'static str {
        match self {
            Self::SeqLockCacheMiss => "alien_cs_seqlock_cache_miss",
            Self::SeqLockContention => "alien_cs_seqlock_contention",
            Self::EbrEpochAdvance => "alien_cs_ebr_epoch_advance",
            Self::EbrReclaim => "alien_cs_ebr_reclaim",
            Self::EbrGracePeriodDelay => "alien_cs_ebr_grace_period_delay",
            Self::FcCombiningPass => "alien_cs_flat_combining_pass",
            Self::RcuUpdate => "alien_cs_rcu_update",
            Self::RcuReaderRefresh => "alien_cs_rcu_reader_refresh",
        }
    }

    const fn level(self) -> &'static str {
        match self {
            Self::SeqLockContention | Self::EbrGracePeriodDelay => "warn",
            Self::SeqLockCacheMiss | Self::FcCombiningPass | Self::RcuReaderRefresh => "debug",
            Self::EbrEpochAdvance | Self::EbrReclaim | Self::RcuUpdate => "info",
        }
    }

    const fn decision_path(self) -> &'static str {
        match self {
            Self::SeqLockCacheMiss => "alien_cs::seqlock::reader_refresh",
            Self::SeqLockContention => "alien_cs::seqlock::writer_wait",
            Self::EbrEpochAdvance => "alien_cs::ebr::advance_epoch",
            Self::EbrReclaim => "alien_cs::ebr::reclaim",
            Self::EbrGracePeriodDelay => "alien_cs::ebr::grace_period_delay",
            Self::FcCombiningPass => "alien_cs::flat_combining::run_pass",
            Self::RcuUpdate => "alien_cs::rcu::update",
            Self::RcuReaderRefresh => "alien_cs::rcu::reader_refresh",
        }
    }

    const fn outcome(self) -> &'static str {
        match self {
            Self::SeqLockContention | Self::EbrGracePeriodDelay => "contention_alert",
            Self::SeqLockCacheMiss | Self::RcuReaderRefresh => "reader_refresh",
            Self::EbrEpochAdvance => "epoch_advance",
            Self::EbrReclaim => "reclaim",
            Self::FcCombiningPass => "combining_pass",
            Self::RcuUpdate => "update",
        }
    }
}

/// A single metric event with structured fields.
#[derive(Debug, Clone)]
pub struct MetricEvent {
    /// What kind of event occurred.
    pub kind: MetricEventKind,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Optional numeric value (e.g., items reclaimed, batch size).
    pub value: u64,
    /// Optional concept identifier (e.g., "seqlock", "ebr").
    pub concept: &'static str,
}

/// Ring buffer for metric events (fixed capacity, overwrites oldest).
pub struct MetricRing {
    events: parking_lot::Mutex<Vec<MetricEvent>>,
    capacity: usize,
    total_emitted: AtomicU64,
    epoch_start: Instant,
}

impl MetricRing {
    /// Create a new metric ring with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            events: parking_lot::Mutex::new(Vec::with_capacity(capacity.min(4096))),
            capacity,
            total_emitted: AtomicU64::new(0),
            epoch_start: Instant::now(),
        }
    }

    /// Record a metric event.
    pub fn emit(&self, kind: MetricEventKind, value: u64, concept: &'static str) {
        let event = MetricEvent {
            kind,
            timestamp_ns: self.epoch_start.elapsed().as_nanos() as u64,
            value,
            concept,
        };

        let mut events = self.events.lock();
        if events.len() >= self.capacity {
            events.remove(0);
        }
        events.push(event);
        self.total_emitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Drain all events from the ring, returning them.
    pub fn drain(&self) -> Vec<MetricEvent> {
        let mut events = self.events.lock();
        events.drain(..).collect()
    }

    /// Get the current number of buffered events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// Check if the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Total events ever emitted (including those overwritten).
    #[must_use]
    pub fn total_emitted(&self) -> u64 {
        self.total_emitted.load(Ordering::Relaxed)
    }

    /// Snapshot the current events without draining.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MetricEvent> {
        self.events.lock().clone()
    }

    /// Count events of a specific kind.
    #[must_use]
    pub fn count_by_kind(&self, kind: MetricEventKind) -> usize {
        self.events.lock().iter().filter(|e| e.kind == kind).count()
    }

    /// Count events for a specific concept.
    #[must_use]
    pub fn count_by_concept(&self, concept: &str) -> usize {
        self.events
            .lock()
            .iter()
            .filter(|e| e.concept == concept)
            .count()
    }

    /// Export buffered Alien CS metric events as deterministic JSONL rows.
    ///
    /// This mirrors the membrane/runtime structured-log contract closely enough
    /// for downstream artifact validation without introducing a logging crate.
    #[must_use]
    pub fn export_jsonl(&self, bead_id: &str, run_id: &str) -> String {
        self.export_jsonl_with_context(&AlienCsLogContext::strict_defaults(bead_id, run_id))
    }

    /// Export buffered Alien CS metric events with explicit logging context.
    #[must_use]
    pub fn export_jsonl_with_context(&self, context: &AlienCsLogContext) -> String {
        let timestamp = now_utc_iso_like();
        let events = self.snapshot();
        let mut out = String::with_capacity(events.len().saturating_mul(320).saturating_add(256));

        for (index, event) in events.iter().enumerate() {
            let decision_id = DecisionId::from_raw((index + 1) as u64);
            let trace_id = decision_id.scoped_trace_id("alien_cs::metric");
            let _ = writeln!(
                &mut out,
                "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{}\",\"bead_id\":\"{}\",\"scenario_id\":\"{}\",\"decision_id\":{},\"schema_version\":\"{}\",\"level\":\"{}\",\"event\":\"{}\",\"controller_id\":\"alien_cs_metrics.v1\",\"mode\":\"{}\",\"api_family\":\"alien_cs\",\"symbol\":\"{}::{}\",\"decision_path\":\"{}\",\"decision_action\":\"observe\",\"outcome\":\"{}\",\"healing_action\":null,\"errno\":0,\"latency_ns\":{},\"metric_kind\":\"{}\",\"metric_value\":{},\"concept\":\"{}\",\"artifact_refs\":[\"crates/frankenlibc-membrane/src/alien_cs_metrics.rs\"]}}",
                trace_id.as_str(),
                context.bead_id,
                context.run_id,
                decision_id.as_u64(),
                MEMBRANE_SCHEMA_VERSION,
                event.kind.level(),
                event.kind.concept_event_name(),
                context.mode,
                context.symbol,
                event.concept,
                event.kind.decision_path(),
                event.kind.outcome(),
                event.timestamp_ns,
                event.kind.concept_event_name(),
                event.value,
                event.concept,
            );
        }

        out
    }
}

/// Compute a contention score from diagnostics.
///
/// Higher score means more contention was observed:
/// - SeqLock: ratio of cache misses to total reads
/// - EBR: pinned threads as fraction of active threads
/// - FC: inverse of batching efficiency (ops per pass)
pub fn compute_contention_score(
    seqlock: Option<&SeqLockDiagnostics>,
    ebr: Option<&EbrDiagnostics>,
    fc: Option<&FlatCombinerDiagnostics>,
) -> f64 {
    let breakdown = compute_contention_breakdown(seqlock, ebr, fc);
    let mut score = 0.0;
    let mut components = 0;

    if seqlock.is_some() {
        score += breakdown.seqlock_cache_miss_ratio;
        components += 1;
        if let Some(sl) = seqlock
            && sl.writes > 0
        {
            score += breakdown.seqlock_contention_per_write;
            components += 1;
        }
    }

    if let Some(e) = ebr
        && e.active_threads > 0
    {
        score += breakdown.ebr_pinned_fraction;
        components += 1;
    }

    if let Some(f) = fc
        && f.total_passes > 0
    {
        score += breakdown.flat_combining_efficiency_loss;
        components += 1;
    }

    if components > 0 {
        score / components as f64
    } else {
        0.0
    }
}

/// Compute a per-concept contention breakdown from diagnostics.
#[must_use]
pub fn compute_contention_breakdown(
    seqlock: Option<&SeqLockDiagnostics>,
    ebr: Option<&EbrDiagnostics>,
    fc: Option<&FlatCombinerDiagnostics>,
) -> AlienCsContentionBreakdown {
    let seqlock_cache_miss_ratio = seqlock.map_or(0.0, |sl| {
        if sl.reads == 0 {
            0.0
        } else {
            sl.cache_misses as f64 / sl.reads as f64
        }
    });
    let seqlock_contention_per_write = seqlock.map_or(0.0, |sl| {
        if sl.writes == 0 {
            0.0
        } else {
            (sl.contention_events as f64 / sl.writes as f64).min(1.0)
        }
    });
    let ebr_pinned_fraction = ebr.map_or(0.0, |diag| {
        if diag.active_threads == 0 {
            0.0
        } else {
            diag.pinned_threads as f64 / diag.active_threads as f64
        }
    });
    let flat_combining_ops_per_pass = fc.map_or(0.0, |diag| {
        if diag.total_passes == 0 {
            0.0
        } else {
            diag.total_ops as f64 / diag.total_passes as f64
        }
    });
    let flat_combining_efficiency_loss = if flat_combining_ops_per_pass > 0.0 {
        1.0 / flat_combining_ops_per_pass.max(1.0)
    } else {
        0.0
    };

    AlienCsContentionBreakdown {
        seqlock_cache_miss_ratio,
        seqlock_contention_per_write,
        ebr_pinned_fraction,
        flat_combining_ops_per_pass,
        flat_combining_efficiency_loss,
    }
}

/// Build a unified snapshot from individual diagnostics.
pub fn build_snapshot(
    seqlock: Option<SeqLockDiagnostics>,
    ebr: Option<EbrDiagnostics>,
    fc: Option<FlatCombinerDiagnostics>,
    rcu: Option<RcuMetrics>,
    epoch_start: Instant,
) -> AlienCsSnapshot {
    let contention = compute_contention_score(seqlock.as_ref(), ebr.as_ref(), fc.as_ref());
    AlienCsSnapshot {
        captured_at_ns: epoch_start.elapsed().as_nanos() as u64,
        seqlock,
        ebr,
        flat_combining: fc,
        rcu,
        contention_score: contention,
    }
}

impl AlienCsSnapshot {
    /// Export a single aggregate snapshot row as JSONL.
    #[must_use]
    pub fn export_jsonl(&self, bead_id: &str, run_id: &str) -> String {
        self.export_jsonl_with_context(&AlienCsLogContext::strict_defaults(bead_id, run_id))
    }

    /// Export a single aggregate snapshot row as JSONL with explicit logging context.
    #[must_use]
    pub fn export_jsonl_with_context(&self, context: &AlienCsLogContext) -> String {
        let timestamp = now_utc_iso_like();
        let level = if self.contention_score >= 0.75 {
            "warn"
        } else {
            "info"
        };
        let seqlock_reads = self.seqlock.as_ref().map_or(0, |diag| diag.reads);
        let seqlock_writes = self.seqlock.as_ref().map_or(0, |diag| diag.writes);
        let ebr_epoch = self.ebr.as_ref().map_or(0, |diag| diag.global_epoch);
        let ebr_active_threads = self.ebr.as_ref().map_or(0, |diag| diag.active_threads);
        let ebr_pinned_threads = self.ebr.as_ref().map_or(0, |diag| diag.pinned_threads);
        let fc_total_ops = self
            .flat_combining
            .as_ref()
            .map_or(0, |diag| diag.total_ops);
        let fc_total_passes = self
            .flat_combining
            .as_ref()
            .map_or(0, |diag| diag.total_passes);
        let rcu_epoch = self.rcu.as_ref().map_or(0, |diag| diag.epoch);
        let rcu_reader_count = self.rcu.as_ref().map_or(0, |diag| diag.reader_count);
        let breakdown = compute_contention_breakdown(
            self.seqlock.as_ref(),
            self.ebr.as_ref(),
            self.flat_combining.as_ref(),
        );
        let trace_id =
            alien_cs_scope_trace_id("alien_cs::snapshot", &context.bead_id, &context.run_id);

        format!(
            "{{\"timestamp\":\"{timestamp}\",\"trace_id\":\"{}\",\"bead_id\":\"{}\",\"scenario_id\":\"{}\",\"decision_id\":0,\"schema_version\":\"{}\",\"level\":\"{level}\",\"event\":\"alien_cs_snapshot\",\"controller_id\":\"alien_cs_metrics.v1\",\"mode\":\"{}\",\"api_family\":\"alien_cs\",\"symbol\":\"{}::snapshot\",\"decision_path\":\"alien_cs::snapshot::build\",\"decision_action\":\"observe\",\"outcome\":\"snapshot\",\"healing_action\":null,\"errno\":0,\"latency_ns\":{},\"contention_score\":{},\"contention_metrics\":{{\"seqlock_cache_miss_ratio\":{},\"seqlock_contention_per_write\":{},\"ebr_pinned_fraction\":{},\"flat_combining_ops_per_pass\":{},\"flat_combining_efficiency_loss\":{}}},\"seqlock_reads\":{seqlock_reads},\"seqlock_writes\":{seqlock_writes},\"ebr_epoch\":{ebr_epoch},\"ebr_active_threads\":{ebr_active_threads},\"ebr_pinned_threads\":{ebr_pinned_threads},\"flat_combining_total_ops\":{fc_total_ops},\"flat_combining_total_passes\":{fc_total_passes},\"rcu_epoch\":{rcu_epoch},\"rcu_reader_count\":{rcu_reader_count},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/alien_cs_metrics.rs\"]}}\n",
            trace_id.as_str(),
            context.bead_id,
            context.run_id,
            MEMBRANE_SCHEMA_VERSION,
            context.mode,
            context.symbol,
            self.captured_at_ns,
            self.contention_score,
            breakdown.seqlock_cache_miss_ratio,
            breakdown.seqlock_contention_per_write,
            breakdown.ebr_pinned_fraction,
            breakdown.flat_combining_ops_per_pass,
            breakdown.flat_combining_efficiency_loss,
        )
    }
}

fn alien_cs_scope_trace_id(scope: &'static str, bead_id: &str, run_id: &str) -> TraceId {
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
        "unknown".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebr::EbrCollector;
    use crate::flat_combining::FlatCombiner;
    use crate::rcu::RcuCell;
    use crate::seqlock::{SeqLock, SeqLockReader};

    #[test]
    fn metric_ring_basic_lifecycle() {
        let ring = MetricRing::new(10);
        assert!(ring.is_empty());
        assert_eq!(ring.total_emitted(), 0);

        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 5, "ebr");

        assert_eq!(ring.len(), 2);
        assert_eq!(ring.total_emitted(), 2);
    }

    #[test]
    fn metric_ring_capacity_overflow() {
        let ring = MetricRing::new(3);

        for i in 0..5u64 {
            ring.emit(MetricEventKind::FcCombiningPass, i, "fc");
        }

        assert_eq!(ring.len(), 3);
        assert_eq!(ring.total_emitted(), 5);

        // Oldest events should be evicted.
        let events = ring.snapshot();
        assert_eq!(events[0].value, 2); // 0 and 1 were evicted
        assert_eq!(events[1].value, 3);
        assert_eq!(events[2].value, 4);
    }

    #[test]
    fn metric_ring_drain() {
        let ring = MetricRing::new(10);
        ring.emit(MetricEventKind::RcuUpdate, 1, "rcu");
        ring.emit(MetricEventKind::RcuReaderRefresh, 2, "rcu");

        let drained = ring.drain();
        assert_eq!(drained.len(), 2);
        assert!(ring.is_empty());
        assert_eq!(ring.total_emitted(), 2); // total preserved
    }

    #[test]
    fn metric_ring_count_by_kind() {
        let ring = MetricRing::new(100);
        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 2, "ebr");
        ring.emit(MetricEventKind::SeqLockCacheMiss, 3, "seqlock");

        assert_eq!(ring.count_by_kind(MetricEventKind::SeqLockCacheMiss), 2);
        assert_eq!(ring.count_by_kind(MetricEventKind::EbrEpochAdvance), 1);
        assert_eq!(ring.count_by_kind(MetricEventKind::RcuUpdate), 0);
    }

    #[test]
    fn metric_ring_count_by_concept() {
        let ring = MetricRing::new(100);
        ring.emit(MetricEventKind::SeqLockCacheMiss, 1, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 2, "ebr");
        ring.emit(MetricEventKind::SeqLockContention, 3, "seqlock");

        assert_eq!(ring.count_by_concept("seqlock"), 2);
        assert_eq!(ring.count_by_concept("ebr"), 1);
        assert_eq!(ring.count_by_concept("rcu"), 0);
    }

    #[test]
    fn contention_score_zero_when_no_data() {
        let score = compute_contention_score(None, None, None);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn contention_score_low_for_cached_reads() {
        let sl = SeqLock::new(42u64);
        let mut reader = crate::seqlock::SeqLockReader::new(&sl);
        // Read many times without writing → all cache hits.
        for _ in 0..100 {
            let _ = reader.read();
        }
        let diag = sl.diagnostics();
        let score = compute_contention_score(Some(&diag), None, None);
        // With 100 reads, 99 cache hits, 1 miss → low contention.
        assert!(score < 0.1, "expected low contention, got {}", score);
    }

    #[test]
    fn contention_score_higher_with_writes() {
        let sl = SeqLock::new(0u64);
        let mut reader = crate::seqlock::SeqLockReader::new(&sl);

        // Alternate read-write: every read misses cache.
        for i in 0..50u64 {
            sl.write_with(|d| *d = i);
            let _ = reader.read();
        }

        let diag = sl.diagnostics();
        let score = compute_contention_score(Some(&diag), None, None);
        // High miss ratio → higher contention score.
        assert!(score > 0.3, "expected moderate contention, got {}", score);
    }

    #[test]
    fn build_snapshot_aggregates_all_concepts() {
        let sl = SeqLock::new(0u64);
        sl.write_with(|d| *d = 1);
        let sl_diag = sl.diagnostics();

        let collector = EbrCollector::new();
        collector.retire(|| {});
        collector.try_advance();
        let ebr_diag = collector.diagnostics();

        let fc = FlatCombiner::new(0u64, 4);
        fc.execute(1u64, |s, o| {
            *s += o;
            *s
        });
        let fc_diag = fc.diagnostics();

        let cell = RcuCell::new(0u64);
        cell.update(1);
        let rcu = RcuMetrics {
            epoch: cell.epoch(),
            reader_count: cell.reader_count(),
        };

        let snap = build_snapshot(
            Some(sl_diag),
            Some(ebr_diag),
            Some(fc_diag),
            Some(rcu),
            Instant::now(),
        );

        assert!(snap.seqlock.is_some());
        assert!(snap.ebr.is_some());
        assert!(snap.flat_combining.is_some());
        assert!(snap.rcu.is_some());
        assert!(snap.contention_score >= 0.0);
    }

    #[test]
    fn metric_event_timestamps_monotonic() {
        let ring = MetricRing::new(100);
        for i in 0..20u64 {
            ring.emit(MetricEventKind::RcuUpdate, i, "rcu");
        }
        let events = ring.snapshot();
        for window in events.windows(2) {
            assert!(
                window[1].timestamp_ns >= window[0].timestamp_ns,
                "timestamps must be monotonic"
            );
        }
    }

    #[test]
    fn contention_score_fc_high_passes_low_batching() {
        // Simulate poor batching: many passes, few ops per pass.
        let fc_diag = FlatCombinerDiagnostics {
            total_ops: 100,
            total_passes: 100, // 1 op per pass = worst batching
            max_batch_size: 1,
            avg_batch_size: 1.0,
            active_slots: 1,
            total_slots: 4,
        };
        let score = compute_contention_score(None, None, Some(&fc_diag));
        // 1/1 = 1.0 efficiency loss → high contention.
        assert!(score > 0.5, "expected high contention, got {}", score);
    }

    #[test]
    fn contention_breakdown_reports_per_concept_components() {
        let seqlock = SeqLockDiagnostics {
            reads: 20,
            cache_hits: 15,
            cache_misses: 5,
            writes: 4,
            contention_events: 3,
            pending_writers: 0,
            hit_ratio: 0.75,
        };
        let ebr = EbrDiagnostics {
            global_epoch: 7,
            active_threads: 4,
            pinned_threads: 1,
            total_retired: 0,
            total_reclaimed: 0,
            pending_per_epoch: [0, 0, 0],
        };
        let fc = FlatCombinerDiagnostics {
            total_ops: 18,
            total_passes: 6,
            max_batch_size: 4,
            avg_batch_size: 3.0,
            active_slots: 2,
            total_slots: 8,
        };

        let breakdown = compute_contention_breakdown(Some(&seqlock), Some(&ebr), Some(&fc));
        assert_eq!(breakdown.seqlock_cache_miss_ratio, 0.25);
        assert_eq!(breakdown.seqlock_contention_per_write, 0.75);
        assert_eq!(breakdown.ebr_pinned_fraction, 0.25);
        assert_eq!(breakdown.flat_combining_ops_per_pass, 3.0);
        assert_eq!(breakdown.flat_combining_efficiency_loss, 1.0 / 3.0);
    }

    #[test]
    fn log_context_sanitizes_export_dimensions() {
        let context = AlienCsLogContext::new("bd bad/1", "run 7", "hard mode", "alien cs/path");
        assert_eq!(context.bead_id, "bd_bad_1");
        assert_eq!(context.run_id, "run_7");
        assert_eq!(context.mode, "hard_mode");
        assert_eq!(context.symbol, "alien_cs_path");
    }

    #[test]
    fn metric_ring_export_jsonl_contains_required_fields() {
        let ring = MetricRing::new(8);
        ring.emit(MetricEventKind::SeqLockContention, 7, "seqlock");
        ring.emit(MetricEventKind::EbrEpochAdvance, 2, "ebr");

        let jsonl = ring.export_jsonl("bd-32e", "alien-cs-smoke");
        let lines: Vec<_> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);

        for (index, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value =
                serde_json::from_str(line).expect("exported line should be valid json");
            for field in [
                "timestamp",
                "trace_id",
                "bead_id",
                "scenario_id",
                "decision_id",
                "schema_version",
                "level",
                "event",
                "controller_id",
                "mode",
                "api_family",
                "symbol",
                "decision_path",
                "decision_action",
                "outcome",
                "errno",
                "latency_ns",
                "metric_kind",
                "metric_value",
                "concept",
                "artifact_refs",
            ] {
                assert!(parsed.get(field).is_some(), "missing field {field}");
            }
            assert_eq!(parsed["bead_id"], "bd-32e");
            assert_eq!(parsed["scenario_id"], "alien-cs-smoke");
            assert_eq!(parsed["decision_id"], (index + 1) as u64);
            assert_eq!(parsed["schema_version"], "1.0");
            assert_eq!(parsed["mode"], "strict");
            assert_eq!(parsed["api_family"], "alien_cs");
            assert_eq!(parsed["decision_action"], "observe");
            assert!(
                parsed["trace_id"]
                    .as_str()
                    .expect("trace_id must be string")
                    .starts_with("alien_cs::metric::")
            );
            assert!(
                parsed["symbol"]
                    .as_str()
                    .expect("symbol must be string")
                    .starts_with("alien_cs::")
            );
            assert_eq!(
                parsed["artifact_refs"][0],
                "crates/frankenlibc-membrane/src/alien_cs_metrics.rs"
            );
            assert_eq!(parsed["metric_value"], if index == 0 { 7 } else { 2 });
        }
    }

    #[test]
    fn metric_ring_export_jsonl_with_context_sanitizes_mode_and_symbol() {
        let ring = MetricRing::new(4);
        ring.emit(MetricEventKind::FcCombiningPass, 3, "flat_combining");
        let context =
            AlienCsLogContext::new("bd 1sp.11", "robot smoke", "hardened mode", "alien cs");

        let jsonl = ring.export_jsonl_with_context(&context);
        let line = jsonl.lines().next().expect("event row should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("event export should be valid json");

        assert_eq!(parsed["bead_id"], "bd_1sp.11");
        assert_eq!(parsed["scenario_id"], "robot_smoke");
        assert_eq!(parsed["mode"], "hardened_mode");
        assert_eq!(parsed["symbol"], "alien_cs::flat_combining");
        assert_eq!(parsed["outcome"], "combining_pass");
    }

    #[test]
    fn snapshot_export_jsonl_contains_aggregate_diagnostics() {
        let snapshot = AlienCsSnapshot {
            captured_at_ns: 42,
            seqlock: Some(SeqLockDiagnostics {
                reads: 11,
                cache_hits: 9,
                cache_misses: 2,
                writes: 3,
                contention_events: 1,
                pending_writers: 0,
                hit_ratio: 9.0 / 11.0,
            }),
            ebr: Some(EbrDiagnostics {
                global_epoch: 5,
                active_threads: 2,
                pinned_threads: 1,
                total_retired: 8,
                total_reclaimed: 3,
                pending_per_epoch: [1, 0, 0],
            }),
            flat_combining: Some(FlatCombinerDiagnostics {
                total_ops: 13,
                total_passes: 4,
                max_batch_size: 5,
                avg_batch_size: 3.25,
                active_slots: 2,
                total_slots: 8,
            }),
            rcu: Some(RcuMetrics {
                epoch: 6,
                reader_count: 3,
            }),
            contention_score: 0.8,
        };

        let jsonl = snapshot.export_jsonl("bd-32e", "aggregate");
        let line = jsonl.lines().next().expect("snapshot row should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("snapshot export should be valid json");

        assert_eq!(parsed["event"], "alien_cs_snapshot");
        assert_eq!(parsed["decision_id"], 0);
        assert_eq!(parsed["schema_version"], "1.0");
        assert_eq!(parsed["level"], "warn");
        assert_eq!(parsed["bead_id"], "bd-32e");
        assert_eq!(parsed["scenario_id"], "aggregate");
        assert_eq!(parsed["trace_id"], "alien_cs::snapshot::bd-32e::aggregate");
        assert_eq!(parsed["mode"], "strict");
        assert_eq!(parsed["decision_action"], "observe");
        assert_eq!(parsed["outcome"], "snapshot");
        assert_eq!(parsed["contention_score"], 0.8);
        assert!(
            (parsed["contention_metrics"]["seqlock_cache_miss_ratio"]
                .as_f64()
                .expect("ratio should be f64")
                - (2.0 / 11.0))
                .abs()
                < 1e-12
        );
        assert!(
            (parsed["contention_metrics"]["seqlock_contention_per_write"]
                .as_f64()
                .expect("ratio should be f64")
                - (1.0 / 3.0))
                .abs()
                < 1e-12
        );
        assert_eq!(parsed["contention_metrics"]["ebr_pinned_fraction"], 0.5);
        assert!(
            (parsed["contention_metrics"]["flat_combining_ops_per_pass"]
                .as_f64()
                .expect("ops per pass should be f64")
                - (13.0 / 4.0))
                .abs()
                < 1e-12
        );
        assert_eq!(parsed["seqlock_reads"], 11);
        assert_eq!(parsed["seqlock_writes"], 3);
        assert_eq!(parsed["ebr_epoch"], 5);
        assert_eq!(parsed["flat_combining_total_ops"], 13);
        assert_eq!(parsed["rcu_epoch"], 6);
        assert_eq!(parsed["rcu_reader_count"], 3);
        assert_eq!(
            parsed["artifact_refs"][0],
            "crates/frankenlibc-membrane/src/alien_cs_metrics.rs"
        );
    }

    #[test]
    fn sanitize_trace_component_rewrites_non_identifier_bytes() {
        assert_eq!(sanitize_trace_component("bd-32e"), "bd-32e");
        assert_eq!(sanitize_trace_component("run id/1"), "run_id_1");
        assert_eq!(sanitize_trace_component(""), "unknown");
    }

    #[test]
    fn snapshot_export_jsonl_with_context_sanitizes_mode_and_symbol() {
        let snapshot = AlienCsSnapshot {
            captured_at_ns: 9,
            seqlock: None,
            ebr: None,
            flat_combining: None,
            rcu: None,
            contention_score: 0.0,
        };
        let context = AlienCsLogContext::new("bd 1sp.11", "rcu smoke", "hard mode", "alien cs");

        let jsonl = snapshot.export_jsonl_with_context(&context);
        let line = jsonl.lines().next().expect("snapshot row should exist");
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("snapshot export should be valid json");

        assert_eq!(parsed["bead_id"], "bd_1sp.11");
        assert_eq!(parsed["scenario_id"], "rcu_smoke");
        assert_eq!(parsed["mode"], "hard_mode");
        assert_eq!(parsed["symbol"], "alien_cs::snapshot");
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Live multi-concept snapshot under concurrent load
    //
    // Creates real instances of all alien CS primitives, exercises
    // them under concurrent pressure, then builds a snapshot and
    // verifies contention score and diagnostics coherence.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn live_multi_concept_snapshot_under_concurrent_load() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Instant;

        let sl = Arc::new(SeqLock::new(0u64));
        let collector = Arc::new(EbrCollector::new());
        let fc = Arc::new(FlatCombiner::new(0u64, 16));
        let rcu = Arc::new(RcuCell::new(0u64));
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        // Thread 1: SeqLock writer + reader
        {
            let sl = Arc::clone(&sl);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..100u64 {
                    sl.write_with(|v| *v = i);
                }
            }));
        }

        // Thread 2: EBR retire + advance
        {
            let collector = Arc::clone(&collector);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let handle = collector.register();
                barrier.wait();
                for _ in 0..100 {
                    let guard = handle.pin();
                    collector.retire(|| {});
                    drop(guard);
                    collector.try_advance();
                }
            }));
        }

        // Thread 3: FlatCombiner operations
        {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..200 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        // Thread 4: RCU updates + reads
        {
            let rcu = Arc::clone(&rcu);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for i in 0..100u64 {
                    rcu.update(i);
                    let _ = *rcu.load();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Build snapshot from live diagnostics
        let epoch_start = Instant::now();
        let sl_diag = sl.diagnostics();
        let ebr_diag = collector.diagnostics();
        let fc_diag = fc.diagnostics();
        let rcu_metrics = RcuMetrics {
            epoch: rcu.epoch(),
            reader_count: rcu.reader_count(),
        };

        let snapshot = build_snapshot(
            Some(sl_diag.clone()),
            Some(ebr_diag.clone()),
            Some(fc_diag.clone()),
            Some(rcu_metrics.clone()),
            epoch_start,
        );

        // Verify diagnostics coherence
        assert!(sl_diag.writes >= 100, "seqlock should have >= 100 writes");
        assert_eq!(fc_diag.total_ops, 200, "flat combiner should have 200 ops");
        assert!(
            ebr_diag.total_retired >= 100,
            "EBR should have retired >= 100 items"
        );
        assert!(
            ebr_diag.total_reclaimed <= ebr_diag.total_retired,
            "EBR reclaimed must not exceed retired"
        );
        assert!(rcu_metrics.epoch > 0, "RCU epoch should have advanced");

        // Contention score should be finite and non-negative
        assert!(
            snapshot.contention_score >= 0.0,
            "contention score must be non-negative"
        );
        assert!(
            snapshot.contention_score.is_finite(),
            "contention score must be finite"
        );

        // Snapshot export should produce valid JSONL
        let jsonl = snapshot.export_jsonl("bd-1sp.9", "live-integration");
        let line = jsonl.lines().next().expect("should have at least one line");
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect("snapshot JSONL should parse");
        assert_eq!(parsed["event"], "alien_cs_snapshot");
        assert_eq!(parsed["bead_id"], "bd-1sp.9");
        assert!(
            parsed["flat_combining_total_ops"].as_u64().unwrap_or(0) > 0,
            "snapshot should include flat combining ops"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Flat combining batching verification
    //
    // Verifies that under high contention, the flat combiner
    // actually batches operations (max_batch_size > 1) and reduces
    // the number of combining passes below total operations.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn flat_combining_batching_verified_under_contention() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let fc = Arc::new(FlatCombiner::new(0u64, 32));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..1000 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let diag = fc.diagnostics();
        assert_eq!(diag.total_ops, 8000, "all operations must complete");
        assert_eq!(
            fc.with_state_ref(|s| *s),
            8000,
            "final state must reflect all increments"
        );

        // Batching verification: under 8 threads, the combiner should
        // batch operations, resulting in fewer passes than total ops
        assert!(
            diag.total_passes < diag.total_ops,
            "combining should reduce passes ({}) below total ops ({})",
            diag.total_passes,
            diag.total_ops,
        );
        assert!(
            diag.max_batch_size > 1,
            "high contention should produce batch sizes > 1, got {}",
            diag.max_batch_size
        );

        // Verify contention score reflects good batching
        let score = compute_contention_score(None, None, Some(&diag));
        assert!(score.is_finite(), "contention score must be finite");
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: Global ring captures live concept events
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn global_ring_captures_rcu_update_events() {
        let ring = global_alien_cs_ring();
        let before = ring.total_emitted();
        let rcu = RcuCell::new(0u64);
        rcu.update(1);
        rcu.update(2);
        rcu.update(3);
        let after = ring.total_emitted();
        assert!(
            after >= before + 3,
            "global ring should capture RCU update events: before={before}, after={after}"
        );
    }

    #[test]
    fn global_ring_captures_ebr_epoch_advance_events() {
        let ring = global_alien_cs_ring();
        let before = ring.total_emitted();
        let collector = EbrCollector::new();
        collector.try_advance();
        collector.try_advance();
        let after = ring.total_emitted();
        assert!(
            after >= before + 2,
            "global ring should capture EBR advance events: before={before}, after={after}"
        );
    }

    #[test]
    fn global_ring_captures_fc_combining_pass_events() {
        let ring = global_alien_cs_ring();
        let before = ring.total_emitted();
        let fc = FlatCombiner::new(0u64, 4);
        fc.execute(1u64, |state, op| {
            *state += op;
            *state
        });
        let after = ring.total_emitted();
        assert!(
            after > before,
            "global ring should capture FC combining pass events: before={before}, after={after}"
        );
    }

    #[test]
    fn global_ring_captures_seqlock_reader_miss_events() {
        let ring = global_alien_cs_ring();
        let before = ring.total_emitted();
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);
        let _ = reader.read();
        sl.write_with(|v| *v = 42);
        let _ = reader.read(); // cache miss -> emits event
        let after = ring.total_emitted();
        assert!(
            after > before,
            "global ring should capture SeqLock cache miss: before={before}, after={after}"
        );
    }

    #[test]
    fn global_ring_event_kinds_match_concept_sources() {
        let ring = global_alien_cs_ring();
        ring.drain();
        let rcu = RcuCell::new(0u64);
        rcu.update(99);
        let collector = EbrCollector::new();
        collector.try_advance();
        let fc = FlatCombiner::new(0u64, 4);
        fc.execute(1u64, |s, o| {
            *s += o;
            *s
        });
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);
        sl.write_with(|v| *v = 1);
        let _ = reader.read();
        let events = ring.snapshot();
        let has_rcu = events.iter().any(|e| e.concept == "rcu");
        let has_ebr = events.iter().any(|e| e.concept == "ebr");
        let has_fc = events.iter().any(|e| e.concept == "flat_combining");
        let has_seqlock = events.iter().any(|e| e.concept == "seqlock");
        assert!(has_rcu, "should have RCU events");
        assert!(has_ebr, "should have EBR events");
        assert!(has_fc, "should have FlatCombiner events");
        assert!(has_seqlock, "should have SeqLock events");
    }
}
