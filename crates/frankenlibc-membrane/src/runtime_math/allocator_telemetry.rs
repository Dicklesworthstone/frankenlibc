//! Bounded observations of actual segment allocator class selections.
//!
//! The strict allocator must not construct RuntimeMathKernel from malloc.
//! Two atomic mailboxes retain a sampled healthy mapping and an urgent mapping
//! until an already initialized kernel can consume them. Healthy traffic never
//! overwrites urgent traffic. Producers do not allocate, lock, or touch TLS.

use std::sync::atomic::{AtomicU64, Ordering};

use super::sos_barrier::size_class_mapping_requires_immediate_evaluation;

/// A coherent observation of the hardened arena, taken while all its shard
/// locks are held. This describes that arena only, not the process heap or RSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArenaFragmentationSnapshot {
    pub successful_allocations: u64,
    pub successful_frees: u64,
    pub live_allocations: u64,
    pub live_requested_bytes: usize,
    /// Live raw extents plus quarantined and parked-retirement extents. Drained
    /// batches are excluded as soon as they leave arena ownership, including
    /// the caller-owned interval before epoch retirement.
    pub retained_backing_bytes: usize,
    /// Gini-Simpson dispersion of live allocations in floor(log2(size)) bins.
    /// Zero-byte allocations share the first bin with one-byte allocations.
    /// Integer proportions make the result deterministic to ppm precision.
    pub size_class_dispersion_ppm: u32,
    /// Live requested bytes divided by backing extents retained by this arena.
    /// Includes header/alignment/redzone overhead in the denominator.
    pub arena_utilization_ppm: u32,
}

impl ArenaFragmentationSnapshot {
    /// Preserve the allocation/free ratio when a long-running process exceeds
    /// the certificate's u32 count interface, instead of clipping both to MAX.
    pub(crate) fn certificate_counts(self) -> (u32, u32) {
        let largest = self.successful_allocations.max(self.successful_frees);
        let scale = largest.div_ceil(u64::from(u32::MAX)).max(1);
        (
            (self.successful_allocations / scale) as u32,
            (self.successful_frees / scale) as u32,
        )
    }
}

/// Updated under an arena shard's existing lock: no additional atomic updates,
/// allocation, TLS, floating arithmetic, or controller lock on the hot path.
pub(crate) struct ArenaFragmentationCounters {
    successful_allocations: u64,
    successful_frees: u64,
    live_requested_bytes: usize,
    live_backing_bytes: usize,
    live_size_bins: [u64; usize::BITS as usize],
    mutations: u8,
}

impl ArenaFragmentationCounters {
    pub(crate) const fn new() -> Self {
        Self {
            successful_allocations: 0,
            successful_frees: 0,
            live_requested_bytes: 0,
            live_backing_bytes: 0,
            live_size_bins: [0; usize::BITS as usize],
            mutations: 0,
        }
    }

    fn note_mutation(&mut self) -> bool {
        self.mutations = self.mutations.wrapping_add(1);
        self.mutations == 0
    }

    pub(crate) fn allocate(&mut self, requested: usize, backing: usize) -> bool {
        self.successful_allocations = self.successful_allocations.saturating_add(1);
        self.live_requested_bytes = self.live_requested_bytes.saturating_add(requested);
        self.live_backing_bytes = self.live_backing_bytes.saturating_add(backing);
        let bin = &mut self.live_size_bins[requested.max(1).ilog2() as usize];
        *bin = bin.saturating_add(1);
        self.note_mutation()
    }

    pub(crate) fn free(&mut self, requested: usize, backing: usize) -> bool {
        self.successful_frees = self.successful_frees.saturating_add(1);
        self.live_requested_bytes = self.live_requested_bytes.saturating_sub(requested);
        self.live_backing_bytes = self.live_backing_bytes.saturating_sub(backing);
        let bin = &mut self.live_size_bins[requested.max(1).ilog2() as usize];
        *bin = bin.saturating_sub(1);
        self.note_mutation()
    }

    pub(crate) fn add(&mut self, other: &Self) {
        self.successful_allocations = self
            .successful_allocations
            .saturating_add(other.successful_allocations);
        self.successful_frees = self.successful_frees.saturating_add(other.successful_frees);
        self.live_requested_bytes = self
            .live_requested_bytes
            .saturating_add(other.live_requested_bytes);
        self.live_backing_bytes = self
            .live_backing_bytes
            .saturating_add(other.live_backing_bytes);
        for (count, other_count) in self.live_size_bins.iter_mut().zip(&other.live_size_bins) {
            *count = count.saturating_add(*other_count);
        }
    }

    pub(crate) fn snapshot(&self, retired_backing_bytes: usize) -> ArenaFragmentationSnapshot {
        let live_allocations = self
            .live_size_bins
            .iter()
            .copied()
            .fold(0u64, u64::saturating_add);
        let concentration_ppm = if live_allocations == 0 {
            1_000_000
        } else {
            self.live_size_bins
                .iter()
                .map(|&count| {
                    let proportion =
                        (u128::from(count) * 1_000_000 / u128::from(live_allocations)) as u64;
                    proportion * proportion
                })
                .sum::<u64>()
                / 1_000_000
        };
        let retained_backing_bytes = self
            .live_backing_bytes
            .saturating_add(retired_backing_bytes);
        let utilization = if retained_backing_bytes == 0 {
            0
        } else {
            ((self.live_requested_bytes as u128) * 1_000_000 / retained_backing_bytes as u128)
                .min(1_000_000) as u32
        };
        ArenaFragmentationSnapshot {
            successful_allocations: self.successful_allocations,
            successful_frees: self.successful_frees,
            live_allocations,
            live_requested_bytes: self.live_requested_bytes,
            retained_backing_bytes,
            size_class_dispersion_ppm: 1_000_000u32.saturating_sub(concentration_ppm as u32),
            arena_utilization_ppm: utilization,
        }
    }
}

/// Ordinary mappings select one observation per 256 class selections.
pub const SEGMENT_SIZE_CLASS_SAMPLE_STRIDE: u64 = 256;

const MEMBERSHIP_BIT: u64 = 1 << 48;
const PRESENT_BIT: u64 = 1 << 49;

/// One real selection of a segment slot's class for a new allocation.
///
/// The request fits the segment allocator's u16 metadata. The mapped extent
/// fits its u32 segment header. These widths retain both values exactly,
/// including rejected class extents outside the certificate's small-size range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSizeClassMapping {
    pub requested_size: u16,
    pub mapped_class_size: u32,
    pub class_membership_valid: bool,
}

impl SegmentSizeClassMapping {
    fn pack(self) -> u64 {
        PRESENT_BIT
            | u64::from(self.requested_size)
            | (u64::from(self.mapped_class_size) << 16)
            | if self.class_membership_valid {
                MEMBERSHIP_BIT
            } else {
                0
            }
    }

    fn unpack(value: u64) -> Option<Self> {
        (value & PRESENT_BIT != 0).then_some(Self {
            requested_size: value as u16,
            mapped_class_size: (value >> 16) as u32,
            class_membership_valid: value & MEMBERSHIP_BIT != 0,
        })
    }
}

/// Small, allocation-free diagnostic view of the producer/consumer bridge.
///
/// Counts are exact after producers and consumers quiesce. During concurrent
/// updates fields are individually atomic, not one transactional snapshot.
/// Each optional mapping is nevertheless a coherent, single-publication tuple.
/// A fork can inherit an in-flight update; these are not transactional fork counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSizeClassTelemetrySnapshot {
    /// Fresh class selections, including mappings rejected before activation.
    pub selections: u64,
    /// Healthy mappings selected by the 1-in-256 cadence.
    pub sampled_selections: u64,
    /// Mappings requiring evaluation without waiting for the healthy cadence.
    pub urgent_selections: u64,
    /// Earlier queued samples replaced by another sample of the same priority.
    pub coalesced_samples: u64,
    /// Samples actually applied to the live SOS controller.
    pub consumed_samples: u64,
    pub pending_healthy: Option<SegmentSizeClassMapping>,
    pub pending_urgent: Option<SegmentSizeClassMapping>,
    /// The last sample applied while holding the SOS controller's own lock.
    pub last_consumed: Option<SegmentSizeClassMapping>,
}

/// Two fixed mailboxes and counters; no initializer or ownership lock.
///
/// Multiple pending samples of the same priority coalesce explicitly. This
/// bounds storage even if a strict process never initializes its math kernel.
pub struct SegmentSizeClassTelemetry {
    selections: AtomicU64,
    sampled_selections: AtomicU64,
    urgent_selections: AtomicU64,
    coalesced_samples: AtomicU64,
    consumed_samples: AtomicU64,
    pending_healthy: AtomicU64,
    pending_urgent: AtomicU64,
    last_consumed: AtomicU64,
}

impl SegmentSizeClassTelemetry {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            selections: AtomicU64::new(0),
            sampled_selections: AtomicU64::new(0),
            urgent_selections: AtomicU64::new(0),
            coalesced_samples: AtomicU64::new(0),
            consumed_samples: AtomicU64::new(0),
            pending_healthy: AtomicU64::new(0),
            pending_urgent: AtomicU64::new(0),
            last_consumed: AtomicU64::new(0),
        }
    }

    /// Publish a real class selection; return whether a sample was queued.
    ///
    /// This is for fresh allocations, including reuse of a retired slot and
    /// a selected mapping rejected before activation. In-place realloc retains
    /// capacity and must not call this method.
    #[inline]
    pub fn record(&self, mapping: SegmentSizeClassMapping) -> bool {
        let ordinal = self
            .selections
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let urgent = size_class_mapping_requires_immediate_evaluation(
            usize::from(mapping.requested_size),
            mapping.mapped_class_size as usize,
            mapping.class_membership_valid,
        );
        let pending = if urgent {
            self.urgent_selections.fetch_add(1, Ordering::Relaxed);
            &self.pending_urgent
        } else {
            if !ordinal.is_multiple_of(SEGMENT_SIZE_CLASS_SAMPLE_STRIDE) {
                return false;
            }
            self.sampled_selections.fetch_add(1, Ordering::Relaxed);
            &self.pending_healthy
        };
        if pending.swap(mapping.pack(), Ordering::AcqRel) != 0 {
            self.coalesced_samples.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending_healthy.load(Ordering::Acquire) != 0
            || self.pending_urgent.load(Ordering::Acquire) != 0
    }

    /// The caller holds the destination SOS controller's lock. Claim urgent
    /// first so a healthy sample published before that fault cannot remain
    /// queued and clear it on a later drain. Still apply healthy before urgent.
    pub(crate) fn take_pending(&self) -> [Option<SegmentSizeClassMapping>; 2] {
        let urgent = SegmentSizeClassMapping::unpack(self.pending_urgent.swap(0, Ordering::AcqRel));
        [
            SegmentSizeClassMapping::unpack(self.pending_healthy.swap(0, Ordering::AcqRel)),
            urgent,
        ]
    }

    pub(crate) fn note_consumed(&self, mapping: SegmentSizeClassMapping) {
        self.last_consumed.store(mapping.pack(), Ordering::Release);
        self.consumed_samples.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> SegmentSizeClassTelemetrySnapshot {
        SegmentSizeClassTelemetrySnapshot {
            selections: self.selections.load(Ordering::Relaxed),
            sampled_selections: self.sampled_selections.load(Ordering::Relaxed),
            urgent_selections: self.urgent_selections.load(Ordering::Relaxed),
            coalesced_samples: self.coalesced_samples.load(Ordering::Relaxed),
            consumed_samples: self.consumed_samples.load(Ordering::Relaxed),
            pending_healthy: SegmentSizeClassMapping::unpack(
                self.pending_healthy.load(Ordering::Acquire),
            ),
            pending_urgent: SegmentSizeClassMapping::unpack(
                self.pending_urgent.load(Ordering::Acquire),
            ),
            last_consumed: SegmentSizeClassMapping::unpack(
                self.last_consumed.load(Ordering::Acquire),
            ),
        }
    }
}

impl Default for SegmentSizeClassTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod fragmentation_tests {
    use super::*;

    #[test]
    fn fragmentation_counts_backing_retained_after_free() {
        let mut counts = ArenaFragmentationCounters::new();
        counts.allocate(64, 128);
        counts.allocate(64, 128);
        let active = counts.snapshot(0);
        assert_eq!(
            (active.successful_allocations, active.successful_frees),
            (2, 0)
        );
        assert_eq!(active.live_allocations, 2);
        assert_eq!(active.live_requested_bytes, 128);
        assert_eq!(active.retained_backing_bytes, 256);
        assert_eq!(active.size_class_dispersion_ppm, 0);
        assert_eq!(active.arena_utilization_ppm, 500_000);

        counts.free(64, 128);
        let one_left = counts.snapshot(128);
        assert_eq!(one_left.live_allocations, 1);
        assert_eq!(
            one_left.retained_backing_bytes,
            active.retained_backing_bytes
        );
        assert_eq!(one_left.arena_utilization_ppm, 250_000);
        counts.free(64, 128);
        let retired = counts.snapshot(256);
        assert_eq!(
            (retired.successful_allocations, retired.successful_frees),
            (2, 2)
        );
        assert_eq!(retired.live_allocations, 0);
        assert_eq!(retired.retained_backing_bytes, 256);
        assert_eq!(retired.arena_utilization_ppm, 0);
        assert_eq!(retired.size_class_dispersion_ppm, 0);
    }

    #[test]
    fn fragmentation_distinguishes_size_distribution_from_byte_volume() {
        let mut uniform = ArenaFragmentationCounters::new();
        uniform.allocate(544, 608);
        uniform.allocate(544, 608);
        let mut small = ArenaFragmentationCounters::new();
        small.allocate(64, 128);
        let mut large = ArenaFragmentationCounters::new();
        large.allocate(1024, 1088);
        small.add(&large);
        let uniform = uniform.snapshot(0);
        let mixed = small.snapshot(0);
        assert_eq!(uniform.live_requested_bytes, mixed.live_requested_bytes);
        assert_eq!(uniform.retained_backing_bytes, mixed.retained_backing_bytes);
        assert_eq!(uniform.arena_utilization_ppm, mixed.arena_utilization_ppm);
        assert_eq!(uniform.size_class_dispersion_ppm, 0);
        assert_eq!(mixed.size_class_dispersion_ppm, 500_000);
    }

    #[test]
    fn fragmentation_sampling_counts_zero_size_and_actual_transitions() {
        let mut counts = ArenaFragmentationCounters::new();
        for cycle in 0..128 {
            assert!(!counts.allocate(0, 64));
            assert_eq!(counts.free(0, 64), cycle == 127);
        }
        let sample = counts.snapshot(128 * 64);
        assert_eq!(
            (sample.successful_allocations, sample.successful_frees),
            (128, 128)
        );
        assert_eq!(sample.live_requested_bytes, 0);
        assert_eq!(sample.retained_backing_bytes, 128 * 64);
        assert_eq!(sample.arena_utilization_ppm, 0);
    }

    #[test]
    fn fragmentation_normalizes_large_counters_without_losing_imbalance() {
        let mut counts = ArenaFragmentationCounters::new();
        counts.successful_allocations = u64::from(u32::MAX) * 8;
        counts.successful_frees = u64::from(u32::MAX) * 2;
        assert_eq!(
            counts.snapshot(0).certificate_counts(),
            (u32::MAX, u32::MAX / 4)
        );
        counts.allocate(usize::MAX, usize::MAX);
        assert_eq!(counts.snapshot(0).arena_utilization_ppm, 1_000_000);
    }
}
