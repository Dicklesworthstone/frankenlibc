//! Bounded observations of actual segment allocator class selections.
//!
//! The strict allocator must not construct RuntimeMathKernel from malloc.
//! Two atomic mailboxes retain a sampled healthy mapping and an urgent mapping
//! until an already initialized kernel can consume them. Healthy traffic never
//! overwrites urgent traffic. Producers do not allocate, lock, or touch TLS.

use std::sync::atomic::{AtomicU64, Ordering};

use super::sos_barrier::size_class_mapping_requires_immediate_evaluation;

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
