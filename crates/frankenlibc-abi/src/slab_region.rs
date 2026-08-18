//! Address-derived slab ownership: the O(1) test that has to be cheap before the
//! rest of the design is worth building (bd-e0y02p).
//!
//! ## Why this module exists on its own
//!
//! The slab design replaces three per-`malloc` costs — an arena hash insert, a
//! size-index insert behind a GLOBAL SPINLOCK, and the matching hash lookup in
//! `free` — with arithmetic on the pointer itself: `ptr & !(SLAB_ALIGN - 1)` is
//! the address of a header carrying the size class. That is only sound if the
//! pointer belongs to a slab region FrankenLibC reserved. Masking an arbitrary
//! pointer and dereferencing the result would read memory this process may not
//! own, which is a fault or a silent false positive, and this is a memory-safety
//! project.
//!
//! So the design's own falsification criterion is about THIS file, not about the
//! allocator: *"if the ownership test is not cheap the whole saving evaporates
//! and the design should be abandoned rather than tuned."* The test is therefore
//! written and measurable before any allocation path changes.
//!
//! ## The shape of the test
//!
//! Two tiers, and the first one carries the traffic:
//!
//! 1. **Envelope reject** — one pair of compares against the lowest base and
//!    highest end of all reserved regions. Every pointer from glibc's own
//!    internals, from the stack, from a foreign `mmap`, or from a library's
//!    static data is outside that envelope and costs two relaxed loads and two
//!    compares. No memory is touched beyond this module's own statics.
//! 2. **Region scan** — only for addresses inside the envelope. Regions are few
//!    (64 slots), large (64 KiB each by default) and aligned, so this is a short
//!    linear scan of contiguous atomics, which predicts and prefetches well. It
//!    is deliberately NOT a hash: at this cardinality a scan beats a hash's
//!    constant factor, and it needs no lock.
//!
//! Neither tier dereferences the candidate pointer. `header_of` returns the
//! header address only after membership is established, so a foreign pointer can
//! never cause a read of foreign memory.
//!
//! ## What must be true for the design to proceed
//!
//! `bench_ownership_reject` and `bench_ownership_accept` exist so the first
//! measurement can be the decisive one. The number to beat is the ~133 ns of
//! fixed per-call overhead the design targets; the number to fear is a test that
//! costs a meaningful fraction of it. The bead's own bar: an fl slab hitting its
//! own free list should land in the same order of magnitude as glibc's ~8.55 ns,
//! and anything above ~30 ns means the remaining membrane accounting is the real
//! floor.
//!
//! NOT WIRED INTO `malloc`/`free` YET, on purpose. This is the piece the design
//! says to measure first, and wiring it in before it is measured would make a
//! refutation expensive to unwind.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Alignment and size granule of a reserved slab region.
///
/// 64 KiB keeps the region count small enough for a linear scan while staying a
/// single power of two, so `addr & !(SLAB_ALIGN - 1)` is one AND. It is also
/// comfortably larger than any small size class, so a region holds many objects
/// and refills are rare.
pub const SLAB_ALIGN: usize = 64 * 1024;

/// Maximum number of reserved regions tracked at once.
///
/// Small on purpose: the envelope check means this bound only limits how many
/// DISTINCT reservations can be live, and each is 64 KiB, so 64 slots covers
/// 4 MiB of slab-backed small allocations. Exhausting it is not a failure — it
/// means later reservations are not slab-tracked and fall back to the existing
/// arena path, which is why `register` returns a bool rather than panicking.
pub const MAX_REGIONS: usize = 64;

/// A reserved region. `len == 0` marks a free slot.
struct RegionSlot {
    base: AtomicUsize,
    len: AtomicUsize,
}

static REGIONS: [RegionSlot; MAX_REGIONS] = [const {
    RegionSlot {
        base: AtomicUsize::new(0),
        len: AtomicUsize::new(0),
    }
}; MAX_REGIONS];

/// Number of slots that have ever been used, so the scan can stop early.
static REGION_HIGH_WATER: AtomicUsize = AtomicUsize::new(0);

/// Lowest base and highest end across all live regions — the envelope.
///
/// `ENVELOPE_LO` starts at `usize::MAX` and `ENVELOPE_HI` at 0, so before any
/// region is registered every address fails `addr >= lo && addr < hi` and the
/// test rejects with two compares. That is the correct answer at that point:
/// nothing is slab-owned yet.
static ENVELOPE_LO: AtomicUsize = AtomicUsize::new(usize::MAX);
static ENVELOPE_HI: AtomicUsize = AtomicUsize::new(0);

/// Record a reserved region. Returns false if the table is full.
///
/// `base` must be `SLAB_ALIGN`-aligned and `len` a non-zero multiple of it;
/// both are checked rather than assumed, because a mis-registered region would
/// make `owns` claim addresses this module cannot mask correctly.
///
/// The envelope is widened monotonically. It is never narrowed on release: a
/// stale-wide envelope only costs a region scan that then correctly answers
/// false, whereas narrowing it under concurrency could transiently exclude a
/// live region and make `owns` answer false for memory that IS slab-owned —
/// which in `free` would leak and in a bounds check would under-report. Trading
/// a little precision for that safety is deliberate.
pub fn register(base: usize, len: usize) -> bool {
    if base == 0 || len == 0 || base % SLAB_ALIGN != 0 || len % SLAB_ALIGN != 0 {
        return false;
    }
    let Some(end) = base.checked_add(len) else {
        return false;
    };

    for (index, slot) in REGIONS.iter().enumerate() {
        // Claim by CAS on `len`: a slot is free exactly when its len is 0, and
        // publishing len last means a reader that sees a non-zero len also sees
        // the base (Release/Acquire pair below).
        if slot.len.load(Ordering::Relaxed) != 0 {
            continue;
        }
        if slot
            .len
            .compare_exchange(0, len, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        slot.base.store(base, Ordering::Release);

        // High water mark, monotonic.
        let mut seen = REGION_HIGH_WATER.load(Ordering::Relaxed);
        while seen < index + 1 {
            match REGION_HIGH_WATER.compare_exchange(
                seen,
                index + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => seen = current,
            }
        }

        widen_envelope(base, end);
        return true;
    }
    false
}

/// Release a region. The envelope is intentionally left as-is; see `register`.
pub fn unregister(base: usize) -> bool {
    for slot in REGIONS.iter().take(REGION_HIGH_WATER.load(Ordering::Acquire)) {
        if slot.len.load(Ordering::Acquire) == 0 {
            continue;
        }
        if slot.base.load(Ordering::Acquire) == base {
            slot.len.store(0, Ordering::Release);
            return true;
        }
    }
    false
}

fn widen_envelope(base: usize, end: usize) {
    let mut lo = ENVELOPE_LO.load(Ordering::Relaxed);
    while base < lo {
        match ENVELOPE_LO.compare_exchange(lo, base, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => lo = current,
        }
    }
    let mut hi = ENVELOPE_HI.load(Ordering::Relaxed);
    while end > hi {
        match ENVELOPE_HI.compare_exchange(hi, end, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break,
            Err(current) => hi = current,
        }
    }
}

/// Is `addr` inside a reserved slab region?
///
/// Touches no memory outside this module. The envelope pair is the hot path: a
/// pointer that never came from a slab is rejected without looking at any
/// region.
#[inline]
pub fn owns(addr: usize) -> bool {
    // Tier 1: envelope. Ordering::Relaxed is sufficient — a stale-narrow
    // envelope can only produce a false negative for a region registered
    // concurrently, and a caller racing its own first allocation against its
    // own first free is already unsound at the C level.
    if addr < ENVELOPE_LO.load(Ordering::Relaxed) || addr >= ENVELOPE_HI.load(Ordering::Relaxed) {
        return false;
    }

    // Tier 2: region scan, bounded by the high-water mark.
    let live = REGION_HIGH_WATER.load(Ordering::Acquire);
    for slot in REGIONS.iter().take(live) {
        let len = slot.len.load(Ordering::Acquire);
        if len == 0 {
            continue;
        }
        let base = slot.base.load(Ordering::Acquire);
        if base == 0 {
            // Claimed but not yet published; treat as absent this round.
            continue;
        }
        if addr >= base && addr - base < len {
            return true;
        }
    }
    false
}

/// The header address for `addr`, or `None` if `addr` is not slab-owned.
///
/// The ownership test runs FIRST and unconditionally. Returning an address
/// rather than a reference is deliberate: this module establishes membership and
/// arithmetic only, and leaves every dereference to the allocator, so there is
/// exactly one place in the design where a header read can happen and it is
/// downstream of a proven-true `owns`.
#[inline]
pub fn header_of(addr: usize) -> Option<usize> {
    if !owns(addr) {
        return None;
    }
    Some(addr & !(SLAB_ALIGN - 1))
}

/// Live region count, for telemetry and tests.
pub fn live_regions() -> usize {
    REGIONS
        .iter()
        .take(REGION_HIGH_WATER.load(Ordering::Acquire))
        .filter(|slot| slot.len.load(Ordering::Acquire) != 0)
        .count()
}

/// Sum `owns` over `reps` addresses that are all OUTSIDE the envelope.
///
/// This is the measurement the design stands or falls on: the reject path is
/// what every foreign pointer pays, and foreign pointers are the common case in
/// a preloaded libc. Returns the count of true answers so the loop cannot be
/// optimised away; it should be 0.
pub fn bench_ownership_reject(start: usize, reps: usize) -> usize {
    let mut hits = 0usize;
    for step in 0..reps {
        // Stride by a cache line so the loop is not a single hot address.
        if owns(start.wrapping_add(step.wrapping_mul(64))) {
            hits += 1;
        }
    }
    hits
}

/// Sum `owns` over `reps` addresses that are all INSIDE a registered region.
///
/// The accept path costs the envelope pair plus a scan to the matching slot, so
/// its cost depends on how many regions precede the match. Measuring it with one
/// region registered gives the floor; measuring with the table full gives the
/// ceiling, and the gap is the argument for or against the linear scan.
pub fn bench_ownership_accept(base: usize, reps: usize) -> usize {
    let mut hits = 0usize;
    for step in 0..reps {
        if owns(base.wrapping_add((step % (SLAB_ALIGN / 64)).wrapping_mul(64))) {
            hits += 1;
        }
    }
    hits
}
