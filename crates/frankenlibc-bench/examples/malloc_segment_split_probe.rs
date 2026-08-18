//! Which `malloc` path serves small allocations — segment, or arena fallback?
//!
//! This is the measurement bd-e0y02p needs FIRST, and it replaces the one the
//! bead originally asked for. The bead proposes an address-derived slab to remove
//! the per-call arena insert, the size-index insert behind a global spinlock, and
//! `free`'s matching lookup. Reading `malloc_abi.rs` shows FrankenLibC already has
//! that: `strict_small_or_host_allocate` tries `segment_allocate` first, and when
//! it succeeds `malloc` records binned stats and never calls
//! `fallback_insert_sized_for_slot` — so on that path the insert, the index and
//! the spinlock are already gone. `MAX_SMALL_SIZE` is 32 KiB, covering every size
//! the ~133 ns fixed gap was measured at.
//!
//! So the design's premise reduces to one unmeasured fact: **does
//! `segment_allocate` actually succeed there?** The existing per-size-class stats
//! cannot say — both paths bin by size, so a small allocation lands in the same
//! bin either way. `segment_path_split()` was added for exactly this question.
//!
//! ## The two outcomes want opposite work
//!
//! * **Segments hit and the gap persists** — the design is refuted by
//!   construction. The remaining cost is framing, the membrane's `decide`/
//!   `observe`, or the allocator reentry guard, and building a second slab would
//!   change nothing. Close the bead and redirect.
//! * **Segments not hit** — the slab exists and is not being used. That is a much
//!   cheaper fix than building another one, and it would also mean the earlier
//!   "cost is diffuse" reading was measuring the fallback path all along.
//!
//! Either way this probe decides it, and it needs no quiet window: it reports a
//! COUNT, not a duration, so contention and clock ramps cannot corrupt it. That
//! is deliberate — the campaign's timing rows need a quiet host, and this one
//! does not, so it can run the moment the volume frees up.
//!
//! Deliberately does NOT print nanoseconds. `malloc_st_probe` already reports
//! absolute per-arm timing, and mixing a timing claim into a structural probe
//! would invite quoting an unquiet number.

use frankenlibc_abi::malloc_abi::{free, malloc, segment_path_split};

/// Sizes the ~133 ns gap was measured at (2026-07-02: 16/64/256/1024 bytes, flat
/// across the range, which is what makes it a FIXED per-call cost).
const SIZES: [usize; 4] = [16, 64, 256, 1024];

/// Enough pairs that a warmed steady state dominates the first-touch refills.
const PAIRS_PER_SIZE: usize = 20_000;

fn main() {
    let (before_segment, before_fallback, arena_ready) = segment_path_split();
    println!(
        "MALLOC_SEGMENT_SPLIT phase=start arena_ready={arena_ready} \
         segment_allocs={before_segment} fallback_allocs={before_fallback}"
    );

    // The coarse answer, free to obtain: with no arena mapped, nothing can be
    // segment-backed and every allocation took the fallback path.
    if !arena_ready {
        println!(
            "MALLOC_SEGMENT_SPLIT verdict=arena_never_mapped \
             note=every_allocation_used_the_fallback_path_so_bd-e0y02p_premise_HOLDS"
        );
    }

    for size in SIZES {
        let (seg_in, fb_in, _) = segment_path_split();
        for _ in 0..PAIRS_PER_SIZE {
            // SAFETY: a plain malloc/free pair through fl's own entry points; the
            // pointer is freed before the next iteration and never dereferenced.
            let ptr = unsafe { malloc(size) };
            if ptr.is_null() {
                println!("MALLOC_SEGMENT_SPLIT size={size} status=malloc_returned_null");
                break;
            }
            unsafe { free(ptr) };
        }
        let (seg_out, fb_out, _) = segment_path_split();
        let seg = seg_out.saturating_sub(seg_in);
        let fb = fb_out.saturating_sub(fb_in);
        let total = seg + fb;
        // Reported as a share, because the absolute counts include whatever the
        // process allocated for its own bookkeeping between samples.
        let share = if total == 0 {
            0.0
        } else {
            (seg as f64) * 100.0 / (total as f64)
        };
        println!(
            "MALLOC_SEGMENT_SPLIT size={size} pairs={PAIRS_PER_SIZE} \
             segment_allocs={seg} fallback_allocs={fb} segment_share_pct={share:.2}"
        );
    }

    let (after_segment, after_fallback, _) = segment_path_split();
    let seg = after_segment.saturating_sub(before_segment);
    let fb = after_fallback.saturating_sub(before_fallback);
    let verdict = if seg == 0 {
        // The slab exists and never ran: fix the gating, do not build a second one.
        "segments_never_hit_premise_HOLDS"
    } else if fb == 0 {
        // The design is already fully in force, so the residual cost is elsewhere.
        "segments_serve_everything_design_REFUTED_by_construction"
    } else {
        // Both ran: the share says which one the measured cost belongs to.
        "mixed_read_the_per_size_shares"
    };
    println!(
        "MALLOC_SEGMENT_SPLIT phase=end segment_allocs={seg} fallback_allocs={fb} \
         verdict={verdict}"
    );
}
