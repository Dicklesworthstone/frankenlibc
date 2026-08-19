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

use frankenlibc_abi::malloc_abi::{free, malloc, malloc_path_counters, malloc_path_counters_full};

/// Sizes the ~133 ns gap was measured at (2026-07-02: 16/64/256/1024 bytes, flat
/// across the range, which is what makes it a FIXED per-call cost).
const SIZES: [usize; 4] = [16, 64, 256, 1024];

/// Enough pairs that a warmed steady state dominates the first-touch refills.
const PAIRS_PER_SIZE: usize = 20_000;

fn main() {
    // WHICH `malloc` DOES A CALL TO `fl::malloc` ACTUALLY REACH?
    //
    // The four-way split above is exhaustive over `malloc_abi::malloc`, so if a
    // run's counters do not move, the call never entered that function. Resolve
    // the symbol three ways and compare against fl's own address: `RTLD_DEFAULT`
    // is what a PLT-routed call binds to, and if that is glibc's `malloc` then a
    // probe's "fl arm" is measuring the host allocator.
    {
        let fl_addr = malloc as *const () as usize;
        let dflt = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"malloc".as_ptr()) } as usize;
        let next = unsafe { libc::dlsym(libc::RTLD_NEXT, c"malloc".as_ptr()) } as usize;
        println!(
            "MALLOC_SYMBOL_RESOLUTION fl_malloc=0x{fl_addr:x} rtld_default=0x{dflt:x} \
             rtld_next=0x{next:x} default_is_fl={} ",
            dflt == fl_addr
        );

        // Direct counter check: a bounded number of calls through the same path
        // the loop uses, with the exhaustive split read either side.
        let (a0, b0, c0, d0) = malloc_path_counters_full();
        for _ in 0..1000 {
            // black_box on BOTH the size and the pointer. Without it LLVM
            // recognises the `malloc`/`free` pair on an unused result and deletes
            // it outright -- fl's entry point is literally named `malloc` with the
            // C ABI, so it is treated as the builtin. That elision is what made
            // this probe's counters read zero.
            let p = unsafe { malloc(std::hint::black_box(32)) };
            std::hint::black_box(p);
            if !p.is_null() {
                unsafe { free(p) };
            }
        }
        let (a1, b1, c1, d1) = malloc_path_counters_full();
        let delta = (a1 - a0) + (b1 - b0) + (c1 - c0) + (d1 - d0);
        println!(
            "MALLOC_ENTRY_CHECK calls=1000 counted_delta={delta} \
             note={}",
            if delta == 0 {
                "ZERO_the_call_does_not_reach_malloc_abi_malloc"
            } else if delta >= 1000 {
                "OK_calls_reach_fl_malloc"
            } else {
                "PARTIAL_some_calls_bypass_fl_malloc"
            }
        );
    }

    let (before_segment, before_fallback, before_nonstrict, arena_ready) = malloc_path_counters();
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
        let (seg_in, fb_in, ns_in, _) = malloc_path_counters();
        for _ in 0..PAIRS_PER_SIZE {
            // SAFETY: a plain malloc/free pair through fl's own entry points; the
            // pointer is freed before the next iteration and never dereferenced.
            //
            // black_box is LOAD-BEARING here, not hygiene: in a release build LLVM
            // treats a `malloc`/`free` pair whose result is unused as the libc
            // builtin and eliminates it, so the loop performed ZERO allocations
            // and every counter read 0 -- which this probe then reported as
            // "segments never hit, premise HOLDS".
            let ptr = unsafe { malloc(std::hint::black_box(size)) };
            std::hint::black_box(ptr);
            if ptr.is_null() {
                println!("MALLOC_SEGMENT_SPLIT size={size} status=malloc_returned_null");
                break;
            }
            unsafe { free(ptr) };
        }
        let (seg_out, fb_out, ns_out, _) = malloc_path_counters();
        let seg = seg_out.saturating_sub(seg_in);
        let fb = fb_out.saturating_sub(fb_in);
        let ns = ns_out.saturating_sub(ns_in);
        let total = seg + fb + ns;
        // Reported as a share, because the absolute counts include whatever the
        // process allocated for its own bookkeeping between samples.
        let share = if total == 0 {
            0.0
        } else {
            (seg as f64) * 100.0 / (total as f64)
        };
        // `accounted` is the guard that was missing: without it a run where NO
        // counter fired printed `segment_allocs=0` and was read as "segments
        // lost", when it actually means the counted branches were never entered.
        println!(
            "MALLOC_SEGMENT_SPLIT size={size} pairs={PAIRS_PER_SIZE} \
             segment_allocs={seg} fallback_allocs={fb} nonstrict_allocs={ns} \
             accounted={total} segment_share_pct={share:.2}"
        );
    }

    let (fseg, ffb, fns, fboot) = malloc_path_counters_full();
    println!(
        "MALLOC_PATH_FULL segment={fseg} fallback={ffb} nonstrict={fns} bootstrap={fboot} \
         sum={}",
        fseg + ffb + fns + fboot
    );
    let (after_segment, after_fallback, after_nonstrict, _) = malloc_path_counters();
    let seg = after_segment.saturating_sub(before_segment);
    let fb = after_fallback.saturating_sub(before_fallback);
    let ns = after_nonstrict.saturating_sub(before_nonstrict);
    let expected = SIZES.len() * PAIRS_PER_SIZE;
    let accounted = seg + fb + ns;
    let verdict = if accounted == 0 {
        // THE GUARD THIS PROBE WAS MISSING. Every counter reading zero does not
        // mean "segments lost" -- it means no counted branch ran, so the split is
        // unmeasured and no verdict may be read from it. Reported as such rather
        // than as a premise-holds.
        "INCONCLUSIVE_no_counter_fired_split_is_uninstrumented_for_this_path"
    } else if accounted * 100 < expected * 50 {
        // Fewer than half the calls landed anywhere countable: still not a basis
        // for a structural decision.
        "INCONCLUSIVE_counters_account_for_under_half_the_calls"
    } else if ns > 0 && seg == 0 && fb == 0 {
        // All traffic took the non-strict membrane pipeline, which does not touch
        // the arena insert or the size index at all -- so the bead's premise is
        // about code this configuration never runs.
        "NONSTRICT_PATH_SERVED_EVERYTHING_premise_is_about_an_unrun_branch"
    } else if seg == 0 {
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
         nonstrict_allocs={ns} accounted={accounted} expected={expected} \
         verdict={verdict}"
    );
}
