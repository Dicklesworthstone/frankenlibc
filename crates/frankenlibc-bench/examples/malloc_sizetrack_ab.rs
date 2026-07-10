//! Swing-2 de-risking microbench: isolate the malloc/free size-tracking cost.
//!
//! The deployed malloc/free is ~10x glibc; the bisection in
//! docs/perf_next_architectural_swings.md attributes much of it to the FALLBACK_ALLOC
//! open-addressing hash table (per-alloc insert + per-free remove, under a spinlock),
//! but also warns the cost may be DIFFUSE. Swing-2 (inline size header) can ONLY
//! eliminate the table-op fraction. This bench measures that fraction directly:
//!
//!   TABLE:  fallback_insert_sized(ptr,sz) + fallback_size(ptr) + fallback_remove(ptr)
//!   HEADER: store sz at ptr[-8] + read ptr[-8] + read ptr[-8]   (the swing-2 op)
//!   GUARDED_HEADER: TABLE exact-start proof + simulated header read
//!   SEGMENT_BITMAP: ptr-derived no-deref segment membership bit test
//!
//! Same set of real host-malloc'd pointers for both, so only the size-tracking scheme
//! differs. If TABLE >> HEADER by ~the full malloc gap, swing-2 is validated; if the
//! delta is small, the malloc cost is diffuse and swing-2 caps at a modest win.
//! GUARDED_HEADER measures the currently provable safe transition: do not dereference
//! header metadata until the no-deref fallback table proves exact pointer membership.
//! SEGMENT_BITMAP measures the next proof primitive before any header wiring: if all
//! frankenlibc heap is carved from power-of-two segments, ownership is derivable from
//! the pointer address with no user-memory dereference and no fault surface.
//!
//! Run: cargo run --release --example malloc_sizetrack_ab --features abi-bench

use std::time::Instant;

const SEGMENT_SHIFT_FOR_BENCH: usize = 22;

struct SegmentMembershipForBench {
    base_segment: usize,
    words: Vec<u64>,
}

impl SegmentMembershipForBench {
    fn new(ptrs: &[*mut libc::c_void]) -> Self {
        let mut min_segment = usize::MAX;
        let mut max_segment = 0usize;
        for &ptr in ptrs {
            let segment = (ptr as usize) >> SEGMENT_SHIFT_FOR_BENCH;
            min_segment = min_segment.min(segment);
            max_segment = max_segment.max(segment);
        }

        let segment_span = max_segment - min_segment + 1;
        let mut words = vec![0u64; segment_span.div_ceil(64)];
        for &ptr in ptrs {
            let segment = (ptr as usize) >> SEGMENT_SHIFT_FOR_BENCH;
            let rel = segment - min_segment;
            words[rel >> 6] |= 1u64 << (rel & 63);
        }

        Self {
            base_segment: min_segment,
            words,
        }
    }

    #[inline(always)]
    fn contains(&self, addr: usize) -> bool {
        let segment = addr >> SEGMENT_SHIFT_FOR_BENCH;
        let rel = segment.wrapping_sub(self.base_segment);
        let word = rel >> 6;
        if word >= self.words.len() {
            return false;
        }
        let mask = 1u64 << (rel & 63);
        (self.words[word] & mask) != 0
    }
}

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    use frankenlibc_abi::malloc_abi as m;

    // A working set of real allocations (host System allocator via Vec). We only use
    // their addresses as keys; the header scheme writes into a separate 16-byte-per-
    // slot backing region so it never corrupts the Vec data.
    const N: usize = 256;
    let sizes: [usize; 4] = [16, 24, 64, 256];
    let mut blocks: Vec<Vec<u8>> = (0..N).map(|i| vec![0u8; sizes[i % 4]]).collect();
    let ptrs: Vec<*mut libc::c_void> = blocks
        .iter_mut()
        .map(|b| b.as_mut_ptr() as *mut libc::c_void)
        .collect();

    // Header backing: one usize per pointer (simulates the inline size slot at ptr[-8]).
    let mut header: Vec<usize> = vec![0usize; N];
    let segment_membership = SegmentMembershipForBench::new(&ptrs);
    assert!(segment_membership.contains(ptrs[0] as usize));
    assert!(!segment_membership.contains(0));
    assert!(!segment_membership.contains(usize::MAX));

    let iters = 40_000u64;
    let segment_iters = iters * 16;
    let rounds = 50;
    let (mut tv, mut hv, mut ghv, mut smv) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());

    // Warm the table once (insert then remove) so its slots/pages are faulted in.
    for (k, &p) in ptrs.iter().enumerate() {
        m::fallback_insert_sized_for_bench(p, sizes[k % 4]);
    }
    for &p in &ptrs {
        m::fallback_remove_sized_for_bench(p);
    }

    for _ in 0..rounds {
        // TABLE: full insert+lookup+remove churn over the working set.
        let t = Instant::now();
        for _ in 0..iters {
            for (k, &p) in ptrs.iter().enumerate() {
                m::fallback_insert_sized_for_bench(p, sizes[k % 4]);
                std::hint::black_box(m::fallback_size_for_bench(p));
                std::hint::black_box(m::fallback_remove_sized_for_bench(p));
            }
        }
        tv.push(t.elapsed().as_nanos() as f64 / (iters * N as u64) as f64);

        // HEADER: the swing-2 op — a single store + two loads per allocation.
        let t = Instant::now();
        for _ in 0..iters {
            for (k, _p) in ptrs.iter().enumerate() {
                unsafe {
                    let slot = header.as_mut_ptr().add(k);
                    std::ptr::write_volatile(slot, sizes[k % 4]);
                    std::hint::black_box(std::ptr::read_volatile(slot));
                    std::hint::black_box(std::ptr::read_volatile(slot));
                }
            }
        }
        hv.push(t.elapsed().as_nanos() as f64 / (iters * N as u64) as f64);

        // GUARDED_HEADER: the only safe transition currently available without new
        // metadata. The existing table proves exact-start membership before the
        // simulated header is read, so this path is no-fault for arbitrary pointers.
        let t = Instant::now();
        for _ in 0..iters {
            for (k, &p) in ptrs.iter().enumerate() {
                unsafe {
                    let slot = header.as_mut_ptr().add(k);
                    std::ptr::write_volatile(slot, sizes[k % 4]);
                }
                m::fallback_insert_sized_for_bench(p, sizes[k % 4]);
                if m::fallback_size_for_bench(p).is_some() {
                    unsafe {
                        let slot = header.as_ptr().add(k);
                        std::hint::black_box(std::ptr::read_volatile(slot));
                        std::hint::black_box(std::ptr::read_volatile(slot));
                    }
                }
                std::hint::black_box(m::fallback_remove_sized_for_bench(p));
            }
        }
        ghv.push(t.elapsed().as_nanos() as f64 / (iters * N as u64) as f64);

        // SEGMENT_BITMAP: prototype the no-deref membership proof alone. This is
        // the address-space half of a segment allocator design; it does not read
        // an inline header and does not change allocator behavior.
        let t = Instant::now();
        for _ in 0..segment_iters {
            for &p in &ptrs {
                std::hint::black_box(segment_membership.contains(std::hint::black_box(p as usize)));
            }
        }
        smv.push(t.elapsed().as_nanos() as f64 / (segment_iters * N as u64) as f64);
    }

    // STATS: the per-alloc+free flat-combining stats recorders (HTM + snapshot-discard).
    let mut sv = Vec::new();
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..iters {
            for k in 0..N {
                m::record_alloc_free_stats_for_bench(sizes[k % 4]);
            }
        }
        sv.push(t.elapsed().as_nanos() as f64 / (iters * N as u64) as f64);
    }
    let stats = pctl(&sv, 0.5);

    // GUARD: the per-alloc reentry guard enter+exit (fs read + slot cache + CAS + drop).
    let mut gv = Vec::new();
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..iters {
            for _ in 0..N {
                m::reentry_guard_enter_exit_for_bench();
            }
        }
        gv.push(t.elapsed().as_nanos() as f64 / (iters * N as u64) as f64);
    }
    let guard = pctl(&gv, 0.5);
    println!(
        "GUARD_AB reentry_enter+exit={guard:.2}ns/call (fs read + slot cache + depth CAS + drop)"
    );

    let table = pctl(&tv, 0.5);
    let head = pctl(&hv, 0.5);
    let guarded_head = pctl(&ghv, 0.5);
    let segment_bitmap = pctl(&smv, 0.5);
    println!(
        "SIZETRACK_AB table={table:.2} header={head:.2} header/table={:.3} table_saves={:.2}ns/op",
        head / table,
        table - head
    );
    println!(
        "SIZETRACK_GUARDED_HEADER_AB table={table:.2} guarded_header={guarded_head:.2} guarded/table={:.3} guarded_tax={:.2}ns/op",
        guarded_head / table,
        guarded_head - table
    );
    println!(
        "SIZETRACK_SEGMENT_BITMAP_AB table={table:.2} segment_bitmap={segment_bitmap:.2} segment/table={:.3} segment_saves={:.2}ns/op",
        segment_bitmap / table,
        table - segment_bitmap
    );
    println!(
        "STATS_AB record_alloc+free={stats:.2}ns/alloc+free-pair (flat-combining HTM + discarded snapshot)"
    );
    println!(
        "  => swing-2 (inline header) can eliminate ~{:.1}ns of the per-alloc+free size-tracking cost (table {table:.2}ns -> header {head:.2}ns).",
        table - head
    );
    println!(
        "  => existing-table guarded header changes table {table:.2}ns -> guarded {guarded_head:.2}ns; this is a safety proof only, not a production speedup."
    );
    println!(
        "  => segment bitmap membership changes table {table:.2}ns -> segment_bitmap {segment_bitmap:.2}ns before any inline-header read."
    );
}
