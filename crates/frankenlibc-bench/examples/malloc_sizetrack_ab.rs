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
//!
//! Same set of real host-malloc'd pointers for both, so only the size-tracking scheme
//! differs. If TABLE >> HEADER by ~the full malloc gap, swing-2 is validated; if the
//! delta is small, the malloc cost is diffuse and swing-2 caps at a modest win.
//!
//! Run: cargo run --release --example malloc_sizetrack_ab --features abi-bench

use std::time::Instant;

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
    let ptrs: Vec<*mut libc::c_void> =
        blocks.iter_mut().map(|b| b.as_mut_ptr() as *mut libc::c_void).collect();

    // Header backing: one usize per pointer (simulates the inline size slot at ptr[-8]).
    let mut header: Vec<usize> = vec![0usize; N];

    let iters = 2000u64;
    let rounds = 100;
    let (mut tv, mut hv) = (Vec::new(), Vec::new());

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
    println!("GUARD_AB reentry_enter+exit={guard:.2}ns/call (fs read + slot cache + depth CAS + drop)");

    let table = pctl(&tv, 0.5);
    let head = pctl(&hv, 0.5);
    println!("SIZETRACK_AB table={table:.2} header={head:.2} header/table={:.3} table_saves={:.2}ns/op", head / table, table - head);
    println!("STATS_AB record_alloc+free={stats:.2}ns/alloc+free-pair (flat-combining HTM + discarded snapshot)");
    println!(
        "  => swing-2 (inline header) can eliminate ~{:.1}ns of the per-alloc+free size-tracking cost (table {table:.2}ns -> header {head:.2}ns).",
        table - head
    );
}
