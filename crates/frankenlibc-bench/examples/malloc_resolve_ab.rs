//! In-process A/B: OLD malloc framing (double slot-resolve: outer guard + native guard
//! re-resolves) vs NEW (native guard reuses the outer guard's slot). Measures exactly the
//! redundant `current_allocator_reentry_slot` resolve that native_libc_malloc pays today.
//! Ratio cancels worker contention. Run: --features abi-bench.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn main() {
    use frankenlibc_abi::malloc_abi as m;
    // warm the last-thread cache + slot
    for _ in 0..10_000 {
        m::bench_malloc_guards_reresolve();
        m::bench_malloc_guards_forslot();
    }
    let iters = 20_000_000u64;
    let (mut ov, mut nv) = (Vec::new(), Vec::new());
    for r in 0..80 {
        let o = || {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(m::bench_malloc_guards_reresolve());
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        };
        let nw = || {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(m::bench_malloc_guards_forslot());
            }
            t.elapsed().as_nanos() as f64 / iters as f64
        };
        if r % 2 == 0 {
            ov.push(o());
            nv.push(nw());
        } else {
            nv.push(nw());
            ov.push(o());
        }
    }
    let (o, nn) = (pctl(&ov, 0.1), pctl(&nv, 0.1));
    println!(
        "malloc-guards OLD(double-resolve)={o:.2}ns NEW(reuse-slot)={nn:.2}ns  delta={:.2}ns  new/old={:.3} ({:.2}x)",
        o - nn,
        nn / o,
        o / nn
    );
}
