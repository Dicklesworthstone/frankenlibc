//! Same-process A/B of the memchr MEDIUM-range kernel (isolated from the ABI floor +
//! contention): OLD per-32B-branch loop vs NEW 64-lane combined tier. Target absent →
//! full scan. Interleaved rounds cancel per-worker load in the new/old ratio.
//!
//! Run: cargo run --release --example memchr_kernel_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    use frankenlibc_core::string::mem;
    for &n in &[48usize, 64, 96, 128, 192, 240] {
        let buf = vec![b'x'; n]; // 'Z' absent → full scan
        assert_eq!(mem::memchr_medium_32bloop_for_bench(&buf, b'Z'),
                   mem::memchr_medium_64lane_for_bench(&buf, b'Z'));
        let iters = 60_000u64;
        let (mut ov, mut nv) = (Vec::new(), Vec::new());
        for r in 0..120 {
            let old_first = r % 2 == 0;
            let mut run_old = || {
                let t = Instant::now();
                for _ in 0..iters { black_box(mem::memchr_medium_32bloop_for_bench(&buf, b'Z')); }
                ov.push(t.elapsed().as_nanos() as f64 / iters as f64);
            };
            let mut run_new = || {
                let t = Instant::now();
                for _ in 0..iters { black_box(mem::memchr_medium_64lane_for_bench(&buf, b'Z')); }
                nv.push(t.elapsed().as_nanos() as f64 / iters as f64);
            };
            if old_first { run_old(); run_new(); } else { run_new(); run_old(); }
        }
        let (o10, n10) = (pctl(&ov, 0.1), pctl(&nv, 0.1));
        let (o50, n50) = (pctl(&ov, 0.5), pctl(&nv, 0.5));
        println!("MEMCHR-KERNEL n={n:<4} p10: old={o10:.2} new={n10:.2} ratio={:.3} | p50 ratio={:.3}  {}",
            n10 / o10, n50 / o50, if n10 < o10 { "NEW WINS" } else { "old" });
    }
}
