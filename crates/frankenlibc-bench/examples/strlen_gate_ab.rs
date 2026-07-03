//! Same-process A/B: deployed-strlen prologue gate, OLD (5-check raw fan-out) vs
//! NEW (cheap bootstrap phase-read), both followed by the strict check. Isolates the
//! four TLS/reentry probes the reorder removes from the hot path. Interleaved rounds
//! cancel per-worker drift in the NEW/OLD ratio.
//!
//! Run: cargo run --release --example strlen_gate_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    use frankenlibc_abi::string_abi as s;

    let iters = 100_000u64;
    let rounds = 200;
    let (mut ov, mut nv) = (Vec::new(), Vec::new());

    // warm
    for _ in 0..10_000 {
        black_box(s::strlen_gate_old_for_bench());
        black_box(s::strlen_gate_new_for_bench());
    }

    for r in 0..rounds {
        let old_first = r % 2 == 0;
        let mut run_old = || {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(s::strlen_gate_old_for_bench());
            }
            ov.push(t.elapsed().as_nanos() as f64 / iters as f64);
        };
        let mut run_new = || {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(s::strlen_gate_new_for_bench());
            }
            nv.push(t.elapsed().as_nanos() as f64 / iters as f64);
        };
        if old_first {
            run_old();
            run_new();
        } else {
            run_new();
            run_old();
        }
    }

    let (o50, n50) = (pctl(&ov, 0.5), pctl(&nv, 0.5));
    let (o10, n10) = (pctl(&ov, 0.1), pctl(&nv, 0.1));
    println!("deployed-strlen prologue gate, per-call ns:");
    println!("  OLD (raw 5-check)  p10={o10:.2} p50={o50:.2}");
    println!("  NEW (bootstrap)    p10={n10:.2} p50={n50:.2}");
    println!(
        "  ratio NEW/OLD  p10={:.3}  p50={:.3}   (<1.0 = reorder wins)",
        n10 / o10,
        n50 / o50
    );
    println!("  gate cost removed/call  p50={:.2} ns", o50 - n50);
}
