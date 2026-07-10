//! A/B for the Resolver `observe()` fast-path lever (cc_fl): adding `ApiFamily::Resolver` to the
//! observe() telemetry fast-path list skips the ~1334 ns non-adverse observe on every resolver call
//! (getaddrinfo + hardened-mode getnameinfo_full). ORIG reconstructs the pre-lever cost via
//! `adverse=true` (which bypasses the fast-path list); CAND is the deployed `observe(Resolver,
//! false)`, now fast. Interleaved paired in ONE binary, order swapped every sample; null control
//! (CAND vs CAND) first. Non-test binary => strict passthrough (deployed mode).
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example resolver_bookkeeping_ab`
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const SAMPLES: usize = 400;
const REPS: usize = 20_000;
const WARMUP: usize = 60;

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}
fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}
fn cv(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    100.0 * (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64).sqrt() / m
}

#[inline(never)]
fn cand() -> u64 {
    for _ in 0..REPS {
        fl::bench_resolver_decide_observe();
    }
    black_box(REPS as u64)
}
#[inline(never)]
fn orig() -> u64 {
    for _ in 0..REPS {
        fl::bench_resolver_decide_observe_slow();
    }
    black_box(REPS as u64)
}
#[inline(never)]
fn stage() -> u64 {
    for _ in 0..REPS {
        fl::bench_resolver_stage_bookkeeping();
    }
    black_box(REPS as u64)
}

fn paired<F: FnMut() -> u64, G: FnMut() -> u64>(mut a: F, mut b: G) -> (Vec<f64>, Vec<f64>) {
    let (mut xa, mut xb) = (Vec::new(), Vec::new());
    for i in 0..SAMPLES {
        let (ta, tb) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            let s = Instant::now();
            black_box(b());
            (t1, s.elapsed())
        } else {
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            let s = Instant::now();
            black_box(a());
            (s.elapsed(), t2)
        };
        if i >= WARMUP {
            xa.push(ta.as_nanos() as f64 / REPS as f64);
            xb.push(tb.as_nanos() as f64 / REPS as f64);
        }
    }
    (xa, xb)
}

fn report(label: &str, o: &[f64], c: &[f64]) {
    let ratio: Vec<f64> = c.iter().zip(o.iter()).map(|(x, y)| x / y).collect();
    println!(
        "{label}: orig {:.1}ns  cand {:.1}ns  paired cand/orig median {:.4} ({:.2}x)  cv={:.1}%",
        median(o),
        median(c),
        median(&ratio),
        1.0 / median(&ratio),
        cv(&ratio),
    );
}

fn main() {
    black_box(cand());
    black_box(orig());
    black_box(stage());

    let (n1, n2) = paired(cand, cand);
    report("NULL CONTROL (cand vs cand)", &n1, &n2);
    let (o, c) = paired(orig, cand);
    report("LEVER observe fast-path (slow->fast)", &o, &c);

    let s = paired(stage, stage).0;
    println!("  reference: resolver_stage_context+record median {:.1}ns", median(&s));
}
