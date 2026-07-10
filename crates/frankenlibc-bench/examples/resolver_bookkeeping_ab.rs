//! Profile the getnameinfo/getaddrinfo Resolver-family membrane bookkeeping components in isolation
//! (cc_fl): the resolver_stage_context+record helper pair vs the decide+observe pair. Determines
//! whether a central helper-level strict fast path captures most of the ~1.3µs, or a body change is
//! needed. Non-test binary => strict_passthrough_active() is true (deployed mode).
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
fn mean(xs: &[f64]) -> f64 { xs.iter().sum::<f64>() / xs.len() as f64 }
fn cv(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 { return 0.0; }
    100.0 * (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64).sqrt() / m
}

#[inline(never)]
fn stage() -> u64 { for _ in 0..REPS { fl::bench_resolver_stage_bookkeeping(); } black_box(REPS as u64) }
#[inline(never)]
fn decide() -> u64 { for _ in 0..REPS { fl::bench_resolver_decide_observe(); } black_box(REPS as u64) }

fn timed(mut f: impl FnMut() -> u64) -> Vec<f64> {
    let mut v = Vec::with_capacity(SAMPLES);
    for i in 0..SAMPLES {
        let s = Instant::now();
        black_box(f());
        if i >= WARMUP { v.push(s.elapsed().as_nanos() as f64 / REPS as f64); }
    }
    v
}

fn main() {
    black_box(stage()); black_box(decide());
    let s = timed(stage);
    let d = timed(decide);
    println!("resolver_stage_context+record : median {:8.2} ns/call  cv={:.1}%", median(&s), cv(&s));
    println!("decide+observe (Resolver)     : median {:8.2} ns/call  cv={:.1}%", median(&d), cv(&d));
    println!("TOTAL bookkeeping             : {:8.2} ns/call", median(&s) + median(&d));
}
