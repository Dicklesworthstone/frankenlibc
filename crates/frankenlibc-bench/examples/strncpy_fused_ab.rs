//! Bounded fused strncpy prefix: exhaustive byte-identity check (fused == two-pass over
//! align × strlen × n, incl. n<strlen, n==strlen, n>strlen, and 32-byte-window edges)
//! plus a same-process timing A/B. The kernel is page-safety-critical and n-bounded, so
//! correctness is validated over every boundary before it's wired into strncpy_core.
//!
//! Run: cargo run --release --example strncpy_fused_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    use frankenlibc_abi::string_abi as s;

    // Exhaustive correctness: reference copy_len = min(strlen, n); dst[..copy_len] == src.
    let mut checks = 0u64;
    for align in 0..33usize {
        for slen in 0..70usize {
            for n in 0..72usize {
                let mut sbuf = vec![0u8; align + slen + 1 + 96];
                for k in 0..slen {
                    sbuf[align + k] = 1 + ((align * 5 + k * 11) % 200) as u8; // non-zero
                }
                sbuf[align + slen] = 0;
                let sp = unsafe { sbuf.as_ptr().add(align) };
                let want = slen.min(n);
                let mut d1 = vec![0x55u8; n + 96];
                let mut d2 = vec![0x55u8; n + 96];
                let l1 = if n == 0 {
                    0
                } else {
                    unsafe { s::bench_strncpy_two_pass(d1.as_mut_ptr(), sp, n) }
                };
                let l2 = if n == 0 {
                    0
                } else {
                    unsafe { s::bench_strncpy_fused(d2.as_mut_ptr(), sp, n) }
                };
                assert_eq!(
                    l1, want,
                    "two-pass copy_len align={align} slen={slen} n={n}"
                );
                assert_eq!(l2, want, "fused copy_len align={align} slen={slen} n={n}");
                assert_eq!(
                    &d1[..want],
                    &d2[..want],
                    "bytes align={align} slen={slen} n={n}"
                );
                // fused must not write beyond copy_len (strncpy pads separately)
                assert_eq!(
                    d2[want], 0x55,
                    "fused overwrote past copy_len align={align} slen={slen} n={n}"
                );
                checks += 1;
            }
        }
    }
    println!("correctness: {checks} (align×slen×n) fused==two-pass, no over-write ✓");

    // Timing A/B: strlen==n (buffer-filling: max double-read savings) and strlen<<n.
    let cases: [(usize, usize); 6] = [
        (16, 16),
        (32, 32),
        (64, 64),
        (128, 128),
        (8, 128),
        (16, 256),
    ];
    for (slen, n) in cases {
        let mut src: Vec<u8> = (0..slen).map(|i| b'a' + (i % 26) as u8).collect();
        src.push(0);
        let mut dst = vec![0u8; n + 64];
        let dp = dst.as_mut_ptr();
        let sp = src.as_ptr();
        let iters = 15_000u64;
        let (mut tv, mut fv) = (Vec::new(), Vec::new());
        for r in 0..80 {
            let two_first = r % 2 == 0;
            let mut run_two = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { s::bench_strncpy_two_pass(dp, sp, n) });
                }
                tv.push(t.elapsed().as_nanos() as f64 / iters as f64);
            };
            let mut run_fused = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { s::bench_strncpy_fused(dp, sp, n) });
                }
                fv.push(t.elapsed().as_nanos() as f64 / iters as f64);
            };
            if two_first {
                run_two();
                run_fused();
            } else {
                run_fused();
                run_two();
            }
        }
        let (t10, f10) = (pctl(&tv, 0.1), pctl(&fv, 0.1));
        println!(
            "STRNCPY slen={slen:<4} n={n:<4} p10: twopass={t10:.2} fused={f10:.2} ratio={:.3}  {}",
            f10 / t10,
            if f10 < t10 { "FUSED WINS" } else { "two-pass" }
        );
    }
}
