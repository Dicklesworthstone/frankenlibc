//! Same-process A/B: deployed strcpy two-pass (scan_c_string + raw_memcpy, reads src
//! twice) vs the existing-but-unwired fused single-pass `fused_strcpy_bytes`. Interleaved
//! rounds cancel per-worker drift in the fused/twopass ratio.
//!
//! Run: cargo run --release --example strcpy_fused_ab --features abi-bench

use std::hint::black_box;
use std::time::Instant;

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

fn main() {
    use frankenlibc_abi::string_abi as s;

    // Exhaustive byte-identity cross-check: fused vs two-pass over every src alignment
    // (0..64) and length (0..200), since the strict-path kernel is what we're wiring in
    // and cfg(test) conformance only exercises the hardened path.
    {
        let mut checks = 0u64;
        for align in 0..64usize {
            for len in 0..200usize {
                let mut sbuf = vec![0u8; align + len + 1 + 64];
                for k in 0..len {
                    sbuf[align + k] = 1 + ((align * 7 + k * 13) % 200) as u8; // non-zero
                }
                sbuf[align + len] = 0; // NUL
                let sp = unsafe { sbuf.as_ptr().add(align) };
                let mut d1 = vec![0xAAu8; len + 1 + 64];
                let mut d2 = vec![0xAAu8; len + 1 + 64];
                let l1 = unsafe { s::bench_strcpy_two_pass(d1.as_mut_ptr(), sp) };
                let l2 = unsafe { s::bench_strcpy_fused(d2.as_mut_ptr(), sp) };
                assert_eq!(l1, len, "two-pass len align={align} len={len}");
                assert_eq!(l2, len, "fused len align={align} len={len}");
                assert_eq!(&d1[..=len], &d2[..=len], "bytes align={align} len={len}");
                checks += 1;
            }
        }
        println!("correctness: {checks} (align×len) fused==two-pass byte-identical ✓");
    }

    let sizes = [8usize, 16, 32, 64, 128, 256];
    let iters = 15_000u64;
    let rounds = 60;

    for &n in &sizes {
        let src: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).chain([0u8]).collect();
        let mut dst = vec![0u8; n + 64];
        // warm + correctness cross-check
        let l1 = unsafe { s::bench_strcpy_two_pass(dst.as_mut_ptr(), src.as_ptr()) };
        let mut dst2 = vec![0u8; n + 64];
        let l2 = unsafe { s::bench_strcpy_fused(dst2.as_mut_ptr(), src.as_ptr()) };
        assert_eq!(l1, l2, "len mismatch n={n}");
        assert_eq!(&dst[..=l1], &dst2[..=l2], "bytes mismatch n={n}");

        let (mut tv, mut fv) = (Vec::new(), Vec::new());
        let dp = dst.as_mut_ptr();
        let sp = src.as_ptr();
        for r in 0..rounds {
            let two_first = r % 2 == 0;
            let mut run_two = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { s::bench_strcpy_two_pass(dp, sp) });
                }
                tv.push(t.elapsed().as_nanos() as f64 / iters as f64);
            };
            let mut run_fused = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { s::bench_strcpy_fused(dp, sp) });
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
        let (t50, f50) = (pctl(&tv, 0.5), pctl(&fv, 0.5));
        let (t10, f10) = (pctl(&tv, 0.1), pctl(&fv, 0.1));
        println!(
            "STRCPY n={n:<4} p10: twopass={t10:.2} fused={f10:.2} ratio={:.3}  |  p50 ratio={:.3}  {}",
            f10 / t10,
            f50 / t50,
            if f10 < t10 { "FUSED WINS" } else { "two-pass" }
        );
    }
}
