//! In-process A/B: NEW deployed fa::memchr (AVX2 asm kernel for n>=128) vs OLD
//! core::memchr (Simd<u8,64> fold). Same absent-needle buffer, same process. Ratio cancels
//! worker — the reliable test of whether the asm kernel actually beats the portable fold.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
fn main() {
    use frankenlibc_abi::string_abi as fa;
    for &n in &[128usize, 256, 512, 1024, 4096, 16384] {
        let mut s = vec![b'a'; n + 16];
        let sp = s.as_mut_ptr();
        let needle = b'z' as i32; // absent
        // correctness: both None
        let new_r = unsafe { fa::memchr(sp as *const _, needle, n) };
        let old_r = frankenlibc_core::string::mem::memchr(
            unsafe { std::slice::from_raw_parts(sp, n) },
            needle as u8,
            n,
        );
        assert_eq!(new_r.is_null(), old_r.is_none(), "mismatch n={n}");
        let iters = 500_000u64;
        let (mut nv, mut ov) = (Vec::new(), Vec::new());
        for r in 0..60 {
            let nw = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memchr(black_box(sp as *const _), needle, n) });
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            let o = || {
                let t = Instant::now();
                for _ in 0..iters {
                    let sl = unsafe { std::slice::from_raw_parts(black_box(sp), n) };
                    black_box(frankenlibc_core::string::mem::memchr(sl, needle as u8, n));
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            if r % 2 == 0 {
                nv.push(nw());
                ov.push(o());
            } else {
                ov.push(o());
                nv.push(nw());
            }
        }
        let (nn, oo) = (pctl(&nv, 0.1), pctl(&ov, 0.1));
        println!(
            "memchr n={n:<6} OLD(core Simd64)={oo:7.1}ns NEW(asm)={nn:7.1}ns  new/old={:.3} ({:.2}x)",
            nn / oo,
            oo / nn
        );
    }
}
