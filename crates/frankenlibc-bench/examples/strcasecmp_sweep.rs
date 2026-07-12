//! Size-sweep: does fl strcasecmp lose to glibc for long case-insensitive-equal strings?
//! scan_strcasecmp is 8-byte SWAR (swar_ascii_lower), 4x narrower than a 32B SIMD scan.
//! s1='A'*n, s2='a'*n (case-differ, ci-equal -> full fold+scan). vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type CmpFn = unsafe extern "C" fn(*const i8, *const i8) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let sl: unsafe extern "C" fn(i32, *const i8) -> *mut i8 =
        unsafe { std::mem::transmute(libc::dlsym(h, b"setlocale\0".as_ptr().cast())) };
    unsafe {
        let _ = sl(6, b"C\0".as_ptr() as *const i8);
    } // C locale so glibc strcasecmp = ASCII fold
    let g: CmpFn = unsafe { std::mem::transmute(libc::dlsym(h, b"strcasecmp\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    for &n in &[64usize, 256, 1024] {
        let mut s1 = vec![b'A'; n + 1];
        s1[n] = 0;
        let mut s2 = vec![b'a'; n + 1];
        s2[n] = 0;
        let (c1, c2) = (s1.as_ptr() as *const i8, s2.as_ptr() as *const i8);
        assert_eq!(
            unsafe { fa::strcasecmp(c1, c2) }.signum(),
            unsafe { g(c1, c2) }.signum(),
            "strcasecmp n={n}"
        );
        let iters = 400_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..50 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strcasecmp(black_box(c1), black_box(c2)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(black_box(c1), black_box(c2)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(black_box(c1), black_box(c2)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strcasecmp(black_box(c1), black_box(c2)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "strcasecmp n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
