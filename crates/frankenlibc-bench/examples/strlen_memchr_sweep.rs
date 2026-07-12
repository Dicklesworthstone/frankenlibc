//! Size-sweep the two most-called scanners: does fl strlen/memchr lose to glibc per-byte?
//! (memory says both are 128B-folded — verify.) 'a'*n + NUL. vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type LenFn = unsafe extern "C" fn(*const i8) -> usize;
type ChrFn = unsafe extern "C" fn(*const core::ffi::c_void, i32, usize) -> *mut core::ffi::c_void;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_len: LenFn = unsafe { std::mem::transmute(libc::dlsym(h, b"strlen\0".as_ptr().cast())) };
    let g_chr: ChrFn = unsafe { std::mem::transmute(libc::dlsym(h, b"memchr\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    for &n in &[64usize, 256, 1024, 4096] {
        let mut s = vec![b'a'; n + 1];
        s[n] = 0;
        let sp = s.as_ptr();
        assert_eq!(unsafe { fa::strlen(sp as *const i8) }, n, "strlen n={n}");
        let needle = b'z' as i32; // absent -> full memchr scan of n bytes
        assert_eq!(
            unsafe { fa::memchr(sp as *const _, needle, n) }.is_null(),
            unsafe { g_chr(sp as *const _, needle, n) }.is_null(),
            "memchr n={n}"
        );
        let iters = 500_000u64;
        // strlen
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strlen(black_box(sp as *const i8)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_len(black_box(sp as *const i8)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_len(black_box(sp as *const i8)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strlen(black_box(sp as *const i8)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "strlen n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
        // memchr (absent)
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memchr(black_box(sp as *const _), needle, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_chr(black_box(sp as *const _), needle, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_chr(black_box(sp as *const _), needle, n) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::memchr(black_box(sp as *const _), needle, n) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "memchr n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
