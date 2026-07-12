//! Size-sweep: does fl wcscmp lose to glibc for long EQUAL wide strings (per-byte gap)?
//! scan_wcscmp_simd loops 8 u32s (32B)/iter with a dual page-guard every iteration (same
//! non-unrolled shape as the fixed scan_strcmp). Test len 64/256/1024 wchars vs glibc.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type WcmpFn = unsafe extern "C" fn(*const i32, *const i32) -> i32;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: WcmpFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wcscmp\0".as_ptr().cast())) };
    use frankenlibc_abi::wchar_abi as wa;
    for &n in &[64usize, 256, 1024] {
        let mut w1: Vec<u32> = vec![b'a' as u32; n + 1];
        w1[n] = 0;
        let mut w2: Vec<u32> = vec![b'a' as u32; n + 1];
        w2[n] = 0;
        let p1 = w1.as_ptr();
        let p2 = w2.as_ptr();
        assert_eq!(
            unsafe { wa::wcscmp(p1, p2) }.signum(),
            unsafe { g(p1 as *const i32, p2 as *const i32) }.signum(),
            "wcscmp n={n}"
        );
        let iters = 400_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..50 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcscmp(black_box(p1), black_box(p2)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p1 as *const i32, p2 as *const i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(p1 as *const i32, p2 as *const i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcscmp(black_box(p1), black_box(p2)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "wcscmp n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
