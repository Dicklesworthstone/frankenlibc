//! Size-sweep substring search: does fl strstr/memmem lose to glibc per-byte? Long haystack
//! 'a'*n + NUL, needle absent (forces full scan). vs glibc (dlmopen). Two needle shapes.
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type StrstrFn = unsafe extern "C" fn(*const i8, *const i8) -> *mut i8;
type MemmemFn = unsafe extern "C" fn(
    *const core::ffi::c_void,
    usize,
    *const core::ffi::c_void,
    usize,
) -> *mut core::ffi::c_void;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_ss: StrstrFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"strstr\0".as_ptr().cast())) };
    let g_mm: MemmemFn =
        unsafe { std::mem::transmute(libc::dlsym(h, b"memmem\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    // needle "abx": first 2 chars match the 'a' run (worst-ish for naive), 3rd never -> BMH-ish
    let needle = b"abx\0";
    let np = needle.as_ptr() as *const i8;
    let nlen = 3usize;
    for &n in &[256usize, 1024, 4096] {
        let mut s = vec![b'a'; n + 1];
        s[n] = 0;
        let sp = s.as_ptr() as *const i8;
        assert_eq!(
            unsafe { fa::strstr(sp, np) }.is_null(),
            unsafe { g_ss(sp, np) }.is_null(),
            "strstr n={n}"
        );
        assert_eq!(
            unsafe { fa::memmem(sp as *const _, n, needle.as_ptr() as *const _, nlen) }.is_null(),
            unsafe { g_mm(sp as *const _, n, needle.as_ptr() as *const _, nlen) }.is_null(),
            "memmem n={n}"
        );
        let iters = 200_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..50 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strstr(black_box(sp), np) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_ss(black_box(sp), np) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_ss(black_box(sp), np) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strstr(black_box(sp), np) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "strstr n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
