//! Size-sweep wcschr/wcslen (wide NUL-terminated): per-byte gap vs glibc? 'a'*n + NUL.
//! wcschr: absent needle (full scan to NUL). wcslen: scan to NUL. vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type ChrFn = unsafe extern "C" fn(*const i32, i32) -> *mut i32;
type LenFn = unsafe extern "C" fn(*const i32) -> usize;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g_chr: ChrFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wcschr\0".as_ptr().cast())) };
    let g_len: LenFn = unsafe { std::mem::transmute(libc::dlsym(h, b"wcslen\0".as_ptr().cast())) };
    use frankenlibc_abi::wchar_abi as wa;
    for &n in &[64usize, 256, 1024, 4096] {
        let mut s: Vec<u32> = vec![b'a' as u32; n + 1];
        s[n] = 0;
        let sp = s.as_ptr();
        let needle = b'z' as u32;
        assert_eq!(
            unsafe { wa::wcschr(sp, needle) }.is_null(),
            unsafe { g_chr(sp as *const i32, needle as i32) }.is_null(),
            "wcschr n={n}"
        );
        assert_eq!(unsafe { wa::wcslen(sp) }, n, "wcslen n={n}");
        let iters = 300_000u64;
        // wcschr
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcschr(black_box(sp), needle) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_chr(black_box(sp as *const i32), needle as i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_chr(black_box(sp as *const i32), needle as i32) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcschr(black_box(sp), needle) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "wcschr n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
        // wcslen
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..40 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcslen(black_box(sp)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_len(black_box(sp as *const i32)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g_len(black_box(sp as *const i32)) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { wa::wcslen(black_box(sp)) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "wcslen n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
