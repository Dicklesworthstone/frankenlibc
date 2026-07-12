//! Size-sweep: does fl strrchr lose per-byte to glibc? strrchr must scan the whole string
//! for the LAST occurrence. Search a char NOT present (full scan -> null). vs glibc (dlmopen).
use std::hint::black_box;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
type ChrFn = unsafe extern "C" fn(*const i8, i32) -> *mut i8;
fn main() {
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    let g: ChrFn = unsafe { std::mem::transmute(libc::dlsym(h, b"strrchr\0".as_ptr().cast())) };
    use frankenlibc_abi::string_abi as fa;
    for &n in &[64usize, 256, 1024, 4096] {
        let mut s = vec![b'a'; n + 1];
        s[n] = 0;
        let sp = s.as_ptr() as *const i8;
        let needle = b'z' as i32; // not present -> full scan, null
        assert_eq!(
            unsafe { fa::strrchr(sp, needle) }.is_null(),
            unsafe { g(sp, needle) }.is_null(),
            "strrchr n={n}"
        );
        let iters = 400_000u64;
        let (mut fl, mut gl) = (Vec::new(), Vec::new());
        for r in 0..50 {
            if r % 2 == 0 {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strrchr(black_box(sp), needle) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(black_box(sp), needle) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            } else {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { g(black_box(sp), needle) });
                }
                gl.push(t.elapsed().as_nanos() as f64 / iters as f64);
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fa::strrchr(black_box(sp), needle) });
                }
                fl.push(t.elapsed().as_nanos() as f64 / iters as f64);
            }
        }
        let (f, gg) = (pctl(&fl, 0.1), pctl(&gl, 0.1));
        println!(
            "strrchr n={n:<5} fl={f:8.1} glibc={gg:8.1} fl/glibc={:.3}{}",
            f / gg,
            if f / gg > 1.2 { "  <-- LOSS" } else { "" }
        );
    }
}
