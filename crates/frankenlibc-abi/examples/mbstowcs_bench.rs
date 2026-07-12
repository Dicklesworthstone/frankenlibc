// mbstowcs head-to-head: fl SIMD UTF-8 decoder vs host glibc per-char state machine.
// Long ASCII-heavy text (the common case) — fl's wide decode should beat glibc's scalar
// loop. Pristine glibc via dlmopen, put in UTF-8 mode via its own setlocale. Output
// verified identical.
use std::ffi::{CString, c_void};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type SetlocaleFn = unsafe extern "C" fn(i32, *const libc::c_char) -> *mut libc::c_char;
        type MbstowcsFn = unsafe extern "C" fn(*mut i32, *const libc::c_char, usize) -> usize;
        let gl_setlocale: SetlocaleFn = std::mem::transmute::<*mut c_void, SetlocaleFn>(
            libc::dlsym(h, b"setlocale\0".as_ptr().cast()),
        );
        let gl_mbstowcs: MbstowcsFn = std::mem::transmute::<*mut c_void, MbstowcsFn>(libc::dlsym(
            h,
            b"mbstowcs\0".as_ptr().cast(),
        ));
        assert!(
            !gl_setlocale(libc::LC_ALL, b"C.UTF-8\0".as_ptr().cast()).is_null(),
            "setlocale failed"
        );

        for &(label, ref src_str) in &[
            (
                "ascii",
                "The quick brown fox jumps over the lazy dog. ".repeat(40),
            ),
            ("mixed", "café résumé naïve façade ".repeat(40)),
        ] {
            let src = src_str.as_bytes();
            let n = src.len();
            let mut fl_dest = vec![0u32; n + 1];
            let fl_len = match frankenlibc_core::string::wchar::mbstowcs(&mut fl_dest, src) {
                Some(l) => l,
                None => {
                    println!("MBSTOWCS {label}: fl returned None");
                    continue;
                }
            };
            let src_c = CString::new(src_str.clone()).unwrap();
            let mut gl_dest = vec![0i32; n + 1];
            let gl_len = gl_mbstowcs(gl_dest.as_mut_ptr(), src_c.as_ptr(), n + 1);
            assert_eq!(
                fl_len, gl_len,
                "mbstowcs {label} len: fl={fl_len} glibc={gl_len}"
            );
            for k in 0..fl_len {
                assert_eq!(fl_dest[k], gl_dest[k] as u32, "mbstowcs {label} char {k}");
            }

            let iters = (50_000_000usize / n).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_core::string::wchar::mbstowcs(
                    black_box(&mut fl_dest),
                    black_box(src),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_mbstowcs(
                    black_box(gl_dest.as_mut_ptr()),
                    black_box(src_c.as_ptr()),
                    n + 1,
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "MBSTOWCS {label} n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
