// mbstowcs COUNT mode (dst==NULL) head-to-head vs host glibc (dlmopen). Count
// mode currently decodes with a scalar per-char `mbtowc` loop just to tally the
// code points. Return value verified equal first. Pristine glibc via dlmopen.
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

        let cyr: String = (0..300)
            .map(|i| char::from_u32(0x0410 + (i % 0x40)).unwrap())
            .collect();
        let cjk: String = (0..300)
            .map(|i| char::from_u32(0x4E00 + (i % 0x400)).unwrap())
            .collect();

        for &(label, ref src_str) in &[
            (
                "ascii",
                "The quick brown fox jumps over the lazy dog. ".repeat(30),
            ),
            ("mixed", "café résumé naïve façade ".repeat(40)),
            ("cyrillic", cyr),
            ("cjk", cjk),
        ] {
            let n = src_str.len();
            let src_c = CString::new(src_str.clone()).unwrap();
            let src_p = src_c.as_ptr() as *const u8; // NUL-terminated, for fl's scanner

            let fl_len = frankenlibc_abi::wchar_abi::mbstowcs(std::ptr::null_mut(), src_p, 0);
            let gl_len = gl_mbstowcs(std::ptr::null_mut(), src_c.as_ptr(), 0);
            assert_eq!(
                fl_len, gl_len,
                "mbstowcs count {label}: fl={fl_len} glibc={gl_len}"
            );

            let iters = (50_000_000usize / n).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::wchar_abi::mbstowcs(
                    std::ptr::null_mut(),
                    black_box(src_p),
                    0,
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_mbstowcs(std::ptr::null_mut(), black_box(src_c.as_ptr()), 0));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "MBSTOWCS_COUNT {label} n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
