// mbsnrtowcs WRITE mode (dst != NULL) head-to-head vs host glibc (dlmopen). Was
// ASCII-bulk + scalar `mbrtowc` per multibyte char; now routed through the SIMD
// `mbs_decode_prefix` (byte-bounded, boundary-safe). Output verified
// byte-identical first. Pristine glibc via dlmopen.
use std::ffi::{CString, c_char, c_void};
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
        type SetlocaleFn = unsafe extern "C" fn(i32, *const c_char) -> *mut c_char;
        type MbsnrtowcsFn =
            unsafe extern "C" fn(*mut i32, *mut *const c_char, usize, usize, *mut c_void) -> usize;
        let gl_setlocale: SetlocaleFn = std::mem::transmute::<*mut c_void, SetlocaleFn>(
            libc::dlsym(h, b"setlocale\0".as_ptr().cast()),
        );
        let gl_mbsnrtowcs: MbsnrtowcsFn = std::mem::transmute::<*mut c_void, MbsnrtowcsFn>(
            libc::dlsym(h, b"mbsnrtowcs\0".as_ptr().cast()),
        );
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
            let base = src_c.as_ptr();
            let nms = n + 1;
            let cap = n + 8;

            let mut fl_dst = vec![0i32; cap];
            let mut fp = base;
            let fl_len = frankenlibc_abi::wchar_abi::mbsnrtowcs(
                fl_dst.as_mut_ptr(),
                &mut fp as *mut *const c_char,
                nms,
                cap,
                std::ptr::null_mut(),
            );
            let mut gl_dst = vec![0i32; cap];
            let mut gp = base;
            let gl_len = gl_mbsnrtowcs(
                gl_dst.as_mut_ptr(),
                &mut gp as *mut *const c_char,
                nms,
                cap,
                std::ptr::null_mut(),
            );
            assert_eq!(fl_len, gl_len, "mbsnrtowcs write {label} len");
            for k in 0..fl_len {
                assert_eq!(fl_dst[k], gl_dst[k], "mbsnrtowcs write {label} char {k}");
            }

            let iters = (50_000_000usize / n).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut p = base;
                black_box(frankenlibc_abi::wchar_abi::mbsnrtowcs(
                    black_box(fl_dst.as_mut_ptr()),
                    black_box(&mut p as *mut *const c_char),
                    nms,
                    cap,
                    std::ptr::null_mut(),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut p = base;
                black_box(gl_mbsnrtowcs(
                    black_box(gl_dst.as_mut_ptr()),
                    black_box(&mut p as *mut *const c_char),
                    nms,
                    cap,
                    std::ptr::null_mut(),
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "MBSNRTOWCS_WRITE {label} n={n} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
