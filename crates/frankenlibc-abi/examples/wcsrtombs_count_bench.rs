// wcsrtombs COUNT mode (dst==NULL) head-to-head vs host glibc (dlmopen). Now
// routed through the SIMD wcs_encoded_len. Return value verified equal first.
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
        type WcsrtombsFn =
            unsafe extern "C" fn(*mut c_char, *mut *const i32, usize, *mut c_void) -> usize;
        let gl_setlocale: SetlocaleFn = std::mem::transmute::<*mut c_void, SetlocaleFn>(
            libc::dlsym(h, b"setlocale\0".as_ptr().cast()),
        );
        let gl_wcsrtombs: WcsrtombsFn = std::mem::transmute::<*mut c_void, WcsrtombsFn>(
            libc::dlsym(h, b"wcsrtombs\0".as_ptr().cast()),
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

        for &(label, ref s) in &[
            (
                "ascii",
                "The quick brown fox jumps over the lazy dog. ".repeat(30),
            ),
            ("mixed", "café résumé naïve façade ".repeat(40)),
            ("cyrillic", cyr),
            ("cjk", cjk),
        ] {
            let mut w: Vec<i32> = s.chars().map(|c| c as i32).collect();
            w.push(0);
            let nchars = w.len();

            let mut fp = w.as_ptr();
            let fl_len = frankenlibc_abi::wchar_abi::wcsrtombs(
                std::ptr::null_mut(),
                &mut fp,
                0,
                std::ptr::null_mut(),
            );
            let mut gp = w.as_ptr();
            let gl_len = gl_wcsrtombs(std::ptr::null_mut(), &mut gp, 0, std::ptr::null_mut());
            assert_eq!(
                fl_len, gl_len,
                "wcsrtombs count {label}: fl={fl_len} glibc={gl_len}"
            );

            let iters = (40_000_000usize / nchars).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut p = w.as_ptr();
                black_box(frankenlibc_abi::wchar_abi::wcsrtombs(
                    std::ptr::null_mut(),
                    black_box(&mut p),
                    0,
                    std::ptr::null_mut(),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut p = w.as_ptr();
                black_box(gl_wcsrtombs(
                    std::ptr::null_mut(),
                    black_box(&mut p),
                    0,
                    std::ptr::null_mut(),
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "WCSRTOMBS_COUNT {label} nchars={nchars} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
