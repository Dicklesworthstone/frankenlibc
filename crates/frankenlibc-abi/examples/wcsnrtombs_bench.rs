// wcsnrtombs head-to-head: fl (n-bounded wide->multibyte, now routed through the
// shared SIMD wcs_simd_prefix) vs host glibc gconv. Pristine glibc via dlmopen so
// `wcsnrtombs` is glibc's, not fl's interposed copy. Output verified byte-identical
// before timing. Interleaved / contiguous-2-byte / contiguous-3-byte wide sources.
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
        type WcsnrtombsFn =
            unsafe extern "C" fn(*mut c_char, *mut *const i32, usize, usize, *mut c_void) -> usize;
        let gl_setlocale: SetlocaleFn = std::mem::transmute::<*mut c_void, SetlocaleFn>(
            libc::dlsym(h, b"setlocale\0".as_ptr().cast()),
        );
        let gl_wcsnrtombs: WcsnrtombsFn = std::mem::transmute::<*mut c_void, WcsnrtombsFn>(
            libc::dlsym(h, b"wcsnrtombs\0".as_ptr().cast()),
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
            let nwc = w.len();
            let cap = s.len() * 4 + 16;

            // Correctness: fl vs glibc, byte-for-byte.
            let mut fl_dst = vec![0i8; cap];
            let mut fp = w.as_ptr();
            let fl_len = frankenlibc_abi::wchar_abi::wcsnrtombs(
                fl_dst.as_mut_ptr(),
                &mut fp,
                nwc,
                fl_dst.len(),
                std::ptr::null_mut(),
            );
            let mut gl_dst = vec![0i8; cap];
            let mut gp = w.as_ptr();
            let gl_len = gl_wcsnrtombs(
                gl_dst.as_mut_ptr(),
                &mut gp,
                nwc,
                gl_dst.len(),
                std::ptr::null_mut(),
            );
            assert_eq!(
                fl_len, gl_len,
                "wcsnrtombs {label} len: fl={fl_len} glibc={gl_len}"
            );
            for k in 0..fl_len {
                assert_eq!(fl_dst[k], gl_dst[k], "wcsnrtombs {label} byte {k}");
            }

            let iters = (40_000_000usize / nwc).max(2000);
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut p = w.as_ptr();
                black_box(frankenlibc_abi::wchar_abi::wcsnrtombs(
                    black_box(fl_dst.as_mut_ptr()),
                    black_box(&mut p),
                    nwc,
                    fl_dst.len(),
                    std::ptr::null_mut(),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut p = w.as_ptr();
                black_box(gl_wcsnrtombs(
                    black_box(gl_dst.as_mut_ptr()),
                    black_box(&mut p),
                    nwc,
                    gl_dst.len(),
                    std::ptr::null_mut(),
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "WCSNRTOMBS {label} nwc={nwc} fl={fl:.0}ns glibc={gl:.0}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
