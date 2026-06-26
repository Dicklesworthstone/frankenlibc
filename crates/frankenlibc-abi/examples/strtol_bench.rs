// strtol head-to-head: fl core integer parser vs host glibc strtol (dlmopen). Decimal,
// negative, max, hex (base 16), octal (base 8). Value-exact check vs glibc on every case.
use std::ffi::{c_void, CString};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::stdlib::conversion::strtol_impl;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type StrtolFn =
            unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char, i32) -> i64;
        let gl_strtol: StrtolFn =
            std::mem::transmute::<*mut c_void, StrtolFn>(libc::dlsym(h, b"strtol\0".as_ptr().cast()));

        let cases: [(&str, i32); 9] = [
            ("42", 10),
            ("1234567890", 10),
            ("9223372036854775807", 10),
            ("-12345", 10),
            ("0xDEADBEEF", 16),
            ("755", 8),
            ("0xFF", 16),
            ("0x1F", 16),
            ("17", 8),
        ];
        for &(s, base) in cases.iter() {
            let bytes = s.as_bytes();
            let (fl_v, _, _) = strtol_impl(bytes, base);
            let cs = CString::new(s).unwrap();
            let gl_v = gl_strtol(cs.as_ptr(), std::ptr::null_mut(), base);
            assert_eq!(fl_v, gl_v, "strtol {s:?} base {base}: fl={fl_v} glibc={gl_v}");
            let iters = 200_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(strtol_impl(black_box(bytes), base));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strtol(black_box(cs.as_ptr()), std::ptr::null_mut(), base));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("STRTOL {s:?} base={base} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x", fl / gl);
        }
    }
}
