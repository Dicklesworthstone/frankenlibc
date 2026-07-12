// strtod head-to-head: fl core parser vs host glibc strtod (dlmopen). Simple numbers are
// the common case (config/CSV/JSON); hard numbers (subnormal/max/halfway) stress rounding.
// Bit-exact correctness check vs glibc on every case.
use std::ffi::{CString, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::stdlib::conversion::strtod_impl;

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type StrtodFn = unsafe extern "C" fn(*const libc::c_char, *mut *mut libc::c_char) -> f64;
        let gl_strtod: StrtodFn = std::mem::transmute::<*mut c_void, StrtodFn>(libc::dlsym(
            h,
            b"strtod\0".as_ptr().cast(),
        ));

        let cases = [
            "3.14159",
            "1.5",
            "123456.789012",
            "0.1",
            "9007199254740993",
            "2.2250738585072014e-308",
            "1.7976931348623157e308",
        ];
        for s in cases.iter() {
            let bytes = s.as_bytes();
            let (fl_v, _, _) = strtod_impl(bytes);
            let cs = CString::new(*s).unwrap();
            let gl_v = gl_strtod(cs.as_ptr(), std::ptr::null_mut());
            assert_eq!(
                fl_v.to_bits(),
                gl_v.to_bits(),
                "strtod {s:?}: fl={fl_v} glibc={gl_v}"
            );
            let iters = 100_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(strtod_impl(black_box(bytes)));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strtod(black_box(cs.as_ptr()), std::ptr::null_mut()));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "STRTOD {s:?} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
