// gcvt head-to-head: fl float->string vs host glibc (dlmopen). Non-variadic, so
// callable directly. Output verified byte-identical before timing.
use std::ffi::{CStr, c_char, c_double, c_int, c_void};
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
        type GcvtFn = unsafe extern "C" fn(c_double, c_int, *mut c_char) -> *mut c_char;
        let gl_gcvt: GcvtFn =
            std::mem::transmute::<*mut c_void, GcvtFn>(libc::dlsym(h, b"gcvt\0".as_ptr().cast()));

        for &(label, v, nd) in &[
            ("pi", 3.14159265358979_f64, 17),
            ("big", 123456.789012345_f64, 15),
            ("small", 0.000123456789_f64, 12),
            ("e20", 1.0e20_f64, 17),
            ("neg", -9876.54321_f64, 10),
            ("round", 2.5_f64, 6),
        ] {
            let mut fl_buf = [0i8; 64];
            let mut gl_buf = [0i8; 64];
            frankenlibc_abi::stdlib_abi::gcvt(v, nd, fl_buf.as_mut_ptr());
            gl_gcvt(v, nd, gl_buf.as_mut_ptr());
            let fl_s = CStr::from_ptr(fl_buf.as_ptr()).to_string_lossy().into_owned();
            let gl_s = CStr::from_ptr(gl_buf.as_ptr()).to_string_lossy().into_owned();
            assert_eq!(fl_s, gl_s, "gcvt {label}: fl={fl_s:?} glibc={gl_s:?}");

            let iters = 2_000_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(frankenlibc_abi::stdlib_abi::gcvt(
                    black_box(v),
                    nd,
                    black_box(fl_buf.as_mut_ptr()),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_gcvt(black_box(v), nd, black_box(gl_buf.as_mut_ptr())));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!("GCVT {label} nd={nd} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x", fl / gl);
        }
    }
}
