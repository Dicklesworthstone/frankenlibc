// snprintf head-to-head: fl (interposed) vs host glibc (dlmopen). Variadic.
// Output verified byte-identical first. Probes pure-literal, single-int, and
// mixed formats — the literal/format-scan path is the strftime-style suspect.
use std::ffi::{CStr, c_char, c_int, c_void};
use std::hint::black_box;
use std::time::Instant;

unsafe extern "C" {
    fn snprintf(s: *mut c_char, n: usize, fmt: *const c_char, ...) -> c_int;
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type SnFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;
        let gl: SnFn = std::mem::transmute::<*mut c_void, SnFn>(libc::dlsym(
            h,
            b"snprintf\0".as_ptr().cast(),
        ));

        let mut fl_buf = [0i8; 128];
        let mut gl_buf = [0i8; 128];

        macro_rules! probe {
            ($label:expr, $fmt:expr, $run_fl:expr, $run_gl:expr) => {{
                let fmt = concat!($fmt, "\0").as_ptr() as *const c_char;
                let fln = $run_fl(fl_buf.as_mut_ptr(), fmt);
                let gln = $run_gl(gl, gl_buf.as_mut_ptr(), fmt);
                let fls = CStr::from_ptr(fl_buf.as_ptr()).to_string_lossy().into_owned();
                let gls = CStr::from_ptr(gl_buf.as_ptr()).to_string_lossy().into_owned();
                assert_eq!((fln, &fls), (gln, &gls), "snprintf {} mismatch", $label);
                let iters = 3_000_000usize;
                let t0 = Instant::now();
                for _ in 0..iters {
                    black_box($run_fl(black_box(fl_buf.as_mut_ptr()), black_box(fmt)));
                }
                let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
                let t1 = Instant::now();
                for _ in 0..iters {
                    black_box($run_gl(gl, black_box(gl_buf.as_mut_ptr()), black_box(fmt)));
                }
                let g = t1.elapsed().as_nanos() as f64 / iters as f64;
                println!("SNPRINTF {} fl={:.1}ns glibc={:.1}ns fl/glibc={:.3}x", $label, fl, g, fl / g);
            }};
        }

        probe!("literal", "the quick brown fox jumps",
            |b, f| snprintf(b, 128, f),
            |gl: SnFn, b, f| gl(b, 128, f));
        probe!("int", "%d",
            |b, f| snprintf(b, 128, f, 12345i32),
            |gl: SnFn, b, f| gl(b, 128, f, 12345i32));
        probe!("mixed", "x=%d y=%d z=%d",
            |b, f| snprintf(b, 128, f, 10i32, 20i32, 30i32),
            |gl: SnFn, b, f| gl(b, 128, f, 10i32, 20i32, 30i32));
        probe!("str", "hello, %s!",
            |b, f| snprintf(b, 128, f, b"world\0".as_ptr() as *const c_char),
            |gl: SnFn, b, f| gl(b, 128, f, b"world\0".as_ptr() as *const c_char));
    }
}
