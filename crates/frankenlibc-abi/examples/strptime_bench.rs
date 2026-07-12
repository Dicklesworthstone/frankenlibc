// strptime head-to-head: fl vs host glibc (dlmopen). Non-variadic. Parses a
// timestamp per a format into a tm. Output (tm fields) verified equal first.
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
        type StrptimeFn =
            unsafe extern "C" fn(*const c_char, *const c_char, *mut libc::tm) -> *mut c_char;
        let gl_strptime: StrptimeFn = std::mem::transmute::<*mut c_void, StrptimeFn>(libc::dlsym(
            h,
            b"strptime\0".as_ptr().cast(),
        ));

        for &(label, input, fmt) in &[
            ("datetime", "2024-06-15 12:30:45", "%Y-%m-%d %H:%M:%S"),
            ("date", "2024-06-15", "%Y-%m-%d"),
            ("time", "12:30:45", "%H:%M:%S"),
            ("named", "Mon Jun 15 2024", "%a %b %d %Y"),
        ] {
            let in_c = CString::new(input).unwrap();
            let fmt_c = CString::new(fmt).unwrap();

            let mut fl_tm: libc::tm = std::mem::zeroed();
            let mut gl_tm: libc::tm = std::mem::zeroed();
            frankenlibc_abi::time_abi::strptime(in_c.as_ptr(), fmt_c.as_ptr(), &mut fl_tm);
            gl_strptime(in_c.as_ptr(), fmt_c.as_ptr(), &mut gl_tm);
            assert_eq!(
                (
                    fl_tm.tm_year,
                    fl_tm.tm_mon,
                    fl_tm.tm_mday,
                    fl_tm.tm_hour,
                    fl_tm.tm_min,
                    fl_tm.tm_sec
                ),
                (
                    gl_tm.tm_year,
                    gl_tm.tm_mon,
                    gl_tm.tm_mday,
                    gl_tm.tm_hour,
                    gl_tm.tm_min,
                    gl_tm.tm_sec
                ),
                "strptime {label} tm mismatch"
            );

            let iters = 2_000_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                let mut tm: libc::tm = std::mem::zeroed();
                black_box(frankenlibc_abi::time_abi::strptime(
                    black_box(in_c.as_ptr()),
                    black_box(fmt_c.as_ptr()),
                    &mut tm,
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                let mut tm: libc::tm = std::mem::zeroed();
                black_box(gl_strptime(
                    black_box(in_c.as_ptr()),
                    black_box(fmt_c.as_ptr()),
                    &mut tm,
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "STRPTIME {label} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
