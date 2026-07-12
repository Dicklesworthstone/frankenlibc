// strftime head-to-head: fl format_strftime vs host glibc strftime (dlmopen). Common
// formats. Output verified byte-equal.
use std::ffi::CString;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::time::{
    BrokenDownTime, broken_down_to_epoch, epoch_to_broken_down, format_strftime,
};

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type StrftimeFn = unsafe extern "C" fn(
            *mut libc::c_char,
            usize,
            *const libc::c_char,
            *const libc::tm,
        ) -> usize;
        let gl_strftime: StrftimeFn = std::mem::transmute::<*mut std::ffi::c_void, StrftimeFn>(
            libc::dlsym(h, b"strftime\0".as_ptr().cast()),
        );

        let seed = BrokenDownTime {
            tm_year: 124,
            tm_mon: 5,
            tm_mday: 15,
            tm_hour: 12,
            tm_min: 30,
            tm_sec: 45,
            ..Default::default()
        };
        let bd = epoch_to_broken_down(broken_down_to_epoch(&seed));
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = bd.tm_year;
        tm.tm_mon = bd.tm_mon;
        tm.tm_mday = bd.tm_mday;
        tm.tm_hour = bd.tm_hour;
        tm.tm_min = bd.tm_min;
        tm.tm_sec = bd.tm_sec;
        tm.tm_wday = bd.tm_wday;
        tm.tm_yday = bd.tm_yday;

        for fmt in [
            "%Y-%m-%d %H:%M:%S", // the one hard-coded fast-path format
            "%H:%M:%S",          // 3 directives, misses fast path
            "%H",                // 1 directive
            "ABCDEFGH",          // 0 directives (pure literal)
        ] {
            let fmt_b = fmt.as_bytes();
            let mut fl_buf = [0u8; 64];
            let n = format_strftime(fmt_b, &bd, &mut fl_buf);
            let fmt_c = CString::new(fmt).unwrap();
            let mut gl_buf = [0i8; 64];
            let gn = gl_strftime(gl_buf.as_mut_ptr(), 64, fmt_c.as_ptr(), &tm);
            let gl_bytes: &[u8] = std::slice::from_raw_parts(gl_buf.as_ptr().cast::<u8>(), gn);
            assert_eq!(&fl_buf[..n], gl_bytes, "strftime {fmt:?} mismatch");

            let iters = 1_000_000usize;
            let t0 = Instant::now();
            for _ in 0..iters {
                black_box(format_strftime(
                    black_box(fmt_b),
                    black_box(&bd),
                    black_box(&mut fl_buf),
                ));
            }
            let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
            let t1 = Instant::now();
            for _ in 0..iters {
                black_box(gl_strftime(
                    black_box(gl_buf.as_mut_ptr()),
                    64,
                    black_box(fmt_c.as_ptr()),
                    black_box(&tm),
                ));
            }
            let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
            println!(
                "STRFTIME {fmt:?} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x",
                fl / gl
            );
        }
    }
}
