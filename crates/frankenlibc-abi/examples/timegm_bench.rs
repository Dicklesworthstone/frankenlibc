// timegm head-to-head: fl O(1) civil-days formula (broken_down_to_epoch) vs host glibc
// timegm (dlmopen). UTC broken-down time -> epoch seconds. Value verified equal.
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::time::{BrokenDownTime, broken_down_to_epoch};

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type TimegmFn = unsafe extern "C" fn(*mut libc::tm) -> i64;
        let gl_timegm: TimegmFn = std::mem::transmute::<*mut std::ffi::c_void, TimegmFn>(
            libc::dlsym(h, b"timegm\0".as_ptr().cast()),
        );

        let bd = BrokenDownTime {
            tm_year: 124, // 2024
            tm_mon: 5,    // June (0-indexed)
            tm_mday: 15,
            tm_hour: 12,
            tm_min: 30,
            tm_sec: 45,
            ..Default::default()
        };
        let fl_e = broken_down_to_epoch(&bd);
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = 124;
        tm.tm_mon = 5;
        tm.tm_mday = 15;
        tm.tm_hour = 12;
        tm.tm_min = 30;
        tm.tm_sec = 45;
        let gl_e = gl_timegm(&mut tm);
        assert_eq!(fl_e, gl_e, "timegm: fl={fl_e} glibc={gl_e}");

        let iters = 2_000_000usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            black_box(broken_down_to_epoch(black_box(&bd)));
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            black_box(gl_timegm(black_box(&mut tm)));
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!(
            "TIMEGM 2024-06-15 fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x",
            fl / gl
        );
    }
}
