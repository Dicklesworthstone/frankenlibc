// gmtime head-to-head: fl O(1) civil-days formula (epoch_to_broken_down) vs host glibc
// gmtime_r (dlmopen). Epoch seconds -> UTC broken-down time. Fields verified equal.
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::time::{broken_down_to_epoch, epoch_to_broken_down, BrokenDownTime};

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type GmtimeRFn = unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm;
        let gl_gmtime_r: GmtimeRFn = std::mem::transmute::<*mut std::ffi::c_void, GmtimeRFn>(
            libc::dlsym(h, b"gmtime_r\0".as_ptr().cast()),
        );

        let bd_in = BrokenDownTime {
            tm_year: 124,
            tm_mon: 5,
            tm_mday: 15,
            tm_hour: 12,
            tm_min: 30,
            tm_sec: 45,
            ..Default::default()
        };
        let epoch = broken_down_to_epoch(&bd_in);
        let fl_bd = epoch_to_broken_down(epoch);
        let mut tm: libc::tm = std::mem::zeroed();
        gl_gmtime_r(&epoch, &mut tm);
        assert_eq!(fl_bd.tm_year, tm.tm_year, "year");
        assert_eq!(fl_bd.tm_mon, tm.tm_mon, "mon");
        assert_eq!(fl_bd.tm_mday, tm.tm_mday, "mday");
        assert_eq!(fl_bd.tm_hour, tm.tm_hour, "hour");
        assert_eq!(fl_bd.tm_min, tm.tm_min, "min");
        assert_eq!(fl_bd.tm_sec, tm.tm_sec, "sec");
        assert_eq!(fl_bd.tm_wday, tm.tm_wday, "wday");
        assert_eq!(fl_bd.tm_yday, tm.tm_yday, "yday");

        let iters = 2_000_000usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            black_box(epoch_to_broken_down(black_box(epoch)));
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            black_box(gl_gmtime_r(black_box(&epoch), black_box(&mut tm)));
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!("GMTIME epoch={epoch} fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x", fl / gl);
    }
}
