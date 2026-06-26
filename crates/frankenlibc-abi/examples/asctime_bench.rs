// asctime head-to-head: fl direct byte-builder (format_asctime) vs host glibc asctime_r
// (dlmopen, historically a sprintf-style format). Broken-down time -> 26-byte string.
// Output verified equal.
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_core::time::{broken_down_to_epoch, epoch_to_broken_down, format_asctime, BrokenDownTime};

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        type AsctimeRFn = unsafe extern "C" fn(*const libc::tm, *mut libc::c_char) -> *mut libc::c_char;
        let gl_asctime_r: AsctimeRFn = std::mem::transmute::<*mut std::ffi::c_void, AsctimeRFn>(
            libc::dlsym(h, b"asctime_r\0".as_ptr().cast()),
        );

        // Full broken-down time (with wday/yday, which asctime needs).
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

        let mut fl_buf = [0u8; 32];
        let n = format_asctime(&bd, &mut fl_buf);
        let mut gl_buf = [0i8; 32];
        gl_asctime_r(&tm, gl_buf.as_mut_ptr());
        let gl_bytes: &[u8] = std::slice::from_raw_parts(gl_buf.as_ptr().cast::<u8>(), n);
        assert_eq!(&fl_buf[..n], gl_bytes, "asctime output mismatch");

        let iters = 2_000_000usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            black_box(format_asctime(black_box(&bd), black_box(&mut fl_buf)));
        }
        let fl = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = Instant::now();
        for _ in 0..iters {
            black_box(gl_asctime_r(black_box(&tm), black_box(gl_buf.as_mut_ptr())));
        }
        let gl = t1.elapsed().as_nanos() as f64 / iters as f64;
        println!("ASCTIME fl={fl:.1}ns glibc={gl:.1}ns fl/glibc={:.3}x", fl / gl);
    }
}
