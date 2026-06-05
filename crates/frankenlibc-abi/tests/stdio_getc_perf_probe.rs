//! Load-robust stdio per-byte cost probe (run with `-- --nocapture`).
//!
//! `criterion` measures each function in its own window, so on a loaded shared
//! worker the cross-function variance (one window idle, the next busy) swamps the
//! real per-impl difference. This probe instead INTERLEAVES frankenlibc and glibc
//! in one tight loop and takes the MIN over many trials — the minimum reflects the
//! true cost of an un-preempted run, which is robust to background load.
//!
//! Resolves bd-2g7oyh.131: is `fgetc_unlocked` (which delegates to the full
//! locked `fgetc`: 2 global registry Mutex acquisitions + a membrane decide() per
//! byte) actually slower than glibc's inline `getc_unlocked`, and by how much?

use std::ffi::{CString, c_int, c_void};
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn getc_unlocked(stream: *mut libc::FILE) -> c_int;
}

const N: usize = 4096;
const TRIALS: usize = 4000;

#[test]
fn stdio_getc_unlocked_min_cost() {
    let data = vec![b'x'; N];
    let mode = CString::new("r").expect("mode");

    let fl_fp = unsafe { fl::fmemopen(data.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!fl_fp.is_null(), "fl::fmemopen NULL");
    let gl_fp = unsafe { libc::fmemopen(data.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!gl_fp.is_null(), "libc::fmemopen NULL");

    let mut fl_min = Duration::MAX;
    let mut gl_min = Duration::MAX;
    for _ in 0..TRIALS {
        unsafe { fl::rewind(fl_fp) };
        let t = Instant::now();
        let mut s = 0i64;
        for _ in 0..N {
            s += unsafe { fl::fgetc_unlocked(fl_fp) } as i64;
        }
        black_box(s);
        fl_min = fl_min.min(t.elapsed());

        unsafe { libc::rewind(gl_fp) };
        let t = Instant::now();
        let mut s = 0i64;
        for _ in 0..N {
            s += unsafe { getc_unlocked(gl_fp) } as i64;
        }
        black_box(s);
        gl_min = gl_min.min(t.elapsed());
    }

    unsafe { fl::fclose(fl_fp) };
    unsafe { libc::fclose(gl_fp) };

    let fl_ns = fl_min.as_nanos() as f64 / N as f64;
    let gl_ns = gl_min.as_nanos() as f64 / N as f64;
    eprintln!(
        "STDIO_GETC_UNLOCKED_PROBE min-of-{TRIALS} 4096B sweep: \
         frankenlibc fgetc_unlocked={fl_ns:.2} ns/byte ({:?} total), \
         glibc getc_unlocked={gl_ns:.2} ns/byte ({:?} total), \
         ratio fl/glibc={:.2}",
        fl_min,
        gl_min,
        fl_ns / gl_ns,
    );
    // Loose sanity bound only (this is a measurement, not a gate): both must make
    // forward progress. The ratio above is the artifact of interest.
    assert!(fl_ns < 100_000.0 && gl_ns < 100_000.0, "implausible per-byte cost");
}
