//! Load-robust stdio per-byte cost guard for `fgetc_unlocked` vs glibc
//! `getc_unlocked` (run with `-- --nocapture` to see the ns/byte numbers).
//!
//! `criterion` measures each function in its own window, so on a loaded shared
//! worker the cross-function variance (one window idle, the next busy) swamps the
//! real per-impl difference. This guard instead INTERLEAVES frankenlibc and glibc
//! in one tight loop and takes the MIN over many trials — the minimum reflects an
//! un-preempted run, which is robust to background load — then asserts a *ratio*
//! bound (absolute ns/byte carry environment overhead that hits both impls
//! equally, so only the ratio is meaningful).
//!
//! Resolved bd-2g7oyh.131: `fgetc_unlocked` delegates to the full `fgetc` (2
//! global registry Mutex acquisitions + a membrane decide() per byte), which
//! looked alarming, but in a RELEASE build it is at parity with glibc's inline
//! getc_unlocked (measured ratio ~1.02; the scary ~4000x seen earlier was purely
//! a debug-build-vs-optimized-glibc artifact — libc.so always ships release with
//! opt-level=3 + LTO). This test guards that parity against regressions. MUST be
//! run `--release` to be meaningful; debug builds are not optimized.

use std::ffi::{CString, c_int, c_void};
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn getc_unlocked(stream: *mut libc::FILE) -> c_int;
}

const N: usize = 1024;
const TRIALS: usize = 600;

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
        "STDIO_GETC_UNLOCKED_PROBE min-of-{TRIALS} {N}B sweep: \
         frankenlibc fgetc_unlocked={fl_ns:.2} ns/byte ({:?} total), \
         glibc getc_unlocked={gl_ns:.2} ns/byte ({:?} total), \
         ratio fl/glibc={:.2}",
        fl_min,
        gl_min,
        fl_ns / gl_ns,
    );
    // Parity gate: only meaningful under `--release`. In debug the abi crate is
    // unoptimized while glibc is not, so the ratio is meaningless — skip the
    // assertion there (the printed numbers are still informative).
    if cfg!(debug_assertions) {
        return;
    }
    let ratio = fl_ns / gl_ns;
    assert!(
        ratio < 3.0,
        "fgetc_unlocked regressed vs glibc getc_unlocked: ratio {ratio:.2} \
         (frankenlibc {fl_ns:.1} ns/byte vs glibc {gl_ns:.1} ns/byte). \
         Release parity baseline was ~1.02 (bd-2g7oyh.131)."
    );
}
