#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc printf oracle by dlsym; redirects process fd 1

//! Differential gate for `printf`'s `%f` / `%.Nf` output (bd-5pfs0p).
//!
//! LANDED BEFORE THE FAST PATH IT WILL GATE. `printf` still takes the general
//! path for floats, so this records the BASELINE the optimisation must
//! preserve. A gate written afterwards can only confirm the change agrees with
//! itself, which is the failure bd-v0388t exists to track.
//!
//! `printf` is the hardest of the five entry points to gate, and the reasons are
//! worth stating because they are what the gate is built around.
//!
//! 1. THERE IS NO DESTINATION ARGUMENT. The output goes to `stdout`, so the only
//!    way to observe it is to redirect process fd 1 and read it back. That makes
//!    this gate mutate global process state, so both arms hold a mutex and
//!    restore fd 1 on every path.
//!
//! 2. fl AND GLIBC HAVE SEPARATE `stdout` FILE OBJECTS over the same fd 1, each
//!    with its OWN buffer. Flushing one does not flush the other. If the gate
//!    flushed only glibc's, fl's bytes would still be sitting in fl's buffer
//!    when the file was read, and the comparison would be against an empty or
//!    truncated capture — a gate that fails for a reason that has nothing to do
//!    with formatting. Each arm therefore flushes ITS OWN stream, through its
//!    own `fflush`, before fd 1 is restored.
//!
//! 3. THE BUFFERING MODE DEPENDS ON WHAT fd 1 IS. Redirecting it to a regular
//!    file makes both streams fully buffered rather than line buffered, which is
//!    the same for both arms and so does not bias the comparison — but it is why
//!    the explicit flush in (2) is mandatory rather than defensive.
//!
//! The oracle is resolved with `dlsym`: `catopen` and `fma` are both confirmed
//! cases where a link-time `extern "C"` reference bound locally in a plain
//! `cargo test`, and `catopen`'s hid a live errno divergence for months.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::Read as _;
use std::sync::{Mutex, MutexGuard};

type Printf = unsafe extern "C" fn(*const c_char, ...) -> c_int;
type Fflush = unsafe extern "C" fn(*mut c_void) -> c_int;

union SymP {
    raw: *mut c_void,
    function: Printf,
}
union SymFl {
    raw: *mut c_void,
    function: Fflush,
}

/// fd 1 is process-global, so only one arm may hold the redirect at a time.
static FD1: Mutex<()> = Mutex::new(());

fn fd1_lock() -> MutexGuard<'static, ()> {
    FD1.lock().unwrap_or_else(|e| e.into_inner())
}

fn libc_handle() -> *mut c_void {
    // SAFETY: the name is a NUL-terminated constant.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6 — the oracle is unavailable");
    h
}

fn host_printf() -> (Printf, Fflush, *mut c_void) {
    let h = libc_handle();
    // SAFETY: handle came from dlopen; names are NUL-terminated constants.
    let (p, f, slot) = unsafe {
        (
            libc::dlsym(h, c"printf".as_ptr()),
            libc::dlsym(h, c"fflush".as_ptr()),
            libc::dlsym(h, c"stdout".as_ptr()).cast::<*mut c_void>(),
        )
    };
    assert!(!p.is_null() && !f.is_null() && !slot.is_null(), "dlsym printf trio");
    assert_ne!(
        p as usize,
        frankenlibc_abi::stdio_abi::printf as *const () as usize,
        "the resolved oracle IS fl's printf — this gate would compare fl to itself"
    );
    // SAFETY: `slot` points at glibc's `stdout` FILE* variable; the symbols have
    // C's documented signatures.
    unsafe { (SymP { raw: p }.function, SymFl { raw: f }.function, *slot) }
}

fn fl_stdout() -> *mut c_void {
    frankenlibc_abi::io_internal_abi::native_stdio_stream_ptr(1)
}

/// Run `emit` with fd 1 pointed at a fresh temp file, flush through `flush_with`
/// on `stream`, restore fd 1, and return (emit's return value, bytes captured).
///
/// The flush happens INSIDE the redirect window and uses the caller's own
/// `fflush`, which is the whole point: fl and glibc buffer independently over
/// the same descriptor.
fn capture<F>(flush_with: Fflush, stream: *mut c_void, emit: F) -> (c_int, Vec<u8>)
where
    F: FnOnce() -> c_int,
{
    let _guard = fd1_lock();
    let dir = std::env::temp_dir().join(format!("fl-printf-{}.out", std::process::id()));
    let path = dir.to_str().expect("ascii temp path").to_string();
    let cpath = CString::new(path.clone()).unwrap();

    // SAFETY: cpath is NUL-terminated; O_TRUNC gives a fresh file each call.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600 as libc::c_uint,
        )
    };
    assert!(fd >= 0, "open temp capture file");
    // SAFETY: fd 1 is a valid descriptor; `saved` restores it below.
    let saved = unsafe { libc::dup(1) };
    assert!(saved >= 0, "dup(1)");
    // SAFETY: both descriptors are open.
    assert!(unsafe { libc::dup2(fd, 1) } >= 0, "dup2 onto fd 1");

    let rc = emit();
    // Flush THIS implementation's stream, not the other's: they are separate
    // FILE objects with separate buffers over the same fd.
    // SAFETY: `stream` is that implementation's live stdout.
    unsafe { flush_with(stream) };

    // SAFETY: restore fd 1 and drop the temporaries.
    unsafe {
        libc::dup2(saved, 1);
        libc::close(saved);
        libc::close(fd);
    }

    let mut buf = Vec::new();
    std::fs::File::open(&path)
        .expect("capture file")
        .read_to_end(&mut buf)
        .expect("read capture");
    let _ = std::fs::remove_file(&path);
    (rc, buf)
}

fn formats() -> Vec<(CString, String)> {
    let mut v = vec![(CString::new("%f").unwrap(), "%f".to_string())];
    for p in 0..=12 {
        // 0 and >9 sit outside the fast path the probe will add and must still
        // agree; a probe that accepted them would be a silent divergence.
        let s = format!("%.{p}f");
        v.push((CString::new(s.clone()).unwrap(), s));
    }
    v
}

fn values() -> Vec<f64> {
    vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        0.125,
        // Money shape: neither integral nor dyadic, the case a fixed-precision
        // fast path exists for.
        1234.56,
        -1234.56,
        0.1,
        // Round-half-to-even traps: the exact binary value sits just below the
        // decimal tie, so round-half-up prints the wrong last digit.
        2.675,
        1.005,
        8.835,
        99.995,
        1e15,
        1e19,
        1e300,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ]
}

#[test]
fn printf_fixed_matches_glibc_on_stdout() {
    let (gprintf, gflush, gstdout) = host_printf();
    let mut compared = 0usize;
    for (fmt, label) in formats() {
        for &value in &values() {
            let f = fmt.as_ptr();
            let (frc, fbytes) = capture(frankenlibc_abi::stdio_abi::fflush, fl_stdout(), || {
                // SAFETY: `fmt` names exactly one double.
                unsafe { frankenlibc_abi::stdio_abi::printf(f, value) }
            });
            let (grc, gbytes) = capture(gflush, gstdout, || {
                // SAFETY: as above, through the dlsym'd host printf.
                unsafe { gprintf(f, value) }
            });

            assert_eq!(
                frc, grc,
                "{label} of {value:?} [{:#018x}]: return fl={frc} glibc={grc}",
                value.to_bits()
            );
            assert_eq!(
                fbytes,
                gbytes,
                "{label} of {value:?} [{:#018x}]: stdout bytes differ\n fl   ={:?}\n glibc={:?}",
                value.to_bits(),
                String::from_utf8_lossy(&fbytes),
                String::from_utf8_lossy(&gbytes)
            );
            // The stream invariant a fast path breaks while the digits stay
            // perfect: the returned count must equal what actually reached fd 1.
            assert_eq!(
                frc as usize,
                fbytes.len(),
                "{label} of {value:?}: fl returned {frc} but {} bytes reached stdout",
                fbytes.len()
            );
            compared += 1;
        }
    }
    assert!(
        compared > 250,
        "only {compared} comparisons ran — the grid collapsed"
    );
    // Printed AFTER the redirect window has closed on every iteration, so it
    // cannot end up inside a capture.
    println!("printf: compared {compared} (format, value) pairs against host glibc");
}

/// Formats the future probe must DECLINE: widths, flags, other conversions, and
/// precisions outside 1..=9. They keep the general path and must still match.
#[test]
fn adjacent_printf_float_formats_still_match_glibc() {
    let (gprintf, gflush, gstdout) = host_printf();
    let specs = [
        "%10.2f", "%-10.2f", "%+.2f", "% .2f", "%010.2f", "%#.2f", "%.0f", "%.10f", "%.15f",
        "%e", "%.2e", "%g", "%.2g", "%a", "%E", "%G",
    ];
    for spec in specs {
        let fmt = CString::new(spec).unwrap();
        for &value in &[0.0f64, -0.0, 1234.56, 0.1, 1e19, f64::INFINITY, f64::NAN] {
            let f = fmt.as_ptr();
            let (frc, fbytes) = capture(frankenlibc_abi::stdio_abi::fflush, fl_stdout(), || {
                // SAFETY: `fmt` names exactly one double.
                unsafe { frankenlibc_abi::stdio_abi::printf(f, value) }
            });
            let (grc, gbytes) = capture(gflush, gstdout, || {
                // SAFETY: as above.
                unsafe { gprintf(f, value) }
            });
            assert_eq!(frc, grc, "{spec} of {value:?}: return value");
            assert_eq!(
                fbytes,
                gbytes,
                "{spec} of {value:?}: stdout bytes differ\n fl   ={:?}\n glibc={:?}",
                String::from_utf8_lossy(&fbytes),
                String::from_utf8_lossy(&gbytes)
            );
        }
    }
}

/// The capture harness itself must be shown to work, or a silently broken
/// redirect would make every comparison above `("", "")` and green.
///
/// This is the "zero is not evidence" check for this file: it asserts the
/// positive fact that a known string round-trips through the redirect, for BOTH
/// implementations, before any differential result is trusted.
#[test]
fn capture_harness_actually_captures() {
    let (gprintf, gflush, gstdout) = host_printf();
    let fmt = CString::new("%.3f").unwrap();
    let f = fmt.as_ptr();

    let (frc, fbytes) = capture(frankenlibc_abi::stdio_abi::fflush, fl_stdout(), || {
        // SAFETY: the format names exactly one double.
        unsafe { frankenlibc_abi::stdio_abi::printf(f, 2.5f64) }
    });
    assert_eq!(fbytes, b"2.500", "fl capture produced {fbytes:?}, expected \"2.500\"");
    assert_eq!(frc, 5, "fl returned {frc}, expected 5");

    let (grc, gbytes) = capture(gflush, gstdout, || {
        // SAFETY: as above.
        unsafe { gprintf(f, 2.5f64) }
    });
    assert_eq!(gbytes, b"2.500", "glibc capture produced {gbytes:?}");
    assert_eq!(grc, 5, "glibc returned {grc}");
}
