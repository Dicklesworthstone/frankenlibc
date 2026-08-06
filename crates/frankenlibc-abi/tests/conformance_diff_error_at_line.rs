#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc error_at_line() oracle; redirects process fd 2

//! Differential gate for glibc's error_at_line() (bd-m70eq2) — previously
//! fl-internal only. error_at_line(status, errnum, file, line, fmt, ...) prints
//! "<progname>:<file>:<line>: <fmt>... [: <strerror(errnum)>]\n" to stderr
//! (exiting only when status != 0, so every case uses status 0). This captures
//! stderr and asserts byte-for-byte equality with glibc across the file:line
//! insertion, errnum == 0 (no suffix) vs set errno, and printf %s/%d args. The
//! consecutive-duplicate suppression (error_one_per_line) is left off (default
//! 0) so each call prints. No mocks.

use std::ffi::{CString, c_char, c_int, c_uint};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn error_at_line(
        status: c_int,
        errnum: c_int,
        file: *const c_char,
        line: c_uint,
        fmt: *const c_char,
        ...
    );
}

static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

fn capture<F: FnOnce()>(f: F) -> Vec<u8> {
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    capture_inner(f)
}

/// Body of [`capture`] without taking CAPTURE_LOCK, for callers that already
/// hold it across a wider critical section (see `with_progname_hook`, which
/// mutates a process-global and so must keep the whole install/call/restore
/// window exclusive — the harness runs these tests in parallel threads).
fn capture_inner<F: FnOnce()>(f: F) -> Vec<u8> {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let saved = unsafe { libc::dup(2) };
    unsafe { libc::dup2(fds[1], 2) };
    f();
    unsafe { libc::fflush(std::ptr::null_mut()) };
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(fds[1]);
    }
    let mut out = Vec::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = file.read_to_end(&mut out);
    out
}

macro_rules! both {
    ($desc:literal, $errnum:expr, $file:expr, $line:expr, $fmt:expr $(, $arg:expr)*) => {{
        let file = CString::new($file).unwrap();
        let fmt = CString::new($fmt).unwrap();
        let g = capture(|| unsafe { error_at_line(0, $errnum, file.as_ptr(), $line, fmt.as_ptr() $(, $arg)*) });
        let f = capture(|| unsafe {
            frankenlibc_abi::stdlib_abi::error_at_line(0, $errnum, file.as_ptr(), $line, fmt.as_ptr() $(, $arg)*)
        });
        assert_eq!(
            f, g,
            "error_at_line(0, {}, {:?}, {}, {:?}) [{}]: fl={:?} glibc={:?}",
            $errnum, $file, $line, $fmt, $desc,
            String::from_utf8_lossy(&f), String::from_utf8_lossy(&g),
        );
    }};
}

#[test]
fn error_at_line_matches_glibc() {
    let foo = CString::new("foo.txt").unwrap();
    both!("plain, no errno", 0, "parse.c", 12u32, "syntax error");
    both!("EINVAL suffix", libc::EINVAL, "io.c", 99u32, "bad value");
    both!("ENOENT suffix", libc::ENOENT, "open.c", 1u32, "missing");
    both!(
        "%s arg",
        0,
        "read.c",
        256u32,
        "cannot read %s",
        foo.as_ptr()
    );
    both!(
        "%s + errno",
        libc::EACCES,
        "read.c",
        257u32,
        "cannot read %s",
        foo.as_ptr()
    );
    both!(
        "%d arg + errno",
        libc::EINVAL,
        "x.c",
        0u32,
        "code %d",
        42 as c_int
    );
    both!("empty fmt + errno", libc::ENOENT, "y.c", 7u32, "");
}

// ---------------------------------------------------------------------------
// error_print_progname (bd-xqg5il)
//
// glibc calls the hook INSTEAD of printing its own "<progname>[:]" prefix:
//
//     if (error_print_progname) (*error_print_progname) ();
//     else { flush_stdout (); fprintf (stderr, "%s: ", program_name); }
//
// so a hook must both replace the default prefix and have its own output land
// ahead of the message. fl previously always printed the default prefix and
// never called the hook. Measured on live glibc 2.42: with a hook installed,
// error(0, 0, "boom") writes "HOOK boom\n" rather than "<progname>: boom\n".
//
// The hook writes to fd 2 with a raw write(), not through stdio, so the two
// arms cannot differ merely by which libc's stderr buffer they went through.
// ---------------------------------------------------------------------------

unsafe extern "C" {
    fn error(status: c_int, errnum: c_int, fmt: *const c_char, ...);
    fn dlopen(filename: *const i8, flag: c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const i8) -> *mut std::ffi::c_void;
}

extern "C" fn marker_progname() {
    let msg = b"HOOK ";
    unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
}

/// Address of glibc's own `error_print_progname` variable.
fn glibc_progname_slot() -> *mut *mut std::ffi::c_void {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, c"error_print_progname".as_ptr());
        assert!(!s.is_null(), "dlsym(error_print_progname) failed");
        s.cast::<*mut std::ffi::c_void>()
    }
}

/// Install `hook` in both impls' slots, run `f`, and always restore.
fn with_progname_hook<T>(hook: *mut std::ffi::c_void, f: impl FnOnce() -> T) -> T {
    // Held across install/call/restore: these slots are process-global, so two
    // of these tests running concurrently would each see the other's hook.
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g_slot = glibc_progname_slot();
    let g_saved = unsafe { *g_slot };
    let f_saved = unsafe { frankenlibc_abi::glibc_internal_abi::error_print_progname };
    unsafe {
        *g_slot = hook;
        frankenlibc_abi::glibc_internal_abi::error_print_progname = hook;
    }
    let out = f();
    unsafe {
        *g_slot = g_saved;
        frankenlibc_abi::glibc_internal_abi::error_print_progname = f_saved;
    }
    out
}

#[test]
fn error_honors_error_print_progname_like_glibc() {
    let hook = marker_progname as *const () as *mut std::ffi::c_void;
    let fmt = CString::new("boom").unwrap();

    let (g, f) = with_progname_hook(hook, || {
        let g = capture_inner(|| unsafe { error(0, 0, fmt.as_ptr()) });
        let f = capture_inner(|| unsafe { frankenlibc_abi::stdlib_abi::error(0, 0, fmt.as_ptr()) });
        (g, f)
    });

    assert_eq!(
        f,
        g,
        "error() with a progname hook: fl={:?} glibc={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&g)
    );
    assert_eq!(
        g,
        b"HOOK boom\n",
        "glibc must call the hook in place of its own prefix, got {:?}",
        String::from_utf8_lossy(&g)
    );
}

#[test]
fn error_at_line_honors_error_print_progname_like_glibc() {
    let hook = marker_progname as *const () as *mut std::ffi::c_void;
    let file = CString::new("read.c").unwrap();
    let fmt = CString::new("cannot read").unwrap();

    let (g, f) = with_progname_hook(hook, || {
        let g = capture_inner(|| unsafe { error_at_line(0, 0, file.as_ptr(), 42, fmt.as_ptr()) });
        let f = capture_inner(|| unsafe {
            frankenlibc_abi::stdlib_abi::error_at_line(0, 0, file.as_ptr(), 42, fmt.as_ptr())
        });
        (g, f)
    });

    assert_eq!(
        f,
        g,
        "error_at_line() with a progname hook: fl={:?} glibc={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&g)
    );
    // The hook replaces only the progname; file:line still follows it.
    assert_eq!(
        g,
        b"HOOK read.c:42: cannot read\n",
        "glibc must keep file:line after the hook output, got {:?}",
        String::from_utf8_lossy(&g)
    );
}

#[test]
fn error_without_hook_still_prints_the_default_prefix() {
    // Negative control for the two arms above: with the hook cleared, both
    // impls must fall back to their own "<progname>" prefix, so those arms are
    // detecting the hook rather than a prefix that never appears.
    //
    // This arm was originally property-based rather than byte-for-byte, because
    // fl resolved its program name to "unknown" where glibc uses argv[0] and the
    // unrelated diff would have swamped the control. That defect (bd-ul4pyl) is
    // fixed — fl now prints program_invocation_name — so the control is back to
    // full byte equality, which subsumes both properties. The property
    // assertions are kept alongside it so a regression still reports WHICH half
    // moved (hook leaked vs prefix wrong) instead of one opaque byte diff.
    let fmt = CString::new("boom").unwrap();
    let (g, f) = with_progname_hook(std::ptr::null_mut(), || {
        let g = capture_inner(|| unsafe { error(0, 0, fmt.as_ptr()) });
        let f = capture_inner(|| unsafe { frankenlibc_abi::stdlib_abi::error(0, 0, fmt.as_ptr()) });
        (g, f)
    });
    assert!(
        !f.starts_with(b"HOOK "),
        "fl must not run the hook once cleared, got {:?}",
        String::from_utf8_lossy(&f)
    );
    assert!(
        f.ends_with(b": boom\n"),
        "fl should fall back to a '<progname>: boom' line, got {:?}",
        String::from_utf8_lossy(&f)
    );
    assert!(
        !g.starts_with(b"HOOK "),
        "the hook must not run once cleared, got {:?}",
        String::from_utf8_lossy(&g)
    );
    assert!(
        g.ends_with(b": boom\n"),
        "expected a default '<progname>: boom' line, got {:?}",
        String::from_utf8_lossy(&g)
    );
    assert_eq!(
        f,
        g,
        "with the hook cleared the default prefix must match glibc byte for byte: \
         fl={:?} glibc={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&g)
    );
}

// ---------------------------------------------------------------------------
// progname resolution (bd-ul4pyl)
//
// glibc's error.c does `#define program_name program_invocation_name` and
// prints that -- the FULL argv[0]. fl printed program_invocation_short_name
// (the basename), and since fl's CRT startup does not run in an rlib test
// binary that global was null too, so the prefix came out as the literal
// "unknown". Both halves are fixed: error()/error_at_line() now read the full
// name, with a /proc/self/cmdline fallback for when startup has not published
// it.
//
// error_matches_glibc above already compares the whole line byte for byte. This
// arm names the specific value, against glibc's own globals read live by dlsym,
// so a regression says "we printed the basename" rather than showing two long
// paths that differ somewhere.
// ---------------------------------------------------------------------------

/// Read a `char *` global out of live glibc.
fn glibc_progname_global(name: &std::ffi::CStr) -> Vec<u8> {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let slot = dlsym(h, name.as_ptr()).cast::<*const c_char>();
        assert!(!slot.is_null(), "dlsym({name:?}) failed");
        let s = *slot;
        assert!(!s.is_null(), "{name:?} is null in this process");
        std::ffi::CStr::from_ptr(s).to_bytes().to_vec()
    }
}

#[test]
fn error_prefix_is_the_full_argv0_not_its_basename() {
    let full = glibc_progname_global(c"program_invocation_name");
    let short = glibc_progname_global(c"program_invocation_short_name");
    // Guard the discriminator itself: if the test binary were invoked as a bare
    // name these two would coincide and the arm below could not tell the bug
    // from the fix.
    assert_ne!(
        full,
        short,
        "this arm needs argv[0] to have a directory component to discriminate \
         full from basename; got {:?}",
        String::from_utf8_lossy(&full)
    );

    let fmt = CString::new("boom").unwrap();
    let f = capture(|| unsafe { frankenlibc_abi::stdlib_abi::error(0, 0, fmt.as_ptr()) });

    let mut expected = full.clone();
    expected.extend_from_slice(b": boom\n");
    assert_eq!(
        f,
        expected,
        "error() should prefix program_invocation_name: fl={:?} expected={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&expected)
    );

    // The two shapes the pre-fix code actually produced.
    let mut basename_prefix = short.clone();
    basename_prefix.extend_from_slice(b": ");
    assert!(
        !f.starts_with(&basename_prefix),
        "error() printed the basename {:?}, not the full argv[0]",
        String::from_utf8_lossy(&short)
    );
    assert!(
        !f.starts_with(b"unknown: "),
        "error() fell back to the literal \"unknown\" prefix; the progname ladder \
         did not resolve a name"
    );
}

#[test]
fn error_at_line_prefix_is_the_full_argv0_not_its_basename() {
    let full = glibc_progname_global(c"program_invocation_name");
    let short = glibc_progname_global(c"program_invocation_short_name");
    assert_ne!(full, short, "argv[0] needs a directory component here");

    let file = CString::new("parse.c").unwrap();
    let fmt = CString::new("syntax error").unwrap();
    let f = capture(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, file.as_ptr(), 12, fmt.as_ptr())
    });

    let mut expected = full.clone();
    expected.extend_from_slice(b":parse.c:12: syntax error\n");
    assert_eq!(
        f,
        expected,
        "error_at_line() should prefix program_invocation_name: fl={:?} expected={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&expected)
    );
    assert!(
        !f.starts_with(b"unknown:"),
        "error_at_line() fell back to the literal \"unknown\" prefix"
    );
}
