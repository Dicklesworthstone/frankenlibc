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

// ---------------------------------------------------------------------------
// error_one_per_line (bd-enxo3y)
//
// glibc's error_at_line suppresses a message whose file+line match the
// IMMEDIATELY PRECEDING call, but only while error_one_per_line is set:
//
//     if (error_one_per_line)
//       {
//         static const char *old_file_name;
//         static unsigned int old_line_number;
//         if (old_line_number == line_number
//             && (file_name == old_file_name
//                 || (old_file_name != NULL && file_name != NULL
//                     && strcmp (old_file_name, file_name) == 0)))
//           return;                      /* print nothing */
//         old_file_name = file_name;
//         old_line_number = line_number;
//       }
//
// Two observables, and the second is the one that is easy to get wrong: a
// suppressed call must ALSO leave error_message_count alone.
//
// fl's suppression shipped with bd-enxo3y cited at the implementation but no
// test ever set error_one_per_line -- the header of this file says as much
// ("left off (default 0) so each call prints"), so every existing arm runs the
// unsuppressed path. These arms drive the suppressed one.
//
// Each impl keeps its own statics, so the sequence is run end-to-end against
// glibc, then end-to-end against fl, and the two transcripts compared. Running
// them call-by-call interleaved would be equivalent here but is fragile if a
// step is ever added in the middle.
// ---------------------------------------------------------------------------

/// Address of glibc's own `error_one_per_line` / `error_message_count`.
fn glibc_int_global(name: &std::ffi::CStr) -> *mut c_int {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, name.as_ptr());
        assert!(!s.is_null(), "dlsym({name:?}) failed");
        s.cast::<c_int>()
    }
}

/// One `error_at_line` call plus the `error_message_count` delta it caused.
struct Step {
    out: Vec<u8>,
    counted: bool,
}

/// Drive the whole file/line sequence through one implementation.
///
/// `call` takes (file, line) and performs the call; `count` reads that impl's
/// `error_message_count`. Both are per-impl because fl and glibc each have their
/// own copy of the counter and of the suppression statics.
fn run_sequence(
    call: &dyn Fn(*const c_char, c_uint),
    count: &dyn Fn() -> u32,
    steps: &[(Option<&CString>, c_uint)],
) -> Vec<Step> {
    steps
        .iter()
        .map(|(file, line)| {
            let ptr = file.map_or(std::ptr::null(), |f| f.as_ptr());
            let before = count();
            let out = capture_inner(|| call(ptr, *line));
            Step {
                out,
                counted: count() != before,
            }
        })
        .collect()
}

fn compare_sequences(fl: &[Step], g: &[Step], labels: &[&str]) {
    for (i, ((f, gg), label)) in fl.iter().zip(g).zip(labels).enumerate() {
        assert_eq!(
            f.out,
            gg.out,
            "step {i} ({label}): fl={:?} glibc={:?}",
            String::from_utf8_lossy(&f.out),
            String::from_utf8_lossy(&gg.out)
        );
        assert_eq!(
            f.counted, gg.counted,
            "step {i} ({label}): error_message_count incremented? fl={} glibc={}",
            f.counted, gg.counted
        );
    }
}

#[test]
fn error_at_line_honors_error_one_per_line_like_glibc() {
    // Whole install/run/restore window is exclusive: error_one_per_line is
    // process-global and every arm in this file shares stderr.
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let g_flag = glibc_int_global(c"error_one_per_line");
    let g_count = glibc_int_global(c"error_message_count");
    let g_flag_saved = unsafe { *g_flag };
    let fl_flag_saved = unsafe { frankenlibc_abi::glibc_internal_abi::error_one_per_line };

    let a = CString::new("a.c").unwrap();
    let a_again = CString::new("a.c").unwrap(); // distinct pointer, equal bytes
    let b = CString::new("b.c").unwrap();
    let prime = CString::new("__prime.c").unwrap();
    let fmt = CString::new("boom").unwrap();

    // Not `&a` twice: glibc short-circuits on pointer equality before strcmp, so
    // reusing one CString would never reach the strcmp branch.
    let steps: &[(Option<&CString>, c_uint)] = &[
        (Some(&a), 1),       // prints: differs from the priming location
        (Some(&a), 1),       // suppressed: same pointer, same line
        (Some(&a), 2),       // prints: same file, different line
        (Some(&b), 2),       // prints: different file, same line
        (Some(&a_again), 2), // prints: different file again (b.c -> a.c)
        (Some(&a_again), 2), // suppressed via strcmp: equal bytes, different pointer
        (None, 2),           // prints: NULL vs "a.c"
        (None, 2),           // suppressed: both NULL, same line
    ];
    let labels = [
        "first a.c:1",
        "repeat a.c:1 (pointer-equal)",
        "a.c:2 (line differs)",
        "b.c:2 (file differs)",
        "a.c:2 again (file differs)",
        "repeat a.c:2 (strcmp-equal, different pointer)",
        "NULL:2 (file becomes NULL)",
        "repeat NULL:2 (both NULL)",
    ];

    unsafe {
        *g_flag = 1;
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = 1;
    }

    // Prime each impl's statics to a location no step uses, so step 0 cannot be
    // suppressed by whatever a previously-run arm left behind.
    let g_call = |f: *const c_char, l: c_uint| unsafe { error_at_line(0, 0, f, l, fmt.as_ptr()) };
    let fl_call = |f: *const c_char, l: c_uint| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, f, l, fmt.as_ptr())
    };
    let g_count_fn = || unsafe { *g_count } as u32;
    let fl_count_fn = || unsafe { frankenlibc_abi::stdlib_abi::error_message_count };

    let _ = capture_inner(|| g_call(prime.as_ptr(), 4242));
    let g_steps = run_sequence(&g_call, &g_count_fn, steps);
    let _ = capture_inner(|| fl_call(prime.as_ptr(), 4242));
    let fl_steps = run_sequence(&fl_call, &fl_count_fn, steps);

    unsafe {
        *g_flag = g_flag_saved;
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = fl_flag_saved;
    }

    compare_sequences(&fl_steps, &g_steps, &labels);

    // Name the property the differential is enforcing, so a regression is not
    // just "step 1 differs": exactly the three repeat steps are suppressed, and
    // a suppressed call prints nothing AND does not bump the counter.
    let suppressed: Vec<usize> = fl_steps
        .iter()
        .enumerate()
        .filter(|(_, s)| s.out.is_empty())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        suppressed,
        vec![1, 5, 7],
        "expected the three repeated locations to be suppressed, got {suppressed:?}"
    );
    for i in [1usize, 5, 7] {
        assert!(
            !fl_steps[i].counted,
            "step {i} was suppressed but still incremented error_message_count"
        );
    }
    for i in [0usize, 2, 3, 4, 6] {
        assert!(
            fl_steps[i].counted,
            "step {i} printed but did not increment error_message_count"
        );
    }
}

#[test]
fn error_at_line_repeats_when_error_one_per_line_is_clear() {
    // Negative control for the arm above: with the flag clear the SAME sequence
    // must print every time. Without this, an implementation that suppressed
    // unconditionally -- or one that never printed at all -- would still satisfy
    // the suppression assertions.
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let g_flag = glibc_int_global(c"error_one_per_line");
    let g_count = glibc_int_global(c"error_message_count");
    let g_flag_saved = unsafe { *g_flag };
    let fl_flag_saved = unsafe { frankenlibc_abi::glibc_internal_abi::error_one_per_line };

    let a = CString::new("a.c").unwrap();
    let fmt = CString::new("boom").unwrap();
    let steps: &[(Option<&CString>, c_uint)] =
        &[(Some(&a), 1), (Some(&a), 1), (Some(&a), 1), (None, 1), (None, 1)];
    let labels = ["a.c:1", "a.c:1", "a.c:1", "NULL:1", "NULL:1"];

    unsafe {
        *g_flag = 0;
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = 0;
    }

    let g_call = |f: *const c_char, l: c_uint| unsafe { error_at_line(0, 0, f, l, fmt.as_ptr()) };
    let fl_call = |f: *const c_char, l: c_uint| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, f, l, fmt.as_ptr())
    };
    let g_steps = run_sequence(&g_call, &(|| unsafe { *g_count } as u32), steps);
    let fl_steps = run_sequence(
        &fl_call,
        &(|| unsafe { frankenlibc_abi::stdlib_abi::error_message_count }),
        steps,
    );

    unsafe {
        *g_flag = g_flag_saved;
        frankenlibc_abi::glibc_internal_abi::error_one_per_line = fl_flag_saved;
    }

    compare_sequences(&fl_steps, &g_steps, &labels);
    for (i, s) in fl_steps.iter().enumerate() {
        assert!(
            !s.out.is_empty(),
            "step {i} was suppressed even though error_one_per_line is clear"
        );
        assert!(s.counted, "step {i} printed but did not count");
    }
}

// ---------------------------------------------------------------------------
// NULL vs empty file_name (bd-0qltjh)
//
// glibc prints the "%s:%d: " file/line group only when file_name is non-NULL,
// and a single space in its place when it is NULL, so a NULL name still yields
// "progname: message" rather than "progname:message". An empty-but-non-NULL
// name is NOT the same case: it still prints the group, as ":<line>: ".
//
// Measured on live glibc 2.42 (cat -A on a compiled C probe):
//   ("f.c", 7) -> "PROG:f.c:7: with file"
//   (NULL,  7) -> "PROG: null file"
//   ("",    7) -> "PROG::7: empty file"
//
// fl emitted nothing at all for the NULL case. Found by the error_one_per_line
// arms above, whose NULL steps were the first in the repo to reach this path.
// ---------------------------------------------------------------------------

#[test]
fn error_at_line_null_filename_keeps_the_space_separator() {
    let with_file = CString::new("f.c").unwrap();
    let empty = CString::new("").unwrap();
    let fmt = CString::new("msg").unwrap();

    // (label, file pointer) — the three shapes, each compared to live glibc.
    let cases: &[(&str, *const c_char)] = &[
        ("non-NULL file", with_file.as_ptr()),
        ("NULL file", std::ptr::null()),
        ("empty-but-non-NULL file", empty.as_ptr()),
    ];

    for (label, file) in cases {
        let g = capture(|| unsafe { error_at_line(0, 0, *file, 7, fmt.as_ptr()) });
        let f = capture(|| unsafe {
            frankenlibc_abi::stdlib_abi::error_at_line(0, 0, *file, 7, fmt.as_ptr())
        });
        assert_eq!(
            f,
            g,
            "error_at_line with {label}: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&f),
            String::from_utf8_lossy(&g)
        );
    }

    // Name the distinction the differential is enforcing, so a regression reads
    // as the bug rather than as two long paths differing near the end. These are
    // the exact shapes measured on glibc 2.42.
    let null_out = capture(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, std::ptr::null(), 7, fmt.as_ptr())
    });
    assert!(
        null_out.ends_with(b": msg\n"),
        "a NULL file_name must still leave a space after the progname colon, got {:?}",
        String::from_utf8_lossy(&null_out)
    );
    // The negative case: the pre-fix output, and what an over-eager fix that
    // dropped the file/line group entirely would also produce.
    assert!(
        !null_out.ends_with(b":msg\n"),
        "NULL file_name produced the pre-fix 'progname:msg' shape: {:?}",
        String::from_utf8_lossy(&null_out)
    );

    let empty_out = capture(|| unsafe {
        frankenlibc_abi::stdlib_abi::error_at_line(0, 0, empty.as_ptr(), 7, fmt.as_ptr())
    });
    assert!(
        empty_out.ends_with(b"::7: msg\n"),
        "an empty-but-non-NULL file_name still prints the ':<line>: ' group, got {:?}",
        String::from_utf8_lossy(&empty_out)
    );
}
