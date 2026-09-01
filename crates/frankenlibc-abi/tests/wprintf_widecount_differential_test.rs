#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wprintf oracle with fd-1 capture

//! Differential test for `wprintf`'s RETURN VALUE vs host glibc. C specifies
//! wprintf returns the number of WIDE CHARACTERS transmitted — NOT the byte
//! length of the encoded output — so for any multibyte output (e.g. `%lc` of a
//! non-ASCII wide char) the two differ. fl previously returned the UTF-8 byte
//! count. This redirects fd 1 to a temp file, runs each format on both fl and
//! glibc, and asserts the return value AND the emitted bytes agree.

use std::ffi::CString;

use frankenlibc_abi::wchar_abi as fl;

#[path = "common/fd_capture.rs"]
mod fd_capture;

unsafe extern "C" {
    fn wprintf(format: *const libc::wchar_t, ...) -> libc::c_int;
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
}

fn widen(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

/// Capture (return value, bytes written to fd 1) for a closure that emits to
/// stdout. `flush` controls whether glibc's buffered stdout is flushed after.
fn capture(tmp_fd: libc::c_int, flush: bool, call: impl FnOnce() -> libc::c_int) -> (i32, Vec<u8>) {
    unsafe {
        libc::ftruncate(tmp_fd, 0);
        libc::lseek(tmp_fd, 0, libc::SEEK_SET);
        // Restored by a Drop guard, INCLUDING on unwind: a panic inside `call()`
        // would skip a straight-line restore and leave this process's STDOUT
        // pointed at the temp file for the rest of the run, swallowing libtest's
        // report of that very failure (bd-ug42ol). Block-scoped so fd 1 is
        // restored before the rewind-and-read below.
        let ret = {
            let _restore = fd_capture::StdFdRestore::new(1);
            libc::dup2(tmp_fd, 1);
            let ret = call();
            if flush {
                fflush(std::ptr::null_mut()); // flush ALL streams (incl glibc stdout)
            }
            ret
        };
        // Read everything written.
        libc::lseek(tmp_fd, 0, libc::SEEK_SET);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = libc::read(tmp_fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        (ret, buf)
    }
}

#[test]
fn wprintf_return_is_wide_count_not_bytes() {
    unsafe {
        let utf8 = CString::new("C.UTF-8").unwrap();
        setlocale(6 /* LC_ALL */, utf8.as_ptr());
        // fl needs the same locale, not just the oracle: `setlocale` here is a
        // link-time symbol that binds GLIBC's in a debug test, and fl has started
        // in POSIX C since b5aef5e3a. Without this the gate compares an ASCII fl
        // against a UTF-8 glibc and fails for a reason unrelated to what it tests.
        frankenlibc_abi::locale_abi::setlocale(6 /* LC_ALL */, utf8.as_ptr());
    }
    let path = CString::new(format!("/tmp/fl_wprintf_cap_{}", std::process::id())).unwrap();
    let tmp_fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(tmp_fd >= 0, "could not open temp capture file");

    let mut fails: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $fmt:expr $(, $arg:expr)*) => {{
            let fmt = widen($fmt);
            let (rf, bf) = capture(tmp_fd, false, || unsafe { fl::wprintf(fmt.as_ptr() $(, $arg)*) });
            let (rg, bg) = capture(tmp_fd, true, || unsafe { wprintf(fmt.as_ptr() $(, $arg)*) });
            // CHECK THE CAPTURE BEFORE COMPARING IT (bd-ug42ol step 2). See
            // `contamination` below: a mismatch here is libtest's bytes in our
            // file, not a divergence, and reporting it as one would fabricate a
            // defect in whichever arm happened to be captured second.
            if let Some(why) = contamination($label, "fl", rf, &bf) {
                fails.push(why);
            } else if let Some(why) = contamination($label, "glibc", rg, &bg) {
                fails.push(why);
            } else if rf != rg || bf != bg {
                fails.push(format!(
                    "{}: fl=(ret={rf}, bytes={:x?}) glibc=(ret={rg}, bytes={:x?})",
                    $label, bf, bg
                ));
            }
        }};
    }

    check!("ascii", "hello");
    check!(
        "euro x3 via %lc",
        "%lc%lc%lc",
        0x20AC_i32,
        0x20AC_i32,
        0x20AC_i32
    );
    check!("mixed", "a%lcb", 0x20AC_i32);
    check!("int+wc", "%d%lc", 42_i32, 0xE9_i32);
    check!("emoji", "%lc!", 0x1F600_i32);
    let ws = widen("wörld");
    check!("wide %ls", "[%ls]", ws.as_ptr());

    unsafe {
        libc::close(tmp_fd);
        libc::unlink(path.as_ptr());
    }

    assert!(
        fails.is_empty(),
        "wprintf return/output diverged from glibc:\n{}",
        fails.join("\n")
    );
}

/// Is this capture contaminated by a writer that is not the call under test?
///
/// bd-ug42ol step 2: CHECK the capture rather than trusting it. libtest writes
/// to **fd 1** from its own threads — the per-test `test <name> ... ok` line when
/// any test completes, and a `has been running for over 60 seconds` line from a
/// watchdog thread WHILE one runs. Either can land in a capture that holds fd 1,
/// and comparing the result then invents a divergence in whichever arm happened
/// to be captured while it arrived.
///
/// `wprintf` returns the number of WIDE CHARACTERS transmitted — that is the very
/// contract this file exists to pin — so the discriminator here is not a byte
/// count but a CHARACTER count: the captured bytes must decode to exactly `ret`
/// characters. Any injected line adds characters and breaks the equality, which
/// makes the residual watchdog case self-identifying instead of a fabricated
/// failure. A negative return is an error path with no output contract, so it is
/// left alone.
fn contamination(label: &str, arm: &str, ret: i32, bytes: &[u8]) -> Option<String> {
    if ret < 0 {
        return None;
    }
    let decoded = String::from_utf8_lossy(bytes);
    let chars = decoded.chars().count();
    if chars == ret as usize {
        return None;
    }
    Some(format!(
        "{label}: CONTAMINATED {arm} capture — wprintf returned {ret} wide chars but the \
         captured bytes decode to {chars}: {decoded:?} ({bytes:x?}). This is another writer's \
         bytes in our fd-1 capture (libtest's result line or its 60-second watchdog), \
         NOT a divergence — bd-ug42ol."
    ))
}

/// The single-`#[test]` property this file depends on, asserted so it cannot be
/// reintroduced silently.
///
/// Every arm above holds fd 1 while it runs. If a SECOND `#[test]` existed in
/// this binary it could COMPLETE inside one of those windows, and libtest would
/// write its result line into our capture. Collapsing the file to one test is
/// what closes that; this pins it. (It does not close the 60-second watchdog
/// case, which no test arrangement can — `contamination` above is what makes
/// that one visible.)
#[test]
fn this_file_declares_exactly_one_other_test() {
    let src = include_str!("wprintf_widecount_differential_test.rs");
    // Count lines that ARE the attribute, not lines that MENTION it. A plain
    // `matches("#[test]")` also counts the doc comments above — including this
    // one — and reports 6 where the answer is 2. Caught before this arm ever
    // ran; it would have failed for a reason that has nothing to do with the
    // property under test.
    let declared = src.lines().filter(|line| line.trim() == "#[test]").count();
    assert_eq!(
        declared, 2,
        "expected exactly two `#[test]` attributes — the capture arm and this \
         assertion itself. A third would let a test COMPLETE inside an fd-1 \
         capture window and put libtest's result line in the captured bytes \
         (bd-ug42ol)."
    );
}
