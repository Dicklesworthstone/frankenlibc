#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc warnx oracle via dlsym + a vararg trampoline

//! `warnx("%Lf")` against the LIVE glibc — the err/warn argument stream.
//!
//! ## Why this file exists separately from the printf one
//!
//! `err_abi` has its OWN copy of the variadic extraction macro. The narrow and
//! wide printf families were fixed by routing long-double formats to the
//! va_list walker; `err`/`warn`/`errx`/`warnx` were NOT, and fixing one copy of
//! the logic proves nothing about another — that is exactly how the wide side
//! stayed broken after the narrow side was fixed
//! (bd-longdouble-varargs-43usjw).
//!
//! ## What is actually being tested
//!
//! A `long double` vararg is class X87 on x86-64 SysV: sixteen bytes in the
//! overflow area, and the integer parameters carry on in registers as though it
//! were not in the sequence. Reading it as a `double` takes eight bytes out of
//! the SSE register save area — which on such a call was never written, since
//! `al` is zero — AND leaves the caller's sixteen stack bytes unconsumed, so
//! every following conversion reads the wrong argument.
//!
//! So the formats here put a conversion AFTER the long double. A format ending
//! at the `%Lf` would print one wrong number and hide the stream corruption.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Read;
use std::sync::{Mutex, OnceLock};

#[path = "common/fd_capture.rs"]
mod fd_capture;

type HostWarnx = unsafe extern "C" fn() -> c_int;

/// `warnx(fmt, <long double>, trailing_int)`.
///
/// Register layout, which is the whole point of writing this by hand: `fmt`
/// stays in RDI, the long double takes the first sixteen-byte stack slot, and
/// the trailing `int` takes the NEXT integer register — the sequence skips the
/// long double entirely. `al` must be zero: an X87 argument uses no SSE
/// register.
///
/// # Safety
///
/// `fmt` must be a NUL-terminated format; `value` sixteen readable bytes;
/// `host` a `warnx`-compatible function.
#[unsafe(naked)]
unsafe extern "C" fn call_warnx_ld_then_int(
    _fmt: *const c_char,
    _value: *const u8,
    _trailing: c_int,
    _host: HostWarnx,
) {
    core::arch::naked_asm!(
        // Entry rsp ≡ 8 (mod 16); 24 brings it to ≡ 0, which is what the ABI
        // wants at the call AND makes [rsp] sixteen-byte aligned for the slot.
        "sub rsp, 24",
        "movups xmm0, [rsi]",
        "movups [rsp], xmm0",
        "mov rsi, rdx",
        "xor eax, eax",
        "call rcx",
        "add rsp, 24",
        "ret",
    )
}

fn host_warnx() -> HostWarnx {
    static H: OnceLock<Option<usize>> = OnceLock::new();
    let addr = (*H.get_or_init(|| {
        // SAFETY: dlopen/dlsym with NUL-terminated names; handle leaked.
        unsafe {
            let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
            if handle.is_null() {
                return None;
            }
            let sym = libc::dlsym(handle, c"warnx".as_ptr());
            if sym.is_null() {
                return None;
            }
            let fl = frankenlibc_abi::err_abi::warnx as *const () as usize;
            assert_ne!(
                sym as usize, fl,
                "the resolved warnx IS fl's own — this gate would compare fl \
                 against itself and pass unconditionally (bd-v0388t)"
            );
            Some(sym as usize)
        }
    }))
    .expect("glibc warnx must resolve");
    // SAFETY: the address came from dlsym on glibc's warnx.
    unsafe { std::mem::transmute::<usize, HostWarnx>(addr) }
}

/// fd 2 is process-wide, so two arms redirecting it concurrently would read
/// each other's bytes. libtest runs the arms of one target on threads of one
/// process, so this is serialised here rather than by requiring
/// `--test-threads=1` — a gate that is only correct under a flag nobody passes
/// reads as a real defect on every sweep (bd-cttqvh).
static STDERR_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with fd 2 redirected to a pipe and return what it wrote.
fn capture_stderr(f: impl FnOnce()) -> String {
    let _guard = STDERR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a two-element array, which is what pipe() writes.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Restored by a Drop guard, INCLUDING on unwind: a panic in `f()` would skip
    // a straight-line restore and leave this process's stderr pointed at the pipe
    // for the rest of the run, swallowing libtest's report of that very failure
    // (bd-ug42ol). Block-scoped so fd 2 is restored BEFORE the read below: while
    // redirected it holds a second reference to the pipe's WRITE end and the
    // reader would never see EOF.
    {
        // SAFETY: dup/dup2 on live descriptors; the guard restores fd 2 on exit.
        let _restore = unsafe { fd_capture::StdFdRestore::new(2) };
        assert!(
            unsafe { libc::dup2(write_fd, 2) } >= 0,
            "dup2 onto 2 failed"
        );

        f();
    }

    // SAFETY: closing our own copy of the write end.
    unsafe {
        libc::close(write_fd);
    }

    let mut out = String::new();
    // SAFETY: `read_fd` is a live descriptor this function owns; `from_raw_fd`
    // takes ownership and closes it on drop.
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(read_fd) };
    file.read_to_string(&mut out).expect("read from pipe");
    out
}

fn x87(digits: &[u8], dexp: i32, negative: bool) -> [u8; 16] {
    let ten = frankenlibc_core::float128::decimal_to_x87_extended(negative, digits, dexp);
    let mut sixteen = [0u8; 16];
    sixteen[..10].copy_from_slice(&ten);
    sixteen
}

/// glibc and fl, same format, same bytes, in one invocation.
fn both(fmt: &str, value: &[u8; 16], trailing: c_int) -> (String, String) {
    let fmt_c = CString::new(fmt).expect("no interior NUL");
    let host = capture_stderr(|| {
        // SAFETY: sixteen readable value bytes; `host_warnx` is glibc's warnx.
        unsafe {
            call_warnx_ld_then_int(fmt_c.as_ptr(), value.as_ptr(), trailing, host_warnx());
        }
    });
    let fl = capture_stderr(|| {
        // SAFETY: as above, with fl's own warnx as the callee.
        unsafe {
            call_warnx_ld_then_int(
                fmt_c.as_ptr(),
                value.as_ptr(),
                trailing,
                std::mem::transmute::<*const (), HostWarnx>(
                    frankenlibc_abi::err_abi::warnx as *const (),
                ),
            );
        }
    });
    (host, fl)
}

/// `warnx` prefixes the program name and both libraries derive it from the same
/// process, but they need not agree on how — so the argument-stream assertions
/// below compare the MESSAGE, and a dedicated arm checks the prefix separately.
fn body(line: &str) -> &str {
    line.split_once(": ").map_or(line, |(_, rest)| rest)
}

/// The trampoline and the capture must both be right before any comparison
/// means anything. Asserting on glibc's output pins the instrument against the
/// incumbent rather than against fl.
#[test]
fn the_warnx_trampoline_and_capture_work() {
    let (host, _fl) = both("%.2Lf|%d", &x87(b"125", -1, false), 4242);
    assert!(
        !host.is_empty(),
        "nothing was captured from glibc's warnx — the fd-2 redirect is broken, \
         not fl"
    );
    assert_eq!(
        body(&host).trim_end(),
        "12.50|4242",
        "glibc must see 12.5 and 4242 — if not, the trampoline is wrong"
    );
    let (host, _fl) = both("%.2Lf|%d", &x87(b"25", -1, false), 7);
    assert_eq!(
        body(&host).trim_end(),
        "2.50|7",
        "distinct inputs must give distinct answers"
    );
}

/// THE POINT OF THE FIX. `err_abi` read every float argument with
/// `next_arg::<f64>()`, so `%Lf` took eight bytes out of an SSE register save
/// area that an X87 call never writes, and left the caller's sixteen stack
/// bytes in place for the next conversion to trip over.
#[test]
fn warnx_long_double_reads_its_own_argument() {
    let value = x87(b"125", -1, false);
    for fmt in ["%.2Lf|%d", "%Lf %d", "%.1Lf[%d]", "%.3Lf%d"] {
        let (host, fl) = both(fmt, &value, 4242);
        assert_eq!(
            body(&fl).trim_end(),
            body(&host).trim_end(),
            "argument stream diverges for {fmt:?} (fl={fl:?} glibc={host:?})"
        );
        assert!(
            fl.contains("4242"),
            "the trailing int was lost for {fmt:?}: {fl:?} — this is the \
             unconsumed-stack-slot bug"
        );
    }
}

/// Values, not just the stream. A reader that consumed sixteen bytes but
/// decoded them wrongly would keep the following argument aligned and pass the
/// arm above.
#[test]
fn warnx_long_double_values_match_live_glibc() {
    for (digits, dexp, negative) in [
        (&b"1"[..], 0, false),
        (b"125", -1, false),
        (b"125", -1, true),
        (b"5", -1, false),
        (b"0", 0, false),
    ] {
        let value = x87(digits, dexp, negative);
        for fmt in ["%Lf|%d", "%.2Lf|%d", "%Le|%d", "%Lg|%d"] {
            let (host, fl) = both(fmt, &value, 4242);
            assert_eq!(
                body(&fl).trim_end(),
                body(&host).trim_end(),
                "{fmt} of {}e{} (negative={negative})",
                String::from_utf8_lossy(digits),
                dexp
            );
        }
    }
}

/// The prefix, checked on its own so a progname divergence cannot be mistaken
/// for an argument-stream one — and cannot hide behind `body()` either.
#[test]
fn warnx_program_name_prefix_matches_live_glibc() {
    let (host, fl) = both("%.2Lf|%d", &x87(b"125", -1, false), 4242);
    let host_prefix = host.split_once(": ").map(|(p, _)| p);
    let fl_prefix = fl.split_once(": ").map(|(p, _)| p);
    assert_eq!(
        fl_prefix, host_prefix,
        "warnx program-name prefix diverges (fl={fl:?} glibc={host:?})"
    );
}

/// The positional path through the same macro.
#[test]
fn positional_warnx_long_double_reads_its_own_argument() {
    let value = x87(b"125", -1, false);
    for fmt in ["%1$.2Lf|%2$d", "%2$d[%1$.1Lf]"] {
        let (host, fl) = both(fmt, &value, 4242);
        assert_eq!(
            body(&fl).trim_end(),
            body(&host).trim_end(),
            "positional argument stream diverges for {fmt:?} (fl={fl:?} glibc={host:?})"
        );
        assert!(
            fl.contains("4242"),
            "the positional int was lost for {fmt:?}: {fl:?}"
        );
    }
}
