#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live glibc syslog oracle via dlsym + a vararg trampoline

//! `syslog("%Lf")` against the LIVE glibc, via `LOG_PERROR`.
//!
//! ## Why a fourth file for the same bug
//!
//! The variadic extraction macro is copied four times in this tree — narrow
//! printf, wide printf, `err`/`warn`, and syslog — and each copy had to be
//! fixed on its own. bd-longdouble-varargs-43usjw records the wide side staying
//! broken for a day after the narrow side was fixed, because a green narrow
//! gate said nothing about it. So syslog gets its own arm rather than a note.
//!
//! ## How the comparison is made observable
//!
//! syslog normally goes to `/dev/log`, which a differential cannot read. Both
//! libraries support `LOG_PERROR`, which additionally writes the message to
//! stderr, so each side is opened with it and stderr is captured through a
//! pipe. Each library keeps its OWN openlog state, so `openlog` is called on
//! each through the same dlsym/native split as `syslog` itself.
//!
//! ## What is being tested
//!
//! A `long double` vararg is class X87: sixteen bytes in the overflow area, and
//! `al` is zero because no SSE register is used. Reading it as a `double` takes
//! eight bytes out of a register save area that was never written.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Read;
use std::sync::{Mutex, OnceLock};

const LOG_PERROR: c_int = 0x20;
const LOG_USER: c_int = 1 << 3;
const LOG_INFO: c_int = 6;

type HostSyslog = unsafe extern "C" fn() -> c_int;
type HostOpenlog = unsafe extern "C" fn(*const c_char, c_int, c_int);

/// `syslog(priority, fmt, <long double>, trailing_int)`.
///
/// `priority` stays in EDI and `fmt` in RSI; the long double takes the first
/// sixteen-byte stack slot; the trailing `int` takes the NEXT integer register,
/// RDX — the sequence skips the long double entirely. `al` must be zero.
///
/// # Safety
///
/// `fmt` must be NUL-terminated, `value` sixteen readable bytes, `host` a
/// `syslog`-compatible function.
#[unsafe(naked)]
unsafe extern "C" fn call_syslog_ld_then_int(
    _priority: c_int,
    _fmt: *const c_char,
    _value: *const u8,
    _trailing: c_int,
    _host: HostSyslog,
) {
    core::arch::naked_asm!(
        // Entry rsp ≡ 8 (mod 16); 24 brings it to ≡ 0, which the ABI wants at
        // the call and which also aligns [rsp] for the sixteen-byte slot.
        "sub rsp, 24",
        "movups xmm0, [rdx]",
        "movups [rsp], xmm0",
        "mov rdx, rcx",
        "xor eax, eax",
        "call r8",
        "add rsp, 24",
        "ret",
    )
}

fn host_sym(name: &std::ffi::CStr, fl_addr: usize, what: &str) -> usize {
    // SAFETY: dlopen/dlsym with NUL-terminated names; handle leaked.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "dlopen libc.so.6");
        let sym = libc::dlsym(handle, name.as_ptr());
        assert!(!sym.is_null(), "glibc {what} must resolve");
        assert_ne!(
            sym as usize, fl_addr,
            "the resolved {what} IS fl's own — this gate would compare fl \
             against itself and pass unconditionally (bd-v0388t)"
        );
        sym as usize
    }
}

fn host_syslog() -> HostSyslog {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| {
        host_sym(
            c"syslog",
            frankenlibc_abi::unistd_abi::syslog as *const () as usize,
            "syslog",
        )
    });
    // SAFETY: the address came from dlsym on glibc's syslog.
    unsafe { std::mem::transmute::<usize, HostSyslog>(addr) }
}

fn host_openlog() -> HostOpenlog {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| {
        host_sym(
            c"openlog",
            frankenlibc_abi::unistd_abi::openlog as *const () as usize,
            "openlog",
        )
    });
    // SAFETY: the address came from dlsym on glibc's openlog.
    unsafe { std::mem::transmute::<usize, HostOpenlog>(addr) }
}

/// fd 2 is process-wide, and so is each library's openlog state. Serialised
/// here rather than by requiring `--test-threads=1`: a gate that is only correct
/// under a flag nobody passes reads as a real defect on every sweep (bd-cttqvh).
static STDERR_LOCK: Mutex<()> = Mutex::new(());

fn capture_stderr(f: impl FnOnce()) -> String {
    let _guard = STDERR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0 as c_int; 2];
    // SAFETY: `fds` is a two-element array, which is what pipe() writes.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // SAFETY: dup/dup2 on live descriptors; the saved fd is restored below.
    let saved = unsafe { libc::dup(2) };
    assert!(saved >= 0, "dup(2) failed");
    // SAFETY: as above.
    assert!(
        unsafe { libc::dup2(write_fd, 2) } >= 0,
        "dup2 onto 2 failed"
    );

    f();

    // SAFETY: restoring the saved descriptor and closing our own copies.
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(write_fd);
    }

    let mut out = String::new();
    // SAFETY: `read_fd` is live and owned here; `from_raw_fd` takes ownership.
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

static IDENT: OnceLock<CString> = OnceLock::new();

fn open_both() {
    let ident = IDENT.get_or_init(|| CString::new("fl-ld-gate").expect("no NUL"));
    // SAFETY: NUL-terminated ident; both openlogs take the same C signature.
    unsafe {
        host_openlog()(ident.as_ptr(), LOG_PERROR, LOG_USER);
        frankenlibc_abi::unistd_abi::openlog(ident.as_ptr(), LOG_PERROR, LOG_USER);
    }
}

/// glibc and fl, same format, same bytes, in one invocation.
fn both(fmt: &str, value: &[u8; 16], trailing: c_int) -> (String, String) {
    open_both();
    let fmt_c = CString::new(fmt).expect("no interior NUL");
    let host = capture_stderr(|| {
        // SAFETY: sixteen readable value bytes; callee is glibc's syslog.
        unsafe {
            call_syslog_ld_then_int(
                LOG_USER | LOG_INFO,
                fmt_c.as_ptr(),
                value.as_ptr(),
                trailing,
                host_syslog(),
            );
        }
    });
    let fl = capture_stderr(|| {
        // SAFETY: as above, with fl's own syslog as the callee.
        unsafe {
            call_syslog_ld_then_int(
                LOG_USER | LOG_INFO,
                fmt_c.as_ptr(),
                value.as_ptr(),
                trailing,
                std::mem::transmute::<*const (), HostSyslog>(
                    frankenlibc_abi::unistd_abi::syslog as *const (),
                ),
            );
        }
    });
    (host, fl)
}

/// `LOG_PERROR` output is `ident[pid]: message`. The two libraries need not
/// spell the prefix identically, so the argument assertions compare the
/// MESSAGE and a dedicated arm compares the prefix.
fn body(line: &str) -> &str {
    line.rsplit_once(": ").map_or(line, |(_, rest)| rest)
}

/// The instrument, pinned against the incumbent rather than against fl. If
/// glibc's own output is not what a working trampoline and capture would
/// produce, nothing below means anything.
#[test]
fn the_syslog_trampoline_and_capture_work() {
    let (host, _fl) = both("%.2Lf|%d", &x87(b"125", -1, false), 4242);
    assert!(
        !host.is_empty(),
        "nothing was captured from glibc's syslog — either LOG_PERROR was not \
         honoured or the fd-2 redirect is broken, neither of which is fl"
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

/// fl must honour LOG_PERROR at all — otherwise every comparison below would be
/// "" vs "" for the wrong reason.
#[test]
fn fl_honours_log_perror() {
    let (_host, fl) = both("%.2Lf|%d", &x87(b"125", -1, false), 4242);
    assert!(
        !fl.is_empty(),
        "fl produced no LOG_PERROR output at all, so a matching comparison \
         would be vacuous"
    );
}

/// THE DEFECT. syslog's copy of the extraction macro read every float argument
/// with `next_arg::<f64>()`, so `%Lf` took eight bytes out of an SSE register
/// save area that an X87 call never writes.
#[test]
fn syslog_long_double_values_match_live_glibc() {
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

/// The positional path through the same macro.
#[test]
fn positional_syslog_long_double_matches_live_glibc() {
    let value = x87(b"125", -1, false);
    for fmt in ["%1$.2Lf|%2$d", "%2$d[%1$.1Lf]"] {
        let (host, fl) = both(fmt, &value, 4242);
        assert_eq!(
            body(&fl).trim_end(),
            body(&host).trim_end(),
            "positional argument stream diverges for {fmt:?} (fl={fl:?} glibc={host:?})"
        );
    }
}
