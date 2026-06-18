#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live host-glibc psiginfo oracle + raw siginfo_t layout

//! `psiginfo` parity vs host glibc (bd-765exy).
//!
//! fl previously printed `"<msg>: SIG<abbrev>\n"` (the signal *abbreviation*),
//! whereas glibc prints the signal *description* followed by a parenthesised
//! `si_code` explanation and a class-specific payload, e.g.
//! `"pfx: Segmentation fault (Address not mapped to object [0x1234])\n"`.
//!
//! This gate captures both glibc's and fl's stderr for an identical
//! `siginfo_t` and asserts byte-for-byte equality across: every standard
//! signal, the per-signal `si_code` tables (fault/chld/poll/etc.), the SI_*
//! sender classes, fault addresses (incl. NULL -> "(nil)"), SIGCHLD pid/uid/
//! status and SIGPOLL band payloads, real-time signals (SIGRTMIN+n /
//! SIGRTMAX-n naming), and out-of-range "Unknown signal N".

use std::ffi::c_char;
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn psiginfo(info: *const libc::siginfo_t, msg: *const c_char);
}

// capture() redirects the process-global fd 2; serialize so parallel tests
// never clobber each other's redirection.
static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

/// Build a siginfo_t with controlled si_signo/si_code and union payload words
/// (offsets match the LP64 kernel layout: payload union begins at byte 16).
fn make_info(signo: i32, code: i32, w16_lo: i32, w20: u32, w24: i32, w16_full: i64) -> libc::siginfo_t {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let base = &mut info as *mut libc::siginfo_t as *mut u8;
    unsafe {
        (base as *mut i32).write(signo); // si_signo @0
        (base.add(8) as *mut i32).write(code); // si_code @8
        if w16_full != 0 {
            (base.add(16) as *mut i64).write(w16_full); // si_addr / si_band @16
        } else {
            (base.add(16) as *mut i32).write(w16_lo); // si_pid @16
            (base.add(20) as *mut u32).write(w20); // si_uid @20
            (base.add(24) as *mut i32).write(w24); // si_status @24
        }
    }
    info
}

fn capture<F: FnOnce()>(f: F) -> String {
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut out = String::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = file.read_to_string(&mut out);
    out
}

fn assert_match(tag: &str, info: &libc::siginfo_t, msg: Option<&str>) {
    let cmsg = msg.map(|m| std::ffi::CString::new(m).unwrap());
    let mp = cmsg.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

    let g = capture(|| unsafe { psiginfo(info, mp) });
    let f = capture(|| unsafe { frankenlibc_abi::signal_abi::psiginfo(info, mp) });
    assert_eq!(g, f, "[{tag}] psiginfo mismatch\n  glibc={g:?}\n  fl   ={f:?}");
}

#[test]
fn standard_signals_si_user() {
    // si_code = SI_USER (0): "Signal sent by kill()" + pid/uid (or addr/etc).
    for signo in 1..=31 {
        let info = make_info(signo, 0, 1234, 1000, 0, 0);
        assert_match(&format!("signo={signo}"), &info, Some("pfx"));
    }
}

#[test]
fn fault_signals_with_address() {
    // SIGILL/SIGFPE/SIGSEGV/SIGBUS print si_addr with %p.
    for signo in [libc::SIGILL, libc::SIGFPE, libc::SIGSEGV, libc::SIGBUS] {
        for addr in [0i64, 0x1234, 0x7fff_dead_beefi64] {
            let info = make_info(signo, 0, 0, 0, 0, addr);
            assert_match(&format!("fault signo={signo} addr={addr:#x}"), &info, Some("p"));
        }
    }
}

#[test]
fn per_signal_si_code_tables() {
    // Each per-signal si_code table entry (1-based).
    let cases: &[(i32, i32)] = &[
        (libc::SIGILL, 1),
        (libc::SIGILL, 8),
        (libc::SIGFPE, 6), // the "Floating-poing" typo entry
        (libc::SIGSEGV, 1),
        (libc::SIGSEGV, 2),
        (libc::SIGBUS, 3),
        (libc::SIGTRAP, 1),
        (libc::SIGTRAP, 2),
        (libc::SIGCHLD, 1),
        (libc::SIGCHLD, 6),
        (libc::SIGPOLL, 1),
        (libc::SIGPOLL, 6),
    ];
    for &(signo, code) in cases {
        // For SIGCHLD give pid/uid/status; SIGPOLL gives band via w16_full.
        let info = if signo == libc::SIGPOLL {
            make_info(signo, code, 0, 0, 0, 7)
        } else {
            make_info(signo, code, 4321, 65534, -9, 0)
        };
        assert_match(&format!("code signo={signo} code={code}"), &info, Some("x"));
    }
}

#[test]
fn si_sender_classes() {
    // SI_QUEUE/SI_TIMER/SI_MESGQ/SI_ASYNCIO/SI_SIGIO/SI_TKILL/SI_KERNEL plus
    // an out-of-table positive code that falls through to the numeric branch.
    for code in [-1, -2, -3, -4, -5, -6, -60, 0x80, 5, 42] {
        let info = make_info(libc::SIGUSR1, code, 11, 22, 0, 0);
        assert_match(&format!("sender code={code}"), &info, Some("m"));
    }
}

#[test]
fn sigchld_payload_and_poll() {
    let chld = make_info(libc::SIGCHLD, 0, 4242, 1000, 7, 0);
    assert_match("sigchld", &chld, Some("c"));
    let poll = make_info(libc::SIGPOLL, 0, 0, 0, 0, 3);
    assert_match("sigpoll", &poll, Some("c"));
}

#[test]
fn realtime_signals() {
    let rtmin = unsafe { libc::SIGRTMIN() };
    let rtmax = unsafe { libc::SIGRTMAX() };
    for signo in [rtmin, rtmin + 1, rtmin + 5, rtmax - 1, rtmax, (rtmin + rtmax) / 2] {
        let info = make_info(signo, 0, 1, 2, 0, 0);
        assert_match(&format!("rt signo={signo}"), &info, Some("rt"));
    }
}

#[test]
fn unknown_signals_and_prefix_variants() {
    for signo in [0, 32, 33, 200] {
        let info = make_info(signo, 0, 0, 0, 0, 0);
        assert_match(&format!("unknown signo={signo}"), &info, Some("u"));
    }
    // Empty and NULL prefix omit the "msg: " portion.
    let info = make_info(libc::SIGINT, 0, 5, 6, 0, 0);
    assert_match("empty-prefix", &info, Some(""));
    assert_match("null-prefix", &info, None);
}
