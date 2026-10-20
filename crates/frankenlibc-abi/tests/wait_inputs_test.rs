#![cfg(target_os = "linux")]
//! Real wait entry points, each in a fresh process with a bounded lifetime.

use std::ffi::{c_int, c_void};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use frankenlibc_abi::poll_abi as wait;

mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
#[path = "../src/wait_snapshot.rs"]
mod wait_snapshot;

const CHILD: &str = "FRANKENLIBC_WAIT_CASE";
const ZERO: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 0,
};
static DELIVERED: AtomicUsize = AtomicUsize::new(0);
extern "C" fn caught(_: c_int) {
    DELIVERED.fetch_add(1, Ordering::Relaxed);
}
fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

struct Pages {
    base: *mut u8,
    page: usize,
}
impl Pages {
    fn new() -> Self {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                2 * page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        assert_eq!(
            unsafe { libc::mprotect(base.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) },
            0
        );
        Self {
            base: base.cast(),
            page,
        }
    }
    fn readonly(&self) {
        assert_eq!(
            unsafe { libc::mprotect(self.base.cast(), self.page, libc::PROT_READ) },
            0
        );
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base.cast(), 2 * self.page) };
    }
}
struct Tracked(*mut c_void);
impl Tracked {
    fn new(bytes: usize) -> Self {
        let p = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes) };
        assert!(!p.is_null());
        assert_eq!(malloc_abi::known_remaining(p as usize), Some(bytes));
        unsafe { ptr::write_bytes(p.cast::<u8>(), 0, bytes) };
        Self(p)
    }
    fn retire(&mut self) -> *mut c_void {
        let p = self.0;
        unsafe { frankenlibc_abi::malloc_abi::free(p) };
        self.0 = ptr::null_mut();
        assert_eq!(malloc_abi::known_remaining(p as usize), Some(0));
        p
    }
}
impl Drop for Tracked {
    fn drop(&mut self) {
        unsafe { frankenlibc_abi::malloc_abi::free(self.0) };
    }
}

unsafe fn invoke(
    entry: &str,
    timeout: *const libc::timespec,
    mask: *const libc::sigset_t,
    ready: Option<c_int>,
) -> (c_int, c_int) {
    if entry.contains("ppoll") {
        let mut fd = libc::pollfd {
            fd: ready.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        };
        let (fds, count) = if ready.is_some() {
            (&mut fd as *mut _, 1)
        } else {
            (ptr::null_mut(), 0)
        };
        let rc = unsafe {
            match entry {
                "ppoll" => wait::ppoll(fds, count, timeout, mask),
                "__ppoll" => wait::__ppoll(fds, count, timeout, mask),
                "native-ppoll" => libc::ppoll(fds, count, timeout, mask),
                _ => panic!("unknown entry {entry}"),
            }
        };
        let e = errno();
        if rc > 0 {
            assert_ne!(fd.revents & libc::POLLIN, 0);
        }
        (rc, e)
    } else {
        let mut set: libc::fd_set = unsafe { std::mem::zeroed() };
        if let Some(fd) = ready {
            assert!(fd >= 0 && fd < libc::FD_SETSIZE as c_int);
            unsafe { libc::FD_SET(fd, &mut set) };
        }
        let nfds = ready.map_or(0, |fd| fd + 1);
        let read = if ready.is_some() {
            &mut set as *mut _
        } else {
            ptr::null_mut()
        };
        let rc = unsafe {
            match entry {
                "pselect" => {
                    wait::pselect(nfds, read, ptr::null_mut(), ptr::null_mut(), timeout, mask)
                }
                "__pselect" => {
                    wait::__pselect(nfds, read, ptr::null_mut(), ptr::null_mut(), timeout, mask)
                }
                "native-pselect" => {
                    libc::pselect(nfds, read, ptr::null_mut(), ptr::null_mut(), timeout, mask)
                }
                _ => panic!("unknown entry {entry}"),
            }
        };
        let e = errno();
        if rc > 0 {
            assert!(unsafe { libc::FD_ISSET(ready.unwrap(), &set) });
        }
        (rc, e)
    }
}

fn pending_signal() -> libc::sigset_t {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = caught as *const () as usize;
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, &action, ptr::null_mut()) },
        0
    );
    let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, ptr::null_mut()) },
        0
    );
    assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
    assert_eq!(DELIVERED.load(Ordering::Relaxed), 0);
    blocked
}

fn deny_copy_routes(pipe_too: bool) {
    // A child-only seccomp policy forces the production copyer's pipe fallback,
    // or denies both mechanisms to verify fail-closed behavior before waiting.
    let mut filters = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let denied = if pipe_too {
        vec![libc::SYS_process_vm_readv, libc::SYS_pipe2]
    } else {
        vec![libc::SYS_process_vm_readv]
    };
    for nr in denied {
        filters.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: nr as u32,
        });
        filters.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        });
    }
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                2,
                &program as *const libc::sock_fprog,
                0,
                0,
            )
        },
        0
    );
}

#[test]
fn wait_input_child() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    unsafe { libc::alarm(10) };
    frankenlibc_abi::malloc_abi::signal_runtime_ready_for_tests();
    let entry = std::env::var("FRANKENLIBC_WAIT_ENTRY").unwrap();
    let call = |ts, mask, ready| unsafe { invoke(&entry, ts, mask, ready) };
    match case.as_str() {
        "zero" => {
            unsafe { *libc::__errno_location() = libc::EDOM };
            assert_eq!(call(&ZERO, ptr::null(), None), (0, libc::EDOM));
        }
        "readonly-timeout" => {
            let pages = Pages::new();
            let ts = pages.base.cast::<libc::timespec>();
            unsafe {
                ts.write(libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000,
                })
            };
            pages.readonly();
            assert_eq!(call(ts, ptr::null(), None).0, 0);
            assert_eq!(unsafe { ((*ts).tv_sec, (*ts).tv_nsec) }, (0, 1_000_000));
        }
        "ready" | "ready-null-timeout" => {
            let raw = unsafe { libc::eventfd(1, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            assert!(raw >= 0);
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let ts = if case == "ready" { &ZERO } else { ptr::null() };
            assert_eq!(call(ts, ptr::null(), Some(fd.as_raw_fd())).0, 1);
            let mut value = 0u64;
            assert_eq!(
                unsafe { libc::read(fd.as_raw_fd(), (&mut value as *mut u64).cast(), 8) },
                8
            );
            assert_eq!(value, 1, "wait must not consume readiness data");
        }
        "negative-seconds" | "invalid-nanos" | "negative-nanos" | "invalid-time-before-mask" => {
            let ts = match case.as_str() {
                "negative-seconds" | "invalid-time-before-mask" => libc::timespec {
                    tv_sec: -1,
                    tv_nsec: 0,
                },
                "negative-nanos" => libc::timespec {
                    tv_sec: 0,
                    tv_nsec: -1,
                },
                _ => libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000_000,
                },
            };
            let mask = if case == "invalid-time-before-mask" {
                ptr::without_provenance(1)
            } else {
                ptr::null()
            };
            assert_eq!(call(&ts, mask, None), (-1, libc::EINVAL));
        }
        "mask-page-edge" => {
            let pages = Pages::new();
            let mask = unsafe { pages.base.add(pages.page - 8).cast::<u64>() };
            unsafe { mask.write(0) };
            pages.readonly();
            assert_eq!(
                call(&ZERO, mask.cast(), None).0,
                0,
                "unused sigset_t tail was read"
            );
        }
        "bad-mask" | "unreadable-mask" => {
            let pages = Pages::new();
            let mask = if case == "bad-mask" {
                ptr::without_provenance(1)
            } else {
                unsafe { pages.base.add(pages.page).cast() }
            };
            assert_eq!(call(&ZERO, mask, None), (-1, libc::EFAULT));
        }
        "signal-unblocked" | "signal-blocked" => {
            let blocked = pending_signal();
            let empty: libc::sigset_t = unsafe { std::mem::zeroed() };
            let unblocks = case == "signal-unblocked";
            let ts = libc::timespec {
                tv_sec: if unblocks { 1 } else { 0 },
                tv_nsec: 0,
            };
            let result = call(&ts, if unblocks { &empty } else { &blocked }, None);
            if unblocks {
                assert_eq!(result, (-1, libc::EINTR));
            } else {
                assert_eq!(result.0, 0);
            }
            assert_eq!(DELIVERED.load(Ordering::Relaxed), usize::from(unblocks));
            assert_eq!((ts.tv_sec, ts.tv_nsec), (if unblocks { 1 } else { 0 }, 0));
            let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, ptr::null(), &mut current) },
                0
            );
            assert_eq!(
                unsafe { libc::sigismember(&current, libc::SIGUSR1) },
                1,
                "signal mask not restored"
            );
        }
        "short-timeout" | "short-mask" => {
            let bytes = if case == "short-timeout" {
                size_of::<libc::timespec>() - 1
            } else {
                7
            };
            let region = Tracked::new(bytes);
            let (ts, mask) = if case == "short-timeout" {
                (region.0.cast_const().cast(), ptr::null())
            } else {
                (&ZERO as *const _, region.0.cast_const().cast())
            };
            assert_eq!(call(ts, mask, None), (-1, libc::EFAULT));
        }
        "bad-timeout" | "unreadable-timeout" | "cross-page-timeout" | "wrapping-timeout" => {
            let pages = Pages::new();
            let ts = match case.as_str() {
                "bad-timeout" => ptr::without_provenance(1),
                "wrapping-timeout" => ptr::without_provenance(usize::MAX - 7),
                "cross-page-timeout" => unsafe { pages.base.add(pages.page - 8).cast() },
                _ => unsafe { pages.base.add(pages.page).cast() },
            };
            assert_eq!(call(ts, ptr::null(), None), (-1, libc::EFAULT));
        }
        "unaligned-timeout" | "unaligned-mask" => {
            let mut words = [0u64; 4];
            let misaligned = unsafe { words.as_mut_ptr().cast::<u8>().add(1) };
            let (ts, mask) = if case == "unaligned-timeout" {
                (misaligned.cast_const().cast(), ptr::null())
            } else {
                (&ZERO as *const _, misaligned.cast_const().cast())
            };
            assert_eq!(call(ts, mask, None).0, 0);
            assert_eq!(words, [0u64; 4]);
        }
        "stale-timeout" | "stale-mask" => {
            let mut region = Tracked::new(if case == "stale-timeout" {
                size_of::<libc::timespec>()
            } else {
                8
            });
            let stale = region.retire();
            let (ts, mask) = if case == "stale-timeout" {
                (stale.cast_const().cast(), ptr::null())
            } else {
                (&ZERO as *const _, stale.cast_const().cast())
            };
            assert_eq!(call(ts, mask, None), (-1, libc::EFAULT));
        }
        "pipe-fallback" | "copy-denied" => {
            let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
            deny_copy_routes(case == "copy-denied");
            let empty: libc::sigset_t = unsafe { std::mem::zeroed() };
            let result = call(&ZERO, &empty, None);
            if case == "copy-denied" {
                assert_eq!(result, (-1, libc::EPERM));
            } else {
                assert_eq!(result.0, 0);
            }
            assert_eq!(
                std::fs::read_dir("/proc/self/fd").unwrap().count(),
                before,
                "copy pipe leaked"
            );
        }
        _ => panic!("unknown case {case}"),
    }
}

#[test]
fn wait_inputs_are_process_isolated() {
    let executable = std::env::current_exe().unwrap();
    let selection = std::env::var("FRANKENLIBC_WAIT_SELECT").ok();
    let mut count = 0;
    let mut run = |mode: &str, entry: &str, case: &str| {
        if selection.as_deref().is_some_and(|select| select != case) {
            return;
        }
        let output = Command::new(&executable)
            .args(["--exact", "wait_input_child", "--nocapture"])
            .env("FRANKENLIBC_MODE", mode)
            .env(CHILD, case)
            .env("FRANKENLIBC_WAIT_ENTRY", entry)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "wait input child failed {mode}/{entry}/{case}: {:?}\n{}\n{}",
            output.status,
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("1 passed; 0 failed;"),
            "child did not execute {mode}/{entry}/{case}"
        );
        count += 1;
    };
    let common = [
        "zero",
        "readonly-timeout",
        "ready",
        "ready-null-timeout",
        "negative-seconds",
        "invalid-nanos",
        "negative-nanos",
        "invalid-time-before-mask",
        "mask-page-edge",
        "bad-mask",
        "unreadable-mask",
        "signal-unblocked",
        "signal-blocked",
    ];
    for entry in ["native-ppoll", "native-pselect"] {
        for case in common {
            run("strict", entry, case);
        }
    }
    for mode in ["strict", "hardened"] {
        for entry in ["ppoll", "__ppoll", "pselect", "__pselect"] {
            for case in common {
                run(mode, entry, case);
            }
            for case in ["short-timeout", "short-mask"] {
                run(mode, entry, case);
            }
            if mode == "hardened" {
                for case in [
                    "bad-timeout",
                    "unreadable-timeout",
                    "cross-page-timeout",
                    "wrapping-timeout",
                    "unaligned-timeout",
                    "unaligned-mask",
                    "stale-timeout",
                    "stale-mask",
                    "pipe-fallback",
                    "copy-denied",
                ] {
                    run(mode, entry, case);
                }
            }
        }
    }
    if selection.is_none() {
        assert_eq!(count, 186);
    } else {
        assert!(count > 0);
    }
    println!("WAIT INPUT ABI: {count} isolated cases passed (including native controls)");
}

#[test]
fn owned_controls_survive_caller_changes() {
    let mut ts = ZERO;
    let mut mask = 0u64;
    let mut input =
        unsafe { wait_snapshot::PreparedWait::prepare(&ts, (&mask as *const u64).cast(), true) }
            .unwrap();
    ts.tv_sec = 999;
    mask = 1u64 << (libc::SIGUSR1 - 1);
    std::hint::black_box((&ts, &mask));
    let (ts_ptr, mask_ptr) = input.kernel_args();
    assert_ne!(ts_ptr, (&ts as *const libc::timespec).cast());
    assert_ne!(
        mask_ptr,
        (&mask as *const u64).cast(),
        "signal snapshot lost ownership"
    );
    assert_eq!(
        unsafe { mask_ptr.cast::<u64>().read() },
        0,
        "signal snapshot lost ownership"
    );
    assert_eq!(
        unsafe { ts_ptr.cast::<libc::timespec>().read().tv_sec },
        0,
        "timeout snapshot lost ownership"
    );
    // Invoke the actual kernel with the prepared pointers. It must not wait
    // 999 seconds, and any remaining-time write must target owned storage.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                ptr::null_mut::<libc::pollfd>(),
                0usize,
                ts_ptr,
                mask_ptr,
                wait_snapshot::KERNEL_SIGSET_BYTES,
            )
        },
        0
    );
    assert_eq!((ts.tv_sec, mask), (999, 1u64 << (libc::SIGUSR1 - 1)));
}
