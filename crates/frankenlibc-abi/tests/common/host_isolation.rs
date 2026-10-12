//! Keep root-run gates from changing the machine they run on.
//!
//! ## Why this exists
//!
//! rch workers run offloaded `cargo test` as root (bd-30sv83). A gate that
//! checks a privileged call's *rejection* path therefore really performs the
//! call there. `conformance_diff_set_host_domainname` did: as root both arms of
//! `sethostname("frankenlibc-test")` / `setdomainname("frankenlibc.test")`
//! succeeded, and two fleet workers ran under those names for at least a week. The
//! test still passed, since its assertions only fired when a call failed.
//! `adjtimex(ADJ_OFFSET)` slewed the worker's clock the same way, and
//! `kexec_load(0, 0, NULL, 0)` unloaded any staged kexec image, and
//! `acct(NULL)` switched off any process accounting the host had enabled.
//!
//! ## How
//!
//! Both helpers run the body on a fresh thread and change only that thread.
//! Linux keeps the UTS namespace and the capability sets per task. The rest of
//! the test binary and the host never see the change, and it ends when the
//! thread exits. A panic in the body is re-raised on the calling thread, so
//! assertion messages reach libtest unchanged.

#![allow(dead_code)] // each gate uses only what it needs

use std::ffi::{CStr, c_int};

/// `CAP_SYS_PACCT` from <linux/capability.h> (gates `acct`).
pub const CAP_SYS_PACCT: u32 = 20;
/// `CAP_SYS_BOOT` from <linux/capability.h> (gates `kexec_load`).
pub const CAP_SYS_BOOT: u32 = 22;
/// `CAP_SYS_TIME` from <linux/capability.h> (gates modifying `adjtimex`).
pub const CAP_SYS_TIME: u32 = 25;

/// Runs `f` on a new thread inside a private UTS namespace. If a
/// `sethostname` / `setdomainname` call succeeds there (the caller is root), it
/// renames only that namespace.
///
/// When the kernel refuses the namespace with EPERM, the caller lacks
/// CAP_SYS_ADMIN, the same capability the setters check. The setters can then
/// only fail, so `f` runs in the host namespace, and the host's names are
/// checked afterwards to prove it. Any other refusal returns `None`. The caller
/// must then skip, and must not run the setters against the real host.
pub fn with_private_uts<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    run_on_fresh_thread(move || {
        // SAFETY: unshare takes a flag word. CLONE_NEWUTS does not imply
        // CLONE_THREAD, so it is allowed in a multithreaded process and moves
        // only the calling thread.
        if unsafe { libc::unshare(libc::CLONE_NEWUTS) } == 0 {
            return Some(f());
        }
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if err != libc::EPERM {
            return None;
        }
        let before = uts_names();
        let out = f();
        assert_eq!(
            uts_names(),
            before,
            "a setter that had to fail with EPERM changed the HOST's hostname/domainname"
        );
        Some(out)
    })
}

/// Runs `f` on a new thread whose effective capability set lacks `cap`, so a
/// privileged call takes its EPERM path even when the test runs as root.
/// Lowering an effective bit is always permitted. For an unprivileged caller
/// it is a no-op.
pub fn without_capability<T: Send + 'static>(
    cap: u32,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    run_on_fresh_thread(move || {
        drop_effective_capability(cap);
        f()
    })
}

/// `(nodename, domainname)` of the calling thread's UTS namespace.
pub fn uts_names() -> (Vec<u8>, Vec<u8>) {
    // SAFETY: utsname is plain old data, and uname fills it completely.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` is a valid, writable utsname.
    let rc = unsafe { libc::uname(&mut uts) };
    assert_eq!(rc, 0, "uname failed: {}", std::io::Error::last_os_error());
    // SAFETY: the kernel NUL-terminates both fields.
    let field = |f: &[libc::c_char]| unsafe { CStr::from_ptr(f.as_ptr()) }.to_bytes().to_vec();
    (field(&uts.nodename), field(&uts.domainname))
}

/// `cap_user_header_t` from <linux/capability.h>.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

/// `cap_user_data_t` element. V3 uses two of them (caps 0-31, 32-63).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn drop_effective_capability(cap: u32) {
    // pid 0 = the calling thread. Capability sets are per thread.
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: one V3 header plus two data slots is the layout capget expects.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    assert_eq!(rc, 0, "capget failed: {}", std::io::Error::last_os_error());
    data[(cap / 32) as usize].effective &= !(1u32 << (cap % 32));
    // SAFETY: same layout. Clearing an effective bit never needs privilege.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut hdr, data.as_ptr()) };
    assert_eq!(rc, 0, "capset failed: {}", std::io::Error::last_os_error());
}

fn run_on_fresh_thread<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match std::thread::spawn(f).join() {
        Ok(v) => v,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
