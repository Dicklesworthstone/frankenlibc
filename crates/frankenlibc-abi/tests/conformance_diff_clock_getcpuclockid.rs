//! Differential gate: clock_getcpuclockid vs live host glibc.
//!
//! fl special-cased pid==0 to CLOCK_PROCESS_CPUTIME_ID (2), but glibc applies the
//! kernel CPUCLOCK encoding (~pid << 3 | CPUCLOCK_SCHED) for EVERY pid — so
//! clock_getcpuclockid(0) yields 0xFFFFFFFA, not 2. We compare the return code
//! AND the written clock_id for pid 0 / self / init / a bogus pid (glibc reached
//! via dlsym).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn getpid() -> c_int;
}
type Fn_ = unsafe extern "C" fn(c_int, *mut c_int) -> c_int;

fn glibc() -> Fn_ {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"clock_getcpuclockid".as_ptr()))
    }
}

#[test]
fn clock_getcpuclockid_matches_glibc() {
    let g = glibc();
    let self_pid = unsafe { getpid() };
    let mut mism = Vec::new();
    // pid 0 (caller), self, init, and a likely-nonexistent pid.
    for &pid in &[0, self_pid, 1, 0x3FFF_FFFF] {
        let mut gc: c_int = -1;
        let mut fc: c_int = -1;
        let gr = unsafe { g(pid, &mut gc) };
        let fr = unsafe { fl::clock_getcpuclockid(pid, &mut fc) };
        // Return code (0 or an errno like ESRCH) must match.
        if gr != fr {
            mism.push(format!("pid={pid}: rc glibc={gr} fl={fr}"));
        }
        // On success the encoded clock_id must match exactly; on failure neither
        // should have written it (both stay -1).
        if gc != fc {
            mism.push(format!("pid={pid}: clock_id glibc={gc:#x} fl={fc:#x}"));
        }
    }
    assert!(mism.is_empty(), "clock_getcpuclockid diverged:\n{}", mism.join("\n"));
}
