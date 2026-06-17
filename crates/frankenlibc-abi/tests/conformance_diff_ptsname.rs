//! Differential gate: ptsname_r / ptsname error contract vs live host glibc.
//!
//! fl returned the raw TIOCGPTN errno (EINVAL) for a non-pty-master fd, but
//! glibc maps that to ENOTTY; and fl rejected buflen==0 with EINVAL where glibc
//! runs the ioctl first (→ ENOTTY for a non-master, or ERANGE for a master).
//! glibc is reached via dlsym; both engines act on the SAME fds.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn posix_openpt(flags: c_int) -> c_int;
    fn grantpt(fd: c_int) -> c_int;
    fn unlockpt(fd: c_int) -> c_int;
    fn open(path: *const c_char, flags: c_int) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
}
type RFn = unsafe extern "C" fn(c_int, *mut c_char, usize) -> c_int;
type PFn = unsafe extern "C" fn(c_int) -> *mut c_char;

fn glibc() -> (RFn, PFn) {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        (
            std::mem::transmute(dlsym(h, c"ptsname_r".as_ptr())),
            std::mem::transmute(dlsym(h, c"ptsname".as_ptr())),
        )
    }
}

const O_RDWR: c_int = 2;
const O_NOCTTY: c_int = 0o400;

#[test]
fn ptsname_r_and_ptsname_match_glibc() {
    let (g_r, g_p) = glibc();
    unsafe {
        let master = posix_openpt(O_RDWR | O_NOCTTY);
        assert!(master >= 0, "posix_openpt failed");
        assert_eq!(grantpt(master), 0);
        assert_eq!(unlockpt(master), 0);
        // Resolve the slave name (via glibc) and open it.
        let mut nbuf = [0i8; 128];
        assert_eq!(g_r(master, nbuf.as_mut_ptr(), 128), 0);
        let slave = open(nbuf.as_ptr(), O_RDWR | O_NOCTTY);
        assert!(slave >= 0, "open slave failed");
        let mut pfds = [0i32; 2];
        assert_eq!(pipe(pfds.as_mut_ptr()), 0);

        let mut mism = Vec::new();
        // (label, fd, buflen)
        let cases: &[(&str, c_int, usize)] = &[
            ("master/64", master, 64),
            ("master/3", master, 3),
            ("master/0", master, 0),
            ("slave/64", slave, 64),
            ("pipe/64", pfds[0], 64),
        ];
        for (label, fd, buflen) in cases {
            let mut gb = [0i8; 128];
            let mut fb = [0i8; 128];
            let gr = g_r(*fd, gb.as_mut_ptr(), *buflen);
            let fr = fl::ptsname_r(*fd, fb.as_mut_ptr(), *buflen);
            if gr != fr {
                mism.push(format!("ptsname_r {label}: glibc rc={gr} fl rc={fr}"));
            } else if gr == 0 && CStr::from_ptr(gb.as_ptr()) != CStr::from_ptr(fb.as_ptr()) {
                mism.push(format!(
                    "ptsname_r {label}: name glibc={:?} fl={:?}",
                    CStr::from_ptr(gb.as_ptr()),
                    CStr::from_ptr(fb.as_ptr())
                ));
            }
        }
        // NOTE: glibc's ptsname_r does NOT null-check `buf` (it segfaults on a
        // NULL buffer on this host); fl deliberately returns EINVAL via its
        // membrane guard, so we do not test/match that crash.
        //
        // ptsname (non-_r): success on master (compare name), NULL+errno on slave.
        let gp = g_p(master);
        let fp = fl::ptsname(master);
        if gp.is_null() != fp.is_null()
            || (!gp.is_null() && CStr::from_ptr(gp) != CStr::from_ptr(fp))
        {
            mism.push("ptsname(master) differs".into());
        }
        let gps = g_p(slave);
        let fps = fl::ptsname(slave);
        if gps.is_null() != fps.is_null() {
            mism.push("ptsname(slave) null-ness differs".into());
        }

        close(slave);
        close(master);
        close(pfds[0]);
        close(pfds[1]);
        assert!(mism.is_empty(), "ptsname diverged:\n{}", mism.join("\n"));
    }
}
