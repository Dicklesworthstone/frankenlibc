#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc hasmntopt oracle + a manual mntent

//! Differential gate for hasmntopt (bd-emgdrv). hasmntopt finds a whole option
//! in mnt_opts: the match must be bounded on the left by start-of-string or ','
//! and on the right by NUL, ',' OR '=' (so a bare name matches "name=value").
//! For each needle fl must return the same offset into mnt_opts as host glibc.
//! No mocks.

use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn hasmntopt(mnt: *const libc::mntent, opt: *const c_char) -> *mut c_char;
}

fn offset(ret: *mut c_char, base: *const c_char) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize) - (base as isize)
    }
}

#[test]
fn hasmntopt_matches_glibc() {
    let opts = CString::new("rw,uid=1000,noauto,mode=0755,ro").unwrap();
    let fsname = CString::new("/dev/sda1").unwrap();
    let dir = CString::new("/mnt").unwrap();
    let typ = CString::new("ext4").unwrap();

    // Only mnt_opts is consulted by hasmntopt, but populate the rest.
    let mut ent: libc::mntent = unsafe { std::mem::zeroed() };
    ent.mnt_fsname = fsname.as_ptr() as *mut c_char;
    ent.mnt_dir = dir.as_ptr() as *mut c_char;
    ent.mnt_type = typ.as_ptr() as *mut c_char;
    ent.mnt_opts = opts.as_ptr() as *mut c_char;
    ent.mnt_freq = 0;
    ent.mnt_passno = 0;

    // Mix of: plain flag, name=value (the '=' boundary the bug missed),
    // last option, substring-not-at-boundary (auto in noauto, no in noauto,
    // 0755 after '='), and absent options.
    for needle in [
        "rw", "uid", "noauto", "mode", "ro", "auto", "gid", "0755", "no", "moun", "",
    ] {
        let c = CString::new(needle).unwrap();
        let g = unsafe { hasmntopt(&ent, c.as_ptr()) };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::hasmntopt(
                &ent as *const libc::mntent as *const c_void,
                c.as_ptr(),
            )
        };
        assert_eq!(
            offset(f, ent.mnt_opts),
            offset(g, ent.mnt_opts),
            "hasmntopt(opts={:?}, needle={needle:?})",
            opts
        );
    }
}

#[test]
fn hasmntopt_value_option_is_found() {
    // Direct regression for bd-emgdrv: a bare name must match a name=value opt.
    let opts = CString::new("defaults,uid=0,gid=0").unwrap();
    let mut ent: libc::mntent = unsafe { std::mem::zeroed() };
    let fsn = CString::new("none").unwrap();
    let d = CString::new("/x").unwrap();
    let t = CString::new("tmpfs").unwrap();
    ent.mnt_fsname = fsn.as_ptr() as *mut c_char;
    ent.mnt_dir = d.as_ptr() as *mut c_char;
    ent.mnt_type = t.as_ptr() as *mut c_char;
    ent.mnt_opts = opts.as_ptr() as *mut c_char;

    let key = CString::new("uid").unwrap();
    let f = unsafe {
        frankenlibc_abi::unistd_abi::hasmntopt(
            &ent as *const libc::mntent as *const c_void,
            key.as_ptr(),
        )
    };
    assert!(
        !f.is_null(),
        "hasmntopt must find 'uid' in 'defaults,uid=0,gid=0'"
    );
    assert_eq!(offset(f, ent.mnt_opts), "defaults,".len() as isize);
}
