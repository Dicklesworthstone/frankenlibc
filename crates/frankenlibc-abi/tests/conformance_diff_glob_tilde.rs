#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc glob() oracle

//! Differential test for `glob` GLOB_TILDE / GLOB_TILDE_CHECK expansion vs host
//! glibc (bd-2g7oyh.92). Covers the cases fl previously did not implement:
//!   - `~user` / `~user/...` → that user's /etc/passwd home directory.
//!   - GLOB_TILDE_CHECK → GLOB_NOMATCH when the `~`/`~user` cannot be resolved
//!     (vs plain GLOB_TILDE, which leaves the tilde literal).
//! `~` / `~/...` (the $HOME case) was already handled and is re-pinned here.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn glob(
        p: *const c_char,
        f: c_int,
        ef: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        g: *mut libc::glob_t,
    ) -> c_int;
    fn globfree(g: *mut libc::glob_t);
}

const GLOB_TILDE: c_int = 0x1000;
const GLOB_TILDE_CHECK: c_int = 0x4000;

fn collect(g: &libc::glob_t, ret: c_int) -> Vec<String> {
    if ret != 0 || g.gl_pathv.is_null() {
        return vec![format!("<ret={ret}>")];
    }
    let mut o = vec![];
    for i in 0..g.gl_pathc {
        let p = unsafe { *g.gl_pathv.add(i) };
        if p.is_null() {
            break;
        }
        let mut b = vec![];
        let mut j = 0isize;
        loop {
            let c = unsafe { *p.offset(j) } as u8;
            if c == 0 {
                break;
            }
            b.push(c);
            j += 1;
        }
        o.push(String::from_utf8_lossy(&b).into_owned());
    }
    o
}

fn run_fl(pat: &str, flags: c_int) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        fl::glob(
            cp.as_ptr(),
            flags,
            None,
            (&mut g) as *mut libc::glob_t as *mut _,
        )
    };
    let out = collect(&g, r);
    if r == 0 {
        unsafe { fl::globfree((&mut g) as *mut libc::glob_t as *mut _) };
    }
    (r, out)
}

fn run_host(pat: &str, flags: c_int) -> (c_int, Vec<String>) {
    let cp = CString::new(pat).unwrap();
    let mut g: libc::glob_t = unsafe { std::mem::zeroed() };
    let r = unsafe { glob(cp.as_ptr(), flags, None, &mut g) };
    let out = collect(&g, r);
    if r == 0 {
        unsafe { globfree(&mut g) };
    }
    (r, out)
}

fn check(pat: &str, flags: c_int) {
    let f = run_fl(pat, flags);
    let h = run_host(pat, flags);
    assert_eq!(
        f, h,
        "glob({pat:?}, {flags:#x}) diverged: fl={f:?} glibc={h:?}"
    );
}

#[test]
fn glob_tilde_matches_glibc() {
    // A `~user` for a definitely-absent user: GLOB_TILDE_CHECK turns the failed
    // expansion into GLOB_NOMATCH, and a failed `~user/...` (the directory does
    // not exist) is NOMATCH under either flag.
    check("~no_such_user_zq7x", GLOB_TILDE_CHECK);
    check("~no_such_user_zq7x/sub", GLOB_TILDE);
    check("~no_such_user_zq7x/sub", GLOB_TILDE_CHECK);
    // NOTE (out of scope): bare `~baduser` + plain GLOB_TILDE — glibc returns
    // the unexpanded pattern as a successful match (ret=0), a glibc oddity
    // unrelated to whether the user exists; fl reports NOMATCH (unchanged from
    // before this fix). Not mirrored.

    // `~user` for an EXISTING user (root always has a passwd entry) expands to
    // its home directory; fl and glibc must then agree on the filesystem verdict.
    check("~root", GLOB_TILDE);
    check("~root", GLOB_TILDE_CHECK);
    check("~root/no_such_entry_zq7x", GLOB_TILDE);
    check("~root/no_such_entry_zq7x", GLOB_TILDE_CHECK);
}

#[test]
fn glob_tilde_home_matches_glibc() {
    // Drive `~`/`~/...` against a controlled $HOME so both engines resolve the
    // same directory (both read the process `HOME`).
    let dir = std::env::temp_dir().join(format!("fl_glob_tilde_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    std::fs::write(dir.join("marker_zq7x"), b"x").unwrap();
    let prev = std::env::var_os("HOME");
    // SAFETY: single-threaded test; restored below.
    unsafe { std::env::set_var("HOME", &dir) };

    check("~/marker_zq7x", GLOB_TILDE);
    check("~/marker_zq7x", GLOB_TILDE_CHECK);
    check("~/no_such_entry_zq7x", GLOB_TILDE);
    check("~", GLOB_TILDE);
    check("~/", GLOB_TILDE);

    match prev {
        Some(v) => unsafe { std::env::set_var("HOME", v) },
        None => unsafe { std::env::remove_var("HOME") },
    }
    let _ = std::fs::remove_dir_all(&dir);
}
