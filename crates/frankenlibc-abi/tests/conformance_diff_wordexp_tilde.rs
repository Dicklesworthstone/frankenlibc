//! Differential gate: wordexp `~`/`~user` tilde expansion vs glibc.
//!
//! glibc expands `~`→$HOME (or the current user's pw_dir if HOME is unset) and
//! `~user`→that user's home directory from /etc/passwd, leaving an unknown
//! user literal. fl previously expanded only `~` and left every `~user`
//! unexpanded. Both read the same /etc/passwd; glibc is reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CStr, CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

#[repr(C)]
struct Wordexp {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type WordexpFn = extern "C" fn(*const c_char, *mut Wordexp, c_int) -> c_int;
type WordfreeFn = extern "C" fn(*mut Wordexp);

fn words_of(w: &Wordexp) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if w.we_wordv.is_null() {
        return out;
    }
    for i in 0..w.we_wordc {
        let p = unsafe { *w.we_wordv.add(i) };
        if p.is_null() {
            break;
        }
        out.push(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec());
    }
    out
}

#[test]
fn wordexp_tilde_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_wordexp: WordexpFn =
        unsafe { std::mem::transmute(dlsym(lib, c"wordexp".as_ptr())) };
    let g_wordfree: WordfreeFn =
        unsafe { std::mem::transmute(dlsym(lib, c"wordfree".as_ptr())) };

    let cases = [
        "~root",
        "~root/sub",
        "~root/a/b",
        "~",
        "~/x",
        "~nonexistentuser12345",
        "~nonexistentuser12345/y",
        "~daemon",
        "~bin",
    ];

    let mut mismatches = Vec::new();
    for &w in &cases {
        let cw = CString::new(w).unwrap();

        let mut gw = Wordexp { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
        let grc = g_wordexp(cw.as_ptr(), &mut gw, 0);
        let gwords = if grc == 0 { words_of(&gw) } else { Vec::new() };

        let mut fw = Wordexp { we_wordc: 0, we_wordv: std::ptr::null_mut(), we_offs: 0 };
        let frc = unsafe { flu::wordexp(cw.as_ptr(), (&mut fw as *mut Wordexp).cast(), 0) };
        let fwords = if frc == 0 { words_of(&fw) } else { Vec::new() };

        if grc != frc || gwords != fwords {
            mismatches.push(format!(
                "{w:?}: glibc(rc={grc}, {:?}) fl(rc={frc}, {:?})",
                gwords.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect::<Vec<_>>(),
                fwords.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect::<Vec<_>>(),
            ));
        }

        if grc == 0 {
            g_wordfree(&mut gw);
        }
        if frc == 0 {
            unsafe { flu::wordfree((&mut fw as *mut Wordexp).cast()) };
        }
    }

    assert!(
        mismatches.is_empty(),
        "wordexp tilde diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
