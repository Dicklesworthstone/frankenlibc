#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc basename/dirname (libgen) oracle

//! Randomized live differential fuzzer for the POSIX (libgen) `basename` and
//! `dirname` vs host glibc. The existing `basename_dirname_differential_probe`
//! is a small fixed battery; this generates random paths over `/`, `.`, and
//! letters — with runs of slashes, trailing slashes, leading slashes, `.`/`..`
//! components and the empty string — and asserts fl's returned component equals
//! glibc's, byte-for-byte. Both functions may modify their input buffer, so each
//! engine gets its own fresh NUL-terminated copy.

use std::ffi::CStr;

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn basename(path: *mut libc::c_char) -> *mut libc::c_char;
    fn dirname(path: *mut libc::c_char) -> *mut libc::c_char;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

/// Random path biased toward the glibc edge cases: slash runs, trailing/leading
/// slashes, `.`/`..`, and the empty string.
fn gen_path(r: &mut Lcg) -> Vec<u8> {
    const TOK: &[&[u8]] = &[b"a", b"bb", b"ccc", b".", b"..", b"/", b"//", b"///"];
    let n = r.below(7);
    let mut p = Vec::new();
    for _ in 0..n {
        p.extend_from_slice(TOK[r.below(TOK.len())]);
    }
    p // may be empty
}

/// Call `f` on a fresh copy of `path` and return the resulting C string bytes.
fn run(f: unsafe extern "C" fn(*mut libc::c_char) -> *mut libc::c_char, path: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = path.to_vec();
    buf.push(0);
    // libgen may return a pointer into `buf` OR a pointer to a static (".", "/").
    let ret = unsafe { f(buf.as_mut_ptr() as *mut libc::c_char) };
    let cs = unsafe { CStr::from_ptr(ret) };
    cs.to_bytes().to_vec()
}

#[test]
fn basename_dirname_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xba5e_d142_8f3c_0011);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let path = gen_path(&mut r);
        if path.contains(&0) {
            continue;
        }

        let fl_base = run(fl::basename, &path);
        let lc_base = run(basename, &path);
        let fl_dir = run(fl::dirname, &path);
        let lc_dir = run(dirname, &path);
        compared += 1;

        if (fl_base != lc_base || fl_dir != lc_dir) && divs.len() < 40 {
            divs.push(format!(
                "path={:?}\n    basename fl={:?} glibc={:?}\n    dirname  fl={:?} glibc={:?}",
                String::from_utf8_lossy(&path),
                String::from_utf8_lossy(&fl_base),
                String::from_utf8_lossy(&lc_base),
                String::from_utf8_lossy(&fl_dir),
                String::from_utf8_lossy(&lc_dir),
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "basename/dirname diverged from glibc ({compared} compared):\n{}",
        divs.join("\n")
    );
    eprintln!("basename/dirname fuzz: {compared} compared, 0 divergences vs host glibc");
}
