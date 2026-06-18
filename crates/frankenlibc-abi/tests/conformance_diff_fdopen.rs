#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fdopen oracle; real fds + temp file

//! Differential gate for fdopen (bd-28e4u6) — no differential gate existed.
//! fdopen(fd, mode) wraps an already-open descriptor in a FILE*. Each impl opens
//! its own O_RDONLY fd on a temp file, fdopen("r")s it, confirms fileno() echoes
//! the same fd, reads the whole file back, and fcloses (which closes the fd).
//! The (non_null, fileno_matches, bytes_read, content_matches) tuple is compared
//! vs glibc; a bad-mode case (fdopen of an O_WRONLY fd with "r") is included.
//! No mocks.

use std::ffi::{c_char, c_int, c_void, CString};

const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn open(p: *const c_char, flags: c_int, ...) -> c_int;
        pub fn fdopen(fd: c_int, mode: *const c_char) -> *mut c_void;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fileno(f: *mut c_void) -> c_int;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn close(fd: c_int) -> c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

const CONTENT: &[u8] = b"fdopen wraps an existing descriptor";

fn tmp() -> (std::path::PathBuf, CString) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CNT: AtomicU64 = AtomicU64::new(0);
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fdopen-{}-{}", std::process::id(), n));
    std::fs::write(&p, CONTENT).unwrap();
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}

/// (non_null, fileno_matches, bytes_read, content_matches)
type R = (bool, bool, usize, bool);

fn read_via_fdopen(
    path: &CString,
    fdopen: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void,
    fread: unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    fileno: unsafe extern "C" fn(*mut c_void) -> c_int,
    fclose: unsafe extern "C" fn(*mut c_void) -> c_int,
) -> R {
    unsafe {
        let fd = g::open(path.as_ptr(), O_RDONLY);
        assert!(fd >= 0, "open failed");
        let f = fdopen(fd, c"r".as_ptr());
        if f.is_null() {
            g::close(fd);
            return (false, false, 0, false);
        }
        let fileno_ok = fileno(f) == fd;
        let mut buf = vec![0u8; CONTENT.len() + 8];
        let r = fread(buf.as_mut_ptr() as *mut c_void, 1, buf.len(), f);
        let ok = r == CONTENT.len() && &buf[..r] == CONTENT;
        fclose(f); // also closes fd
        (true, fileno_ok, r, ok)
    }
}

#[test]
fn fdopen_read_matches_glibc() {
    let (p, c) = tmp();
    let gr = read_via_fdopen(&c, g::fdopen, g::fread, g::fileno, g::fclose);
    let fr = read_via_fdopen(&c, fl::fdopen, fl::fread, fl::fileno, fl::fclose);
    let _ = std::fs::remove_file(&p);
    assert_eq!(fr, gr, "fdopen read: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr, (true, true, CONTENT.len(), true), "glibc reference");
}

#[test]
fn fdopen_bad_mode_matches_glibc() {
    // fdopen of an O_WRONLY fd with read mode "r": glibc accepts it (mode/flag
    // mismatch is not validated by fdopen on Linux), so just compare behavior.
    let (p, c) = tmp();
    let probe = |fdopen: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void, fclose: unsafe extern "C" fn(*mut c_void) -> c_int| unsafe {
        let fd = g::open(c.as_ptr(), O_WRONLY);
        if fd < 0 { return None; }
        let f = fdopen(fd, c"r".as_ptr());
        let nn = !f.is_null();
        if nn { fclose(f); } else { g::close(fd); }
        Some(nn)
    };
    let gr = probe(g::fdopen, g::fclose);
    let fr = probe(fl::fdopen, fl::fclose);
    let _ = std::fs::remove_file(&p);
    assert_eq!(fr, gr, "fdopen(O_WRONLY fd, \"r\") acceptance: fl={fr:?} glibc={gr:?}");
}
