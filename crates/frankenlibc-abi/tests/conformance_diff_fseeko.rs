#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fseeko/ftello oracle; tmpfile streams

//! Differential gate for fseeko / ftello / fseeko64 / ftello64 (bd-ry8x9p) — the
//! off_t-based seek/tell had no differential gate. Each impl writes a 100-byte
//! ramp (byte i == i) to its own tmpfile, then exercises SEEK_SET / SEEK_CUR /
//! SEEK_END positioning, reading back the byte at each landing point. The
//! sequence of (seek-rc, ftell-position, read-byte) is compared vs glibc; the
//! *64 variants are checked the same way. No mocks.

use std::ffi::c_long as off_t;
use std::ffi::{c_int, c_void};

const SEEK_SET: c_int = 0;
const SEEK_CUR: c_int = 1;
const SEEK_END: c_int = 2;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn tmpfile() -> *mut c_void;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fseeko(f: *mut c_void, off: off_t, whence: c_int) -> c_int;
        pub fn ftello(f: *mut c_void) -> off_t;
        pub fn fseeko64(f: *mut c_void, off: i64, whence: c_int) -> c_int;
        pub fn ftello64(f: *mut c_void) -> i64;
    }
}
use frankenlibc_abi::stdio_abi as fl;

/// Returns the (rc, position, byte) observations for a SET/CUR/END walk.
type Walk = Vec<(c_int, i64, i32)>;

fn read_byte(
    f: *mut c_void,
    fread: unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
) -> i32 {
    let mut b = [0u8; 1];
    let n = unsafe { fread(b.as_mut_ptr() as *mut c_void, 1, 1, f) };
    if n == 1 { b[0] as i32 } else { -1 }
}

#[allow(clippy::too_many_arguments)]
fn walk(
    open: unsafe extern "C" fn() -> *mut c_void,
    fwrite: unsafe extern "C" fn(*const c_void, usize, usize, *mut c_void) -> usize,
    fread: unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    fclose: unsafe extern "C" fn(*mut c_void) -> c_int,
    seek: &dyn Fn(*mut c_void, i64, c_int) -> c_int,
    tell: &dyn Fn(*mut c_void) -> i64,
) -> Walk {
    let ramp: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
    let mut out = Vec::new();
    unsafe {
        let f = open();
        assert!(!f.is_null());
        fwrite(ramp.as_ptr() as *const c_void, 1, ramp.len(), f);
        // SEEK_SET 50 -> read byte 50
        let r1 = seek(f, 50, SEEK_SET);
        out.push((r1, tell(f), read_byte(f, fread))); // tell == 50, byte 50 (then pos 51)
        // SEEK_CUR +9 (now at 51 -> 60) -> read byte 60
        let r2 = seek(f, 9, SEEK_CUR);
        out.push((r2, tell(f), read_byte(f, fread)));
        // SEEK_END -20 -> pos 80 -> read byte 80
        let r3 = seek(f, -20, SEEK_END);
        out.push((r3, tell(f), read_byte(f, fread)));
        // SEEK_END 0 -> pos 100 (EOF) -> read -> -1
        let r4 = seek(f, 0, SEEK_END);
        out.push((r4, tell(f), read_byte(f, fread)));
        fclose(f);
    }
    out
}

#[test]
fn fseeko_ftello_match_glibc() {
    let gw = walk(
        g::tmpfile,
        g::fwrite,
        g::fread,
        g::fclose,
        &|f, o, w| unsafe { g::fseeko(f, o, w) },
        &|f| unsafe { g::ftello(f) },
    );
    let fw = walk(
        fl::tmpfile,
        fl::fwrite,
        fl::fread,
        fl::fclose,
        &|f, o, w| unsafe { fl::fseeko(f, o, w) },
        &|f| unsafe { fl::ftello(f) },
    );
    assert_eq!(fw, gw, "fseeko/ftello walk: fl={fw:?} glibc={gw:?}");
    assert_eq!(
        gw,
        vec![(0, 50, 50), (0, 60, 60), (0, 80, 80), (0, 100, -1)],
        "glibc reference walk"
    );
}

#[test]
fn fseeko64_ftello64_match_glibc() {
    let gw = walk(
        g::tmpfile,
        g::fwrite,
        g::fread,
        g::fclose,
        &|f, o, w| unsafe { g::fseeko64(f, o, w) },
        &|f| unsafe { g::ftello64(f) },
    );
    let fw = walk(
        fl::tmpfile,
        fl::fwrite,
        fl::fread,
        fl::fclose,
        &|f, o, w| unsafe { fl::fseeko64(f, o, w) },
        &|f| unsafe { fl::ftello64(f) },
    );
    assert_eq!(fw, gw, "fseeko64/ftello64 walk: fl={fw:?} glibc={gw:?}");
    assert_eq!(
        gw,
        vec![(0, 50, 50), (0, 60, 60), (0, 80, 80), (0, 100, -1)],
        "glibc reference walk (64)"
    );
}
