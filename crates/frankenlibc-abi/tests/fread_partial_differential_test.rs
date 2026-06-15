#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fread oracle via fmemopen

//! Differential test for `fread` partial-element semantics vs host glibc. The
//! subtle, well-specified behavior: fread copies ALL available bytes into the
//! destination — INCLUDING the bytes of an incomplete trailing element — and
//! advances the file position by them, but the RETURN value counts only the
//! number of COMPLETE elements. Also covers size==0 / nmemb==0 (return 0, no
//! read) and the EOF flag. Both engines read the same bytes through their own
//! `fmemopen` stream and the (ret, ftell, buf, eof) tuple is compared.

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn fmemopen(buf: *mut libc::c_void, size: usize, mode: *const libc::c_char) -> *mut libc::FILE;
    fn fread(ptr: *mut libc::c_void, size: usize, nmemb: usize, stream: *mut libc::FILE) -> usize;
    fn ftell(stream: *mut libc::FILE) -> libc::c_long;
    fn feof(stream: *mut libc::FILE) -> libc::c_int;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
}

#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    ret: usize,
    tell: i64,
    buf: Vec<u8>,
    eof: i32,
}

fn run(data: &[u8], size: usize, nmemb: usize, glibc: bool) -> Outcome {
    let mut owned = data.to_vec();
    let mode = b"rb\0";
    let cap = size.saturating_mul(nmemb).max(1) + 8;
    let mut dst = vec![b'Z'; cap];
    if glibc {
        let s = unsafe {
            fmemopen(
                owned.as_mut_ptr() as *mut libc::c_void,
                owned.len(),
                mode.as_ptr() as *const libc::c_char,
            )
        };
        let ret = unsafe { fread(dst.as_mut_ptr() as *mut libc::c_void, size, nmemb, s) };
        let tell = unsafe { ftell(s) } as i64;
        let eof = unsafe { feof(s) };
        unsafe { fclose(s) };
        Outcome {
            ret,
            tell,
            buf: dst,
            eof: (eof != 0) as i32,
        }
    } else {
        let s = unsafe {
            fl::fmemopen(
                owned.as_mut_ptr() as *mut libc::c_void,
                owned.len(),
                mode.as_ptr() as *const libc::c_char,
            )
        };
        let ret = unsafe { fl::fread(dst.as_mut_ptr() as *mut libc::c_void, size, nmemb, s) };
        let tell = unsafe { fl::ftell(s) } as i64;
        let eof = unsafe { fl::feof(s) };
        unsafe { fl::fclose(s) };
        Outcome {
            ret,
            tell,
            buf: dst,
            eof: (eof != 0) as i32,
        }
    }
}

#[test]
fn fread_partial_element_matches_glibc() {
    // (data, size, nmemb)
    let cases: &[(&[u8], usize, usize)] = &[
        (b"abcdefg", 3, 4),     // 7 bytes, want 12: 2 complete + 1 partial byte
        (b"abcd", 3, 2),        // 4 bytes: 1 complete + 1 partial
        (b"abcdef", 3, 2),      // exact fit: 2 complete
        (b"xyz", 0, 5),         // size 0
        (b"xyz", 5, 0),         // nmemb 0
        (b"a", 4, 1),           // 1 byte, want a 4-byte element: 0 complete, 1 partial byte
        (b"", 3, 2),            // empty
        (b"abcdefghij", 1, 10), // byte-wise exact
        (b"abcdefghij", 4, 3),  // 10 bytes, want 12: 2 complete + 2 partial
        (b"abcdefghij", 10, 5), // 10 bytes, want 50: 1 complete exactly
    ];
    let mut fails = Vec::new();
    for &(data, size, nmemb) in cases {
        let f = run(data, size, nmemb, false);
        let g = run(data, size, nmemb, true);
        if f != g {
            fails.push(format!(
                "data={:?} size={size} nmemb={nmemb}\n    fl   ={f:?}\n    glibc={g:?}",
                String::from_utf8_lossy(data)
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "fread diverged from glibc:\n{}",
        fails.join("\n")
    );
}
