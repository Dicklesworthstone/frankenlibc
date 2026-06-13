#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fgets oracle via fmemopen

//! Differential test for `fgets` vs host glibc. Drives identical reads through
//! each engine's `fmemopen` stream and compares the returned pointer disposition
//! (buffer vs NULL), the bytes written, and the file position. Covers the subtle
//! cases: binary safety (reads through an embedded NUL up to a newline), a final
//! line with no trailing newline, EOF (NULL when no chars read), and the size
//! degeneracies n==1 (returns the buffer with a lone NUL, consumes nothing) and
//! n==0 (returns NULL).

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn fmemopen(buf: *mut libc::c_void, size: usize, mode: *const libc::c_char) -> *mut libc::FILE;
    fn fgets(s: *mut libc::c_char, n: libc::c_int, stream: *mut libc::FILE) -> *mut libc::c_char;
    fn ftell(stream: *mut libc::FILE) -> libc::c_long;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
}

/// Outcome of one fgets: (returned-non-null, buffer bytes view, ftell).
#[derive(Debug, PartialEq, Eq)]
struct Step {
    ok: bool,
    buf: Vec<u8>,
    tell: i64,
}

const SENT: u8 = 0x5a;
const VIEW: usize = 8;

fn run(data: &[u8], ns: &[i32], glibc: bool) -> Vec<Step> {
    let mut owned = data.to_vec();
    let mode = b"rb\0";
    let stream: *mut libc::FILE = if glibc {
        unsafe {
            fmemopen(
                owned.as_mut_ptr() as *mut libc::c_void,
                owned.len(),
                mode.as_ptr() as *const libc::c_char,
            )
        }
    } else {
        unsafe {
            fl::fmemopen(
                owned.as_mut_ptr() as *mut libc::c_void,
                owned.len(),
                mode.as_ptr() as *const libc::c_char,
            ) as *mut libc::FILE
        }
    };
    assert!(!stream.is_null());
    let mut steps = Vec::new();
    for &n in ns {
        let mut buf = vec![SENT; VIEW + 4];
        let ret = if glibc {
            unsafe { fgets(buf.as_mut_ptr() as *mut libc::c_char, n, stream) }
        } else {
            unsafe {
                fl::fgets(
                    buf.as_mut_ptr() as *mut libc::c_char,
                    n,
                    stream as *mut libc::c_void,
                )
            }
        };
        let tell = if glibc {
            unsafe { ftell(stream) }
        } else {
            unsafe { fl::ftell(stream as *mut libc::c_void) }
        } as i64;
        steps.push(Step {
            ok: !ret.is_null(),
            buf: buf[..VIEW].to_vec(),
            tell,
        });
    }
    if glibc {
        unsafe { fclose(stream) };
    } else {
        unsafe { fl::fclose(stream as *mut libc::c_void) };
    }
    steps
}

#[test]
fn fgets_matches_glibc() {
    // (data, sequence of n values)
    let cases: &[(&[u8], &[i32])] = &[
        (b"ab\x00c\ndef", &[10, 10, 10]), // embedded NUL, second line no newline, then EOF
        (b"xyz", &[1, 2, 10]),            // n=1 (lone NUL), n=2 (1 char), rest
        (b"xyz", &[0, 10]),               // n=0 -> NULL, then normal
        (b"ab\ncd", &[3, 3, 3]),          // newline straddling the n-1 boundary
        (b"", &[10]),                     // empty -> NULL
        (b"\n\n\n", &[10, 10, 10, 10]),   // bare newlines
        (b"hello", &[1, 1, 1]),           // repeated n=1 never advances
    ];
    let mut fails = Vec::new();
    for &(data, ns) in cases {
        let f = run(data, ns, false);
        let g = run(data, ns, true);
        if f != g {
            fails.push(format!(
                "data={:?} ns={ns:?}\n    fl   ={f:02x?}\n    glibc={g:02x?}",
                String::from_utf8_lossy(data)
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "fgets diverged from glibc:\n{}",
        fails.join("\n")
    );
}
