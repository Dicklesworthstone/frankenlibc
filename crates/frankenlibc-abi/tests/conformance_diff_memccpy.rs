#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc memccpy oracle + raw buffers

//! Differential gate for memccpy (bd-955wh9). memccpy copies bytes from src to
//! dst, stopping right AFTER the first occurrence of byte `c` (which is copied);
//! it returns a pointer to the byte in dst following that copy, or NULL if `c`
//! is not among the first `n` bytes (in which case all n bytes are copied). For
//! each scenario fl must agree with host glibc on the returned offset and the
//! resulting dst bytes. No mocks.

use std::ffi::{c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type Memccpy = unsafe extern "C" fn(*mut c_void, *const c_void, c_int, usize) -> *mut c_void;

/// Host glibc's `memccpy`, resolved by `dlsym` rather than declared at link
/// time (bd-v0388t).
///
/// A link-time `unsafe extern "C" { fn memccpy(..) }` is not reliably glibc in
/// an abi test binary: `catopen` and `fma` are both confirmed cases where such
/// a reference bound locally in a plain `cargo test`, and `catopen`'s was hiding
/// a live errno divergence. `host_fn` also asserts the resolved address is not
/// fl's own, so a collapsed oracle fails loudly instead of comparing fl to
/// itself.
fn glibc_memccpy() -> Memccpy {
    // SAFETY: `Memccpy` matches C's documented memccpy signature.
    unsafe {
        dlsym_oracle::host_fn(
            c"memccpy",
            frankenlibc_abi::string_abi::memccpy as *const (),
        )
    }
}

const FILL: u8 = 0xAB;

fn off(ret: *mut c_void, base: *const u8) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize) - (base as isize)
    }
}

#[test]
fn memccpy_matches_glibc() {
    let memccpy = glibc_memccpy();
    // (src bytes, stop byte, n)
    let cases: &[(&[u8], u8, usize)] = &[
        (b"hello", b'l', 10), // stop at first 'l' (idx 2) -> copy 3, ret 3
        (b"hello", b'h', 10), // stop at idx 0 -> copy 1, ret 1
        (b"hello", b'o', 10), // stop at last -> copy 5, ret 5
        (b"hello", b'z', 5),  // not found -> copy all 5, ret NULL
        (b"hello", b'o', 3),  // 'o' not in first 3 -> copy 3, ret NULL
        (b"hello", b'l', 4),  // 'l' at idx 2 within n=4 -> copy 3, ret 3
        (b"", b'x', 0),       // n=0 -> NULL, nothing copied
        (b"aaaa", b'a', 4),   // first byte matches -> copy 1, ret 1
        (b"\x00bc", 0, 4),    // stop byte is NUL at idx 0 -> copy 1, ret 1
    ];
    for &(src, c, n) in cases {
        let mut gd = [FILL; 16];
        let mut fd = [FILL; 16];
        // src buffer at least n bytes (pad with sentinel beyond src content).
        let mut sbuf = [FILL; 16];
        sbuf[..src.len()].copy_from_slice(src);

        let rg = unsafe {
            memccpy(
                gd.as_mut_ptr() as *mut c_void,
                sbuf.as_ptr() as *const c_void,
                c as c_int,
                n,
            )
        };
        let rf = unsafe {
            frankenlibc_abi::string_abi::memccpy(
                fd.as_mut_ptr() as *mut c_void,
                sbuf.as_ptr() as *const c_void,
                c as c_int,
                n,
            )
        };
        assert_eq!(
            off(rf, fd.as_ptr()),
            off(rg, gd.as_ptr()),
            "memccpy(src={src:?}, c={c}, n={n}) return offset"
        );
        assert_eq!(fd, gd, "memccpy(src={src:?}, c={c}, n={n}) dst bytes");
    }
}
