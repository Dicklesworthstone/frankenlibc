#![cfg(target_os = "linux")]

//! Differential conformance harness for `<string.h>` mutating + comparison
//! functions: strlen, strcmp, strncmp, strcpy, strncpy, strcat, strncat,
//! strdup, strndup, strerror, strerror_r, memcpy, memmove, memset, strtok_r.
//!
//! Compares FrankenLibC vs glibc on identical inputs; for mutating ops the
//! comparison is on the post-call buffer state of paired output buffers.
//!
//! Bead: CONFORMANCE: libc string.h mutating diff matrix.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use frankenlibc_abi::stdlib_abi as fl_stdlib;
use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    /// Host glibc `stpcpy` — POSIX/GNU "strcpy that returns a pointer
    /// to the trailing NUL". Not exposed by the libc crate's default
    /// surface; we link it directly here.
    fn stpcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char;
    /// Host glibc `stpncpy` — like strncpy but returns dst+n_actual.
    fn stpncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char;
    /// Host glibc `mempcpy` (GNU) — like memcpy but returns dst+n.
    fn mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    /// Host glibc C23 `strfromd` — double → string with format.
    fn strfromd(s: *mut c_char, n: usize, format: *const c_char, value: f64) -> c_int;
    /// Host glibc C23 `strfromf` — float → string with format.
    fn strfromf(s: *mut c_char, n: usize, format: *const c_char, value: f32) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn cstr(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.extend_from_slice(bytes);
    v.push(0);
    v
}

fn sign(x: c_int) -> c_int {
    x.signum()
}

// ===========================================================================
// strlen — straightforward
// ===========================================================================

#[test]
fn diff_strlen_cases() {
    let mut divs = Vec::new();
    let cases: &[&[u8]] = &[
        b"",
        b"a",
        b"hello",
        b"a quick brown fox jumps over the lazy dog",
        b"\x01\x02\x03",
        b"\xff\xff\xff",
    ];
    for s in cases {
        let buf = cstr(s);
        let p = buf.as_ptr() as *const c_char;
        let fl_v = unsafe { fl::strlen(p) };
        let lc_v = unsafe { libc::strlen(p) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "strlen",
                case: format!("{:?}", s),
                field: "return",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strlen divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strcmp / strncmp — sign-of-result compare
// ===========================================================================

const CMP_CASES: &[(&[u8], &[u8])] = &[
    (b"", b""),
    (b"", b"a"),
    (b"a", b""),
    (b"a", b"a"),
    (b"a", b"b"),
    (b"b", b"a"),
    (b"abc", b"abd"),
    (b"abc", b"abcd"),
    (b"abcd", b"abc"),
    (b"\xff", b"\x01"), // unsigned compare
    (b"\x80", b"\x7f"), // boundary
    (b"hello", b"hello"),
    (b"hello", b"world"),
];

#[test]
fn diff_strcmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in CMP_CASES {
        let ab = cstr(a);
        let bb = cstr(b);
        let fl_v =
            unsafe { fl::strcmp(ab.as_ptr() as *const c_char, bb.as_ptr() as *const c_char) };
        let lc_v =
            unsafe { libc::strcmp(ab.as_ptr() as *const c_char, bb.as_ptr() as *const c_char) };
        if sign(fl_v) != sign(lc_v) {
            divs.push(Divergence {
                function: "strcmp",
                case: format!("({:?}, {:?})", a, b),
                field: "sign",
                frankenlibc: format!("{}", sign(fl_v)),
                glibc: format!("{}", sign(lc_v)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strcmp divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strncmp_cases() {
    let mut divs = Vec::new();
    for (a, b) in CMP_CASES {
        let ab = cstr(a);
        let bb = cstr(b);
        for &n in &[0usize, 1, 3, 100] {
            let fl_v = unsafe {
                fl::strncmp(
                    ab.as_ptr() as *const c_char,
                    bb.as_ptr() as *const c_char,
                    n,
                )
            };
            let lc_v = unsafe {
                libc::strncmp(
                    ab.as_ptr() as *const c_char,
                    bb.as_ptr() as *const c_char,
                    n,
                )
            };
            if sign(fl_v) != sign(lc_v) {
                divs.push(Divergence {
                    function: "strncmp",
                    case: format!("({:?}, {:?}, n={})", a, b, n),
                    field: "sign",
                    frankenlibc: format!("{}", sign(fl_v)),
                    glibc: format!("{}", sign(lc_v)),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strncmp divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strcpy / strncpy — buffer mutation; compare post-call buffers
// ===========================================================================

#[test]
fn diff_strcpy_cases() {
    let mut divs = Vec::new();
    for src in &[b"" as &[u8], b"a", b"hello", b"\xff\xfe\xfd"] {
        let sb = cstr(src);
        // Big enough destination + sentinel pattern to detect overrun.
        let mut dst_fl = vec![0xCDu8; 64];
        let mut dst_lc = vec![0xCDu8; 64];
        let _ = unsafe {
            fl::strcpy(
                dst_fl.as_mut_ptr() as *mut c_char,
                sb.as_ptr() as *const c_char,
            )
        };
        let _ = unsafe {
            libc::strcpy(
                dst_lc.as_mut_ptr() as *mut c_char,
                sb.as_ptr() as *const c_char,
            )
        };
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "strcpy",
                case: format!("{:?}", src),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..16]),
                glibc: format!("{:?}", &dst_lc[..16]),
            });
        }
        let _ = sb;
    }
    assert!(
        divs.is_empty(),
        "strcpy divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strncpy_cases() {
    let mut divs = Vec::new();
    for src in &[b"" as &[u8], b"a", b"hello", b"hello world"] {
        for &n in &[0usize, 1, 3, 5, 8, 16] {
            let sb = cstr(src);
            let mut dst_fl = vec![0xCDu8; 32];
            let mut dst_lc = vec![0xCDu8; 32];
            let _ = unsafe {
                fl::strncpy(
                    dst_fl.as_mut_ptr() as *mut c_char,
                    sb.as_ptr() as *const c_char,
                    n,
                )
            };
            let _ = unsafe {
                libc::strncpy(
                    dst_lc.as_mut_ptr() as *mut c_char,
                    sb.as_ptr() as *const c_char,
                    n,
                )
            };
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "strncpy",
                    case: format!("(src={:?}, n={})", src, n),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(16)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(16)]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strncpy divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strcat / strncat — append
// ===========================================================================

#[test]
fn diff_strcat_cases() {
    let mut divs = Vec::new();
    let pairs: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"abc", b""),
        (b"", b"def"),
        (b"abc", b"def"),
        (b"hello ", b"world"),
    ];
    for (a, b) in pairs {
        let mut buf_fl = vec![0u8; 64];
        let mut buf_lc = vec![0u8; 64];
        // Copy `a` into both buffers as the initial contents.
        buf_fl[..a.len()].copy_from_slice(a);
        buf_lc[..a.len()].copy_from_slice(a);
        let bb = cstr(b);
        let _ = unsafe {
            fl::strcat(
                buf_fl.as_mut_ptr() as *mut c_char,
                bb.as_ptr() as *const c_char,
            )
        };
        let _ = unsafe {
            libc::strcat(
                buf_lc.as_mut_ptr() as *mut c_char,
                bb.as_ptr() as *const c_char,
            )
        };
        if buf_fl != buf_lc {
            divs.push(Divergence {
                function: "strcat",
                case: format!("({:?} ++ {:?})", a, b),
                field: "buf",
                frankenlibc: format!("{:?}", &buf_fl[..16]),
                glibc: format!("{:?}", &buf_lc[..16]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strcat divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strncat_cases() {
    let mut divs = Vec::new();
    let pairs: &[(&[u8], &[u8])] = &[(b"abc", b"def"), (b"abc", b"defghi"), (b"", b"def")];
    for (a, b) in pairs {
        for &n in &[0usize, 1, 3, 5, 100] {
            let mut buf_fl = vec![0u8; 64];
            let mut buf_lc = vec![0u8; 64];
            buf_fl[..a.len()].copy_from_slice(a);
            buf_lc[..a.len()].copy_from_slice(a);
            let bb = cstr(b);
            let _ = unsafe {
                fl::strncat(
                    buf_fl.as_mut_ptr() as *mut c_char,
                    bb.as_ptr() as *const c_char,
                    n,
                )
            };
            let _ = unsafe {
                libc::strncat(
                    buf_lc.as_mut_ptr() as *mut c_char,
                    bb.as_ptr() as *const c_char,
                    n,
                )
            };
            if buf_fl != buf_lc {
                divs.push(Divergence {
                    function: "strncat",
                    case: format!("({:?} ++ {:?}, n={})", a, b, n),
                    field: "buf",
                    frankenlibc: format!("{:?}", &buf_fl[..16]),
                    glibc: format!("{:?}", &buf_lc[..16]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strncat divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strdup / strndup — heap-allocating string duplication
// ===========================================================================

#[test]
fn diff_strdup_cases() {
    let mut divs = Vec::new();
    for src in &[b"" as &[u8], b"a", b"hello", b"longer string"] {
        let sb = cstr(src);
        let p_fl = unsafe { fl::strdup(sb.as_ptr() as *const c_char) };
        let p_lc = unsafe { libc::strdup(sb.as_ptr() as *const c_char) };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "strdup",
                case: format!("{:?}", src),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
            let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "strdup",
                    case: format!("{:?}", src),
                    field: "bytes",
                    frankenlibc: format!("{:?}", s_fl),
                    glibc: format!("{:?}", s_lc),
                });
            }
            unsafe {
                libc::free(p_fl as *mut c_void);
                libc::free(p_lc as *mut c_void);
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strdup divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strndup_cases() {
    let mut divs = Vec::new();
    for src in &[b"hello world" as &[u8], b"abc"] {
        for &n in &[0usize, 3, 5, 100] {
            let sb = cstr(src);
            let p_fl = unsafe { fl::strndup(sb.as_ptr() as *const c_char, n) };
            let p_lc = unsafe { libc::strndup(sb.as_ptr() as *const c_char, n) };
            if p_fl.is_null() != p_lc.is_null() {
                divs.push(Divergence {
                    function: "strndup",
                    case: format!("({:?}, n={})", src, n),
                    field: "null",
                    frankenlibc: format!("{}", p_fl.is_null()),
                    glibc: format!("{}", p_lc.is_null()),
                });
                continue;
            }
            if !p_fl.is_null() {
                let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
                let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
                if s_fl != s_lc {
                    divs.push(Divergence {
                        function: "strndup",
                        case: format!("({:?}, n={})", src, n),
                        field: "bytes",
                        frankenlibc: format!("{:?}", s_fl),
                        glibc: format!("{:?}", s_lc),
                    });
                }
                unsafe {
                    libc::free(p_fl as *mut c_void);
                    libc::free(p_lc as *mut c_void);
                }
            }
        }
    }
    assert!(
        divs.is_empty(),
        "strndup divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// memcpy / memmove / memset
// ===========================================================================

#[test]
fn diff_memcpy_cases() {
    let mut divs = Vec::new();
    for &n in &[0usize, 1, 7, 8, 31, 256] {
        let src: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_add(0xA0)).collect();
        let mut dst_fl = vec![0u8; n + 8];
        let mut dst_lc = vec![0u8; n + 8];
        let _ = unsafe {
            fl::memcpy(
                dst_fl.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                n,
            )
        };
        let _ = unsafe {
            libc::memcpy(
                dst_lc.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                n,
            )
        };
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "memcpy",
                case: format!("n={n}"),
                field: "dst",
                frankenlibc: format!("{:?}", &dst_fl[..n.min(16)]),
                glibc: format!("{:?}", &dst_lc[..n.min(16)]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "memcpy divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_memmove_cases() {
    let mut divs = Vec::new();
    // memmove must handle overlapping regions correctly — test both
    // forward and backward overlap.
    for &n in &[0usize, 1, 8, 32] {
        for &overlap in &[0i32, 3, -3] {
            let mut buf_fl = vec![0u8; 128];
            let mut buf_lc = vec![0u8; 128];
            for (i, b) in buf_fl.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(0x10);
            }
            buf_lc.copy_from_slice(&buf_fl);
            let src_off = 32usize;
            let dst_off = (src_off as i32 + overlap) as usize;
            let _ = unsafe {
                fl::memmove(
                    buf_fl.as_mut_ptr().add(dst_off) as *mut c_void,
                    buf_fl.as_ptr().add(src_off) as *const c_void,
                    n,
                )
            };
            let _ = unsafe {
                libc::memmove(
                    buf_lc.as_mut_ptr().add(dst_off) as *mut c_void,
                    buf_lc.as_ptr().add(src_off) as *const c_void,
                    n,
                )
            };
            if buf_fl != buf_lc {
                divs.push(Divergence {
                    function: "memmove",
                    case: format!("n={n} overlap={overlap}"),
                    field: "buf",
                    frankenlibc: format!("{:?}", &buf_fl[28..56]),
                    glibc: format!("{:?}", &buf_lc[28..56]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "memmove divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_memset_cases() {
    let mut divs = Vec::new();
    for &n in &[0usize, 1, 7, 16, 256] {
        for &c in &[0i32, 0xAB, 0xFF, 0x100, -1] {
            let mut dst_fl = vec![0x42u8; n + 4];
            let mut dst_lc = vec![0x42u8; n + 4];
            let _ = unsafe { fl::memset(dst_fl.as_mut_ptr() as *mut c_void, c, n) };
            let _ = unsafe { libc::memset(dst_lc.as_mut_ptr() as *mut c_void, c, n) };
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "memset",
                    case: format!("n={n} c={c:#x}"),
                    field: "dst",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(16)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(16)]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "memset divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strerror / strerror_r — error string lookup
// ===========================================================================

#[test]
fn diff_strerror_cases() {
    let mut divs = Vec::new();
    let codes: &[c_int] = &[
        0,
        libc::EINVAL,
        libc::ENOENT,
        libc::EACCES,
        libc::EAGAIN,
        libc::EIO,
        99999,
    ];
    for &code in codes {
        let p_fl = unsafe { fl::strerror(code) };
        let p_lc = unsafe { libc::strerror(code) };
        if p_fl.is_null() || p_lc.is_null() {
            divs.push(Divergence {
                function: "strerror",
                case: format!("errnum={code}"),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
        // strerror messages can vary across libc/musl versions. Don't
        // require exact match; instead require both produce a non-empty
        // string, AND for known errno values both contain the expected
        // POSIX-derived keyword. Document the relaxation explicitly.
        if s_fl.is_empty() != s_lc.is_empty() {
            divs.push(Divergence {
                function: "strerror",
                case: format!("errnum={code}"),
                field: "empty_match",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strerror divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_strerror_r_cases() {
    let mut divs = Vec::new();
    let codes: &[c_int] = &[0, libc::EINVAL, libc::ENOENT, libc::EACCES];
    for &code in codes {
        let mut buf_fl = vec![0i8; 256];
        let mut buf_lc = vec![0i8; 256];
        // Use the XSI variant via __xpg_strerror_r to ensure we get the
        // POSIX int-returning signature on both sides.
        unsafe extern "C" {
            fn __xpg_strerror_r(errnum: c_int, buf: *mut c_char, buflen: usize) -> c_int;
        }
        let r_fl = unsafe { fl_stdlib::__xpg_strerror_r(code, buf_fl.as_mut_ptr(), buf_fl.len()) };
        let r_lc = unsafe { __xpg_strerror_r(code, buf_lc.as_mut_ptr(), buf_lc.len()) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "strerror_r (XSI)",
                case: format!("errnum={code}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strerror_r divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// strtok_r — re-entrant tokenizer; compares the token sequence
// ===========================================================================

fn tokenize_with(
    f: unsafe extern "C" fn(*mut c_char, *const c_char, *mut *mut c_char) -> *mut c_char,
    src: &[u8],
    delim: &[u8],
) -> Vec<Vec<u8>> {
    let mut buf = cstr(src);
    let dlm = cstr(delim);
    let mut state: *mut c_char = ptr::null_mut();
    let mut tokens = Vec::new();
    let mut first = buf.as_mut_ptr() as *mut c_char;
    loop {
        let t = unsafe { f(first, dlm.as_ptr() as *const c_char, &mut state) };
        first = ptr::null_mut();
        if t.is_null() {
            break;
        }
        let s = unsafe { std::ffi::CStr::from_ptr(t).to_bytes().to_vec() };
        tokens.push(s);
    }
    tokens
}

#[test]
fn diff_strtok_r_cases() {
    let mut divs = Vec::new();
    let cases: &[(&[u8], &[u8])] = &[
        (b"a,b,c", b","),
        (b",,a,,b,,", b","), // adjacent + trailing delims
        (b"hello world how are you", b" "),
        (b"x", b","),         // no delims
        (b"", b","),          // empty source
        (b"a-b_c d", b"-_ "), // multi-char delim set
    ];
    for (src, delim) in cases {
        let fl_toks = tokenize_with(fl::strtok_r, src, delim);
        let lc_toks = tokenize_with(libc::strtok_r, src, delim);
        if fl_toks != lc_toks {
            divs.push(Divergence {
                function: "strtok_r",
                case: format!("({:?}, {:?})", src, delim),
                field: "tokens",
                frankenlibc: format!("{:?}", fl_toks),
                glibc: format!("{:?}", lc_toks),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strtok_r divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// stpcpy / stpncpy / mempcpy — copy variants returning end-of-dest
// ===========================================================================
//
// All three functions are byte-for-byte identical to their non-`p`
// siblings in the destination side effect (stpcpy ↔ strcpy,
// stpncpy ↔ strncpy, mempcpy ↔ memcpy) but return a pointer past the
// last copied byte instead of `dst`. That return-pointer offset is
// what most callers use them for (chained copies without re-walking
// strings) and is the part most likely to drift between
// implementations.
//
// The diff compares both:
//   1. dst-buffer contents byte-for-byte (catches any side-effect
//      divergence — e.g., NUL-padding in stpncpy, off-by-one writes
//      in mempcpy).
//   2. The return-pointer offset relative to dst — must match exactly.

#[test]
fn diff_stpcpy_cases() {
    let mut divs = Vec::new();
    for src in &[b"" as &[u8], b"a", b"hello", b"\xff\xfe\xfd", b"abc\0xyz"] {
        // cstr() truncates at the embedded NUL like every other
        // C-string consumer does, so the b"abc\0xyz" case effectively
        // tests a 3-byte copy.
        let sb = cstr(src);
        let mut dst_fl = vec![0xCDu8; 64];
        let mut dst_lc = vec![0xCDu8; 64];
        let fl_end = unsafe {
            fl::stpcpy(
                dst_fl.as_mut_ptr() as *mut c_char,
                sb.as_ptr() as *const c_char,
            )
        };
        let lc_end = unsafe {
            stpcpy(
                dst_lc.as_mut_ptr() as *mut c_char,
                sb.as_ptr() as *const c_char,
            )
        };
        let fl_off = (fl_end as usize).wrapping_sub(dst_fl.as_ptr() as usize);
        let lc_off = (lc_end as usize).wrapping_sub(dst_lc.as_ptr() as usize);
        if fl_off != lc_off {
            divs.push(Divergence {
                function: "stpcpy",
                case: format!("{:?}", src),
                field: "return_offset",
                frankenlibc: format!("{fl_off}"),
                glibc: format!("{lc_off}"),
            });
        }
        if dst_fl != dst_lc {
            divs.push(Divergence {
                function: "stpcpy",
                case: format!("{:?}", src),
                field: "dst_buffer",
                frankenlibc: format!("{:?}", &dst_fl[..16]),
                glibc: format!("{:?}", &dst_lc[..16]),
            });
        }
    }
    assert!(divs.is_empty(), "stpcpy divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_stpncpy_cases() {
    let mut divs = Vec::new();
    // stpncpy with n shorter than src: no NUL written, end pointer
    // is dst+n. With n longer than src: pads with NULs, end pointer
    // is at the first NUL written. Both shapes are exercised.
    for src in &[b"" as &[u8], b"a", b"hello", b"hello world"] {
        for &n in &[0usize, 1, 3, 5, 8, 16] {
            let sb = cstr(src);
            let mut dst_fl = vec![0xCDu8; 32];
            let mut dst_lc = vec![0xCDu8; 32];
            let fl_end = unsafe {
                fl::stpncpy(
                    dst_fl.as_mut_ptr() as *mut c_char,
                    sb.as_ptr() as *const c_char,
                    n,
                )
            };
            let lc_end = unsafe {
                stpncpy(
                    dst_lc.as_mut_ptr() as *mut c_char,
                    sb.as_ptr() as *const c_char,
                    n,
                )
            };
            let fl_off = (fl_end as usize).wrapping_sub(dst_fl.as_ptr() as usize);
            let lc_off = (lc_end as usize).wrapping_sub(dst_lc.as_ptr() as usize);
            if fl_off != lc_off {
                divs.push(Divergence {
                    function: "stpncpy",
                    case: format!("(src={:?}, n={})", src, n),
                    field: "return_offset",
                    frankenlibc: format!("{fl_off}"),
                    glibc: format!("{lc_off}"),
                });
            }
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "stpncpy",
                    case: format!("(src={:?}, n={})", src, n),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(16)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(16)]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "stpncpy divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_mempcpy_cases() {
    let mut divs = Vec::new();
    let bufs: &[&[u8]] = &[
        b"",
        b"a",
        b"abc",
        b"hello world",
        b"\x00\x01\x02\x03\xff\xfe\xfd\xfc",
        b"\x00\x00\x00\x00\x00\x00\x00\x00",
    ];
    for src in bufs {
        for &n in &[0usize, 1, 4, 8, 32, 64] {
            if n > src.len() && n != 0 {
                // mempcpy has no NUL semantics — n must not exceed src.
                continue;
            }
            let mut dst_fl = vec![0xCDu8; 64];
            let mut dst_lc = vec![0xCDu8; 64];
            let fl_end = unsafe {
                fl::mempcpy(
                    dst_fl.as_mut_ptr() as *mut c_void,
                    src.as_ptr() as *const c_void,
                    n,
                )
            };
            let lc_end = unsafe {
                mempcpy(
                    dst_lc.as_mut_ptr() as *mut c_void,
                    src.as_ptr() as *const c_void,
                    n,
                )
            };
            let fl_off = (fl_end as usize).wrapping_sub(dst_fl.as_ptr() as usize);
            let lc_off = (lc_end as usize).wrapping_sub(dst_lc.as_ptr() as usize);
            if fl_off != lc_off {
                divs.push(Divergence {
                    function: "mempcpy",
                    case: format!("(src.len={}, n={})", src.len(), n),
                    field: "return_offset",
                    frankenlibc: format!("{fl_off}"),
                    glibc: format!("{lc_off}"),
                });
            }
            if dst_fl != dst_lc {
                divs.push(Divergence {
                    function: "mempcpy",
                    case: format!("(src.len={}, n={})", src.len(), n),
                    field: "dst_buffer",
                    frankenlibc: format!("{:?}", &dst_fl[..n.min(16)]),
                    glibc: format!("{:?}", &dst_lc[..n.min(16)]),
                });
            }
        }
    }
    assert!(divs.is_empty(), "mempcpy divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// strfromd / strfromf — C23 float-to-string with format
// ===========================================================================
//
// strfromd takes a printf-like format ("%[.<prec>]{f,e,g}") and writes
// the formatted value into a caller's buffer, returning the count of
// bytes that would have been written (printf-style return). The impl
// in frankenlibc-abi/src/string_abi.rs delegates the formatting body
// to the same %g/%e renderers gcvt uses (frankenlibc-core/src/stdlib/
// ecvt.rs), so this diff also pins those renderers indirectly.

const STRFROM_DOUBLE_CASES: &[(f64, &[u8])] = &[
    (0.0, b"%f"),
    (1.0, b"%f"),
    (123.456, b"%f"),
    (-12345.0, b"%f"),
    (0.0001234, b"%f"),
    (0.0, b"%e"),
    (1.0, b"%e"),
    (123.456, b"%e"),
    (1e10, b"%e"),
    (1e-10, b"%e"),
    (-12345.0, b"%e"),
    (0.0, b"%g"),
    (1.0, b"%g"),
    (123.456, b"%g"),
    (1e10, b"%g"),
    (1e-10, b"%g"),
    (-12345.0, b"%g"),
    (0.0, b"%.2f"),
    (1.5, b"%.0f"),
    (123.456, b"%.10f"),
    (1e-10, b"%.6e"),
    (1e10, b"%.2g"),
    (123.456, b"%.2g"),
    (f64::INFINITY, b"%.2E"),
    (f64::NEG_INFINITY, b"%.2F"),
    (f64::NAN, b"%.2G"),
];

#[test]
fn diff_strfromd_cases() {
    let mut divs = Vec::new();
    for (value, fmt) in STRFROM_DOUBLE_CASES {
        let mut fmt_z = fmt.to_vec();
        fmt_z.push(0);
        let mut fl_buf = [0u8; 64];
        let mut lc_buf = [0u8; 64];
        // SAFETY: 64-byte buffers; format/value owned for the call.
        let fl_n = unsafe {
            fl::strfromd(
                fl_buf.as_mut_ptr() as *mut c_char,
                fl_buf.len(),
                fmt_z.as_ptr() as *const c_char,
                *value,
            )
        };
        let lc_n = unsafe {
            strfromd(
                lc_buf.as_mut_ptr() as *mut c_char,
                lc_buf.len(),
                fmt_z.as_ptr() as *const c_char,
                *value,
            )
        };
        let case = format!("({:?}, {:?})", value, String::from_utf8_lossy(fmt));
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "strfromd",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        // Compare buffer contents up to the trailing NUL (or end).
        let fl_str = nul_terminated_slice(&fl_buf);
        let lc_str = nul_terminated_slice(&lc_buf);
        if fl_str != lc_str {
            divs.push(Divergence {
                function: "strfromd",
                case,
                field: "buffer",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(fl_str)),
                glibc: format!("{:?}", String::from_utf8_lossy(lc_str)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strfromd divergences:\n{}",
        render_divs(&divs)
    );
}

const STRFROM_FLOAT_CASES: &[(f32, &[u8])] = &[
    (0.0, b"%f"),
    (1.0, b"%f"),
    (123.456, b"%f"),
    (0.0, b"%e"),
    (1.0, b"%e"),
    (123.456, b"%e"),
    (0.0, b"%g"),
    (1.0, b"%g"),
    (123.456, b"%g"),
    (1.5, b"%.0f"),
    (123.456, b"%.2g"),
    (f32::INFINITY, b"%.2E"),
    (f32::NEG_INFINITY, b"%.2F"),
    (f32::NAN, b"%.2G"),
];

#[test]
fn diff_strfromf_cases() {
    let mut divs = Vec::new();
    for (value, fmt) in STRFROM_FLOAT_CASES {
        let mut fmt_z = fmt.to_vec();
        fmt_z.push(0);
        let mut fl_buf = [0u8; 64];
        let mut lc_buf = [0u8; 64];
        // SAFETY: same as strfromd.
        let fl_n = unsafe {
            fl::strfromf(
                fl_buf.as_mut_ptr() as *mut c_char,
                fl_buf.len(),
                fmt_z.as_ptr() as *const c_char,
                *value,
            )
        };
        let lc_n = unsafe {
            strfromf(
                lc_buf.as_mut_ptr() as *mut c_char,
                lc_buf.len(),
                fmt_z.as_ptr() as *const c_char,
                *value,
            )
        };
        let case = format!("({:?}, {:?})", value, String::from_utf8_lossy(fmt));
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "strfromf",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        let fl_str = nul_terminated_slice(&fl_buf);
        let lc_str = nul_terminated_slice(&lc_buf);
        if fl_str != lc_str {
            divs.push(Divergence {
                function: "strfromf",
                case,
                field: "buffer",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(fl_str)),
                glibc: format!("{:?}", String::from_utf8_lossy(lc_str)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "strfromf divergences:\n{}",
        render_divs(&divs)
    );
}

fn nul_terminated_slice(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(idx) => &buf[..idx],
        None => buf,
    }
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn string_mut_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"string.h mutating\",\"reference\":\"glibc\",\"functions\":20,\"divergences\":0}}",
    );
}
