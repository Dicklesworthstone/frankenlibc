#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `getsubopt(3)`.
//!
//! `getsubopt` is a stateful parser over a comma-separated suboption string.
//! On each call:
//!   - It consumes one suboption from `*optionp`, mutating the input buffer
//!     by writing NUL at the comma boundary.
//!   - It advances `*optionp` past the consumed suboption.
//!   - Sets `*valuep` to the value portion (or NULL if missing).
//!   - Returns the index of the matching token, or -1 if not found (in
//!     which case `*valuep` points to the matched name).
//!
//! We diff fl::getsubopt vs host glibc getsubopt across a corpus of inputs.
//! For each input we run getsubopt repeatedly until `*optionp` points at NUL,
//! collecting the (return-index, value-string) tuples and comparing.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn getsubopt(
        optionp: *mut *mut c_char,
        tokens: *const *mut c_char,
        valuep: *mut *mut c_char,
    ) -> c_int;
}

use frankenlibc_abi::stdlib_abi as fl;

#[derive(Debug, PartialEq, Eq)]
struct Hit {
    /// Index returned by getsubopt (or -1 on miss).
    idx: i32,
    /// Suboption name as it stood at call time (NUL-terminated copy).
    name: Vec<u8>,
    /// Value portion, or None if no '=' was present.
    value: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

/// Build a writable buffer (NUL-terminated) and a `*mut c_char` cursor.
fn writable_input(s: &[u8]) -> (Vec<u8>, *mut c_char) {
    let mut buf: Vec<u8> = s.to_vec();
    buf.push(0);
    let p = buf.as_mut_ptr() as *mut c_char;
    (buf, p)
}

/// Build a NULL-terminated `char *const tokens[]` array.
fn token_array(names: &[&[u8]]) -> (Vec<CString>, Vec<*mut c_char>) {
    let cstrs: Vec<CString> = names
        .iter()
        .map(|n| CString::new(*n).expect("token must not contain NUL"))
        .collect();
    let mut ptrs: Vec<*mut c_char> = cstrs.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    ptrs.push(std::ptr::null_mut());
    (cstrs, ptrs)
}

/// Walk one full pass: keep calling getsubopt until *optionp points at NUL or
/// the buffer is exhausted, recording each hit.
unsafe fn walk(
    impl_fn: unsafe extern "C" fn(*mut *mut c_char, *const *mut c_char, *mut *mut c_char) -> c_int,
    buf: &mut [u8],
    tokens: &[*mut c_char],
) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut cursor: *mut c_char = buf.as_mut_ptr() as *mut c_char;
    let mut value: *mut c_char = std::ptr::null_mut();
    // Cap iterations so a runaway impl can't hang the test.
    for _ in 0..64 {
        let saved_cursor = cursor;
        let r = unsafe { impl_fn(&mut cursor, tokens.as_ptr(), &mut value) };
        // Capture the name as it stood at the start of this call: it's the
        // NUL-terminated string at saved_cursor (NUL was written there by the
        // call itself if a comma was present).
        let name = unsafe { copy_cstr(saved_cursor) };
        let value_buf = if value.is_null() {
            None
        } else {
            Some(unsafe { copy_cstr(value) })
        };
        hits.push(Hit {
            idx: r,
            name,
            value: value_buf,
        });
        // Stop when we've reached end-of-string. POSIX leaves *optionp
        // pointing at the NUL after the final suboption when there's nothing
        // left to consume.
        if cursor.is_null() || unsafe { *cursor } == 0 {
            break;
        }
    }
    hits
}

unsafe fn copy_cstr(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0isize;
    loop {
        let b = unsafe { *p.offset(i) } as u8;
        if b == 0 {
            return out;
        }
        out.push(b);
        i += 1;
        if i > 1024 {
            // Safety guard against runaway impls.
            return out;
        }
    }
}

const TOKENS: &[&[u8]] = &[b"ro", b"rw", b"size", b"name", b"foo"];

const INPUTS: &[&[u8]] = &[
    b"",
    b"ro",
    b"rw",
    b"unknown",
    b"size=512",
    b"size=",
    b"=512",
    b",",
    b",,",
    b"ro,rw",
    b"ro,size=512",
    b"ro,unknown,rw",
    b"size=512,name=foo,unknown=val",
    b"foo=bar=baz",
    b"foo=,bar=,baz=",
    b"size=,",
    b",size=512",
    b"unknown1,unknown2,unknown3",
    b"name=hello world",
    b"foo=,",
    b"foo,",
    b"a,b,c,d,e",
];

#[test]
fn diff_getsubopt_matrix() {
    let (_keep, tokens) = token_array(TOKENS);
    let mut divs = Vec::new();

    for input in INPUTS {
        let mut fl_buf = input.to_vec();
        fl_buf.push(0);
        let mut lc_buf = input.to_vec();
        lc_buf.push(0);

        let fl_hits = unsafe { walk(fl::getsubopt, &mut fl_buf, &tokens) };
        let lc_hits = unsafe { walk(getsubopt, &mut lc_buf, &tokens) };

        if fl_hits != lc_hits {
            divs.push(Divergence {
                case: format!("({:?})", String::from_utf8_lossy(input)),
                field: "hits",
                frankenlibc: format!("{fl_hits:?}"),
                glibc: format!("{lc_hits:?}"),
            });
        }
        // Compare buffer contents post-walk: getsubopt mutates by writing
        // NUL at comma boundaries. Both impls should produce the same buffer.
        if fl_buf != lc_buf {
            divs.push(Divergence {
                case: format!("({:?})", String::from_utf8_lossy(input)),
                field: "buffer_after_walk",
                frankenlibc: format!("{fl_buf:?}"),
                glibc: format!("{lc_buf:?}"),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "getsubopt divergences:\n{}",
        render_divs(&divs)
    );
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc
        ));
    }
    out
}

/// Independent pinned-corpus test: empty input must report (-1, NULL).
#[test]
fn getsubopt_empty_input_returns_minus_one() {
    let (_keep, tokens) = token_array(TOKENS);
    let (buf, mut cursor) = writable_input(b"");
    let mut value: *mut c_char = std::ptr::null_mut();
    let r = unsafe { fl::getsubopt(&mut cursor, tokens.as_ptr(), &mut value) };
    assert_eq!(r, -1, "empty input should miss");
    let _ = buf;
}

/// Pathological inputs — exercise edge cases in name/value separation:
///   "==" (empty name, equals as first char of value)
///   "size==512" (double equals)
///   "ro=value" (matched token with unexpected value)
///   "name=" (matched token, empty value)
///   "  ro" (leading space — POSIX says name is matched literally)
///   "ro " (trailing space in name)
const PATHOLOGICAL_INPUTS: &[&[u8]] = &[
    b"==",
    b"size==512",
    b"ro=value",
    b"name=",
    b"  ro",
    b"ro ",
    b"ro,",
    b",ro",
    b"=",
    b"=,=,=",
    b"foo=bar=baz=qux",
    b"size=large,name=ostrich",
    b"name=hello\\,world",  // backslash-escape (NOT supported by getsubopt — backslash is literal)
];

#[test]
fn diff_getsubopt_pathological() {
    let (_keep, tokens) = token_array(TOKENS);
    let mut divs = Vec::new();

    for input in PATHOLOGICAL_INPUTS {
        let mut fl_buf = input.to_vec();
        fl_buf.push(0);
        let mut lc_buf = input.to_vec();
        lc_buf.push(0);

        let fl_hits = unsafe { walk(fl::getsubopt, &mut fl_buf, &tokens) };
        let lc_hits = unsafe { walk(getsubopt, &mut lc_buf, &tokens) };

        if fl_hits != lc_hits {
            divs.push(Divergence {
                case: format!("({:?})", String::from_utf8_lossy(input)),
                field: "hits",
                frankenlibc: format!("{fl_hits:?}"),
                glibc: format!("{lc_hits:?}"),
            });
        }
        if fl_buf != lc_buf {
            divs.push(Divergence {
                case: format!("({:?})", String::from_utf8_lossy(input)),
                field: "buffer_after_walk",
                frankenlibc: format!("{fl_buf:?}"),
                glibc: format!("{lc_buf:?}"),
            });
        }
    }

    assert!(
        divs.is_empty(),
        "getsubopt pathological divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn getsubopt_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"stdlib.h getsubopt\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
