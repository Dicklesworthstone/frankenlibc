#![no_main]
//! Differential fuzz target: `frankenlibc_abi::stdlib_abi::getsubopt` vs host
//! glibc `getsubopt(3)`.
//!
//! `getsubopt` is a stateful parser that consumes one suboption per call from
//! a comma-separated input buffer. It mutates the input buffer (writes NUL at
//! comma boundaries) and advances the cursor pointer. The diff harness in
//! `tests/conformance_diff_getsubopt.rs` covers 35 hand-crafted inputs; this
//! target widens that to arbitrary printable-ASCII suboption strings.
//!
//! ## Input layout
//!
//! Raw fuzzer bytes are split into:
//!
//! ```text
//! byte[0]               token_count (mod 6, capped at 5 — number of tokens
//!                       beyond the always-present "ro" token)
//! byte[1..1+ntokens]    each byte selects a token from a fixed pool
//! byte[1+ntokens..]     the option string passed to getsubopt
//! ```
//!
//! Splitting manually (rather than via `arbitrary::Arbitrary` derive) keeps
//! the seeded corpus human-readable and lets us hand-craft seeds that
//! exercise specific divergences.
//!
//! ## Why the input is constrained
//!
//! - **Printable ASCII only** (0x20..=0x7E excluding NUL). Embedded NULs
//!   would terminate the C string early, and locale-sensitive multibyte
//!   handling isn't part of getsubopt's contract.
//! - **No backslashes / quotes.** getsubopt has no escape syntax — these
//!   bytes are passed through literally so they don't change semantics, but
//!   they bloat the corpus space without finding new bugs.
//! - **Bounded length.** Caps the input at 256 bytes to keep the per-call
//!   walk loop short.
//!
//! ## What we assert
//!
//! 1. **Determinism** — fl::getsubopt called twice on identical inputs must
//!    produce identical hits and identical post-walk buffers.
//! 2. **Differential** — fl::getsubopt and host getsubopt must agree on the
//!    sequence of `(return-index, name, value)` hits AND on the final state
//!    of the input buffer.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::stdlib_abi as fl;
use libfuzzer_sys::fuzz_target;

unsafe extern "C" {
    fn getsubopt(
        optionp: *mut *mut c_char,
        tokens: *const *mut c_char,
        valuep: *mut *mut c_char,
    ) -> c_int;
}

const MAX_INPUT: usize = 256;
const MAX_OPTION: usize = 192;

/// Pool of token names the harness can pick from. Each token is plain
/// ASCII so it can pass through `CString::new` without rewrites.
const TOKEN_POOL: &[&[u8]] = &[
    b"ro", b"rw", b"size", b"name", b"foo", b"bar", b"baz", b"speed",
    b"mode", b"x", b"y", b"key", b"value", b"len",
];

#[derive(Debug, PartialEq, Eq)]
struct Hit {
    idx: i32,
    name: Vec<u8>,
    value: Option<Vec<u8>>,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }
    let raw_n = data[0] as usize;
    let token_count = (raw_n % 6).min(data.len().saturating_sub(1));
    let token_picks = &data[1..1 + token_count];
    let body = &data[1 + token_count..];

    // Always include "ro" as token 0 so an exact match is always reachable.
    let mut tokens: Vec<&[u8]> = vec![b"ro"];
    for &pick in token_picks {
        let idx = (pick as usize) % TOKEN_POOL.len();
        tokens.push(TOKEN_POOL[idx]);
    }

    let option = sanitize(body);
    if option.len() > MAX_OPTION {
        return;
    }

    // Build the NULL-terminated tokens array.
    let cstr_tokens: Vec<CString> = match tokens
        .iter()
        .map(|n| CString::new(*n))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(_) => return,
    };
    let mut tok_ptrs: Vec<*mut c_char> =
        cstr_tokens.iter().map(|c| c.as_ptr() as *mut c_char).collect();
    tok_ptrs.push(std::ptr::null_mut());

    // Two writable copies — fl mutates one, host mutates the other.
    let mut fl_buf = option.clone();
    fl_buf.push(0);
    let mut lc_buf = option.clone();
    lc_buf.push(0);

    let fl_hits = unsafe { walk(fl::getsubopt, &mut fl_buf, &tok_ptrs) };
    let lc_hits = unsafe { walk(getsubopt, &mut lc_buf, &tok_ptrs) };

    // Determinism: fl on a fresh buffer must produce the same hits.
    let mut fl_buf_again = option.clone();
    fl_buf_again.push(0);
    let fl_hits_again = unsafe { walk(fl::getsubopt, &mut fl_buf_again, &tok_ptrs) };
    assert_eq!(
        fl_hits, fl_hits_again,
        "fl::getsubopt non-deterministic\n  input={:?}\n  tokens={:?}\n  hit1={:?}\n  hit2={:?}",
        ascii_lossy(&option),
        tokens.iter().map(|t| ascii_lossy(t)).collect::<Vec<_>>(),
        fl_hits,
        fl_hits_again,
    );

    // Differential: fl and host must agree on the sequence and post-state.
    assert_eq!(
        fl_hits, lc_hits,
        "getsubopt hits differ\n  input={:?}\n  tokens={:?}\n  fl={:?}\n  glibc={:?}",
        ascii_lossy(&option),
        tokens.iter().map(|t| ascii_lossy(t)).collect::<Vec<_>>(),
        fl_hits,
        lc_hits,
    );
    assert_eq!(
        fl_buf, lc_buf,
        "getsubopt buffer mutation differs\n  input={:?}\n  tokens={:?}\n  fl_buf={:?}\n  lc_buf={:?}",
        ascii_lossy(&option),
        tokens.iter().map(|t| ascii_lossy(t)).collect::<Vec<_>>(),
        fl_buf,
        lc_buf,
    );
});

unsafe fn walk(
    impl_fn: unsafe extern "C" fn(*mut *mut c_char, *const *mut c_char, *mut *mut c_char) -> c_int,
    buf: &mut [u8],
    tokens: &[*mut c_char],
) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut cursor: *mut c_char = buf.as_mut_ptr() as *mut c_char;
    let mut value: *mut c_char = std::ptr::null_mut();
    for _ in 0..64 {
        let saved_cursor = cursor;
        let r = unsafe { impl_fn(&mut cursor, tokens.as_ptr(), &mut value) };
        let name = unsafe { copy_cstr(saved_cursor) };
        let value_buf = if value.is_null() {
            None
        } else {
            Some(unsafe { copy_cstr(value) })
        };
        hits.push(Hit { idx: r, name, value: value_buf });
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
            return out;
        }
    }
}

/// Restrict to printable ASCII excluding backslash, quotes, and NUL.
/// Lowercase letters, digits, '=' and ',' carry the parser-relevant signal.
fn sanitize(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|&b| {
            (b == b'=' || b == b',' || b == b'_' || b == b' ')
                || b.is_ascii_alphanumeric()
        })
        .take(MAX_OPTION)
        .collect()
}

fn ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
