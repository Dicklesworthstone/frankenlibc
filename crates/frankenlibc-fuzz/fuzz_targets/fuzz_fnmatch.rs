#![no_main]
//! Differential fuzz target: frankenlibc-core `fnmatch_match` vs host
//! `libc::fnmatch`.
//!
//! POSIX `<fnmatch.h>` is one of the most edge-case-laden bits of the
//! string surface — bracket parsing, leading-period rules, PATHNAME
//! semantics, NOESCAPE, LEADING_DIR, CASEFOLD all interact. The pure
//! Rust port in `frankenlibc-core::string::fnmatch` is exercised by
//! unit tests but had no fuzz coverage. This harness drives the engine
//! against the host C library's fnmatch as the differential oracle and
//! also runs internal property checks (determinism, canonical
//! identities).
//!
//! ## Input layout
//!
//! Raw fuzzer bytes are split into:
//!
//! ```text
//! byte[0]              flag_bits (low 5 bits used as the FNM_* mask)
//! byte[1]              pattern_len (mod (body.len()+1))
//! byte[2 .. 2+plen]    pattern
//! byte[2+plen ..]      text
//! ```
//!
//! Splitting manually (rather than via `arbitrary::Arbitrary` derive)
//! lets us ship a hand-crafted seed corpus that covers specific
//! fnmatch features instead of relying on libFuzzer to rediscover
//! plausible patterns from scratch.
//!
//! ## Why the input is constrained
//!
//! Inputs are deliberately filtered to make divergences meaningful:
//!
//! - **Printable ASCII only** (0x20..=0x7E). Locale-sensitive folding
//!   and multi-byte UTF-8 handling are different conversations across
//!   glibc/musl/Rust; fuzzing them here would surface non-bugs.
//! - **No embedded NUL.** We hand C strings to `libc::fnmatch` through
//!   `CString`, which would otherwise reject the input.
//! - **No POSIX collating extensions** (`[[:`, `[.`, `[=`). The core
//!   port intentionally doesn't support these (documented in
//!   fnmatch.rs); glibc does. Including them would produce spurious
//!   diffs that aren't real bugs.
//!
//! Any disagreement between the two engines on the remaining input
//! space is a real divergence worth investigating.

use std::ffi::CString;

use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256;
const MAX_PATTERN: usize = 96;
const MAX_TEXT: usize = 96;
// Mask of flag bits we exercise — exactly the five flags the core
// engine implements, bit-compatible with libc::FNM_*.
const FLAG_MASK: u8 = 0x1F;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 || data.len() > MAX_INPUT {
        return;
    }
    let flag_byte = data[0];
    let plen_byte = data[1];
    let body = &data[2..];

    let split = if body.is_empty() {
        0
    } else {
        usize::from(plen_byte) % (body.len() + 1)
    };
    let pat = sanitize(&body[..split], MAX_PATTERN);
    let txt = sanitize(&body[split..], MAX_TEXT);
    if has_posix_extension(&pat) {
        return;
    }

    let raw_flags = u32::from(flag_byte & FLAG_MASK);
    let core_flags = FnmatchFlags::from_bits(raw_flags);
    let libc_flags = raw_flags as libc::c_int;

    // 1. Determinism — same input must produce the same answer.
    let core_match = fnmatch_match(&pat, &txt, core_flags);
    assert_eq!(
        core_match,
        fnmatch_match(&pat, &txt, core_flags),
        "core fnmatch_match is non-deterministic: pat={:?} txt={:?} flags=0x{:x}",
        ascii_lossy(&pat),
        ascii_lossy(&txt),
        raw_flags,
    );

    // 2. Canonical identity — empty pattern matches iff text is empty
    //    when LEADING_DIR isn't set. (LEADING_DIR allows pattern to
    //    match a leading-slash prefix of text, which decouples from
    //    this identity.)
    if pat.is_empty() && !core_flags.contains(FnmatchFlags::LEADING_DIR) {
        assert_eq!(
            core_match,
            txt.is_empty(),
            "empty pattern violates identity: txt={:?} flags=0x{:x}",
            ascii_lossy(&txt),
            raw_flags,
        );
    }

    // 3. Differential — host libc::fnmatch as the oracle.
    let Ok(pat_c) = CString::new(pat.clone()) else {
        return;
    };
    let Ok(txt_c) = CString::new(txt.clone()) else {
        return;
    };
    // SAFETY: both pointers are NUL-terminated CStrings owned for the
    // duration of the call; libc::fnmatch is reentrant and reads only.
    let libc_rc = unsafe { libc::fnmatch(pat_c.as_ptr(), txt_c.as_ptr(), libc_flags) };
    // Treat any return code other than 0 (match) and FNM_NOMATCH as
    // "host couldn't decide" — bail rather than assert. Some glibc
    // versions emit FNM_NOSYS / errors for things our engine handles,
    // and we don't want to flag those as bugs of *our* engine.
    if libc_rc != 0 && libc_rc != libc::FNM_NOMATCH {
        return;
    }
    let libc_match = libc_rc == 0;

    assert_eq!(
        core_match,
        libc_match,
        "fnmatch divergence: pat={:?} txt={:?} flags=0x{:x}: core={} libc={}",
        ascii_lossy(&pat),
        ascii_lossy(&txt),
        raw_flags,
        core_match,
        libc_match,
    );
});

/// Restrict to printable ASCII and bound the slice — see module doc.
fn sanitize(input: &[u8], max_len: usize) -> Vec<u8> {
    input
        .iter()
        .take(max_len)
        .copied()
        .filter(|&b| (0x20..=0x7E).contains(&b))
        .collect()
}

/// Detect POSIX bracket extensions the core engine intentionally skips.
fn has_posix_extension(pat: &[u8]) -> bool {
    pat.windows(2)
        .any(|w| w == b"[:" || w == b"[." || w == b"[=")
}

fn ascii_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
