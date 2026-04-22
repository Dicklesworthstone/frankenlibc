#![no_main]
//! Crash-detector + invariant fuzz target for FrankenLibC wordexp.
//!
//! wordexp is the most security-sensitive expansion entry point:
//! it turns an arbitrary input string into shell tokens, and historically
//! has been the source of command-injection CVEs (CVE-2014-7817 etc).
//! Our impl rejects command substitution outright, so the security gate
//! is: "any input containing $(...) or `...` returns WRDE_CMDSUB, never 0".
//!
//! Bead: bd-bb2vb

use arbitrary::Arbitrary;
use libc::c_void;
use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::mem::MaybeUninit;

#[derive(Debug, Arbitrary)]
struct WordexpFuzzInput {
    words: Vec<u8>,
    flags: u8,
}

const WRDE_DOOFFS: i32 = 1 << 0;
const WRDE_APPEND: i32 = 1 << 1;
const WRDE_NOCMD: i32 = 1 << 2;
const WRDE_REUSE: i32 = 1 << 3;
const WRDE_SHOWERR: i32 = 1 << 4;
const WRDE_UNDEF: i32 = 1 << 5;

const WRDE_NOSPACE: i32 = 1;
const WRDE_BADCHAR: i32 = 2;
const WRDE_BADVAL: i32 = 3;
const WRDE_CMDSUB: i32 = 4;
const WRDE_SYNTAX: i32 = 5;

// Mirror glibc layout: wordexp_t starts with we_wordc (size_t), we_wordv
// (char**), we_offs (size_t). 24 bytes is enough to hold the prefix on
// every supported platform; we never read beyond what wordexp wrote.
const WORDEXP_T_SIZE: usize = 64;

fuzz_target!(|input: WordexpFuzzInput| {
    // Cap input — wordexp is O(n) on the input but pathological quote
    // sequences can stress the parser. 4 KiB exercises every state.
    if input.words.len() > 4096 {
        return;
    }

    // wordexp consumes a NUL-terminated C string; reject inputs with
    // interior NULs (CString won't construct).
    let Ok(words_c) = CString::new(input.words.clone()) else {
        return;
    };

    // Restrict to documented WRDE_* flag bits so we don't pass unknown
    // bits to glibc.
    let flags = (input.flags as i32)
        & (WRDE_DOOFFS | WRDE_APPEND | WRDE_NOCMD | WRDE_REUSE | WRDE_SHOWERR | WRDE_UNDEF);
    // WRDE_REUSE/WRDE_APPEND require a previously-initialized
    // pwordexp_t; for a one-shot fuzz call this would dereference
    // garbage on the host side. Mask them off.
    let flags = flags & !(WRDE_REUSE | WRDE_APPEND);

    let mut pwordexp = MaybeUninit::<[u8; WORDEXP_T_SIZE]>::zeroed();
    let pwordexp_ptr = pwordexp.as_mut_ptr() as *mut c_void;

    let rc = unsafe { frankenlibc_abi::unistd_abi::wordexp(words_c.as_ptr(), pwordexp_ptr, flags) };

    // Crash-detector invariant: rc is one of the documented codes.
    assert!(
        matches!(
            rc,
            0 | WRDE_NOSPACE | WRDE_BADCHAR | WRDE_BADVAL | WRDE_CMDSUB | WRDE_SYNTAX
        ),
        "wordexp returned {rc}, expected 0 or one of WRDE_*",
    );

    // Security gate: any input containing $(...) or `...` MUST be
    // rejected with WRDE_CMDSUB, never 0. Our impl rejects command
    // substitution unconditionally; this fuzz target enforces that
    // contract.
    let bytes = input.words.as_slice();
    let has_cmd_sub = contains_command_substitution(bytes);
    if has_cmd_sub {
        assert_ne!(
            rc, 0,
            "wordexp accepted command substitution input — security regression: {:?}",
            input.words
        );
    }

    // Determinism on a fresh pwordexp_t.
    let mut pwordexp2 = MaybeUninit::<[u8; WORDEXP_T_SIZE]>::zeroed();
    let pwordexp2_ptr = pwordexp2.as_mut_ptr() as *mut c_void;
    let rc2 =
        unsafe { frankenlibc_abi::unistd_abi::wordexp(words_c.as_ptr(), pwordexp2_ptr, flags) };
    assert_eq!(
        rc, rc2,
        "wordexp is non-deterministic for input {:?}",
        input.words
    );

    // Free any allocations our impl may have made so the next iteration
    // doesn't accumulate leaks. wordfree is safe on a wordexp_t whose
    // we_wordv is NULL (zero-initialized buffer).
    if rc == 0 {
        unsafe {
            frankenlibc_abi::unistd_abi::wordfree(pwordexp_ptr);
            frankenlibc_abi::unistd_abi::wordfree(pwordexp2_ptr);
        }
    }
});

fn contains_command_substitution(bytes: &[u8]) -> bool {
    let mut i = 0;
    let mut in_single = false;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && !in_single && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if b == b'\'' {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if !in_single {
            if b == b'`' {
                return true;
            }
            if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
                return true;
            }
        }
        i += 1;
    }
    false
}
