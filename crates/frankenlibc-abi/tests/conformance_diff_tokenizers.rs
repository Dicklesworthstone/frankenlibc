#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

//! Differential conformance harness for mutating string tokenizers.
//!
//! `strsep` and `strtok_r` are stateful in different ways: both mutate the
//! input buffer, while `strsep` updates the caller's cursor and `strtok_r`
//! carries continuation state through `saveptr`. This harness compares
//! FrankenLibC against the live host glibc for token sequences, returned
//! offsets, continuation offsets after successful tokens, and final buffer
//! mutation.

use std::ffi::c_char;

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    #[link_name = "strsep"]
    fn libc_strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char;

    #[link_name = "strtok_r"]
    fn libc_strtok_r(
        s: *mut c_char,
        delim: *const c_char,
        saveptr: *mut *mut c_char,
    ) -> *mut c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PtrPos {
    Null,
    Offset(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Step {
    returned: PtrPos,
    token: Vec<u8>,
    continuation: PtrPos,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    steps: Vec<Step>,
    final_buffer: Vec<u8>,
}

fn c_buffer(bytes: &[u8]) -> Vec<u8> {
    assert!(
        !bytes.contains(&0),
        "test inputs encode the terminal NUL separately"
    );
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.extend_from_slice(bytes);
    out.push(0);
    out
}

fn ptr_pos(base: *const u8, len: usize, ptr: *const c_char) -> PtrPos {
    if ptr.is_null() {
        return PtrPos::Null;
    }

    let base_addr = base as usize;
    let end_addr = base_addr + len;
    let ptr_addr = ptr as usize;
    assert!(
        (base_addr..=end_addr).contains(&ptr_addr),
        "tokenizer returned a pointer outside its input buffer: base={base_addr:#x} len={len} ptr={ptr_addr:#x}"
    );
    PtrPos::Offset(ptr_addr - base_addr)
}

unsafe fn read_token(ptr: *const c_char) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        // SAFETY: callers pass a non-null tokenizer return pointer into the
        // same NUL-terminated test buffer.
        let byte = unsafe { *ptr.add(offset) as u8 };
        if byte == 0 {
            return out;
        }
        out.push(byte);
        offset += 1;
    }
}

fn run_strsep(input: &[u8], delim: &[u8], host: bool) -> Observation {
    let mut buffer = c_buffer(input);
    let delim = c_buffer(delim);
    let base = buffer.as_mut_ptr();
    let len = buffer.len();
    let mut cursor = base.cast::<c_char>();
    let mut steps = Vec::new();

    loop {
        let returned = if host {
            // SAFETY: `cursor` and `delim` are valid NUL-terminated test
            // buffers, and `cursor` itself is a valid out-parameter.
            unsafe { libc_strsep(&mut cursor, delim.as_ptr().cast()) }
        } else {
            // SAFETY: same preconditions as the host call above.
            unsafe { fl::strsep(&mut cursor, delim.as_ptr().cast()) }
        };

        if returned.is_null() {
            assert!(
                cursor.is_null(),
                "strsep terminal call left cursor non-null"
            );
            break;
        }

        steps.push(Step {
            returned: ptr_pos(base, len, returned),
            // SAFETY: `returned` is non-null and points into `buffer`.
            token: unsafe { read_token(returned) },
            continuation: ptr_pos(base, len, cursor),
        });

        assert!(
            steps.len() <= input.len() + 2,
            "strsep did not terminate for input={input:?} delim={delim:?}"
        );
    }

    Observation {
        steps,
        final_buffer: buffer,
    }
}

fn run_strtok_r(input: &[u8], delim: &[u8], host: bool) -> Observation {
    let mut buffer = c_buffer(input);
    let delim = c_buffer(delim);
    let base = buffer.as_mut_ptr();
    let len = buffer.len();
    let mut saveptr = std::ptr::null_mut::<c_char>();
    let mut next_input = base.cast::<c_char>();
    let mut steps = Vec::new();

    loop {
        let returned = if host {
            // SAFETY: `next_input` is either the initial test buffer or NULL,
            // `delim` is NUL-terminated, and `saveptr` is a valid out-param.
            unsafe { libc_strtok_r(next_input, delim.as_ptr().cast(), &mut saveptr) }
        } else {
            // SAFETY: same preconditions as the host call above.
            unsafe { fl::strtok_r(next_input, delim.as_ptr().cast(), &mut saveptr) }
        };
        next_input = std::ptr::null_mut();

        if returned.is_null() {
            break;
        }

        steps.push(Step {
            returned: ptr_pos(base, len, returned),
            // SAFETY: `returned` is non-null and points into `buffer`.
            token: unsafe { read_token(returned) },
            continuation: ptr_pos(base, len, saveptr),
        });

        assert!(
            steps.len() <= input.len() + 1,
            "strtok_r did not terminate for input={input:?} delim={delim:?}"
        );
    }

    Observation {
        steps,
        final_buffer: buffer,
    }
}

fn assert_same(label: &str, input: &[u8], delim: &[u8], fl_obs: Observation, glibc: Observation) {
    assert_eq!(
        fl_obs, glibc,
        "{label} diverged for input={input:?} delim={delim:?}\nfrankenlibc={fl_obs:#?}\nglibc={glibc:#?}"
    );
}

#[test]
fn diff_strsep_matches_glibc_token_cursor_and_mutation() {
    const CASES: &[(&[u8], &[u8])] = &[
        (b"", b","),
        (b"abc", b""),
        (b"abc", b","),
        (b"a,b,c", b","),
        (b"a,,b", b","),
        (b",a,b", b","),
        (b"a,b,", b","),
        (b",,,", b","),
        (b"a:b;c", b":;"),
        (b"word  gap\tend", b" \t"),
        (b"no-match", b"XYZ"),
    ];

    for (input, delim) in CASES {
        assert_same(
            "strsep",
            input,
            delim,
            run_strsep(input, delim, false),
            run_strsep(input, delim, true),
        );
    }
}

#[test]
fn diff_strtok_r_matches_glibc_tokens_saveptr_and_mutation() {
    const CASES: &[(&[u8], &[u8])] = &[
        (b"", b","),
        (b"abc", b""),
        (b"abc", b","),
        (b"a,b,c", b","),
        (b"a,,b", b","),
        (b",a,b", b","),
        (b"a,b,", b","),
        (b",,,", b","),
        (b"a:b;c", b":;"),
        (b"  x  y ", b" "),
        (b"word  gap\tend", b" \t"),
        (b"no-match", b"XYZ"),
    ];

    for (input, delim) in CASES {
        assert_same(
            "strtok_r",
            input,
            delim,
            run_strtok_r(input, delim, false),
            run_strtok_r(input, delim, true),
        );
    }
}
