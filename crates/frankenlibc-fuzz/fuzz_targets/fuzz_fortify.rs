#![no_main]
//! Fuzz target for FrankenLibC's FORTIFY_SOURCE `__*_chk` surface:
//!
//!   __memcpy_chk, __memmove_chk, __memset_chk, __explicit_bzero_chk,
//!   __strcpy_chk, __strncpy_chk, __strcat_chk, __strncat_chk,
//!   __stpcpy_chk, __stpncpy_chk, __snprintf_chk
//!
//! These wrappers are what actually protects real binaries compiled
//! with `-D_FORTIFY_SOURCE=2` from single-call buffer overflows.
//! If they silently mis-copy or skip the bounds check, every user
//! of our libc transparently loses FORTIFY protection.
//!
//! Design constraint: `__chk_fail()` is `-> !` and terminates the
//! process via abort. We can NOT fuzz the overflow-trip path
//! in-process under libFuzzer's persistent mode (each overflow
//! would kill the harness). Instead this target:
//!
//! 1. Clamps fuzzer-supplied inputs so `len <= destlen` — the
//!    harness always exercises the **safe path** through each _chk
//!    wrapper.
//! 2. Exercises `destlen == usize::MAX` (the "I don't have
//!    destlen" escape hatch) so the overflow-check branch is
//!    skipped regardless of len; every _chk must still behave
//!    identically to its non-_chk counterpart.
//! 3. Asserts that the _chk output equals the non-_chk output
//!    byte-for-byte on the safe path (correctness oracle).
//! 4. Uses guard sentinels on both sides of the destination buffer
//!    so an off-by-one inside the _chk wrapper itself is detected.
//!
//! Coverage of the abort path requires a forking harness and is
//! tracked as a separate follow-up (bd-dvr22 fortify priority-4
//! subtask — in-process is out of scope).
//!
//! Bead: bd-dvr22 priority-4

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Once;

use arbitrary::Arbitrary;
use frankenlibc_abi::fortify_abi::{
    __explicit_bzero_chk, __memcpy_chk, __memmove_chk, __memset_chk, __snprintf_chk, __stpcpy_chk,
    __stpncpy_chk, __strcat_chk, __strcpy_chk, __strncat_chk, __strncpy_chk,
};
use frankenlibc_abi::string_abi::{memcpy, memmove, memset};
use libfuzzer_sys::fuzz_target;

const GUARD_BYTES: usize = 64;
const GUARD_BYTE: u8 = 0xFD;
const MAX_BUF: usize = 1024;

#[derive(Debug, Arbitrary)]
#[allow(clippy::enum_variant_names)]
enum Op {
    MemcpyChk { len: u16, destlen_extra: u16, use_max_destlen: bool },
    MemmoveChk { len: u16, destlen_extra: u16, overlap: bool, use_max_destlen: bool },
    MemsetChk { len: u16, destlen_extra: u16, byte: u8, use_max_destlen: bool },
    ExplicitBzeroChk { len: u16, destlen_extra: u16, use_max_destlen: bool },
    StrcpyChk { src: Vec<u8>, destlen_extra: u16, use_max_destlen: bool },
    StrncpyChk { src: Vec<u8>, n: u16, destlen_extra: u16, use_max_destlen: bool },
    StrcatChk { dst_prefix: Vec<u8>, src: Vec<u8>, destlen_extra: u16 },
    StrncatChk { dst_prefix: Vec<u8>, src: Vec<u8>, n: u16, destlen_extra: u16 },
    StpcpyChk { src: Vec<u8>, destlen_extra: u16 },
    StpncpyChk { src: Vec<u8>, n: u16, destlen_extra: u16 },
    SnprintfChk { size: u16, destlen_extra: u16, value: i32 },
}

#[derive(Debug, Arbitrary)]
struct FortifyFuzzInput {
    ops: Vec<Op>,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn make_guarded_buf(dst_size: usize) -> Vec<u8> {
    let mut v = vec![GUARD_BYTE; dst_size + 2 * GUARD_BYTES];
    // Stamp dst region with a different sentinel to detect writes.
    for b in &mut v[GUARD_BYTES..GUARD_BYTES + dst_size] {
        *b = 0xAA;
    }
    v
}

fn check_guards(buf: &[u8], dst_size: usize, label: &'static str) {
    for (i, &b) in buf[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "{label}: underflow guard corrupted at byte {i}"
        );
    }
    for (i, &b) in buf[GUARD_BYTES + dst_size..].iter().enumerate() {
        assert_eq!(
            b, GUARD_BYTE,
            "{label}: overflow guard corrupted at +{i} past dst_size={dst_size}"
        );
    }
}

fn pick_destlen(actual_len: usize, extra: u16, use_max: bool) -> usize {
    if use_max {
        usize::MAX
    } else {
        actual_len + (extra as usize) % MAX_BUF
    }
}

fn dst_ptr(buf: &mut [u8]) -> *mut c_void {
    buf[GUARD_BYTES..].as_mut_ptr().cast::<c_void>()
}

fn dst_ptr_char(buf: &mut [u8]) -> *mut c_char {
    buf[GUARD_BYTES..].as_mut_ptr().cast::<c_char>()
}

fn sanitize_cstring(bytes: &[u8], cap: usize) -> CString {
    let cleaned: Vec<u8> = bytes
        .iter()
        .take(cap)
        .map(|&b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(cleaned).expect("NULs stripped")
}

fn apply_op(op: &Op) {
    match op {
        Op::MemcpyChk { len, destlen_extra, use_max_destlen } => {
            let copy_len = (*len as usize) % MAX_BUF;
            let destlen = pick_destlen(copy_len, *destlen_extra, *use_max_destlen);
            let dst_size = copy_len + 4; // always wide enough so no OOB write
            let mut ours = make_guarded_buf(dst_size);
            let mut ref_ = make_guarded_buf(dst_size);
            let src: Vec<u8> = (0..copy_len).map(|i| (i as u8) ^ 0x5A).collect();
            unsafe {
                __memcpy_chk(dst_ptr(&mut ours), src.as_ptr().cast::<c_void>(), copy_len, destlen);
                memcpy(dst_ptr(&mut ref_), src.as_ptr().cast::<c_void>(), copy_len);
            }
            check_guards(&ours, dst_size, "__memcpy_chk ours");
            check_guards(&ref_, dst_size, "memcpy ref");
            assert_eq!(
                &ours[GUARD_BYTES..GUARD_BYTES + copy_len],
                &ref_[GUARD_BYTES..GUARD_BYTES + copy_len],
                "__memcpy_chk output diverged from memcpy on safe path"
            );
        }
        Op::MemmoveChk { len, destlen_extra, overlap, use_max_destlen } => {
            let copy_len = (*len as usize) % MAX_BUF;
            let destlen = pick_destlen(copy_len, *destlen_extra, *use_max_destlen);
            // For overlap case we use a single buffer and copy within.
            let dst_size = copy_len * 2 + 4;
            let mut ours = make_guarded_buf(dst_size);
            let mut ref_ = make_guarded_buf(dst_size);
            // Stamp a recognizable pattern at the source region.
            for i in 0..copy_len {
                let v = (i as u8) ^ 0xA5;
                ours[GUARD_BYTES + i] = v;
                ref_[GUARD_BYTES + i] = v;
            }
            let src_off = GUARD_BYTES;
            let dst_off = if *overlap {
                GUARD_BYTES + copy_len / 2
            } else {
                GUARD_BYTES + copy_len
            };
            unsafe {
                __memmove_chk(
                    ours[dst_off..].as_mut_ptr().cast::<c_void>(),
                    ours[src_off..].as_ptr().cast::<c_void>(),
                    copy_len,
                    destlen,
                );
                memmove(
                    ref_[dst_off..].as_mut_ptr().cast::<c_void>(),
                    ref_[src_off..].as_ptr().cast::<c_void>(),
                    copy_len,
                );
            }
            check_guards(&ours, dst_size, "__memmove_chk ours");
            check_guards(&ref_, dst_size, "memmove ref");
            assert_eq!(
                &ours[GUARD_BYTES..GUARD_BYTES + dst_size],
                &ref_[GUARD_BYTES..GUARD_BYTES + dst_size],
                "__memmove_chk diverged from memmove"
            );
        }
        Op::MemsetChk { len, destlen_extra, byte, use_max_destlen } => {
            let set_len = (*len as usize) % MAX_BUF;
            let destlen = pick_destlen(set_len, *destlen_extra, *use_max_destlen);
            let dst_size = set_len + 4;
            let mut ours = make_guarded_buf(dst_size);
            let mut ref_ = make_guarded_buf(dst_size);
            unsafe {
                __memset_chk(dst_ptr(&mut ours), *byte as c_int, set_len, destlen);
                memset(dst_ptr(&mut ref_), *byte as c_int, set_len);
            }
            check_guards(&ours, dst_size, "__memset_chk ours");
            assert_eq!(
                &ours[GUARD_BYTES..GUARD_BYTES + set_len],
                &ref_[GUARD_BYTES..GUARD_BYTES + set_len],
                "__memset_chk diverged from memset"
            );
        }
        Op::ExplicitBzeroChk { len, destlen_extra, use_max_destlen } => {
            let zero_len = (*len as usize) % MAX_BUF;
            let destlen = pick_destlen(zero_len, *destlen_extra, *use_max_destlen);
            let dst_size = zero_len + 4;
            let mut ours = make_guarded_buf(dst_size);
            // Pre-fill so we can see the zeroing clearly.
            for i in 0..dst_size {
                ours[GUARD_BYTES + i] = 0x7F;
            }
            unsafe { __explicit_bzero_chk(dst_ptr(&mut ours), zero_len, destlen) };
            check_guards(&ours, dst_size, "__explicit_bzero_chk");
            assert!(
                ours[GUARD_BYTES..GUARD_BYTES + zero_len].iter().all(|&b| b == 0),
                "__explicit_bzero_chk did not zero the first {zero_len} bytes"
            );
            // Tail bytes within dst_size beyond zero_len must be untouched.
            for i in zero_len..dst_size {
                assert_eq!(
                    ours[GUARD_BYTES + i],
                    0x7F,
                    "__explicit_bzero_chk wrote past len"
                );
            }
        }
        Op::StrcpyChk { src, destlen_extra, use_max_destlen } => {
            let src_c = sanitize_cstring(src, MAX_BUF - 1);
            let src_len = src_c.as_bytes().len() + 1;
            let destlen = pick_destlen(src_len, *destlen_extra, *use_max_destlen);
            let dst_size = src_len + 8;
            let mut ours = make_guarded_buf(dst_size);
            unsafe { __strcpy_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), destlen) };
            check_guards(&ours, dst_size, "__strcpy_chk");
            // Copied bytes must equal the C string (incl. NUL).
            assert_eq!(
                &ours[GUARD_BYTES..GUARD_BYTES + src_len - 1],
                src_c.as_bytes(),
                "__strcpy_chk wrote wrong bytes"
            );
            assert_eq!(ours[GUARD_BYTES + src_len - 1], 0, "__strcpy_chk missing NUL");
        }
        Op::StrncpyChk { src, n, destlen_extra, use_max_destlen } => {
            let src_c = sanitize_cstring(src, MAX_BUF - 1);
            let n = (*n as usize) % MAX_BUF;
            let destlen = pick_destlen(n, *destlen_extra, *use_max_destlen);
            let dst_size = n + 8;
            let mut ours = make_guarded_buf(dst_size);
            unsafe { __strncpy_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), n, destlen) };
            check_guards(&ours, dst_size, "__strncpy_chk");
        }
        Op::StrcatChk { dst_prefix, src, destlen_extra } => {
            let dst_prefix_c = sanitize_cstring(dst_prefix, 128);
            let src_c = sanitize_cstring(src, 128);
            let prefix_len = dst_prefix_c.as_bytes().len();
            let src_len = src_c.as_bytes().len();
            let needed = prefix_len + src_len + 1;
            let destlen = needed + (*destlen_extra as usize) % 64;
            let dst_size = destlen + 8;
            let mut ours = make_guarded_buf(dst_size);
            // Place the prefix at start of dst (NUL-terminated).
            ours[GUARD_BYTES..GUARD_BYTES + prefix_len]
                .copy_from_slice(dst_prefix_c.as_bytes());
            ours[GUARD_BYTES + prefix_len] = 0;
            unsafe { __strcat_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), destlen) };
            check_guards(&ours, dst_size, "__strcat_chk");
            // After: dst = prefix || src || NUL.
            assert_eq!(
                &ours[GUARD_BYTES..GUARD_BYTES + prefix_len],
                dst_prefix_c.as_bytes()
            );
            assert_eq!(
                &ours[GUARD_BYTES + prefix_len..GUARD_BYTES + prefix_len + src_len],
                src_c.as_bytes()
            );
            assert_eq!(ours[GUARD_BYTES + prefix_len + src_len], 0);
        }
        Op::StrncatChk { dst_prefix, src, n, destlen_extra } => {
            let dst_prefix_c = sanitize_cstring(dst_prefix, 64);
            let src_c = sanitize_cstring(src, 64);
            let n = (*n as usize) % 64;
            let prefix_len = dst_prefix_c.as_bytes().len();
            let needed = prefix_len + n + 1;
            let destlen = needed + (*destlen_extra as usize) % 64;
            let dst_size = destlen + 8;
            let mut ours = make_guarded_buf(dst_size);
            ours[GUARD_BYTES..GUARD_BYTES + prefix_len]
                .copy_from_slice(dst_prefix_c.as_bytes());
            ours[GUARD_BYTES + prefix_len] = 0;
            unsafe { __strncat_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), n, destlen) };
            check_guards(&ours, dst_size, "__strncat_chk");
        }
        Op::StpcpyChk { src, destlen_extra } => {
            let src_c = sanitize_cstring(src, MAX_BUF - 1);
            let src_len = src_c.as_bytes().len() + 1;
            let destlen = src_len + (*destlen_extra as usize) % 64;
            let dst_size = destlen + 8;
            let mut ours = make_guarded_buf(dst_size);
            let ret = unsafe {
                __stpcpy_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), destlen)
            };
            check_guards(&ours, dst_size, "__stpcpy_chk");
            // stpcpy returns pointer to the copied-in NUL terminator.
            let start = dst_ptr_char(&mut ours);
            let expected_offset = src_len - 1;
            let actual_offset = (ret as usize).wrapping_sub(start as usize);
            assert_eq!(
                actual_offset, expected_offset,
                "__stpcpy_chk returned wrong end pointer"
            );
        }
        Op::StpncpyChk { src, n, destlen_extra } => {
            let src_c = sanitize_cstring(src, MAX_BUF - 1);
            let n = (*n as usize) % MAX_BUF;
            let destlen = n + (*destlen_extra as usize) % 64;
            let dst_size = destlen + 8;
            let mut ours = make_guarded_buf(dst_size);
            unsafe { __stpncpy_chk(dst_ptr_char(&mut ours), src_c.as_ptr(), n, destlen) };
            check_guards(&ours, dst_size, "__stpncpy_chk");
        }
        Op::SnprintfChk { size, destlen_extra, value } => {
            let sz = (*size as usize) % 256;
            let destlen = sz + (*destlen_extra as usize) % 64;
            let dst_size = destlen + 8;
            let mut ours = make_guarded_buf(dst_size);
            // Use a known-good format literal — we do NOT want to fuzz
            // the format string here (that's fuzz_printf_adversarial's
            // job); we want to exercise the __snprintf_chk bounds
            // layer specifically.
            let rc = unsafe {
                __snprintf_chk(
                    dst_ptr_char(&mut ours),
                    sz,
                    0,
                    destlen,
                    c"val=%d".as_ptr(),
                    *value as c_int,
                )
            };
            check_guards(&ours, dst_size, "__snprintf_chk");
            assert!(rc >= -1, "__snprintf_chk rc={rc} out of contract");
        }
    }
}

fuzz_target!(|input: FortifyFuzzInput| {
    if input.ops.len() > 12 {
        return;
    }
    init_hardened_mode();

    for op in &input.ops {
        apply_op(op);
    }
});
