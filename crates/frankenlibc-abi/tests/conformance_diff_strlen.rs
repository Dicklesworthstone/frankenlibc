//! Differential gate for the public `strlen`/`strnlen` ABI after routing their
//! NUL scans through the SWAR `scan_c_string`. fl must agree with host glibc
//! `strlen`/`strnlen` for every length, pointer alignment, and (for strnlen)
//! every bound straddling the terminator.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::string_abi::{strlen as fl_strlen, strnlen as fl_strnlen};
use std::os::raw::c_char;

#[test]
fn strlen_strnlen_match_glibc() {
    let mut checked = 0u64;
    for align_off in 0usize..8 {
        for len in 0usize..260 {
            // Non-zero body (mix high-bit bytes to exercise the haszero lane), NUL,
            // then non-zero trailing guard so an overrun would change the answer.
            let mut content: Vec<u8> = (0..len)
                .map(|k| {
                    let b = (k as u8).wrapping_mul(91).wrapping_add(3);
                    if b == 0 { 0x80 } else { b }
                })
                .collect();
            content.push(0);
            content.extend([0xFF, 0x80, 0x41, 0xFF, 0x80, 0x01, 0xFF, 0x80]);

            // 8-aligned backing; place string at align_off.
            let mut backing: Vec<u64> = vec![0u64; (align_off + content.len()) / 8 + 2];
            let base = backing.as_mut_ptr().cast::<u8>();
            unsafe {
                for (k, &b) in content.iter().enumerate() {
                    *base.add(align_off + k) = b;
                }
            }
            let p = unsafe { base.add(align_off) } as *const c_char;

            // strlen.
            let fl = unsafe { fl_strlen(p) };
            let gl = unsafe { libc::strlen(p) };
            assert_eq!(
                fl, gl,
                "strlen align={align_off} len={len}: fl={fl} gl={gl}"
            );

            // strnlen over bounds straddling the terminator.
            for &bound in &[
                0usize,
                len.saturating_sub(1),
                len,
                len + 1,
                len + 8,
                len + 200,
            ] {
                let fln = unsafe { fl_strnlen(p, bound) };
                let gln = unsafe { libc::strnlen(p, bound) };
                assert_eq!(
                    fln, gln,
                    "strnlen align={align_off} len={len} bound={bound}: fl={fln} gl={gln}"
                );
                checked += 1;
            }
            checked += 1;
        }
    }
    assert!(checked > 12000, "corpus unexpectedly small: {checked}");
}

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

/// Host glibc `strlen`, resolved with `dlsym` so it cannot bind to fl's export
/// in this binary (bd-v0388t).
fn host_strlen() -> StrlenFn {
    // SAFETY: signature matches POSIX strlen exactly.
    unsafe { dlsym_oracle::host_fn(c"strlen", fl_strlen as *const ()) }
}

/// Unbounded strlen from every offset of a 64-byte block, for lengths across
/// and beyond the two aligned blocks the baseline build checks inline before
/// dispatching the rest (bd-rc0923-epic-eeuy4f.13), and for strings whose NUL
/// is the last byte before a `PROT_NONE` page. The bytes of the first block
/// before the string are NUL, so a head check that failed to mask them would
/// return early; a read past the page end would fault. Every result must equal
/// host glibc and the length written.
#[test]
fn strlen_every_block_offset_and_guard_page_end_match_glibc() {
    const PAGE: usize = 4096;
    let fill = |k: usize| -> u8 {
        let b = (k as u8).wrapping_mul(91).wrapping_add(3);
        if b == 0 { 0x80 } else { b }
    };
    // SAFETY: a fresh private anonymous mapping, checked below.
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            3 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(map, libc::MAP_FAILED, "mmap failed");
    let base = map.cast::<u8>();
    // SAFETY: the third page lies inside the mapping just created.
    let rc = unsafe { libc::mprotect(base.add(2 * PAGE).cast(), PAGE, libc::PROT_NONE) };
    assert_eq!(rc, 0, "mprotect failed");

    let mut compared = 0usize;
    let mut check = |start: usize, len: usize| {
        // SAFETY: every index below is inside the two readable pages.
        unsafe {
            for k in (start & !63)..start {
                *base.add(k) = 0;
            }
            for k in 0..len {
                *base.add(start + k) = fill(k);
            }
            *base.add(start + len) = 0;
            for k in start + len + 1..(start + len + 9).min(2 * PAGE) {
                *base.add(k) = 0xFF;
            }
        }
        let p = unsafe { base.add(start) }.cast::<c_char>();
        let gl = unsafe { host_strlen()(p) };
        let fl = unsafe { fl_strlen(p) };
        assert_eq!(
            fl, gl,
            "strlen(start={start}, len={len}): fl={fl} glibc={gl}"
        );
        assert_eq!(
            fl, len,
            "strlen(start={start}) must be the {len} bytes written"
        );
        compared += 1;
    };
    // Every offset in a 64-byte block (PAGE / 2 is 64-aligned).
    for off in 0..64 {
        for len in 0..=300 {
            check(PAGE / 2 + off, len);
        }
    }
    // The NUL on the last readable byte.
    for len in 0..=300 {
        check(2 * PAGE - 1 - len, len);
    }
    assert_eq!(compared, 64 * 301 + 301);
    // SAFETY: unmapping the mapping created above; nothing refers to it now.
    assert_eq!(unsafe { libc::munmap(map, 3 * PAGE) }, 0);
}
