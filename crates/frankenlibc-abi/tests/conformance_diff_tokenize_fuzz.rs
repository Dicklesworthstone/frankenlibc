#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Randomized live differential of the in-place tokenizers `strtok_r` and
//! `strsep` against host glibc/BSD over 20000 random (source, delimiter-set)
//! pairs. conformance_diff_string_mut already pins ~6 hand-picked cases per
//! function; this adds broad random coverage of the delimiter-classification
//! and empty-field/leading-delim/trailing-delim/no-delim corners.
//!
//! Both tokenizers operate on a caller-owned mutable buffer (strtok_r via an
//! explicit saveptr, strsep via *stringp) with no process-global state, so each
//! engine is driven on its own fresh buffer copy and the token sequences are
//! compared directly — no symbol-sharing caveats.

use frankenlibc_abi::string_abi as fa;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

unsafe extern "C" {
    fn strtok_r(s: *mut c_char, d: *const c_char, sp: *mut *mut c_char) -> *mut c_char;
    fn strsep(sp: *mut *mut c_char, d: *const c_char) -> *mut c_char;
}
type TokR = unsafe extern "C" fn(*mut c_char, *const c_char, *mut *mut c_char) -> *mut c_char;
type Sep = unsafe extern "C" fn(*mut *mut c_char, *const c_char) -> *mut c_char;

fn tok_seq(f: TokR, src: &[u8], delim: &[u8]) -> Vec<Vec<u8>> {
    let mut buf: Vec<u8> = src.to_vec();
    buf.push(0);
    let d = CString::new(delim).unwrap();
    let mut out = Vec::new();
    let mut sp: *mut c_char = std::ptr::null_mut();
    let mut first = buf.as_mut_ptr() as *mut c_char;
    loop {
        let t = unsafe { f(first, d.as_ptr(), &mut sp) };
        first = std::ptr::null_mut();
        if t.is_null() {
            break;
        }
        out.push(unsafe { CStr::from_ptr(t) }.to_bytes().to_vec());
        if out.len() > 200 {
            break;
        }
    }
    out
}

fn sep_seq(f: Sep, src: &[u8], delim: &[u8]) -> Vec<Option<Vec<u8>>> {
    let mut buf: Vec<u8> = src.to_vec();
    buf.push(0);
    let d = CString::new(delim).unwrap();
    let mut out = Vec::new();
    let mut p = buf.as_mut_ptr() as *mut c_char;
    for _ in 0..=src.len() + 2 {
        if p.is_null() {
            break;
        }
        let t = unsafe { f(&mut p, d.as_ptr()) };
        if t.is_null() {
            out.push(None);
            break;
        }
        out.push(Some(unsafe { CStr::from_ptr(t) }.to_bytes().to_vec()));
    }
    out
}

#[test]
fn tokenize_differential_fuzz_vs_glibc() {
    let alpha = *b"abc, -_;x,";
    // Includes >4-byte delimiter sets (`, -_;` = 5, `abc, -_` = 7) to cover the
    // fused bitmap tokenizer path (delim_len > 4), members drawn from `alpha`.
    let delimsets: &[&[u8]] = &[
        b",", b", ", b"-_ ", b";", b"abc", b" ", b",;", b"xyz", b"", b", -_;", b"abc, -_",
    ];
    let mut seed: u64 = 0xC0FFEE;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut div: Vec<String> = Vec::new();
    let (mut td, mut sd) = (0u32, 0u32);
    for _ in 0..20000 {
        let len = (rng() as usize) % 12;
        let src: Vec<u8> = (0..len)
            .map(|_| alpha[(rng() as usize) % alpha.len()])
            .collect();
        let delim = delimsets[(rng() as usize) % delimsets.len()];
        let (ft, ht) = (
            tok_seq(fa::strtok_r, &src, delim),
            tok_seq(strtok_r, &src, delim),
        );
        if ft != ht {
            td += 1;
            if div.len() < 10 {
                div.push(format!(
                    "strtok_r src={:?} delim={:?}\n    fl={:?}\n    gl={:?}",
                    String::from_utf8_lossy(&src),
                    String::from_utf8_lossy(delim),
                    ft,
                    ht
                ));
            }
        }
        let (fs, hs) = (
            sep_seq(fa::strsep, &src, delim),
            sep_seq(strsep, &src, delim),
        );
        if fs != hs {
            sd += 1;
            if div.len() < 10 {
                div.push(format!(
                    "strsep src={:?} delim={:?}\n    fl={:?}\n    gl={:?}",
                    String::from_utf8_lossy(&src),
                    String::from_utf8_lossy(delim),
                    fs,
                    hs
                ));
            }
        }
    }
    assert!(
        td == 0 && sd == 0,
        "tokenizer divergences (strtok_r={td}, strsep={sd}):\n  {}",
        div.join("\n  ")
    );
}

/// PAGE-SAFETY proof for the >4-byte-delim fused PSHUFB tokenizer scan: place a
/// NUL-terminated string ending at every offset in the last 40 bytes of a mapped
/// page whose successor page is PROT_NONE, run strtok_r with a 6-char delimiter set
/// (routes through `scan_c_string_pshufb`), and require no SIGSEGV + correct tokens.
/// The 32-byte AVX2 windows sit right against the guard page, so any over-read past
/// the terminating NUL's page would fault.
#[test]
fn strtok_pshufb_does_not_overread_past_guard_page() {
    let page = 4096usize;
    let delim = CString::new(" \t\n\r\x0c\x0b").unwrap(); // 6 chars → PSHUFB path
    unsafe {
        let base = libc::mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(base, libc::MAP_FAILED, "mmap failed");
        let base = base.cast::<u8>();
        assert_eq!(
            libc::mprotect(base.add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );
        // Content: alternating token bytes and delimiter (space) so the scan stops
        // at real delimiters AND runs to the NUL against the guard page.
        for back in 1..=40usize {
            let start = base.add(page - back);
            for k in 0..(back - 1) {
                // pattern: 'a','a',' ','a','a',' ',... — tokens of length ≤2.
                *start.add(k) = if (k % 3) == 2 { b' ' } else { b'a' };
            }
            *start.add(back - 1) = 0;

            // Reference token sequence via a heap copy (safe, away from the guard).
            let mut heap: Vec<u8> = std::slice::from_raw_parts(start, back).to_vec();
            let want = tok_seq(strtok_r, &heap[..back - 1], delim.to_bytes());

            // fl strtok_r driven IN PLACE on the guard-adjacent buffer.
            let _ = &mut heap;
            let mut sp: *mut c_char = std::ptr::null_mut();
            let mut got: Vec<Vec<u8>> = Vec::new();
            let mut cur = start as *mut c_char;
            loop {
                let t = fa::strtok_r(cur, delim.as_ptr(), &mut sp);
                cur = std::ptr::null_mut();
                if t.is_null() {
                    break;
                }
                got.push(CStr::from_ptr(t).to_bytes().to_vec());
            }
            assert_eq!(
                got, want,
                "strtok_r PSHUFB wrong/overread near guard (back={back})"
            );
        }
        libc::munmap(base.cast(), page * 2);
    }
}
