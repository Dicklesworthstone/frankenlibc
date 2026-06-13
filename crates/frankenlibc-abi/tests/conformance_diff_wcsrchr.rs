//! Differential + page-safety gate for the public `wcsrchr` ABI after routing
//! the common unbounded path through the portable-SIMD c-or-NUL scanner. The
//! optimized path must preserve last-target-before-NUL ordering, `c == 0`
//! terminator behavior, high/sign-bit wchar values, alignment variation, and
//! guard-page no-overread behavior.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::wcsrchr as fl_wcsrchr;
use sha2::{Digest, Sha256};
use std::fmt::Write;

unsafe extern "C" {
    fn wcsrchr(s: *const u32, c: u32) -> *mut u32;
}

fn corpus_alphabet() -> [u32; 6] {
    [
        b'a' as u32,
        b'Z' as u32,
        0x100,
        0x1_0000,
        0x8000_0000,
        0x7FFF_FFFF,
    ]
}

fn corpus_targets() -> [u32; 8] {
    [
        b'a' as u32,
        b'Z' as u32,
        0x100,
        0x1_0000,
        0x8000_0000,
        0x7FFF_FFFF,
        0,
        0x999,
    ]
}

#[test]
fn wcsrchr_matches_glibc() {
    let alphabet = corpus_alphabet();
    let targets = corpus_targets();
    let mut checked = 0u64;

    for align_off in 0usize..8 {
        for len in 0usize..80 {
            let body: Vec<u32> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
            let mut content = body;
            content.push(0);
            content.extend([b'a' as u32, 0x100, 0x8000_0000, b'Z' as u32]);

            let mut backing = vec![0u32; align_off + content.len() + 8];
            for (k, &cc) in content.iter().enumerate() {
                backing[align_off + k] = cc;
            }
            let p = unsafe { backing.as_ptr().add(align_off) };

            for &target in &targets {
                let fl = unsafe { fl_wcsrchr(p, target) };
                let gl = unsafe { wcsrchr(p, target) };
                let fo = if fl.is_null() {
                    None
                } else {
                    Some(unsafe { fl.offset_from(p) })
                };
                let go = if gl.is_null() {
                    None
                } else {
                    Some(unsafe { gl.offset_from(p) })
                };
                assert_eq!(
                    fo, go,
                    "wcsrchr align={align_off} len={len} target={target:#x}: fl={fo:?} gl={go:?}"
                );
                checked += 1;
            }
        }
    }

    assert_eq!(checked, 5120);
}

#[test]
fn wcsrchr_golden_sha256_is_stable() {
    let alphabet = corpus_alphabet();
    let targets = corpus_targets();
    let mut hasher = Sha256::new();
    let mut checked = 0u64;

    for align_off in 0usize..8 {
        for len in 0usize..80 {
            let body: Vec<u32> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
            let mut content = body;
            content.push(0);
            content.extend([b'a' as u32, 0x100, 0x8000_0000, b'Z' as u32]);

            let mut backing = vec![0u32; align_off + content.len() + 8];
            for (k, &cc) in content.iter().enumerate() {
                backing[align_off + k] = cc;
            }
            let p = unsafe { backing.as_ptr().add(align_off) };

            for &target in &targets {
                let fl = unsafe { fl_wcsrchr(p, target) };
                let offset = if fl.is_null() {
                    u64::MAX
                } else {
                    unsafe { fl.offset_from(p) as u64 }
                };
                hasher.update((align_off as u64).to_le_bytes());
                hasher.update((len as u64).to_le_bytes());
                hasher.update(target.to_le_bytes());
                hasher.update(offset.to_le_bytes());
                checked += 1;
            }
        }
    }

    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    eprintln!("wcsrchr golden sha256: {hex}");
    assert_eq!(checked, 5120);
    assert_eq!(
        hex,
        "3fb98cbeed206dcbbf6fa27007b4ac83bc76438ae30817652b8a07a340b54f77"
    );
}

#[test]
fn wcsrchr_does_not_overread_past_guard_page() {
    let page = 4096usize;
    let wchars = page / 4;
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
        let base = base.cast::<u32>();
        assert_eq!(
            libc::mprotect(base.cast::<u8>().add(page).cast(), page, libc::PROT_NONE),
            0,
            "mprotect failed"
        );

        for back in 1..=10usize {
            let start = base.add(wchars - back);
            for k in 0..(back - 1) {
                *start.add(k) = if k % 2 == 0 { b'a' as u32 } else { b'b' as u32 };
            }
            *start.add(back - 1) = 0;
            let _ = fl_wcsrchr(start, b'Z' as u32);
            let _ = fl_wcsrchr(start, b'a' as u32);
            let _ = fl_wcsrchr(start, 0);
        }

        libc::munmap(base.cast(), page * 2);
    }
}
