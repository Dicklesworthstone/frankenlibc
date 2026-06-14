//! Differential + page-safety gate for the public `wcschr` ABI after routing its
//! common-path scan through the portable-SIMD `wide_find_or_nul_simd`. fl must
//! agree with host glibc `wcschr` for every target (incl. '\0', high/sign-bit,
//! absent), NUL position, and pointer alignment, including targets on SIMD
//! window boundaries; and the vector loads must not fault past a NUL flush
//! against an unmapped page.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::wcschr as fl_wcschr;
use sha2::{Digest, Sha256};

unsafe extern "C" {
    fn wcschr(s: *const u32, c: u32) -> *mut u32;
}

#[test]
fn wcschr_matches_glibc() {
    let mut checked = 0u64;
    let alphabet: [u32; 6] = [
        b'a' as u32,
        b'Z' as u32,
        0x100,
        0x1_0000,
        0x8000_0000,
        0x7FFF_FFFF,
    ];
    for align_off in 0usize..8 {
        for len in 0usize..80 {
            let body: Vec<u32> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
            let mut content = body.clone();
            content.push(0);
            content.extend([b'a' as u32, 0x100, 0x8000_0000, b'Z' as u32]); // post-NUL guard

            // 32-byte-overaligned backing (Vec<u32> is 4-aligned; over-allocate and
            // place at element offset align_off so the start alignment varies).
            let mut backing = vec![0u32; align_off + content.len() + 8];
            for (k, &cc) in content.iter().enumerate() {
                backing[align_off + k] = cc;
            }
            let p = unsafe { backing.as_ptr().add(align_off) };

            for &t in &[
                b'a' as u32,
                b'Z' as u32,
                0x100,
                0x1_0000,
                0x8000_0000,
                0x7FFF_FFFF,
                0u32,
                0x999u32,
            ] {
                let fl = unsafe { fl_wcschr(p, t) };
                let gl = unsafe { wcschr(p, t) };
                let fo = if fl.is_null() {
                    None
                } else {
                    Some(fl as usize - p as usize)
                };
                let go = if gl.is_null() {
                    None
                } else {
                    Some(gl as usize - p as usize)
                };
                assert_eq!(
                    fo, go,
                    "wcschr align={align_off} len={len} target={t:#x}: fl={fo:?} gl={go:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 3000, "corpus unexpectedly small: {checked}");
}

#[test]
fn wcschr_golden_sha256_is_stable() {
    let alphabet: [u32; 6] = [
        b'a' as u32,
        b'Z' as u32,
        0x100,
        0x1_0000,
        0x8000_0000,
        0x7FFF_FFFF,
    ];
    let mut hasher = Sha256::new();
    let mut checked = 0u64;

    for align_off in 0usize..8 {
        for len in 0usize..80 {
            let body: Vec<u32> = (0..len).map(|k| alphabet[k % alphabet.len()]).collect();
            let mut content = body.clone();
            content.push(0);
            content.extend([b'a' as u32, 0x100, 0x8000_0000, b'Z' as u32]);

            let mut backing = vec![0u32; align_off + content.len() + 8];
            for (k, &cc) in content.iter().enumerate() {
                backing[align_off + k] = cc;
            }
            let p = unsafe { backing.as_ptr().add(align_off) };

            for &target in &[
                b'a' as u32,
                b'Z' as u32,
                0x100,
                0x1_0000,
                0x8000_0000,
                0x7FFF_FFFF,
                0u32,
                0x999u32,
            ] {
                let fl = unsafe { fl_wcschr(p, target) };
                let offset = if fl.is_null() {
                    u64::MAX
                } else {
                    ((fl as usize - p as usize) / std::mem::size_of::<u32>()) as u64
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
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("wcschr golden sha256: {hex}");
    assert_eq!(checked, 5120);
    assert_eq!(
        hex,
        "74cd189be1d0e04e13b908ac1256b77def756c937664e6cae18f93315090f6eb"
    );
}

#[test]
fn wcschr_does_not_overread_past_guard_page() {
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
                *start.add(k) = b'a' as u32;
            }
            *start.add(back - 1) = 0;
            // Search for an absent char (forces full scan to the NUL) and a present one.
            let _ = fl_wcschr(start, b'Z' as u32);
            let _ = fl_wcschr(start, b'a' as u32);
            let _ = fl_wcschr(start, 0);
        }
        libc::munmap(base.cast(), page * 2);
    }
}
