#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Isomorphism + golden gate for folding strcpy/stpcpy onto one shared scan
//! (strcpy_core). Two redundant O(n) passes were removed: (1) strcpy's common
//! (non-repair) path scanned the source length, then re-scanned it again before
//! copying — the second scan is gone; (2) stpcpy was strcpy() then strlen() on
//! the just-copied string — it now returns the written-NUL position from the
//! single copy scan. 200000 random (source, src/dst alignment) cases agree
//! exactly with host glibc strcpy AND stpcpy on both the destination bytes and
//! the return pointer; a golden sha256 of the stpcpy end offsets pins it.

use std::os::raw::c_char;
use frankenlibc_abi::string_abi as fa;
use sha2::{Digest, Sha256};

unsafe extern "C" {
    fn strcpy(d: *mut c_char, s: *const c_char) -> *mut c_char;
    fn stpcpy(d: *mut c_char, s: *const c_char) -> *mut c_char;
}

#[test]
fn strcpy_stpcpy_match_glibc() {
    let mut seed: u64 = 0x55;
    let mut rng = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut h = Sha256::new();
    let mut div = 0u32;
    for _ in 0..200000 {
        let len = (rng() as usize) % 150;
        let soff = (rng() as usize) % 8;
        let doff = (rng() as usize) % 8;
        let body: Vec<u8> = (0..len).map(|_| ((rng() % 94) + 33) as u8).collect();
        let mut sback = vec![b'q'; soff];
        sback.extend_from_slice(&body);
        sback.push(0);
        let sp = unsafe { sback.as_ptr().add(soff) } as *const c_char;

        let mut d1 = vec![0u8; doff + len + 16];
        let mut d2 = vec![0u8; doff + len + 16];
        let fp = unsafe { d1.as_mut_ptr().add(doff) } as *mut c_char;
        let gp = unsafe { d2.as_mut_ptr().add(doff) } as *mut c_char;
        let fr = unsafe { fa::strcpy(fp, sp) };
        let gr = unsafe { strcpy(gp, sp) };
        if (fr as usize - fp as usize) != (gr as usize - gp as usize)
            || d1[doff..doff + len + 1] != d2[doff..doff + len + 1]
        {
            div += 1;
            if div <= 5 {
                eprintln!("DIV strcpy len={len}");
            }
        }

        let mut e1 = vec![0u8; doff + len + 16];
        let mut e2 = vec![0u8; doff + len + 16];
        let ep = unsafe { e1.as_mut_ptr().add(doff) } as *mut c_char;
        let eqp = unsafe { e2.as_mut_ptr().add(doff) } as *mut c_char;
        let fe = unsafe { fa::stpcpy(ep, sp) };
        let ge = unsafe { stpcpy(eqp, sp) };
        let (feo, geo) = (fe as usize - ep as usize, ge as usize - eqp as usize);
        if feo != geo || e1[doff..doff + len + 1] != e2[doff..doff + len + 1] {
            div += 1;
            if div <= 5 {
                eprintln!("DIV stpcpy len={len} feo={feo} geo={geo}");
            }
        }
        h.update((feo as u64).to_le_bytes());
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("strcpy/stpcpy golden sha256: {hex}");
    assert_eq!(div, 0, "strcpy/stpcpy diverged from glibc in {div} cases");
    assert_eq!(
        hex,
        "a87a0b80a8df7dde132406974923f9b1c689d9af4619a6d75e420005ce088eb0",
        "strcpy/stpcpy golden changed"
    );
}
