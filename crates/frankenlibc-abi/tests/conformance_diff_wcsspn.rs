//! Differential gate for the public `wcsspn`/`wcscspn`/`wcspbrk` ABI after
//! replacing the O(n*m) `slice.contains` membership with the O(1) WideCharSet
//! (256-bit ASCII bitset + non-ASCII fallback). fl must match host glibc for
//! every string/set pair, covering: ASCII-only sets (bitset path), sets with
//! codepoints >= 256 (fallback path), strings mixing both, empty sets, and the
//! `>= 256` boundary (255 vs 256 vs 257) where the bitset gives way to the list.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::{
    wcscspn as fl_wcscspn, wcspbrk as fl_wcspbrk, wcsspn as fl_wcsspn,
};

unsafe extern "C" {
    fn wcsspn(s: *const u32, accept: *const u32) -> usize;
    fn wcscspn(s: *const u32, reject: *const u32) -> usize;
    fn wcspbrk(s: *const u32, accept: *const u32) -> *mut u32;
}

fn wstr(v: &[u32]) -> Vec<u32> {
    let mut o = v.to_vec();
    o.push(0);
    o
}

fn check(s: &[u32], set: &[u32]) {
    let sw = wstr(s);
    let setw = wstr(set);
    let sp = sw.as_ptr();
    let setp = setw.as_ptr();

    let fl_spn = unsafe { fl_wcsspn(sp, setp) };
    let gl_spn = unsafe { wcsspn(sp, setp) };
    assert_eq!(fl_spn, gl_spn, "wcsspn s={s:?} set={set:?}");

    let fl_cspn = unsafe { fl_wcscspn(sp, setp) };
    let gl_cspn = unsafe { wcscspn(sp, setp) };
    assert_eq!(fl_cspn, gl_cspn, "wcscspn s={s:?} set={set:?}");

    let fl_pb = unsafe { fl_wcspbrk(sp, setp) };
    let gl_pb = unsafe { wcspbrk(sp, setp) };
    let fo = if fl_pb.is_null() { None } else { Some(fl_pb as usize - sp as usize) };
    let go = if gl_pb.is_null() { None } else { Some(gl_pb as usize - sp as usize) };
    assert_eq!(fo, go, "wcspbrk s={s:?} set={set:?}");
}

#[test]
fn wcsspn_family_matches_glibc() {
    let a = b'a' as u32;
    let b = b'b' as u32;
    let c = b'c' as u32;
    let z = b'z' as u32;
    // Codepoints straddling the 256 boundary + larger ones.
    let cases_sets: &[&[u32]] = &[
        &[],
        &[a],
        &[a, b, c],
        &[a, b, c, z, b' ' as u32, b'\t' as u32],
        &[255, 256, 257],          // bitset/fallback boundary
        &[a, 256, 0x1_0000],       // mixed ASCII + non-ASCII
        &[0x10_FFFF, 256, 257],    // all non-ASCII
    ];
    let cases_strs: &[&[u32]] = &[
        &[],
        &[a],
        &[a, a, a, b, c],
        &[a, b, c, b' ' as u32, z, z],
        &[a, 255, 256, 257, b],
        &[256, 256, a, 0x1_0000],
        &[0x1_0000, 0x10_FFFF, a, b],
        &[z, z, z, z, z, z, z, z, z, a], // longer, late mismatch
    ];
    for set in cases_sets {
        for s in cases_strs {
            check(s, set);
        }
    }

    // A longer deterministic sweep mixing ASCII + occasional non-ASCII.
    let set: Vec<u32> = (b'a'..=b'f').map(|x| x as u32).chain([256u32, 0x1_0000]).collect();
    for seed in 0u32..200 {
        let len = (seed % 40) as usize;
        let s: Vec<u32> = (0..len)
            .map(|k| {
                let r = (seed.wrapping_mul(2654435761).wrapping_add(k as u32 * 40503)) % 10;
                match r {
                    0..=5 => (b'a' + (r as u8)) as u32, // mostly in-set ASCII
                    6 => 256,
                    7 => 0x1_0000,
                    8 => b'x' as u32,  // not in set
                    _ => 257,          // non-ASCII not in set
                }
            })
            .collect();
        check(&s, &set);
    }
}
