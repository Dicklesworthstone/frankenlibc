//! Differential gate for the public `wcsstr` ABI after replacing the brute-force
//! O(n*m) search with a SIMD-first-element-prefiltered search. fl must return the
//! same match position as host glibc `wcsstr` across many haystack/needle pairs:
//! present/absent needles, empty needle, needle longer than haystack, matches at
//! the start/middle/end, overlapping-prefix worst cases ("aaa..."), matches that
//! straddle the 8-element SIMD window boundary, and non-ASCII (>0x7F) elements.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi::wcsstr as fl_wcsstr;

unsafe extern "C" {
    fn wcsstr(haystack: *const u32, needle: *const u32) -> *mut u32;
}

fn wstr(v: &[u32]) -> Vec<u32> {
    let mut o = v.to_vec();
    o.push(0);
    o
}

fn check(hay: &[u32], needle: &[u32]) {
    let hw = wstr(hay);
    let nw = wstr(needle);
    let hp = hw.as_ptr();
    let np = nw.as_ptr();
    let fl = unsafe { fl_wcsstr(hp, np) };
    let gl = unsafe { wcsstr(hp, np) };
    let fo = if fl.is_null() {
        None
    } else {
        Some(fl as usize - hp as usize)
    };
    let go = if gl.is_null() {
        None
    } else {
        Some(gl as usize - hp as usize)
    };
    assert_eq!(
        fo, go,
        "wcsstr hay={hay:?} needle={needle:?}: fl={fo:?} gl={go:?}"
    );
}

#[test]
fn wcsstr_matches_glibc() {
    let a = b'a' as u32;
    let b = b'b' as u32;
    let c = b'c' as u32;
    let big = 0x1_0000u32;

    // Curated edge cases.
    check(&[], &[]);
    check(&[a, b, c], &[]);
    check(&[a, b, c], &[a]);
    check(&[a, b, c], &[c]);
    check(&[a, b, c], &[a, b, c]);
    check(&[a, b, c], &[a, b, c, a]); // needle longer
    check(&[a, b, c], &[b, c]);
    check(&[a, b, c], &[x()]); // absent
    check(&[a, a, a, a, b], &[a, a, b]); // overlapping prefix
    check(&[a, a, a, a, a], &[a, a, a, a, a, a]); // needle longer, all 'a'
    check(&[big, a, big, b, big], &[big, b]); // non-ASCII needle[0]
    check(&[a, big, a, big, c], &[big, c]);

    // Sweep: needle[0]='a', match straddling the 8-element window boundary.
    for pre in 0usize..20 {
        let mut hay: Vec<u32> = vec![b; pre]; // 'b' padding (needle[0]='a' absent here)
        hay.extend([a, b, c, a, b, c]); // the searchable region
        for nlen in 1usize..=6 {
            let needle: Vec<u32> = [a, b, c, a, b, c][..nlen].to_vec();
            check(&hay, &needle);
        }
        // Absent needle that shares the first element.
        check(&hay, &[a, a, a]);
    }

    // Deterministic random sweep over a small alphabet (forces many needle[0] hits).
    let alpha = [a, b, c, big];
    for seed in 0u32..300 {
        let hlen = (seed % 50) as usize;
        let hay: Vec<u32> = (0..hlen)
            .map(|k| {
                alpha[((seed
                    .wrapping_mul(2654435761)
                    .wrapping_add((k as u32).wrapping_mul(40503)))
                    % 4) as usize]
            })
            .collect();
        let nlen = 1 + (seed % 5) as usize;
        let needle: Vec<u32> = (0..nlen)
            .map(|k| {
                alpha[((seed
                    .wrapping_mul(40503)
                    .wrapping_add((k as u32).wrapping_mul(2654435761)))
                    % 4) as usize]
            })
            .collect();
        check(&hay, &needle);
    }
}

fn x() -> u32 {
    b'x' as u32
}
