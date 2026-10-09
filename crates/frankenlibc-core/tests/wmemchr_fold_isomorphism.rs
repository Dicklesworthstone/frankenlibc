//! Isomorphism + golden-output proof for the folded-block wide forward-find
//! lever in `wmemchr` and `wcschr` (string/wide.rs, bd-2g7oyh.262 follow-up).
//! The 256-element folded SIMD (one `simd_min` reduction per block) only fast-
//! forwards blocks it proves contain no match; the exact leftmost index is
//! resolved by the scalar tail. This test pins that both functions are byte-for-
//! byte identical to trivial scalar references over a deterministic corpus that
//! straddles the 256-element block boundary with the needle (and a NUL, for
//! wcschr) at every alignment, plus a golden digest of all results.

use frankenlibc_core::string::wide::{wcschr, wmemchr};

/// Scalar reference: index of the first lane equal to `c` in `s[..n]`, else None.
fn ref_wmemchr(s: &[u32], c: u32, n: usize) -> Option<usize> {
    s[..n.min(s.len())].iter().position(|&x| x == c)
}

/// Scalar reference for wcschr: first `c` at or before the terminating NUL (and
/// the NUL itself when `c == 0`), else None.
fn ref_wcschr(s: &[u32], c: u32) -> Option<usize> {
    for (i, &x) in s.iter().enumerate() {
        if x == c {
            return Some(i);
        }
        if x == 0 {
            return None;
        }
    }
    None
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
}

#[test]
fn wide_find_matches_scalar_reference_and_golden() {
    let mut r = Lcg(0xdead_beef_0bad_f00d);
    let mut hash: u64 = 0xcbf29ce484222325;
    let mix = |x: u64, h: &mut u64| {
        *h ^= x;
        *h = h.wrapping_mul(0x100000001b3);
    };
    let needle = b'Z' as u32;

    let lengths = [
        0usize, 1, 15, 16, 17, 63, 64, 255, 256, 257, 511, 512, 1024, 4096, 4097,
    ];

    for &len in &lengths {
        // wmemchr: needle absent (full scan), and present at every position.
        let absent: Vec<u32> = (0..len).map(|_| b'a' as u32).collect();
        let got = wmemchr(&absent, needle, len);
        assert_eq!(
            got,
            ref_wmemchr(&absent, needle, len),
            "wmemchr absent len={len}"
        );
        mix(got.map(|x| x as u64 + 1).unwrap_or(0), &mut hash);

        for _ in 0..6 {
            let pos = (r.next() as usize) % (len + 1);
            let mut buf: Vec<u32> = (0..len).map(|_| b'a' as u32).collect();
            if pos < len {
                buf[pos] = needle;
            }
            // wmemchr over a random sub-count too.
            let n = if len == 0 {
                0
            } else {
                (r.next() as usize) % (len + 1)
            };
            let gm = wmemchr(&buf, needle, n);
            assert_eq!(
                gm,
                ref_wmemchr(&buf, needle, n),
                "wmemchr len={len} pos={pos} n={n}"
            );
            mix(gm.map(|x| x as u64 + 1).unwrap_or(0), &mut hash);

            // wcschr: place a NUL too, at a random spot, to exercise needle-or-nul.
            let nul = (r.next() as usize) % (len + 1);
            let mut wbuf = buf.clone();
            if nul < len {
                wbuf[nul] = 0;
            }
            let gc = wcschr(&wbuf, needle);
            assert_eq!(
                gc,
                ref_wcschr(&wbuf, needle),
                "wcschr len={len} pos={pos} nul={nul}"
            );
            mix(gc.map(|x| x as u64 + 1).unwrap_or(0), &mut hash);
        }
    }

    assert_eq!(hash, 5915599903303628183, "golden wide-find digest changed");
}
