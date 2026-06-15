//! Isomorphism + golden-output proof for the folded-block `wcsnlen` lever
//! (string/wide.rs, bd-2g7oyh.262 follow-up). The 256-element folded SIMD only
//! fast-forwards NUL-free blocks; the exact terminator index is resolved by the
//! scalar tail. This pins that `wcsnlen` is byte-for-byte identical to the
//! trivial scalar reference (first NUL within the maxlen bound, else the bound)
//! over a deterministic corpus straddling the 256-element block boundary with
//! the NUL and the maxlen bound at every alignment, plus a golden digest.

use frankenlibc_core::string::wide::wcsnlen;

/// Scalar reference: index of the first 0 within `s[..min(maxlen, len)]`, else
/// the bound itself.
fn ref_wcsnlen(s: &[u32], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    s[..limit].iter().position(|&c| c == 0).unwrap_or(limit)
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
fn wcsnlen_matches_scalar_reference_and_golden() {
    let mut r = Lcg(0xfeed_face_dead_2025);
    let mut hash: u64 = 0xcbf29ce484222325;
    let mix = |x: u64, h: &mut u64| {
        *h ^= x;
        *h = h.wrapping_mul(0x100000001b3);
    };

    let lengths = [
        0usize, 1, 15, 16, 17, 63, 64, 255, 256, 257, 511, 512, 1024, 4096, 4097,
    ];

    for &len in &lengths {
        // No-NUL buffer (forces the scan to the bound), with assorted maxlen.
        let full: Vec<u32> = (0..len).map(|i| 1 + (i as u32 % 0x10_FFFE)).collect();
        for &m in &[0usize, 1, len / 2, len, len + 1, usize::MAX] {
            let got = wcsnlen(&full, m);
            assert_eq!(
                got,
                ref_wcsnlen(&full, m),
                "wcsnlen no-NUL len={len} maxlen={m}"
            );
            mix(got as u64, &mut hash);
        }

        // NUL at a random position, with a random maxlen bound.
        for _ in 0..6 {
            let nul_pos = (r.next() as usize) % (len + 1);
            let mut buf: Vec<u32> = (0..len)
                .map(|_| 1 + (r.next() as u32 % 0x10_FFFE))
                .collect();
            if nul_pos < len {
                buf[nul_pos] = 0;
            }
            let m = (r.next() as usize) % (len + 2);
            let got = wcsnlen(&buf, m);
            assert_eq!(
                got,
                ref_wcsnlen(&buf, m),
                "wcsnlen len={len} nul={nul_pos} maxlen={m}"
            );
            mix(got as u64, &mut hash);
        }
    }

    assert_eq!(hash, 2675721401778663386, "golden wcsnlen digest changed");
}
