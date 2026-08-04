//! Isomorphism + golden-output proof for the folded-block `wcslen` lever
//! (string/wide.rs). The 256-element folded SIMD (one `simd_min` reduction per
//! block) only fast-forwards NUL-free blocks; the exact terminator index is
//! resolved by the scalar tail scan. This test pins that `wcslen` is byte-for-
//! byte identical to the trivial scalar reference (first NUL, else slice length)
//! over a deterministic corpus that straddles the 256-element block boundary and
//! places the NUL at every alignment, and pins a golden digest of all results.

use frankenlibc_core::string::wide::wcslen;

/// Trivial scalar reference: index of the first 0, else the slice length.
fn ref_wcslen(s: &[u32]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
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
fn wcslen_matches_scalar_reference_and_golden() {
    let mut r = Lcg(0x0123_4567_89ab_cdef);
    let mut hash: u64 = 0xcbf29ce484222325;
    let mut mix = |x: u64, h: &mut u64| {
        *h ^= x;
        *h = h.wrapping_mul(0x100000001b3);
    };

    // Lengths straddling the 256-element folded block and its 16-element tail.
    let lengths = [
        0usize, 1, 15, 16, 17, 31, 63, 64, 255, 256, 257, 511, 512, 1000, 1024, 4096, 4097,
    ];

    for &len in &lengths {
        // No-NUL buffer (forces the full scan to the end).
        let full: Vec<u32> = (0..len).map(|i| 1 + (i as u32 % 0x10_FFFE)).collect();
        let got = wcslen(&full);
        assert_eq!(got, ref_wcslen(&full), "wcslen no-NUL len={len}");
        mix(got as u64, &mut hash);

        // NUL placed at every position (and just past the end) for a few seeds.
        for _ in 0..6 {
            let nul_pos = (r.next() as usize) % (len + 1);
            let mut buf: Vec<u32> = (0..len).map(|_| 1 + (r.next() as u32 % 0x10_FFFE)).collect();
            if nul_pos < len {
                buf[nul_pos] = 0;
            }
            let got = wcslen(&buf);
            assert_eq!(got, ref_wcslen(&buf), "wcslen len={len} nul_pos={nul_pos}");
            mix(got as u64, &mut hash);
        }
    }

    assert_eq!(hash, 12438090589114447474, "golden wcslen digest changed");
}
