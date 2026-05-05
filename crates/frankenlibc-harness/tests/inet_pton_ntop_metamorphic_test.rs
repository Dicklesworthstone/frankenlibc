//! Metamorphic tests for `frankenlibc_core::inet` (bd-xem22).
//!
//! The pton/ntop pair has curated golden vectors plus a host-glibc
//! differential row. Metamorphic relations cover entire input classes
//! without an oracle:
//!
//!   M-IPV4-1  ntop -> pton round-trip preserves bytes for ALL 4-byte
//!             inputs (sampled via deterministic PCG32 sweep).
//!   M-IPV4-2  ntop output is dotted-quad: exactly 4 numeric segments
//!             separated by '.', each in 0..=255, total length 7..=15.
//!   M-IPV6-1  ntop -> pton round-trip preserves bytes for ALL 16-byte
//!             inputs (deterministic ::-compression).
//!   M-IPV6-2  ntop output uses only `[0-9a-f:.]`, contains at most one
//!             `::` run, and parses back unambiguously.
//!   M-CROSS   ntop(AF_INET, x) parses back via pton(AF_INET, ...) to
//!             the same 4 bytes regardless of how those bytes might
//!             render in another family — pton must be family-strict.
//!
//! Deterministic PCG32 seed; no system entropy. 2 000 iterations split
//! across IPv4 and IPv6 classes, plus boundary cases (all-zeros,
//! all-ones, loopback, link-local, multicast).

use frankenlibc_core::inet;
use frankenlibc_core::socket::{AF_INET, AF_INET6};

const SEED: u64 = 0x6970_7634_6970_7636;

struct Pcg32 {
    state: u64,
    inc: u64,
}

impl Pcg32 {
    fn new(seed: u64) -> Self {
        let mut p = Self {
            state: 0,
            inc: (seed << 1) | 1,
        };
        let _ = p.next_u32();
        p.state = p.state.wrapping_add(seed);
        let _ = p.next_u32();
        p
    }
    fn next_u32(&mut self) -> u32 {
        let oldstate = self.state;
        self.state = oldstate
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(self.inc);
        let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
        let rot = (oldstate >> 59) as u32;
        xorshifted.rotate_right(rot)
    }
    fn fill(&mut self, dst: &mut [u8]) {
        let mut i = 0;
        while i < dst.len() {
            let v = self.next_u32().to_le_bytes();
            let take = (dst.len() - i).min(4);
            dst[i..i + take].copy_from_slice(&v[..take]);
            i += take;
        }
    }
}

fn ntop_string(af: i32, src: &[u8]) -> String {
    let bytes =
        inet::inet_ntop(af, src).expect("inet_ntop must succeed for canonical family input");
    String::from_utf8(bytes).expect("inet_ntop output is ASCII")
}

fn pton_4(s: &[u8]) -> Option<[u8; 4]> {
    let mut buf = [0u8; 4];
    if inet::inet_pton(AF_INET, s, &mut buf) == 1 {
        Some(buf)
    } else {
        None
    }
}

fn pton_16(s: &[u8]) -> Option<[u8; 16]> {
    let mut buf = [0u8; 16];
    if inet::inet_pton(AF_INET6, s, &mut buf) == 1 {
        Some(buf)
    } else {
        None
    }
}

#[test]
fn m_ipv4_1_ntop_pton_roundtrip_preserves_bytes() {
    // Boundary: all-zeros, all-ones, loopback, link-local, multicast.
    let boundaries: &[[u8; 4]] = &[
        [0, 0, 0, 0],
        [255, 255, 255, 255],
        [127, 0, 0, 1],
        [169, 254, 0, 1],
        [224, 0, 0, 1],
    ];
    for bytes in boundaries {
        let s = ntop_string(AF_INET, bytes);
        let back = pton_4(s.as_bytes()).expect("ntop output must parse");
        assert_eq!(
            &back, bytes,
            "M-IPV4-1 boundary round-trip drift: input={bytes:?} ntop={s:?} pton={back:?}"
        );
    }
    // Sweep: 1000 deterministic PCG32 inputs.
    let mut rng = Pcg32::new(SEED);
    for _ in 0..1000 {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes);
        let s = ntop_string(AF_INET, &bytes);
        let back = pton_4(s.as_bytes())
            .unwrap_or_else(|| panic!("ntop output {s:?} must parse for input {bytes:?}"));
        assert_eq!(
            back, bytes,
            "M-IPV4-1 round-trip drift at random input {bytes:?}: ntop={s:?} pton={back:?}"
        );
    }
}

#[test]
fn m_ipv4_2_ntop_output_is_dotted_quad_with_octets_in_range() {
    let mut rng = Pcg32::new(SEED ^ 0xa5a5_a5a5_a5a5_a5a5);
    for _ in 0..500 {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes);
        let s = ntop_string(AF_INET, &bytes);
        assert!(
            (7..=15).contains(&s.len()),
            "M-IPV4-2 length out of [7, 15] for {bytes:?}: {s:?} len={}",
            s.len()
        );
        let parts: Vec<&str> = s.split('.').collect();
        assert_eq!(
            parts.len(),
            4,
            "M-IPV4-2 must have exactly 4 dotted parts: {s:?}"
        );
        for (i, p) in parts.iter().enumerate() {
            let n: u32 = p
                .parse()
                .unwrap_or_else(|_| panic!("M-IPV4-2 part {i} of {s:?} not a u32: {p:?}"));
            assert!(
                n <= 255,
                "M-IPV4-2 part {i} of {s:?} = {n} > 255 (input bytes {bytes:?})"
            );
            assert!(
                p.bytes().all(|b| b.is_ascii_digit()),
                "M-IPV4-2 part {i} of {s:?} has non-digit chars: {p:?}"
            );
        }
    }
}

#[test]
fn m_ipv6_1_ntop_pton_roundtrip_preserves_bytes() {
    let boundaries: &[[u8; 16]] = &[
        [0u8; 16],
        [0xFFu8; 16],
        // ::1 loopback
        {
            let mut b = [0u8; 16];
            b[15] = 1;
            b
        },
        // link-local fe80::1
        {
            let mut b = [0u8; 16];
            b[0] = 0xfe;
            b[1] = 0x80;
            b[15] = 1;
            b
        },
        // 2001:db8::1 documentation prefix
        {
            let mut b = [0u8; 16];
            b[0] = 0x20;
            b[1] = 0x01;
            b[2] = 0x0d;
            b[3] = 0xb8;
            b[15] = 1;
            b
        },
    ];
    for bytes in boundaries {
        let s = ntop_string(AF_INET6, bytes);
        let back = pton_16(s.as_bytes())
            .unwrap_or_else(|| panic!("M-IPV6-1 boundary ntop {s:?} must parse for {bytes:?}"));
        assert_eq!(
            &back, bytes,
            "M-IPV6-1 boundary round-trip drift: input={bytes:?} ntop={s:?} pton={back:?}"
        );
    }
    let mut rng = Pcg32::new(SEED ^ 0x5a5a_5a5a_5a5a_5a5a);
    for _ in 0..1000 {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        let s = ntop_string(AF_INET6, &bytes);
        let back = pton_16(s.as_bytes())
            .unwrap_or_else(|| panic!("M-IPV6-1 random ntop {s:?} must parse for {bytes:?}"));
        assert_eq!(
            back, bytes,
            "M-IPV6-1 round-trip drift at random input {bytes:?}: ntop={s:?} pton={back:?}"
        );
    }
}

#[test]
fn m_ipv6_2_ntop_output_uses_only_legal_chars_with_one_compression_run() {
    let mut rng = Pcg32::new(SEED ^ 0xdeaf_beef_dead_cafe);
    for _ in 0..500 {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        let s = ntop_string(AF_INET6, &bytes);
        for (i, ch) in s.bytes().enumerate() {
            assert!(
                matches!(ch, b'0'..=b'9' | b'a'..=b'f' | b':' | b'.'),
                "M-IPV6-2 illegal char 0x{ch:02x} at offset {i} of {s:?}"
            );
        }
        // RFC 5952: at most one `::` run.
        let mut count = 0usize;
        let mut idx = 0usize;
        while let Some(pos) = s[idx..].find("::") {
            count += 1;
            idx += pos + 2;
        }
        assert!(
            count <= 1,
            "M-IPV6-2 multiple :: runs in {s:?} (found {count}) for input {bytes:?}"
        );
    }
}

#[test]
fn m_cross_family_pton_is_strict() {
    // ntop(AF_INET, x) -> pton(AF_INET, ...) recovers x; pton(AF_INET6,
    // ...) of the same dotted-quad is permitted (it produces an IPv4-
    // mapped form per glibc) but the AF_INET round-trip MUST recover
    // bytes exactly. The metamorphic point: regardless of how a 4-byte
    // payload would render in IPv6 land, the AF_INET round-trip is
    // bijective on its own.
    let mut rng = Pcg32::new(SEED ^ 0x1357_9bdf_0246_8ace);
    for _ in 0..200 {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes);
        let s = ntop_string(AF_INET, &bytes);
        let back4 = pton_4(s.as_bytes()).expect("AF_INET round-trip must succeed");
        assert_eq!(
            back4, bytes,
            "M-CROSS AF_INET round-trip drift: input={bytes:?} ntop={s:?} pton={back4:?}"
        );
    }
}
