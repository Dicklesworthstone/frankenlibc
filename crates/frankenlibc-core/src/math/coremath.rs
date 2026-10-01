//! Correctly-rounded binary64 kernels ported from the CORE-MATH project
//! (<https://core-math.gitlabpages.inria.fr/>), the code glibc 2.43 ships for
//! these functions. Because both are correctly rounded (round-to-nearest), a
//! faithful port returns the same bits as glibc on every input (bd-otip6a).
//!
//! Copyright (c) 2023-2025 Alexei Sibidanov <sibid@uvic.ca>, Paul Zimmermann
//! and the CORE-MATH authors; MIT licence:
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to
//! deal in the Software without restriction, including without limitation the
//! rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
//! sell copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions: The above
//! copyright notice and this permission notice shall be included in all copies
//! or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
//! WITHOUT WARRANTY OF ANY KIND.
//!
//! Constants keep the upstream C99 hex-float spelling through `hf!`, which is
//! evaluated at compile time and rejects any literal that is not exactly a
//! normal binary64 value, so the tables can be diffed against upstream.
//!
//! The C sources were verified correctly rounded both with and without FMA
//! contraction, so only the explicit `__builtin_fma` calls are kept as
//! `mul_add`; every other operation is a plain IEEE operation.

use super::erf_data::{
    ERF_C, ERF_C2, ERF_TINY_EXCEPTIONS, ERFC_ASYMPT_EXCEPTIONS, ERFC_E2, ERFC_NEG_EXCEPTIONS,
    ERFC_POS_EXCEPTIONS, ERFC_T, ERFC_TACC, EXP_T1, EXP_T2,
};

const MASK52: u64 = u64::MAX >> 12;

/// Parse a C99 hex-float literal (`[-]0x<hex>[.<hex>]p<[+-]dec>`) at compile time.
const fn parse_hf(s: &str) -> f64 {
    let b = s.as_bytes();
    let mut i = 0;
    let neg = b[0] == b'-';
    if neg {
        i = 1;
    }
    assert!(b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X'));
    i += 2;
    let mut m: u64 = 0;
    let mut frac_digits: i32 = 0;
    let mut seen_point = false;
    while b[i] != b'p' && b[i] != b'P' {
        let c = b[i];
        if c == b'.' {
            seen_point = true;
        } else {
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex digit"),
            };
            assert!(m < (1u64 << 59), "hex mantissa too long");
            m = (m << 4) | d as u64;
            if seen_point {
                frac_digits += 1;
            }
        }
        i += 1;
    }
    i += 1;
    let eneg = b[i] == b'-';
    if b[i] == b'-' || b[i] == b'+' {
        i += 1;
    }
    let mut p: i32 = 0;
    while i < b.len() {
        p = p * 10 + (b[i] - b'0') as i32;
        i += 1;
    }
    if eneg {
        p = -p;
    }
    let sign = if neg { 1u64 << 63 } else { 0 };
    if m == 0 {
        return f64::from_bits(sign);
    }
    let mut e = p - 4 * frac_digits;
    while m & 1 == 0 {
        m >>= 1;
        e += 1;
    }
    let len = 64 - m.leading_zeros() as i32;
    assert!(len <= 53, "hex literal is not exactly representable");
    let biased = e + len - 1 + 1023;
    assert!(
        biased >= 1 && biased <= 2046,
        "hex literal outside the normal range"
    );
    let frac = (m << (53 - len)) & MASK52;
    f64::from_bits(sign | ((biased as u64) << 52) | frac)
}

/// A hex-float constant, parsed in a `const` block so that it is evaluated at
/// compile time in expression position too (a bare `const fn` call inside a
/// function body may run at runtime).
macro_rules! hf {
    ($s:literal) => {
        const { parse_hf($s) }
    };
}

// --- double-double helpers shared by the CORE-MATH kernels -----------------

#[inline(always)]
fn fasttwosum(x: f64, y: f64) -> (f64, f64) {
    let s = x + y;
    let z = s - x;
    (s, y - z)
}

#[inline(always)]
fn fasttwosub(x: f64, y: f64) -> (f64, f64) {
    let s = x - y;
    let z = x - s;
    (s, z - y)
}

#[inline(always)]
fn adddd(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let s = xh + ch;
    let d = s - xh;
    (s, ((ch - d) + (xh + (d - s))) + (xl + cl))
}

#[inline(always)]
fn muldd_acc(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let ahlh = ch * xl;
    let alhh = cl * xh;
    let ahhh = ch * xh;
    let mut ahhl = ch.mul_add(xh, -ahhh);
    ahhl += alhh + ahlh;
    fasttwosum(ahhh, ahhl)
}

/// `muldd_acc` without the final fasttwosum normalisation.
#[inline(always)]
fn muldd(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let ahlh = ch * xl;
    let alhh = cl * xh;
    let ahhh = ch * xh;
    let ahhl = ch.mul_add(xh, -ahhh);
    (ahhh, ahhl + (alhh + ahlh))
}

#[inline(always)]
fn mulddd(xh: f64, xl: f64, ch: f64) -> (f64, f64) {
    let hh = xh * ch;
    (hh, ch.mul_add(xh, -hh) + xl * ch)
}

/// Double-double Horner evaluation of `c` at `xh + xl`; `l` is the low-order
/// tail added to the leading coefficient.
#[inline(always)]
fn polydd(xh: f64, xl: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let (mut ch, mut cl) = fasttwosum(c[i][0], l);
    cl += c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = muldd_acc(xh, xl, ch, cl);
        let (th, tl) = fasttwosum(c[i][0], ch);
        ch = th;
        cl += tl + c[i][1];
    }
    (ch, cl)
}

// --- atanh (CORE-MATH src/binary64/atanh/atanh.c) ---------------------------

const LOG_B: [(u16, i16); 32] = [
    (301, 27565),
    (7189, 24786),
    (13383, 22167),
    (18923, 19696),
    (23845, 17361),
    (28184, 15150),
    (31969, 13054),
    (35231, 11064),
    (37996, 9173),
    (40288, 7372),
    (42129, 5657),
    (43542, 4020),
    (44546, 2457),
    (45160, 962),
    (45399, -468),
    (45281, -1838),
    (44821, -3151),
    (44032, -4412),
    (42929, -5622),
    (41522, -6786),
    (39825, -7905),
    (37848, -8982),
    (35602, -10020),
    (33097, -11020),
    (30341, -11985),
    (27345, -12916),
    (24115, -13816),
    (20661, -14685),
    (16989, -15526),
    (13107, -16339),
    (9022, -17126),
    (4740, -17889),
];

const LOG_R1: [f64; 33] = [
    hf!("0x1p+0"),
    hf!("0x1.f5076p-1"),
    hf!("0x1.ea4bp-1"),
    hf!("0x1.dfc98p-1"),
    hf!("0x1.d5818p-1"),
    hf!("0x1.cb72p-1"),
    hf!("0x1.c199cp-1"),
    hf!("0x1.b7f76p-1"),
    hf!("0x1.ae8ap-1"),
    hf!("0x1.a5504p-1"),
    hf!("0x1.9c492p-1"),
    hf!("0x1.93738p-1"),
    hf!("0x1.8ace6p-1"),
    hf!("0x1.8258ap-1"),
    hf!("0x1.7a114p-1"),
    hf!("0x1.71f76p-1"),
    hf!("0x1.6a09ep-1"),
    hf!("0x1.6247ep-1"),
    hf!("0x1.5ab08p-1"),
    hf!("0x1.5342cp-1"),
    hf!("0x1.4bfdap-1"),
    hf!("0x1.44e08p-1"),
    hf!("0x1.3dea6p-1"),
    hf!("0x1.371a8p-1"),
    hf!("0x1.306fep-1"),
    hf!("0x1.29e9ep-1"),
    hf!("0x1.2387ap-1"),
    hf!("0x1.1d488p-1"),
    hf!("0x1.172b8p-1"),
    hf!("0x1.11302p-1"),
    hf!("0x1.0b558p-1"),
    hf!("0x1.059bp-1"),
    hf!("0x1p-1"),
];

const LOG_R2: [f64; 33] = [
    hf!("0x1p+0"),
    hf!("0x1.ffa74p-1"),
    hf!("0x1.ff4eap-1"),
    hf!("0x1.fef62p-1"),
    hf!("0x1.fe9dap-1"),
    hf!("0x1.fe452p-1"),
    hf!("0x1.fdeccp-1"),
    hf!("0x1.fd946p-1"),
    hf!("0x1.fd3c2p-1"),
    hf!("0x1.fce3ep-1"),
    hf!("0x1.fc8bcp-1"),
    hf!("0x1.fc33ap-1"),
    hf!("0x1.fbdbap-1"),
    hf!("0x1.fb83ap-1"),
    hf!("0x1.fb2bcp-1"),
    hf!("0x1.fad3ep-1"),
    hf!("0x1.fa7c2p-1"),
    hf!("0x1.fa246p-1"),
    hf!("0x1.f9ccap-1"),
    hf!("0x1.f975p-1"),
    hf!("0x1.f91d8p-1"),
    hf!("0x1.f8c6p-1"),
    hf!("0x1.f86e8p-1"),
    hf!("0x1.f8172p-1"),
    hf!("0x1.f7bfep-1"),
    hf!("0x1.f768ap-1"),
    hf!("0x1.f7116p-1"),
    hf!("0x1.f6ba4p-1"),
    hf!("0x1.f6632p-1"),
    hf!("0x1.f60c2p-1"),
    hf!("0x1.f5b52p-1"),
    hf!("0x1.f55e4p-1"),
    hf!("0x1.f5076p-1"),
];

/// `(low, high)` parts of -log(r1[i]).
const ATANH_L1: [[f64; 2]; 33] = [
    [hf!("0x0p+0"), hf!("0x0p+0")],
    [hf!("-0x1.532c1269e2038p-27"), hf!("0x1.62e5p-7")],
    [hf!("0x1.ce42d81b54e84p-27"), hf!("0x1.62e3cp-6")],
    [hf!("-0x1.25826f815ec3dp-26"), hf!("0x1.0a2acp-5")],
    [hf!("0x1.0db1b1e7cee11p-26"), hf!("0x1.62e4ap-5")],
    [hf!("-0x1.1f3a8c6c95003p-26"), hf!("0x1.bb9dcp-5")],
    [hf!("-0x1.774cd4fb8c30dp-26"), hf!("0x1.0a2b2p-4")],
    [hf!("0x1.452e56c030a0ap-29"), hf!("0x1.3687fp-4")],
    [hf!("0x1.6b63c4966a79ap-28"), hf!("0x1.62e41p-4")],
    [hf!("-0x1.b20a21ccb525ep-28"), hf!("0x1.8f40ap-4")],
    [hf!("0x1.4006cfb3d8f85p-26"), hf!("0x1.bb9d1p-4")],
    [hf!("-0x1.cdb026b310c41p-26"), hf!("0x1.e7f9bp-4")],
    [hf!("-0x1.69124fdc0f16dp-26"), hf!("0x1.0a2b08p-3")],
    [hf!("-0x1.084656cdc2727p-26"), hf!("0x1.205958p-3")],
    [hf!("-0x1.376fa8b0357fdp-26"), hf!("0x1.3687cp-3")],
    [hf!("0x1.e56ae55a47b4ap-28"), hf!("0x1.4cb5e8p-3")],
    [hf!("0x1.070ff8834eeb4p-26"), hf!("0x1.62e44p-3")],
    [hf!("0x1.623516109f4fep-26"), hf!("0x1.79129p-3")],
    [hf!("-0x1.ec656b95fbdacp-29"), hf!("0x1.8f40bp-3")],
    [hf!("0x1.f0ca2e729f51p-28"), hf!("0x1.a56ed8p-3")],
    [hf!("-0x1.7d260a858354ap-26"), hf!("0x1.bb9d68p-3")],
    [hf!("0x1.e7279075503d3p-27"), hf!("0x1.d1cb9p-3")],
    [hf!("0x1.39e1a0a503873p-27"), hf!("0x1.e7f9dp-3")],
    [hf!("0x1.cd86d7b87c3d6p-26"), hf!("0x1.fe27d8p-3")],
    [hf!("0x1.060ab88de341ep-26"), hf!("0x1.0a2b24p-2")],
    [hf!("0x1.20a860d3f939p-28"), hf!("0x1.154244p-2")],
    [hf!("-0x1.dacee95fc2f1p-27"), hf!("0x1.205974p-2")],
    [hf!("0x1.45de3a86e0acap-26"), hf!("0x1.2b707p-2")],
    [hf!("0x1.c164cbfb991afp-27"), hf!("0x1.3687bp-2")],
    [hf!("0x1.d3f66b24225efp-26"), hf!("0x1.419ec4p-2")],
    [hf!("0x1.fc023efa144bap-26"), hf!("0x1.4cb5f8p-2")],
    [hf!("0x1.086a8af6f26cp-28"), hf!("0x1.57cd28p-2")],
    [hf!("-0x1.05c610ca86c39p-30"), hf!("0x1.62e43p-2")],
];

/// `(low, high)` parts of -log(r2[i]).
const ATANH_L2: [[f64; 2]; 33] = [
    [hf!("0x0p+0"), hf!("0x0p+0")],
    [hf!("-0x1.37e152a129e4ep-28"), hf!("0x1.632p-12")],
    [hf!("-0x1.3f6c916b8be9cp-26"), hf!("0x1.63p-11")],
    [hf!("0x1.20505936739d5p-26"), hf!("0x1.0a24p-10")],
    [hf!("-0x1.23e2e8cb541bap-26"), hf!("0x1.62dcp-10")],
    [hf!("-0x1.acb7983ac4f5ep-32"), hf!("0x1.bbap-10")],
    [hf!("0x1.6f7c7689c63aep-28"), hf!("0x1.0a2ap-9")],
    [hf!("0x1.f5ca695b4c58bp-30"), hf!("0x1.368cp-9")],
    [hf!("-0x1.c6c18bd953226p-27"), hf!("0x1.62e6p-9")],
    [hf!("0x1.7a516c34846bdp-26"), hf!("0x1.8f46p-9")],
    [hf!("-0x1.f3b83dd8b853p-27"), hf!("0x1.bbap-9")],
    [hf!("-0x1.c3459046e4e57p-31"), hf!("0x1.e8p-9")],
    [hf!("0x1.b5c7e34cb79f6p-38"), hf!("0x1.0a2cp-8")],
    [hf!("-0x1.2487e9af9a692p-27"), hf!("0x1.205cp-8")],
    [hf!("0x1.f21bbc4ad79cep-26"), hf!("0x1.3687p-8")],
    [hf!("-0x1.550ffc857b731p-29"), hf!("0x1.4cb7p-8")],
    [hf!("0x1.87458ec1b7b34p-27"), hf!("0x1.62e2p-8")],
    [hf!("0x1.103d4fe83ee81p-26"), hf!("0x1.7911p-8")],
    [hf!("0x1.810483d3b398cp-27"), hf!("0x1.8f44p-8")],
    [hf!("-0x1.2085cb340608ep-27"), hf!("0x1.a573p-8")],
    [hf!("0x1.12698a119c42fp-26"), hf!("0x1.bb9dp-8")],
    [hf!("-0x1.edb8c172b4c33p-26"), hf!("0x1.d1ccp-8")],
    [hf!("-0x1.8b55b87a5e238p-26"), hf!("0x1.e7fep-8")],
    [hf!("0x1.be5e17763f78ap-26"), hf!("0x1.fe2bp-8")],
    [hf!("-0x1.c2d496790073ep-30"), hf!("0x1.0a2a8p-7")],
    [hf!("0x1.6542f523abeecp-26"), hf!("0x1.1541p-7")],
    [hf!("-0x1.b7fdbe5b193f8p-26"), hf!("0x1.205ap-7")],
    [hf!("0x1.fa4d42fe30c7cp-26"), hf!("0x1.2b7p-7")],
    [hf!("0x1.0d46ad04adc86p-26"), hf!("0x1.36888p-7")],
    [hf!("-0x1.1c22d02d17c4cp-26"), hf!("0x1.419fp-7")],
    [hf!("0x1.a7d1e330dcccep-30"), hf!("0x1.4cb7p-7")],
    [hf!("0x1.187025e656ba3p-31"), hf!("0x1.57cdp-7")],
    [hf!("-0x1.532c1269e2038p-27"), hf!("0x1.62e5p-7")],
];

/// Accurate path for |x| < 1/4: odd series of atanh in double-double.
#[inline(never)]
fn atanh_zero(x: f64) -> f64 {
    const CH: [[f64; 2]; 13] = [
        [hf!("0x1.5555555555555p-2"), hf!("0x1.5555555555555p-56")],
        [hf!("0x1.999999999999ap-3"), hf!("-0x1.999999999611cp-57")],
        [hf!("0x1.2492492492492p-3"), hf!("0x1.2492490f76b25p-57")],
        [hf!("0x1.c71c71c71c71cp-4"), hf!("0x1.c71cd5c38a112p-58")],
        [hf!("0x1.745d1745d1746p-4"), hf!("-0x1.7556c4165f4cap-59")],
        [hf!("0x1.3b13b13b13b14p-4"), hf!("-0x1.b893c3b36052ep-59")],
        [hf!("0x1.1111111111105p-4"), hf!("0x1.4e1afd723ed1fp-59")],
        [hf!("0x1.e1e1e1e1e2678p-5"), hf!("-0x1.f86ea96fb1435p-59")],
        [hf!("0x1.af286bc9f90ccp-5"), hf!("0x1.1e51a6e54fde9p-60")],
        [hf!("0x1.8618618c779b6p-5"), hf!("-0x1.ab913de95c3bfp-61")],
        [hf!("0x1.642c84aa383ebp-5"), hf!("0x1.632e747641b12p-59")],
        [hf!("0x1.47ae2d205013cp-5"), hf!("-0x1.0c9617e7bcff2p-60")],
        [hf!("0x1.2f664d60473f9p-5"), hf!("0x1.3adb3e2b7f35ep-61")],
    ];
    const CL: [f64; 5] = [
        hf!("0x1.1a9a91fd692afp-5"),
        hf!("0x1.06dfbb35e7f44p-5"),
        hf!("0x1.037bed4d7588fp-5"),
        hf!("0x1.5aca6d6d720d6p-6"),
        hf!("0x1.99ea5700d53a5p-5"),
    ];
    let x2 = x * x;
    let x2l = x.mul_add(x, -x2);
    let y2 = x2 * (CL[0] + x2 * (CL[1] + x2 * (CL[2] + x2 * (CL[3] + x2 * CL[4]))));
    let (y1, y2) = polydd(x2, x2l, &CH, y2);
    let (y1, y2) = mulddd(y1, y2, x);
    let (y1, y2) = muldd_acc(x2, x2l, y1, y2);
    let (y0, y1) = fasttwosum(x, y1);
    let (mut y1, y2) = fasttwosum(y1, y2);
    let mut t = y1.to_bits();
    if t & MASK52 == 0 {
        if (y2.to_bits() ^ t) >> 63 != 0 {
            t = t.wrapping_sub(1);
        } else {
            t = t.wrapping_add(1);
        }
        y1 = f64::from_bits(t);
    }
    y0 + y1
}

/// The two hard cases left after `atanh_refine`: `(x, high, low)`.
const ATANH_DB: [[f64; 3]; 2] = [
    [
        hf!("0x1.2dbb7b1c91363p-2"),
        hf!("0x1.36f33d51c264dp-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.c493dc899e4a5p-2"),
        hf!("0x1.e611aa58ab608p-2"),
        hf!("-0x1p-56"),
    ],
];

#[inline(never)]
fn atanh_database(x: f64, f: f64) -> f64 {
    let ax = x.abs();
    let sgn = 1.0f64.copysign(x);
    for e in &ATANH_DB {
        if e[0] == ax {
            return sgn * e[1] + sgn * e[2];
        }
    }
    f
}

const LOG_T1: [f64; 17] = [
    hf!("0x1p+0"),
    hf!("0x1.ea4afap-1"),
    hf!("0x1.d5818ep-1"),
    hf!("0x1.c199bep-1"),
    hf!("0x1.ae89f98p-1"),
    hf!("0x1.9c4918p-1"),
    hf!("0x1.8ace54p-1"),
    hf!("0x1.7a1147p-1"),
    hf!("0x1.6a09e68p-1"),
    hf!("0x1.5ab07ep-1"),
    hf!("0x1.4bfdad8p-1"),
    hf!("0x1.3dea65p-1"),
    hf!("0x1.306fe08p-1"),
    hf!("0x1.2387a7p-1"),
    hf!("0x1.172b84p-1"),
    hf!("0x1.0b5587p-1"),
    hf!("0x1p-1"),
];
const LOG_T2: [f64; 16] = [
    hf!("0x1p+0"),
    hf!("0x1.fe9d968p-1"),
    hf!("0x1.fd3c228p-1"),
    hf!("0x1.fbdba38p-1"),
    hf!("0x1.fa7c18p-1"),
    hf!("0x1.f91d8p-1"),
    hf!("0x1.f7bfdbp-1"),
    hf!("0x1.f663278p-1"),
    hf!("0x1.f507658p-1"),
    hf!("0x1.f3ac948p-1"),
    hf!("0x1.f252b38p-1"),
    hf!("0x1.f0f9c2p-1"),
    hf!("0x1.efa1bfp-1"),
    hf!("0x1.ee4aaap-1"),
    hf!("0x1.ecf483p-1"),
    hf!("0x1.eb9f488p-1"),
];
const LOG_T3: [f64; 16] = [
    hf!("0x1p+0"),
    hf!("0x1.ffe9d2p-1"),
    hf!("0x1.ffd3a58p-1"),
    hf!("0x1.ffbd798p-1"),
    hf!("0x1.ffa74e8p-1"),
    hf!("0x1.ff91248p-1"),
    hf!("0x1.ff7afb8p-1"),
    hf!("0x1.ff64d38p-1"),
    hf!("0x1.ff4eac8p-1"),
    hf!("0x1.ff38868p-1"),
    hf!("0x1.ff22618p-1"),
    hf!("0x1.ff0c3dp-1"),
    hf!("0x1.fef61ap-1"),
    hf!("0x1.fedff78p-1"),
    hf!("0x1.fec9d68p-1"),
    hf!("0x1.feb3b6p-1"),
];
const LOG_T4: [f64; 16] = [
    hf!("0x1p+0"),
    hf!("0x1.fffe9dp-1"),
    hf!("0x1.fffd3ap-1"),
    hf!("0x1.fffbd78p-1"),
    hf!("0x1.fffa748p-1"),
    hf!("0x1.fff9118p-1"),
    hf!("0x1.fff7ae8p-1"),
    hf!("0x1.fff64cp-1"),
    hf!("0x1.fff4e9p-1"),
    hf!("0x1.fff386p-1"),
    hf!("0x1.fff2238p-1"),
    hf!("0x1.fff0c08p-1"),
    hf!("0x1.ffef5d8p-1"),
    hf!("0x1.ffedfa8p-1"),
    hf!("0x1.ffec98p-1"),
    hf!("0x1.ffeb35p-1"),
];

/// Triple-double -log(t1[i]), -log(t2[i]), -log(t3[i]), -log(t4[i]).
const LOG_LL: [[[f64; 3]; 17]; 4] = [
    [
        [hf!("0x0p+0"), hf!("0x0p+0"), hf!("0x0p+0")],
        [
            hf!("0x1.62e432b24p-6"),
            hf!("-0x1.745af34bb54b8p-42"),
            hf!("-0x1.17e3ec05cde7p-97"),
        ],
        [
            hf!("0x1.62e42e4a8p-5"),
            hf!("0x1.111a4eadf312p-44"),
            hf!("0x1.cff3027abb119p-93"),
        ],
        [
            hf!("0x1.0a2b233f1p-4"),
            hf!("-0x1.88ac4ec78af8p-42"),
            hf!("0x1.4fa087ca75dfdp-93"),
        ],
        [
            hf!("0x1.62e43056cp-4"),
            hf!("0x1.6bd65e8b0b7p-46"),
            hf!("-0x1.b18e160362c24p-95"),
        ],
        [
            hf!("0x1.bb9d3cbd6p-4"),
            hf!("0x1.de14aa55ec2bp-42"),
            hf!("-0x1.c6ac3f1862a6bp-94"),
        ],
        [
            hf!("0x1.0a2b244dap-3"),
            hf!("0x1.94def487fea7p-42"),
            hf!("-0x1.dead1a4581acfp-94"),
        ],
        [
            hf!("0x1.3687aa9b78p-3"),
            hf!("0x1.9cec9a50db22p-43"),
            hf!("0x1.34a70684f8e0ep-93"),
        ],
        [
            hf!("0x1.62e42fabap-3"),
            hf!("-0x1.d69047a3aebp-44"),
            hf!("-0x1.4e061f79144e2p-95"),
        ],
        [
            hf!("0x1.8f40b56d28p-3"),
            hf!("0x1.de7d755fd2e2p-42"),
            hf!("0x1.bdc7ecf001489p-94"),
        ],
        [
            hf!("0x1.bb9d3b61fp-3"),
            hf!("0x1.c14f1445b12p-46"),
            hf!("0x1.a1d78cbdc5b58p-93"),
        ],
        [
            hf!("0x1.e7f9c11f08p-3"),
            hf!("-0x1.6e3e0000dae7p-43"),
            hf!("0x1.6a4559fadde98p-94"),
        ],
        [
            hf!("0x1.0a2b242ec4p-2"),
            hf!("0x1.bb7cf852a5fe8p-42"),
            hf!("0x1.a6aef11ee43bdp-93"),
        ],
        [
            hf!("0x1.205966c764p-2"),
            hf!("0x1.ad3a5f214294p-45"),
            hf!("0x1.5cc344fa10652p-93"),
        ],
        [
            hf!("0x1.3687a98aacp-2"),
            hf!("0x1.1623671842fp-45"),
            hf!("-0x1.0b428fe1f9e43p-94"),
        ],
        [
            hf!("0x1.4cb5ec93f4p-2"),
            hf!("0x1.3d50980ea513p-42"),
            hf!("0x1.67f0ea083b1c4p-93"),
        ],
        [
            hf!("0x1.62e42fefa4p-2"),
            hf!("-0x1.8432a1b0e264p-44"),
            hf!("0x1.803f2f6af40f3p-93"),
        ],
    ],
    [
        [hf!("0x0p+0"), hf!("0x0p+0"), hf!("0x0p+0")],
        [
            hf!("0x1.62e462b4p-10"),
            hf!("0x1.061d003b97318p-42"),
            hf!("0x1.d7faee66a2e1ep-93"),
        ],
        [
            hf!("0x1.62e44c92p-9"),
            hf!("0x1.95a7bff5e239p-42"),
            hf!("-0x1.f7e788a87135p-95"),
        ],
        [
            hf!("0x1.0a2b1e33p-8"),
            hf!("0x1.2a3a1a65aa3ap-43"),
            hf!("-0x1.54599c9605442p-93"),
        ],
        [
            hf!("0x1.62e4367cp-8"),
            hf!("-0x1.4a995b6d9ddcp-45"),
            hf!("-0x1.56bb79b254f33p-100"),
        ],
        [
            hf!("0x1.bb9d449ap-8"),
            hf!("0x1.8a119c42e9bcp-42"),
            hf!("-0x1.8ecf7d8d661f1p-93"),
        ],
        [
            hf!("0x1.0a2b1f19p-7"),
            hf!("0x1.8863771bd10a8p-42"),
            hf!("0x1.e9731de7f0155p-94"),
        ],
        [
            hf!("0x1.3687ad11p-7"),
            hf!("0x1.e026a347ca1c8p-42"),
            hf!("0x1.fadc62522444dp-97"),
        ],
        [
            hf!("0x1.62e436f28p-7"),
            hf!("0x1.25b84f71b70b8p-42"),
            hf!("-0x1.fcb3f98612d27p-96"),
        ],
        [
            hf!("0x1.8f40b7b38p-7"),
            hf!("-0x1.62a0a4fd4758p-43"),
            hf!("0x1.3cb3c35d9f6a1p-93"),
        ],
        [
            hf!("0x1.bb9d3abbp-7"),
            hf!("-0x1.0ec48f94d786p-42"),
            hf!("-0x1.6b47d410e4cc7p-93"),
        ],
        [
            hf!("0x1.e7f9bb23p-7"),
            hf!("0x1.e4415cbc97ap-43"),
            hf!("-0x1.3729fdb677231p-93"),
        ],
        [
            hf!("0x1.0a2b22478p-6"),
            hf!("-0x1.cb73f4505b03p-42"),
            hf!("-0x1.1b3b3a3bc370ap-93"),
        ],
        [
            hf!("0x1.2059691e8p-6"),
            hf!("-0x1.abcc3412f264p-43"),
            hf!("-0x1.fe6e998e48673p-95"),
        ],
        [
            hf!("0x1.3687a768p-6"),
            hf!("-0x1.43901e5c97a9p-42"),
            hf!("0x1.b54cdd52a5d88p-96"),
        ],
        [
            hf!("0x1.4cb5eb5d8p-6"),
            hf!("-0x1.8f106f00f13b8p-42"),
            hf!("-0x1.8f793f5fce148p-93"),
        ],
        [
            hf!("0x1.62e432b24p-6"),
            hf!("-0x1.745af34bb54b8p-42"),
            hf!("-0x1.17e3ec05cde7p-97"),
        ],
    ],
    [
        [hf!("0x0p+0"), hf!("0x0p+0"), hf!("0x0p+0")],
        [
            hf!("0x1.62e7bp-14"),
            hf!("-0x1.868625640a68p-44"),
            hf!("-0x1.34bf0db910f65p-93"),
        ],
        [
            hf!("0x1.62e35f6p-13"),
            hf!("-0x1.2ee3d96b696ap-43"),
            hf!("0x1.a2948cd558655p-94"),
        ],
        [
            hf!("0x1.0a2b4b2p-12"),
            hf!("0x1.53edbcf1165p-47"),
            hf!("-0x1.cfc26ccf6d0e4p-97"),
        ],
        [
            hf!("0x1.62e4be1p-12"),
            hf!("0x1.783e334614p-52"),
            hf!("-0x1.04b96da30e63ap-93"),
        ],
        [
            hf!("0x1.bb9e085p-12"),
            hf!("-0x1.60785f20acb2p-43"),
            hf!("-0x1.f33369bf7dff1p-96"),
        ],
        [
            hf!("0x1.0a2b94dp-11"),
            hf!("0x1.fd4b3a273353p-42"),
            hf!("-0x1.685a35575eff1p-96"),
        ],
        [
            hf!("0x1.368810f8p-11"),
            hf!("0x1.7ded26dc813p-47"),
            hf!("-0x1.4c4d1abca79bfp-96"),
        ],
        [
            hf!("0x1.62e47878p-11"),
            hf!("0x1.7d2bee9a1f63p-42"),
            hf!("0x1.860233b7ad13p-93"),
        ],
        [
            hf!("0x1.8f40cb48p-11"),
            hf!("-0x1.af034eaf471cp-42"),
            hf!("0x1.ae748822d57b7p-94"),
        ],
        [
            hf!("0x1.bb9d094p-11"),
            hf!("-0x1.7a223013a20fp-42"),
            hf!("-0x1.1e499087075b6p-93"),
        ],
        [
            hf!("0x1.e7fa32c8p-11"),
            hf!("-0x1.b2e67b1b59bdp-43"),
            hf!("-0x1.54a41eda30fa6p-93"),
        ],
        [
            hf!("0x1.0a2b237p-10"),
            hf!("-0x1.7ad97ff4ac7ap-44"),
            hf!("0x1.f932da91371ddp-93"),
        ],
        [
            hf!("0x1.2059a338p-10"),
            hf!("-0x1.96422d90df4p-44"),
            hf!("-0x1.90800fbbf2ed3p-94"),
        ],
        [
            hf!("0x1.36879824p-10"),
            hf!("0x1.0f9054001812p-44"),
            hf!("0x1.9567e01e48f9ap-93"),
        ],
        [
            hf!("0x1.4cb602cp-10"),
            hf!("-0x1.0d709a5ec0b5p-43"),
            hf!("0x1.253dfd44635d2p-94"),
        ],
        [
            hf!("0x1.62e462b4p-10"),
            hf!("0x1.061d003b97318p-42"),
            hf!("0x1.d7faee66a2e1ep-93"),
        ],
    ],
    [
        [hf!("0x0p+0"), hf!("0x0p+0"), hf!("0x0p+0")],
        [
            hf!("0x1.63007cp-18"),
            hf!("-0x1.db0e38e5aaaap-43"),
            hf!("0x1.259a7b94815b9p-93"),
        ],
        [
            hf!("0x1.6300f6p-17"),
            hf!("0x1.2b1c75580438p-44"),
            hf!("0x1.78cabba01e3e4p-93"),
        ],
        [
            hf!("0x1.0a2115p-16"),
            hf!("-0x1.5ff223730759p-42"),
            hf!("0x1.8074feacfe49dp-95"),
        ],
        [
            hf!("0x1.62e1ecp-16"),
            hf!("-0x1.85d6f6487ce4p-45"),
            hf!("0x1.05485074b9276p-93"),
        ],
        [
            hf!("0x1.bba301p-16"),
            hf!("-0x1.af5d58a7c921p-43"),
            hf!("-0x1.30a8c0fd2ff5fp-93"),
        ],
        [
            hf!("0x1.0a32298p-15"),
            hf!("0x1.590faa0883bdp-43"),
            hf!("0x1.95e9bda999947p-93"),
        ],
        [
            hf!("0x1.3682f1p-15"),
            hf!("0x1.f0224376efaf8p-42"),
            hf!("-0x1.5843c0db50d1p-93"),
        ],
        [
            hf!("0x1.62e3d8p-15"),
            hf!("-0x1.142c13daed4ap-43"),
            hf!("0x1.c68a61183ce87p-93"),
        ],
        [
            hf!("0x1.8f44dd8p-15"),
            hf!("-0x1.aa489f399931p-43"),
            hf!("0x1.11c5c376854eap-94"),
        ],
        [
            hf!("0x1.bb9601p-15"),
            hf!("0x1.9904d8b6a3638p-42"),
            hf!("0x1.8c89554493c8fp-93"),
        ],
        [
            hf!("0x1.e7f744p-15"),
            hf!("0x1.5785ddbe7cba8p-42"),
            hf!("0x1.e7ff3cde7d70cp-94"),
        ],
        [
            hf!("0x1.0a2c53p-14"),
            hf!("-0x1.6d9e8780d0d5p-43"),
            hf!("0x1.ad9c178106693p-94"),
        ],
        [
            hf!("0x1.205d134p-14"),
            hf!("-0x1.214a2e893fccp-43"),
            hf!("0x1.548a9500c9822p-93"),
        ],
        [
            hf!("0x1.3685e28p-14"),
            hf!("0x1.e23588646103p-43"),
            hf!("0x1.2a97b26da2d88p-94"),
        ],
        [
            hf!("0x1.4cb6c18p-14"),
            hf!("0x1.2b7cfcea9e0d8p-42"),
            hf!("-0x1.5095048a6b824p-93"),
        ],
        [
            hf!("0x1.62e7bp-14"),
            hf!("-0x1.868625640a68p-44"),
            hf!("-0x1.34bf0db910f65p-93"),
        ],
    ],
];

/// log(1+x) - x tail used by every `*_refine`: double-double degree 2..4
/// (`REFINE_CH`) and double degree 5..7 (`REFINE_CL`) coefficients.
const REFINE_CH: [[f64; 2]; 3] = [
    [hf!("0x1p-1"), hf!("0x1.24b67ee516e3bp-111")],
    [hf!("-0x1p-2"), hf!("-0x1.932ce43199a8dp-110")],
    [hf!("0x1.5555555555555p-3"), hf!("0x1.55540c15cf91fp-57")],
];
const REFINE_CL: [f64; 3] = [
    hf!("-0x1p-3"),
    hf!("0x1.9999999a0754fp-4"),
    hf!("-0x1.55555555c3157p-4"),
];

/// Accurate path for |x| >= 1/4: log(zh + zl) in triple-double, where
/// `a` ~ log2(zh + zl) selects the table indices.
#[inline(never)]
fn atanh_refine(x: f64, zh: f64, zl: f64, a: f64) -> f64 {
    const CH: [[f64; 2]; 3] = REFINE_CH;
    const CL: [f64; 3] = REFINE_CL;
    const L20: f64 = hf!("0x1.62e42fefa3ap-2");
    const L21: f64 = hf!("-0x1.0ca86c3898dp-50");
    const L22: f64 = hf!("0x1.f97b57a079ap-104");

    let mut t = zh.to_bits();
    let e = (t >> 52) as i32 - 0x3ff;
    t &= MASK52;
    t |= 0x3ffu64 << 52;
    let tf = f64::from_bits(t);
    let ed = e as f64;
    let v = (a - ed + hf!("0x1.00008p+0")).to_bits();
    let i = v.wrapping_sub(0x3ffu64 << 52) >> (52 - 16);
    let i1 = (i >> 12) as usize;
    let i2 = ((i >> 8) & 0xf) as usize;
    let i3 = ((i >> 4) & 0xf) as usize;
    let i4 = (i & 0xf) as usize;
    let el2 = L22 * ed;
    let el1 = L21 * ed;
    let el0 = L20 * ed;
    let ll = &LOG_LL;
    let l0 = ll[0][i1][0] + ll[1][i2][0] + (ll[2][i3][0] + ll[3][i4][0]) + el0;
    let l1 = ll[0][i1][1] + ll[1][i2][1] + (ll[2][i3][1] + ll[3][i4][1]);
    let l2 = ll[0][i1][2] + ll[1][i2][2] + (ll[2][i3][2] + ll[3][i4][2]);
    let t12 = LOG_T1[i1] * LOG_T2[i2];
    let t34 = LOG_T3[i3] * LOG_T4[i4];
    let th = t12 * t34;
    let tl = t12.mul_add(t34, -th);
    let dh = th * tf;
    let dl = th.mul_add(tf, -dh);
    let sh = tl * tf;
    let sl = tl.mul_add(tf, -sh);
    let (xh, mut xl) = fasttwosum(dh - 1.0, dl);
    let zl_scaled = f64::from_bits(zl.to_bits().wrapping_sub(((e as i64) << 52) as u64));
    xl += th * zl_scaled;
    let (xh, xl) = adddd(xh, xl, sh, sl);
    let sl = xh * (CL[0] + xh * (CL[1] + xh * CL[2]));
    let (sh, sl) = polydd(xh, xl, &CH, sl);
    let (sh, sl) = muldd_acc(xh, xl, sh, sl);
    let (sh, sl) = adddd(sh, sl, el1, el2);
    let (sh, sl) = adddd(sh, sl, l1, l2);
    let (mut v0, v2) = fasttwosum(l0, sh);
    let (mut v1, _) = fasttwosum(v2, sl);
    let mut tb = v1.to_bits();
    if tb & MASK52 == 0 {
        // v1 a power of 2: v1 and v2 have the same sign in every such case.
        tb = tb.wrapping_add(1);
        v1 = f64::from_bits(tb);
    }
    let er = tb.wrapping_add(1) & MASK52;
    let de = ((v0.to_bits() >> 52) & 0x7ff).wrapping_sub((tb >> 52) & 0x7ff);
    let sgn = 1.0f64.copysign(x);
    v0 *= sgn;
    v1 *= sgn;
    let res = v0 + v1;
    if de > 104 || er < 3 {
        return atanh_database(x, res);
    }
    res
}

/// Correctly rounded `atanh`.
pub fn atanh(x: f64) -> f64 {
    let ax = x.abs();
    let aix = ax.to_bits();
    if aix >= 0x3ff0_0000_0000_0000 {
        if aix == 0x3ff0_0000_0000_0000 {
            // Pole: ±inf with FE_DIVBYZERO.
            return 1.0f64.copysign(x) / 0.0;
        }
        if aix > 0x7ff0_0000_0000_0000 {
            return x + x;
        }
        // Domain error: the default NaN with FE_INVALID, as sqrt(-1).
        return (-ax).sqrt();
    }

    if aix < 0x3fd0_0000_0000_0000 {
        // |x| < 1/4
        if aix < 0x3e4d_12ed_0af1_a27f {
            // atanh(x) rounds to x for |x| < 0x1.d12ed0af1a27fp-27.
            return x.mul_add(hf!("0x1p-55"), x);
        }
        const C: [f64; 9] = [
            hf!("0x1.999999999999ap-3"),
            hf!("0x1.2492492492244p-3"),
            hf!("0x1.c71c71c79715fp-4"),
            hf!("0x1.745d16f777723p-4"),
            hf!("0x1.3b13ca4174634p-4"),
            hf!("0x1.110c9724989bdp-4"),
            hf!("0x1.e2d17608a5b2ep-5"),
            hf!("0x1.a0b56308cba0bp-5"),
            hf!("0x1.fb6341208ad2ep-5"),
        ];
        let x2 = x * x;
        let dx2 = x.mul_add(x, -x2);
        let x4 = x2 * x2;
        let x3 = x2 * x;
        let x8 = x4 * x4;
        let dx3 = x2.mul_add(x, -x3) + dx2 * x;
        let p = (C[0] + x2 * C[1])
            + x4 * (C[2] + x2 * C[3])
            + x8 * ((C[4] + x2 * C[5]) + x4 * (C[6] + x2 * C[7]) + x8 * C[8]);
        let t = x2.mul_add(p, hf!("0x1.5555555555555p-56"));
        let (ph, pl) = fasttwosum(hf!("0x1.5555555555555p-2"), t);
        let (ph, mut pl) = muldd(ph, pl, x3, dx3);
        let (ph, tl) = fasttwosum(x, ph);
        pl += tl;
        let eps = x * (x4 * hf!("0x1.dp-53") + hf!("0x1p-103"));
        let lb = ph + (pl - eps);
        let ub = ph + (pl + eps);
        if lb == ub {
            return lb;
        }
        return atanh_zero(x);
    }

    // |x| >= 1/4: atanh(x) = log((1 + |x|)/(1 - |x|))/2.
    let (ph, pl) = fasttwosum(1.0, ax);
    let (qh, ql) = fasttwosub(1.0, ax);
    let iqh = 1.0 / qh;
    let th = ph * iqh;
    let tl = ph.mul_add(iqh, -th) + (pl + ph * ((-qh).mul_add(iqh, 1.0) - ql * iqh)) * iqh;

    const C: [f64; 5] = [
        hf!("-0x1p+0"),
        hf!("0x1.555555555553p+0"),
        hf!("-0x1.fffffffffffap+0"),
        hf!("0x1.99999e33a6366p+1"),
        hf!("-0x1.555559ef9525fp+2"),
    ];
    let mut t = th.to_bits();
    let e = (t >> 52) as i32 - 0x3ff;
    t &= MASK52;
    let ed = e as f64;
    let i = (t >> (52 - 5)) as usize;
    let d = (t & (u64::MAX >> 17)) as i64;
    let (c0, c1) = LOG_B[i];
    let j = t
        .wrapping_add((c0 as u64) << 33)
        .wrapping_add((c1 as i64).wrapping_mul(d >> 16) as u64)
        >> (52 - 10);
    t |= 0x3ffu64 << 52;
    let tf = f64::from_bits(t);
    let i1 = (j >> 5) as usize;
    let i2 = (j & 0x1f) as usize;
    let r = (0.5 * LOG_R1[i1]) * LOG_R2[i2];
    let dx = r.mul_add(tf, -0.5);
    let dx2 = dx * dx;
    let rx = r * tf;
    let dxl = r.mul_add(tf, -rx);
    let f = dx2 * ((C[0] + dx * C[1]) + dx2 * (C[2] + dx * C[3] + dx2 * C[4]));
    const L2H: f64 = hf!("0x1.62e42fefa3ap-2");
    const L2L: f64 = hf!("-0x1.0ca86c3898dp-50");
    let lh = (ATANH_L1[i1][1] + ATANH_L2[i2][1]) + L2H * ed;
    let (mut lh, mut ll) = fasttwosum(lh, rx - 0.5);
    ll += L2L * ed + (ATANH_L1[i1][0] + ATANH_L2[i2][0]) + dxl + 0.5 * tl / th;
    ll += f;
    let sgn = 1.0f64.copysign(x);
    lh *= sgn;
    ll *= sgn;
    let eps = 38e-24 + dx2 * hf!("0x1p-49");
    let lb = lh + (ll - eps);
    let ub = lh + (ll + eps);
    if lb == ub {
        return lb;
    }
    let (th, tl) = fasttwosum(th, tl);
    atanh_refine(x, th, tl, hf!("0x1.71547652b82fep+1") * (lh + ll).abs())
}

// --- asinh / acosh (CORE-MATH src/binary64/{asinh,acosh}) -------------------
//
// asinh.c and acosh.c each carry their own variants of the double-double
// helpers; the variants below are kept distinct so each kernel performs
// exactly the upstream operation sequence.

/// asinh.c `muldd_acc`: the product normalised with the `z = x - s; e = z + y`
/// FastTwoSum variant.
#[inline(always)]
fn muldd_acc_alt(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let ahlh = ch * xl;
    let alhh = cl * xh;
    let ahhh = ch * xh;
    let mut ahhl = ch.mul_add(xh, -ahhh);
    ahhl += alhh + ahlh;
    let s = ahhh + ahhl;
    (s, (ahhh - s) + ahhl)
}

/// asinh.c / acosh.c `mulddd`: double-double times double, normalised.
#[inline(always)]
fn mulddd_norm(xh: f64, xl: f64, ch: f64) -> (f64, f64) {
    let ahlh = ch * xl;
    let ahhh = ch * xh;
    let mut ahhl = ch.mul_add(xh, -ahhh);
    ahhl += ahlh;
    let s = ahhh + ahhl;
    (s, (ahhh - s) + ahhl)
}

/// asinh.c `polydd`.
#[inline(always)]
fn polydd_alt(xh: f64, xl: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let mut ch = c[i][0] + l;
    let mut cl = ((c[i][0] - ch) + l) + c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = muldd_acc_alt(xh, xl, ch, cl);
        let th = ch + c[i][0];
        let tl = (c[i][0] - th) + ch;
        ch = th;
        cl += tl + c[i][1];
    }
    (ch, cl)
}

/// acosh.c `adddd`: TwoSum(xh, ch) + (xl + cl).
#[inline(always)]
fn adddd_twosum(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let s = xh + ch;
    let a_prime = s - ch;
    let b_prime = s - a_prime;
    let t = (xh - a_prime) + (ch - b_prime);
    (s, t + (xl + cl))
}

/// Table indices `(i1, i2)` for the 2^(-i1/32) * 2^(-i2/1024) range reduction
/// of a mantissa `m` (exponent field cleared): a piecewise-linear log2(1+m).
#[inline(always)]
fn log_table_index(m: u64) -> (usize, usize) {
    let i = (m >> (52 - 5)) as usize;
    let d = (m & (u64::MAX >> 17)) as i64;
    let (c0, c1) = LOG_B[i];
    let j = m
        .wrapping_add((c0 as u64) << 33)
        .wrapping_add((c1 as i64).wrapping_mul(d >> 16) as u64)
        >> (52 - 10);
    ((j >> 5) as usize, (j & 0x1f) as usize)
}

/// `(low, high)` parts of -log(r1[i]) (asinh/acosh scaling).
const LOG2_L1: [[f64; 2]; 33] = [
    [hf!("0x0p+0"), hf!("0x0p+0")],
    [hf!("-0x1.269e2038315b3p-46"), hf!("0x1.62e4eacd4p-6")],
    [hf!("-0x1.3f2558bddfc47p-45"), hf!("0x1.62e3ce7218p-5")],
    [hf!("0x1.07ea13c34efb5p-45"), hf!("0x1.0a2ab6d3ecp-4")],
    [hf!("0x1.8f3e77084d3bap-44"), hf!("0x1.62e4a86d8cp-4")],
    [hf!("-0x1.8d92a005f1a7ep-46"), hf!("0x1.bb9db7062cp-4")],
    [hf!("0x1.58239e799bfe5p-44"), hf!("0x1.0a2b1a22ccp-3")],
    [hf!("-0x1.a93fcf5f593b7p-44"), hf!("0x1.3687f0a298p-3")],
    [hf!("-0x1.db4cac32fd2b5p-46"), hf!("0x1.62e4116b64p-3")],
    [hf!("-0x1.0e65a92ee0f3bp-46"), hf!("0x1.8f409e4df6p-3")],
    [hf!("-0x1.8261383d475f1p-44"), hf!("0x1.bb9d15001cp-3")],
    [hf!("-0x1.359886207513bp-44"), hf!("0x1.e7f9a8c94p-3")],
    [hf!("0x1.811f87496ceb7p-44"), hf!("0x1.0a2b052ddbp-2")],
    [hf!("0x1.4991ec6cb435cp-44"), hf!("0x1.205955ef73p-2")],
    [hf!("-0x1.4581abfeb8927p-44"), hf!("0x1.3687bd9121p-2")],
    [hf!("0x1.cab48f6942703p-44"), hf!("0x1.4cb5e8f2b5p-2")],
    [hf!("-0x1.df2c452fde132p-47"), hf!("0x1.62e4420e2p-2")],
    [hf!("0x1.6109f4fdb74bdp-45"), hf!("0x1.791292c46ap-2")],
    [hf!("-0x1.6b95fbdac7696p-44"), hf!("0x1.8f40af84e7p-2")],
    [hf!("0x1.7394fa880cbdap-46"), hf!("0x1.a56ed8f865p-2")],
    [hf!("-0x1.50b06a94eccabp-46"), hf!("0x1.bb9d6505b4p-2")],
    [hf!("-0x1.be2abf0b38989p-44"), hf!("0x1.d1cb91e728p-2")],
    [hf!("-0x1.7d6bf1e34da04p-44"), hf!("0x1.e7f9d139e2p-2")],
    [hf!("-0x1.423c1e14de6edp-44"), hf!("0x1.fe27db9b0ep-2")],
    [hf!("0x1.c46f1a0efbbc2p-44"), hf!("0x1.0a2b25060a8p-1")],
    [hf!("0x1.834fe4e3e6018p-45"), hf!("0x1.154244482ap-1")],
    [hf!("0x1.6a03d0f02b65p-46"), hf!("0x1.20597312988p-1")],
    [hf!("0x1.d437056526f3p-44"), hf!("0x1.2b707145dep-1")],
    [hf!("-0x1.a0233728405c5p-45"), hf!("0x1.3687b0e0b28p-1")],
    [hf!("-0x1.4dbdda10d2bf1p-45"), hf!("0x1.419ec5d3f68p-1")],
    [hf!("0x1.f7d0a25d154f2p-44"), hf!("0x1.4cb5f9fc02p-1")],
    [hf!("0x1.15ede4d803b18p-44"), hf!("0x1.57cd28421a8p-1")],
    [hf!("0x1.ef35793c7673p-45"), hf!("0x1.62e42fefa38p-1")],
];

/// `(low, high)` parts of -log(r2[i]) (asinh/acosh scaling).
const LOG2_L2: [[f64; 2]; 33] = [
    [hf!("0x0p+0"), hf!("0x0p+0")],
    [hf!("0x1.5abdac3638e99p-44"), hf!("0x1.631ec81ep-11")],
    [hf!("-0x1.16b8be9bbe239p-45"), hf!("0x1.62fd8127p-10")],
    [hf!("-0x1.364c6315542ebp-44"), hf!("0x1.0a2520508p-9")],
    [hf!("0x1.734abe459c9p-45"), hf!("0x1.62dadc1dp-9")],
    [hf!("0x1.0cf8a761431bfp-44"), hf!("0x1.bb9ff94dp-9")],
    [hf!("0x1.da2718eb78708p-45"), hf!("0x1.0a2a2def8p-8")],
    [hf!("0x1.34ada62c59b93p-44"), hf!("0x1.368c0fae4p-8")],
    [hf!("0x1.d09ab376682d4p-44"), hf!("0x1.62e58e4f8p-8")],
    [hf!("-0x1.3cb7b94329211p-45"), hf!("0x1.8f46bd28cp-8")],
    [hf!("-0x1.eec5c297c41dp-45"), hf!("0x1.bb9f8312p-8")],
    [hf!("-0x1.6411b9395d15p-44"), hf!("0x1.e7fff8f3p-8")],
    [hf!("-0x1.1c0e59a43053cp-44"), hf!("0x1.0a2c0006ep-7")],
    [hf!("0x1.6506596e077b6p-46"), hf!("0x1.205bdb6fp-7")],
    [hf!("0x1.e256bce6faa27p-44"), hf!("0x1.36877c86ep-7")],
    [hf!("0x1.bd42467b0c8d1p-51"), hf!("0x1.4cb6f5578p-7")],
    [hf!("-0x1.c4f92132ff0fp-44"), hf!("0x1.62e230e8cp-7")],
    [hf!("-0x1.80be08bfab39p-44"), hf!("0x1.7911440f6p-7")],
    [hf!("-0x1.f0b1319ceb1f7p-44"), hf!("0x1.8f443020ap-7")],
    [hf!("0x1.a65fcfb8de99bp-45"), hf!("0x1.a572dbef4p-7")],
    [hf!("0x1.4233885d3779cp-46"), hf!("0x1.bb9d449a6p-7")],
    [hf!("0x1.f46a59e646edbp-44"), hf!("0x1.d1cb8491cp-7")],
    [hf!("-0x1.c3d2f11c11446p-44"), hf!("0x1.e7fd9d2aap-7")],
    [hf!("0x1.7763f78a1e0ccp-45"), hf!("0x1.fe2b6f978p-7")],
    [hf!("0x1.b4c37fc60c043p-44"), hf!("0x1.0a2a7c7a5p-6")],
    [hf!("-0x1.5b8a822859be3p-46"), hf!("0x1.15412ca86p-6")],
    [hf!("-0x1.f2d8c9fc064p-44"), hf!("0x1.2059c9005p-6")],
    [hf!("-0x1.e80e79c20378dp-44"), hf!("0x1.2b703f49bp-6")],
    [hf!("0x1.68256e4329bdbp-44"), hf!("0x1.3688a1a8dp-6")],
    [hf!("0x1.7e9741da248c3p-44"), hf!("0x1.419edc7bap-6")],
    [hf!("0x1.e330dccce602bp-45"), hf!("0x1.4cb7034fap-6")],
    [hf!("0x1.2f32b5d18eefbp-49"), hf!("0x1.57cd01187p-6")],
    [hf!("-0x1.269e2038315b3p-46"), hf!("0x1.62e4eacd4p-6")],
];

/// log(1+dx) - dx on |dx| < 2^-11.3 (asinh/acosh).
const LOG2_C: [f64; 5] = [
    hf!("-0x1p-1"),
    hf!("0x1.555555555553p-2"),
    hf!("-0x1.fffffffffffap-3"),
    hf!("0x1.99999e33a6366p-3"),
    hf!("-0x1.555559ef9525fp-3"),
];
const LOG2_L2H: f64 = hf!("0x1.62e42fefa38p-1");
const LOG2_L2L: f64 = hf!("0x1.ef35793c7673p-45");
const LOG2_L20: f64 = hf!("0x1.62e42fefa38p-2");
const LOG2_L21: f64 = hf!("0x1.ef35793c768p-46");
const LOG2_L22: f64 = hf!("-0x1.9ff0342542fc3p-91");

/// Fast-path log reduction shared by asinh and acosh: for a mantissa `m`
/// (exponent field cleared) returns `(i1, i2, dx, f)` with `dx = r*t - 1`
/// and `f ~ log(1+dx) - dx`.
#[inline(always)]
fn log2_reduce(m: u64) -> (usize, usize, f64, f64) {
    let (i1, i2) = log_table_index(m);
    let tf = f64::from_bits(m | (0x3ffu64 << 52));
    let r = LOG_R1[i1] * LOG_R2[i2];
    let dx = r.mul_add(tf, -1.0);
    let dx2 = dx * dx;
    let c = &LOG2_C;
    let f = dx2 * ((c[0] + dx * c[1]) + dx2 * ((c[2] + dx * c[3]) + dx2 * c[4]));
    (i1, i2, dx, f)
}

/// Double-double helper set one kernel's refinement runs with.
type PolyDd = fn(f64, f64, &[[f64; 2]], f64) -> (f64, f64);
type DdOp = fn(f64, f64, f64, f64) -> (f64, f64);

/// Triple-double log(zh + zl)/2 refinement shared by asinh and acosh, where
/// `e` is the exponent `zh` is scaled by and `a` ~ log2(zh + zl). Returns the
/// unscaled `(v0, v1, v2)`.
#[inline(always)]
fn log2_refine_core(
    zh: f64,
    zl: f64,
    e: i32,
    a: f64,
    polydd_fn: PolyDd,
    muldd_acc_fn: DdOp,
    adddd_fn: DdOp,
) -> (f64, f64, f64) {
    let tf = f64::from_bits((zh.to_bits() & MASK52) | (0x3ffu64 << 52));
    let ed = e as f64;
    let v = (a - ed + hf!("0x1.00008p+0")).to_bits();
    let i = v.wrapping_sub(0x3ffu64 << 52) >> (52 - 16);
    let i1 = ((i >> 12) & 0x1f) as usize;
    let i2 = ((i >> 8) & 0xf) as usize;
    let i3 = ((i >> 4) & 0xf) as usize;
    let i4 = (i & 0xf) as usize;
    let el2 = LOG2_L22 * ed;
    let el1 = LOG2_L21 * ed;
    let el0 = LOG2_L20 * ed;
    let ll = &LOG_LL;
    let mut l0 = ll[0][i1][0] + ll[1][i2][0] + (ll[2][i3][0] + ll[3][i4][0]);
    let l1 = ll[0][i1][1] + ll[1][i2][1] + (ll[2][i3][1] + ll[3][i4][1]);
    let l2 = ll[0][i1][2] + ll[1][i2][2] + (ll[2][i3][2] + ll[3][i4][2]);
    l0 += el0;
    let t12 = LOG_T1[i1] * LOG_T2[i2];
    let t34 = LOG_T3[i3] * LOG_T4[i4];
    let th = t12 * t34;
    let tl = t12.mul_add(t34, -th);
    let dh = th * tf;
    let dl = th.mul_add(tf, -dh);
    let sh = tl * tf;
    let sl = tl.mul_add(tf, -sh);
    let (xh, mut xl) = fasttwosum(dh - 1.0, dl);
    if zl != 0.0 {
        let zl_scaled = f64::from_bits(zl.to_bits().wrapping_sub(((e as i64) << 52) as u64));
        xl += th * zl_scaled;
    }
    let (xh, xl) = adddd_fn(xh, xl, sh, sl);
    let cl = &REFINE_CL;
    let sl = xh * (cl[0] + xh * (cl[1] + xh * cl[2]));
    let (sh, sl) = polydd_fn(xh, xl, &REFINE_CH, sl);
    let (sh, sl) = muldd_acc_fn(xh, xl, sh, sl);
    let (sh, sl) = adddd_fn(sh, sl, el1, el2);
    let (sh, sl) = adddd_fn(sh, sl, l1, l2);
    let (v0, v2) = fasttwosum(l0, sh);
    let (v1, v2) = fasttwosum(v2, sl);
    (v0, v1, v2)
}

/// Nudge `v1` off an exact power of two towards `v2`, where the final
/// rounding could otherwise land on a tie. Returns `(v1, bits of v1)`.
#[inline(always)]
fn nudge_power_of_two(v1: f64, v2: f64) -> (f64, u64) {
    let mut t = v1.to_bits();
    if t & MASK52 == 0 {
        if (v2.to_bits() ^ t) >> 63 != 0 {
            t = t.wrapping_sub(1);
        } else {
            t = t.wrapping_add(1);
        }
        return (f64::from_bits(t), t);
    }
    (v1, t)
}

/// asinh accurate path for |x| < 1/4: odd series in double-double.
#[inline(never)]
fn asinh_zero(x: f64, x2h: f64, x2l: f64) -> f64 {
    const CH: [[f64; 2]; 12] = [
        [hf!("-0x1.5555555555555p-3"), hf!("-0x1.5555555555555p-57")],
        [hf!("0x1.3333333333333p-4"), hf!("0x1.99999999949dfp-59")],
        [hf!("-0x1.6db6db6db6db7p-5"), hf!("0x1.2492496091b0cp-60")],
        [hf!("0x1.f1c71c71c71c7p-6"), hf!("0x1.c71a35cfa0671p-62")],
        [hf!("-0x1.6e8ba2e8ba2e9p-6"), hf!("0x1.17f937248cf81p-60")],
        [hf!("0x1.1c4ec4ec4ec4fp-6"), hf!("-0x1.74e3c1dfd4c3dp-60")],
        [hf!("-0x1.c999999999977p-7"), hf!("-0x1.38e7a467ecc55p-61")],
        [hf!("0x1.7a87878786c7ep-7"), hf!("0x1.a83c7bace55ebp-61")],
        [hf!("-0x1.3fde50d764083p-7"), hf!("-0x1.d024df7fa0542p-61")],
        [hf!("0x1.12ef3ceae4d12p-7"), hf!("-0x1.ba9c13deb261fp-61")],
        [hf!("-0x1.df3bd104aa267p-8"), hf!("-0x1.546da9bc5b32ap-62")],
        [hf!("0x1.a685fc5de7a04p-8"), hf!("0x1.40d284a1d67f9p-62")],
    ];
    const CL: [f64; 5] = [
        hf!("-0x1.7828d553ec8p-8"),
        hf!("0x1.51712f7bee368p-8"),
        hf!("-0x1.2e6d98527bcc6p-8"),
        hf!("0x1.0095da47b392cp-8"),
        hf!("-0x1.3b92d6368192cp-9"),
    ];
    let y2 = x2h * (CL[0] + x2h * (CL[1] + x2h * (CL[2] + x2h * (CL[3] + x2h * CL[4]))));
    let (y1, y2) = polydd_alt(x2h, x2l, &CH, y2);
    let (y1, y2) = muldd_acc_alt(y1, y2, x2h, x2l);
    let (y1, y2) = mulddd_norm(y1, y2, x);
    let (y0, y1) = fasttwosum(x, y1);
    let (y1, y2) = fasttwosum(y1, y2);
    let (y1, _) = nudge_power_of_two(y1, y2);
    y0 + y1
}

/// Inputs where the asinh refinement cannot decide: `(|x|, high, low)`.
const ASINH_DB: [[f64; 3]; 35] = [
    [
        hf!("0x1.00f9476450863p-2"),
        hf!("0x1.fcb35067f343cp-3"),
        hf!("0x1p-57"),
    ],
    [
        hf!("0x1.1f0a79315b287p-2"),
        hf!("0x1.1b68aae88febap-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.2b9618ff7acb7p-2"),
        hf!("0x1.27781d9aa4e25p-2"),
        hf!("-0x1p-56"),
    ],
    [
        hf!("0x1.389ef683f3aa7p-2"),
        hf!("0x1.33f52db6df1afp-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.3b07e0c779ddap-2"),
        hf!("0x1.364303e1ad8f6p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.48441df33b6d3p-2"),
        hf!("0x1.42e385800f0a4p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.687bd068c1c1ep-2"),
        hf!("0x1.616cc75d49226p-2"),
        hf!("-0x1p-56"),
    ],
    [
        hf!("0x1.8740c4453a056p-2"),
        hf!("0x1.7e4f2ad132a1dp-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.891acda11167ep-2"),
        hf!("0x1.8009d924a3ffdp-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.bafc3479fc9ccp-2"),
        hf!("0x1.ae3773250e7d2p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.c59869f17b483p-2"),
        hf!("0x1.b7efa91915c95p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.c8be879787986p-2"),
        hf!("0x1.bad0485e0fe0ap-2"),
        hf!("-0x1p-56"),
    ],
    [
        hf!("0x1.e73b46abb01e1p-2"),
        hf!("0x1.d68039861ab53p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.ed6236da268bp-2"),
        hf!("0x1.dc0cb8f638126p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.f399ebafc1951p-2"),
        hf!("0x1.e1a4f519fab77p-2"),
        hf!("-0x1p-56"),
    ],
    [
        hf!("0x1.f70975ab0d471p-2"),
        hf!("0x1.e4bae8bcd6ea6p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.fbdd4a37760b7p-2"),
        hf!("0x1.e90f16eb88c09p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.fee72efb4bfddp-2"),
        hf!("0x1.ebc791a88bed8p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.02339d6bdb741p-1"),
        hf!("0x1.f0b2264e34555p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.09e7c831b1a23p-1"),
        hf!("0x1.fe694c3c89138p-2"),
        hf!("0x1p-56"),
    ],
    [
        hf!("0x1.16d32c862fc3bp-1"),
        hf!("0x1.0a9c9334066dbp-1"),
        hf!("-0x1p-55"),
    ],
    [
        hf!("0x1.857954132083dp-1"),
        hf!("0x1.67425fe575c88p-1"),
        hf!("-0x1p-55"),
    ],
    [
        hf!("0x1.8a5c3b60f7e11p-1"),
        hf!("0x1.6b23ad4415a17p-1"),
        hf!("-0x1p-55"),
    ],
    [
        hf!("0x1.9740eb419dd04p-1"),
        hf!("0x1.754ab7535d47dp-1"),
        hf!("0x1p-55"),
    ],
    [
        hf!("0x1.a16d9cc06011ap-1"),
        hf!("0x1.7d3755d851062p-1"),
        hf!("-0x1p-55"),
    ],
    [
        hf!("0x1.bb635be2213d1p-1"),
        hf!("0x1.91167cae3cfa9p-1"),
        hf!("0x1p-55"),
    ],
    [
        hf!("0x1.d4b21ebf542fp-1"),
        hf!("0x1.a3fc7e4dd47d1p-1"),
        hf!("-0x1p-55"),
    ],
    [
        hf!("0x1.7b8516ffd2406p+0"),
        hf!("0x1.2f5d3b178914ap+0"),
        hf!("0x1p-54"),
    ],
    [
        hf!("0x1.9295b9116e2e2p+0"),
        hf!("0x1.3bffa8863976p+0"),
        hf!("0x1p-54"),
    ],
    [
        hf!("0x1.fedc65e32714p+0"),
        hf!("0x1.710f91e844f9bp+0"),
        hf!("0x1p-54"),
    ],
    [
        hf!("0x1.57e377b3f0b4bp+1"),
        hf!("0x1.b6e2c73f41415p+0"),
        hf!("0x1p-54"),
    ],
    [
        hf!("0x1.6056b06a21918p+3"),
        hf!("0x1.8c0a26d055288p+1"),
        hf!("0x1p-53"),
    ],
    [
        hf!("0x1.843e1b5e5979cp+4"),
        hf!("0x1.f0f978201eb84p+1"),
        hf!("0x1p-53"),
    ],
    [
        hf!("0x1.fee8f69c4cd25p+10"),
        hf!("0x1.0a19aebb51e9p+3"),
        hf!("-0x1p-51"),
    ],
    [
        hf!("0x1.0fbc6c02b1c9p+24"),
        hf!("0x1.16369cd53bb69p+4"),
        hf!("0x1p-50"),
    ],
];

/// asinh accurate path: log(zh + zl) where zh + zl ~ |x| + sqrt(x^2 + 1).
#[inline(never)]
fn asinh_refine(x: f64, zh: f64, zl: f64, a: f64) -> f64 {
    let e = (zh.to_bits() >> 52) as i32 - 0x3ff + i32::from(zl == 0.0);
    let (v0, v1, v2) = log2_refine_core(zh, zl, e, a, polydd_alt, muldd_acc_alt, adddd);
    let (v0, v1) = fasttwosum(v0, v1);
    let (v1, v2) = fasttwosum(v1, v2);
    let s2 = 2.0f64.copysign(x);
    let v0 = v0 * s2;
    let (v1, t) = nudge_power_of_two(v1 * s2, v2 * s2);
    let er = t.wrapping_add(41) & MASK52;
    let de = ((v0.to_bits() >> 52) & 0x7ff).wrapping_sub((t >> 52) & 0x7ff);
    let res = v0 + v1;
    if de > 99 || er < 80 {
        let ax = x.abs();
        let sgn = 1.0f64.copysign(x);
        for d in &ASINH_DB {
            if d[0] == ax {
                return sgn * d[1] + sgn * d[2];
            }
        }
    }
    res
}

/// Correctly rounded `asinh`.
pub fn asinh(x: f64) -> f64 {
    let ax = x.abs();
    let u = ax.to_bits();
    if u < 0x3fbb_0000_0000_0000 {
        // |x| < 0x1.bp-4
        if u < 0x3e57_1374_4912_3ef7 {
            // |x| < 0x1.7137449123ef7p-26: asinh(x) rounds to x. x = ±0 is
            // returned as is since fma(-2^-60, -0, -0) is +0.
            if u == 0 {
                return x;
            }
            return hf!("-0x1p-60").mul_add(x, x);
        }
        let x2h = x * x;
        let x2l = x.mul_add(x, -x2h);
        let x3h = x2h * x;
        let sl = if u < 0x3f93_0000_0000_0000 {
            if u < 0x3f30_0000_0000_0000 {
                if u < 0x3e5a_0000_0000_0000 {
                    x3h * hf!("-0x1.5555555555555p-3")
                } else {
                    x3h * (hf!("-0x1.5555555555555p-3") + x2h * hf!("0x1.3333327c57c6p-4"))
                }
            } else {
                const CL: [f64; 4] = [
                    hf!("-0x1.5555555555555p-3"),
                    hf!("0x1.333333332f2ffp-4"),
                    hf!("-0x1.6db6d9a665159p-5"),
                    hf!("0x1.f186866d775fp-6"),
                ];
                x3h * (CL[0] + x2h * (CL[1] + x2h * (CL[2] + x2h * CL[3])))
            }
        } else {
            const CL: [f64; 7] = [
                hf!("-0x1.5555555555555p-3"),
                hf!("0x1.333333333331p-4"),
                hf!("-0x1.6db6db6da466cp-5"),
                hf!("0x1.f1c71c2ea7be4p-6"),
                hf!("-0x1.6e8b651b09d72p-6"),
                hf!("0x1.1c309fc0e69c2p-6"),
                hf!("-0x1.bab7833c1ep-7"),
            ];
            let c1 = CL[1] + x2h * CL[2];
            let c3 = CL[3] + x2h * CL[4];
            let c5 = CL[5] + x2h * CL[6];
            let x4 = x2h * x2h;
            x3h * (CL[0] + x2h * (c1 + x4 * (c3 + x4 * c5)))
        };
        let eps = hf!("0x1.79p-53") * x3h;
        let lb = x + (sl - eps);
        let ub = x + (sl + eps);
        if lb == ub {
            return lb;
        }
        return asinh_zero(x, x2h, x2l);
    }

    // |x| >= 0x1.bp-4: asinh(|x|) = log(|x| + sqrt(x^2 + 1)) = log(ah + al).
    let mut x2h = 0.0;
    let mut x2l = 0.0;
    let ah;
    let mut al;
    let mut off = 0x3ff;
    if u < 0x4190_0000_0000_0000 {
        // |x| < 2^26
        x2h = x * x;
        x2l = x.mul_add(x, -x2h);
        let (th, mut tl) = if u < 0x3ff0_0000_0000_0000 {
            fasttwosum(1.0, x2h)
        } else {
            fasttwosum(x2h, 1.0)
        };
        tl += x2l;
        let sh = th.sqrt();
        let rs = 0.5 / th;
        al = (tl - sh.mul_add(sh, -th)) * (rs * sh);
        let (s, t) = fasttwosum(sh, ax);
        ah = s;
        al += t;
    } else if u < 0x4330_0000_0000_0000 {
        // |x| < 2^52
        ah = 2.0 * ax;
        al = 0.5 / ax;
    } else {
        if u >= 0x7ff0_0000_0000_0000 {
            return x + x; // ±inf or NaN
        }
        off = 0x3fe;
        ah = ax;
        al = 0.0;
    }

    let t = ah.to_bits();
    let e = (t >> 52) as i32 - off;
    let ed = e as f64;
    let (i1, i2, dx, f) = log2_reduce(t & MASK52);
    let lh = LOG2_L2H * ed + (LOG2_L1[i1][1] + LOG2_L2[i2][1]);
    let mut ll = LOG2_L2L * ed + LOG2_L1[i1][0] + LOG2_L2[i2][0] + al / ah + f;
    ll += dx;
    let sgn = 1.0f64.copysign(x);
    let lh = lh * sgn;
    let ll = ll * sgn;
    let eps = 1.63e-19;
    let lb = lh + (ll - eps);
    let ub = lh + (ll + eps);
    if lb == ub {
        return lb;
    }
    if ax < hf!("0x1p-2") {
        return asinh_zero(x, x2h, x2l);
    }
    asinh_refine(x, ah, al, hf!("0x1.71547652b82fep+0") * lb.abs())
}

/// acosh accurate path for 1 < x < 0x1.1e83e425aee63p+0, with `z = x - 1`
/// and `sh + sl ~ sqrt(2z)`.
#[inline(never)]
fn acosh_one(z: f64, sh: f64, sl: f64) -> f64 {
    const CH: [[f64; 2]; 10] = [
        [hf!("-0x1.5555555555555p-4"), hf!("-0x1.5555555554af1p-58")],
        [hf!("0x1.3333333333333p-6"), hf!("0x1.9999998933f0ep-61")],
        [hf!("-0x1.6db6db6db6db7p-8"), hf!("0x1.24929b16ec6b7p-63")],
        [hf!("0x1.f1c71c71c71c7p-10"), hf!("0x1.c56d45e265e2cp-66")],
        [hf!("-0x1.6e8ba2e8ba2e9p-11"), hf!("0x1.6d50ce7188d3dp-65")],
        [hf!("0x1.1c4ec4ec4ec43p-12"), hf!("0x1.c6791d1cf399ap-66")],
        [hf!("-0x1.c99999999914fp-14"), hf!("0x1.ee0d9408a2e2ap-68")],
        [hf!("0x1.7a878787648e2p-15"), hf!("-0x1.1cea281e08012p-69")],
        [hf!("-0x1.3fde50d0cb4b9p-16"), hf!("0x1.0335101403d9dp-72")],
        [hf!("0x1.12ef3bf8a0a74p-17"), hf!("0x1.f9c6b51787043p-80")],
    ];
    const CL: [f64; 6] = [
        hf!("-0x1.df3b9d1296ea9p-19"),
        hf!("0x1.a681d7d2298ebp-20"),
        hf!("-0x1.77ead7b1ca449p-21"),
        hf!("0x1.4edd2ddb3721fp-22"),
        hf!("-0x1.1bf173531ee23p-23"),
        hf!("0x1.613229230e255p-25"),
    ];
    let y2 = z * (CL[0] + z * (CL[1] + z * (CL[2] + z * (CL[3] + z * (CL[4] + z * CL[5])))));
    let (y1, y2) = polydd(z, 0.0, &CH, y2);
    let (y1, y2) = mulddd_norm(y1, y2, z);
    let (y0, mut y1) = fasttwosum(1.0, y1);
    y1 += y2;
    let (y0, y1) = muldd_acc(y0, y1, sh, sl);
    y0 + y1
}

/// Inputs where the acosh refinement cannot decide: `(x, high, low)`.
const ACOSH_DB: [[f64; 3]; 7] = [
    [
        hf!("0x1.5bff041b260fep+0"),
        hf!("0x1.a6031cd5f93bap-1"),
        hf!("0x1p-55"),
    ],
    [
        hf!("0x1.9efdca62b700ap+0"),
        hf!("0x1.104b648f113a1p+0"),
        hf!("0x1p-54"),
    ],
    [
        hf!("0x1.a5bf3acfde4b2p+0"),
        hf!("0x1.1585720f35cd9p+0"),
        hf!("-0x1p-54"),
    ],
    [
        hf!("0x1.45ea160ddc71fp+7"),
        hf!("0x1.725811dcf6782p+2"),
        hf!("0x1p-52"),
    ],
    [
        hf!("0x1.2a686e4b567cep+10"),
        hf!("0x1.f1c928e7f1e65p+2"),
        hf!("0x1p-52"),
    ],
    [
        hf!("0x1.cb62eec26bd78p+15"),
        hf!("0x1.759a2ad4c4d56p+3"),
        hf!("0x1p-51"),
    ],
    [
        hf!("0x1.3bf8009648dcp+16"),
        hf!("0x1.7fce95ea5c653p+3"),
        hf!("-0x1p-53"),
    ],
];

/// acosh accurate path; `a` ~ acosh(x)/log(2).
#[inline(never)]
fn acosh_refine(x: f64, a: f64) -> f64 {
    let ix = x.to_bits();
    let (zh, zl, huge) = if ix < 0x4190_0000_0000_0000 {
        // x < 2^26
        let x2h = x * x;
        let x2l = x.mul_add(x, -x2h);
        let (wh, wl) = fasttwosum(x2h - 1.0, x2l);
        let sh = wh.sqrt();
        let sl = (wl - sh.mul_add(sh, -wh)) / (2.0 * sh);
        let (zh, mut zl) = fasttwosum(x, sh);
        zl += sl;
        let (zh, zl) = fasttwosum(zh, zl);
        (zh, zl, 0)
    } else if ix < 0x4330_0000_0000_0000 {
        (2.0 * x, -0.5 / x, 0)
    } else {
        // zh = x with e + 1 below, so that 2x cannot overflow.
        (x, 0.0, 1)
    };
    let e = (zh.to_bits() >> 52) as i32 - 0x3ff + huge;
    let (v0, v1, v2) = log2_refine_core(zh, zl, e, a, polydd, muldd_acc, adddd_twosum);
    let v0 = v0 * 2.0;
    let (v1, t) = nudge_power_of_two(v1 * 2.0, v2 * 2.0);
    let er = t.wrapping_add(7) & MASK52;
    let de = ((v0.to_bits() >> 52) & 0x7ff).wrapping_sub((t >> 52) & 0x7ff);
    let res = v0 + v1;
    if de > 102 || er < 15 {
        for d in &ACOSH_DB {
            if d[0] == x {
                return d[1] + d[2];
            }
        }
    }
    res
}

/// Correctly rounded `acosh`.
pub fn acosh(x: f64) -> f64 {
    let ix = x.to_bits();
    if ix >= 0x7ff0_0000_0000_0000 {
        // x < 0 (sign bit set), +inf or NaN.
        let aix = ix << 1;
        if ix == 0x7ff0_0000_0000_0000 || aix > (0x7ffu64 << 53) {
            return x + x;
        }
        // Domain error: the default NaN with FE_INVALID (runtime sqrt of a
        // negative number, as upstream's 0.0/0.0).
        return (-1.0 - x.abs()).sqrt();
    }
    if ix <= 0x3ff0_0000_0000_0000 {
        // 0 <= x <= 1
        if ix == 0x3ff0_0000_0000_0000 {
            return 0.0;
        }
        return (-1.0 - x).sqrt();
    }
    // x > 1
    let g;
    let eps;
    let mut off = 0x3fe;
    let mut t = ix;
    if ix < 0x3ff1_e83e_425a_ee63 {
        // 1 < x < 0x1.1e83e425aee63p+0: acosh(1+z) = sqrt(2z) * (1 + series).
        let z = x - 1.0;
        let iz = (-0.25) / z;
        let zt = 2.0 * z;
        let sh = zt.sqrt();
        let sl = sh.mul_add(sh, -zt) * (sh * iz);
        const CL: [f64; 9] = [
            hf!("-0x1.5555555555555p-4"),
            hf!("0x1.3333333332f95p-6"),
            hf!("-0x1.6db6db6d5534cp-8"),
            hf!("0x1.f1c71c1e04356p-10"),
            hf!("-0x1.6e8b8e3e40d58p-11"),
            hf!("0x1.1c4ba825ac4fep-12"),
            hf!("-0x1.c9045534e6d9ep-14"),
            hf!("0x1.71fedae26a76bp-15"),
            hf!("-0x1.f1f4f8cc65342p-17"),
        ];
        let z2 = z * z;
        let z4 = z2 * z2;
        let p = CL[0]
            + z * (((CL[1] + z * CL[2]) + z2 * (CL[3] + z * CL[4]))
                + z4 * ((CL[5] + z * CL[6]) + z2 * (CL[7] + z * CL[8])));
        let ds = (sh * z).mul_add(p, sl);
        let eps = ds * hf!("0x1.00p-50") - hf!("0x1p-104") * sh;
        let lb = sh + (ds - eps);
        let ub = sh + (ds + eps);
        if lb == ub {
            return lb;
        }
        return acosh_one(z, sh, sl);
    } else if ix < 0x405b_f000_0000_0000 {
        // x < 111.75: log(x + sqrt(x^2 - 1)) via the double-double sum.
        off = 0x3ff;
        let x2h = x * x;
        let wh = x2h - 1.0;
        let wl = x.mul_add(x, -x2h);
        let sh = wh.sqrt();
        let ish = 0.5 / wh;
        let sl = (wl - sh.mul_add(sh, -wh)) * (sh * ish);
        let (th, mut tl) = fasttwosum(x, sh);
        tl += sl;
        t = th.to_bits();
        g = tl / th;
        eps = hf!("0x1.81p-63");
    } else if ix < 0x4087_1000_0000_0000 {
        // 111.75 <= x < 738: log(2x) + g(1/x^2).
        const CL: [f64; 4] = [
            hf!("0x1.5c4b6148816e2p-66"),
            hf!("-0x1.000000000005cp-2"),
            hf!("-0x1.7fffffebf3e6cp-4"),
            hf!("-0x1.aab6691f2bae7p-5"),
        ];
        let z = 1.0 / (x * x);
        g = CL[0] + z * (CL[1] + z * (CL[2] + z * CL[3]));
        eps = hf!("0x1.c3p-63");
    } else if ix < 0x40e0_1000_0000_0000 {
        // 738 <= x < 32896
        const CL: [f64; 3] = [
            hf!("-0x1.7f77c8429c6c6p-67"),
            hf!("-0x1.ffffffffff214p-3"),
            hf!("-0x1.8000268641bfep-4"),
        ];
        let z = 1.0 / (x * x);
        g = CL[0] + z * (CL[1] + z * CL[2]);
        eps = hf!("0x1.9ap-63");
    } else if ix < 0x41ea_0000_0000_0000 {
        // 32896 <= x < 0x1.ap+31
        const CL: [f64; 2] = [hf!("0x1.7a0ed2effdd1p-67"), hf!("-0x1.000000017d048p-2")];
        let z = 1.0 / (x * x);
        g = CL[0] + z * CL[1];
        eps = hf!("0x1.99p-63");
    } else {
        g = 0.0;
        eps = hf!("0x1.b2p-63");
    }
    let e = (t >> 52) as i32 - off;
    let ed = e as f64;
    let (i1, i2, dx, f) = log2_reduce(t & MASK52);
    let lh = (LOG2_L1[i1][1] + LOG2_L2[i2][1]) + LOG2_L2H * ed;
    let t1 = (LOG2_L2L * ed) + (LOG2_L1[i1][0] + LOG2_L2[i2][0]);
    let t2 = f + t1;
    let t3 = g + t2;
    let ll = dx + t3;
    let lb = lh + (ll - eps);
    let ub = lh + (ll + eps);
    if lb == ub {
        return lb;
    }
    acosh_refine(x, hf!("0x1.71547652b82fep+0") * lb)
}

// --- erf (CORE-MATH src/binary64/erf/erf.c) ---------------------------------

/// TwoSum: `hi + lo = a + b` exactly, no magnitude precondition.
#[inline(always)]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let hi = a + b;
    let aa = hi - b;
    let bb = hi - aa;
    (hi, (a - aa) + (b - bb))
}

/// Exact product: `hi + lo = a * b`.
#[inline(always)]
fn a_mul(a: f64, b: f64) -> (f64, f64) {
    let hi = a * b;
    (hi, a.mul_add(b, -hi))
}

/// Double-double 2/sqrt(pi).
const ERF_CH: f64 = hf!("0x1.20dd750429b6dp+0");
const ERF_CL: f64 = hf!("0x1.1ae3a914fed8p-56");

/// Fast erf(z) for 0 <= z <= 0x1.7afb48dc96626p+2 as `(h, l, err)`, with
/// |(h + l)/erf(z) - 1| < err.
#[inline(always)]
fn erf_fast(z: f64) -> (f64, f64, f64) {
    if z < 0.0625 {
        // Odd minimax polynomial on [0, 1/16], double-double degrees 1 and 3.
        const C0: [f64; 8] = [
            hf!("0x1.20dd750429b6dp+0"),
            hf!("0x1.1ae3a7862d9c4p-56"),
            hf!("-0x1.812746b0379e7p-2"),
            hf!("0x1.f1a64d72722a2p-57"),
            hf!("0x1.ce2f21a042b7fp-4"),
            hf!("-0x1.b82ce31189904p-6"),
            hf!("0x1.565bbf8a0fe0bp-8"),
            hf!("-0x1.bf9f8d2c202e4p-11"),
        ];
        let (z2h, z2l) = a_mul(z, z);
        let z4 = z2h * z2h;
        let c9 = C0[7].mul_add(z2h, C0[6]);
        let c5 = C0[5].mul_add(z2h, C0[4]);
        let c5 = c9.mul_add(z4, c5);
        let (th, tl) = a_mul(z2h, c5);
        let (h, mut l) = fasttwosum(C0[2], th);
        l += tl + C0[3];
        let h_copy = h;
        let (th, mut tl) = a_mul(z2h, h);
        tl += z2h.mul_add(l, C0[1]);
        let (h, mut l) = fasttwosum(C0[0], th);
        l += z2l.mul_add(h_copy, tl);
        let (h, tl) = a_mul(h, z);
        let l = l.mul_add(z, tl);
        return (h, l, hf!("0x1.78p-69"));
    }
    // i/16 <= z < (i+1)/16; z - 1/32 - v/16 is exact.
    let v = (16.0 * z).floor();
    let i = (16.0 * z) as usize;
    let z = (z - 0.03125) - 0.0625 * v;
    let c = &ERF_C[i - 1];
    let z2 = z * z;
    let z4 = z2 * z2;
    let c9 = c[12].mul_add(z, c[11]);
    let mut c7 = c[10].mul_add(z, c[9]);
    let c5 = c[8].mul_add(z, c[7]);
    let (c3h, mut c3l) = fasttwosum(c[5], z * c[6]);
    c7 = c9.mul_add(z2, c7);
    let (c3h, tl) = fasttwosum(c3h, c5 * z2);
    c3l += tl;
    let (c3h, tl) = fasttwosum(c3h, c7 * z4);
    c3l += tl;
    let (th, tl) = a_mul(z, c3h);
    let (c2h, mut c2l) = fasttwosum(c[4], th);
    c2l += z.mul_add(c3l, tl);
    let (th, tl) = a_mul(z, c2h);
    let (h, mut l) = fasttwosum(c[2], th);
    l += tl + z.mul_add(c2l, c[3]);
    let (th, tl) = a_mul(z, h);
    let tl = z.mul_add(l, tl);
    let (h, mut l) = fasttwosum(c[0], th);
    l += tl + c[1];
    (h, l, hf!("0x1.11p-69"))
}

/// Accurate erf(z) for 2^-61 <= z < 1/8 as a double-double.
#[inline(never)]
fn erf_accurate_tiny(z: f64) -> (f64, f64) {
    let exc = &ERF_TINY_EXCEPTIONS;
    let (mut i, mut j) = (0, exc.len());
    while i + 1 < j {
        let k = (i + j) / 2;
        if exc[k][0] <= z {
            i = k;
        } else {
            j = k;
        }
    }
    if z == exc[i][0] {
        return (exc[i][1], exc[i][2]);
    }
    // Odd polynomial: double-double degrees 1..7, double degrees 9..21.
    const P: [f64; 15] = [
        hf!("0x1.20dd750429b6dp+0"),
        hf!("0x1.1ae3a914fed8p-56"),
        hf!("-0x1.812746b0379e7p-2"),
        hf!("0x1.ee12e49ca96bap-57"),
        hf!("0x1.ce2f21a042be2p-4"),
        hf!("-0x1.2871bc0a0a0dp-58"),
        hf!("-0x1.b82ce31288b51p-6"),
        hf!("0x1.1003accf1355cp-61"),
        hf!("0x1.565bcd0e6a53fp-8"),
        hf!("-0x1.c02db40040cc3p-11"),
        hf!("0x1.f9a326fa3cf5p-14"),
        hf!("-0x1.f4d25e3c73ce9p-17"),
        hf!("0x1.b9eb332b31646p-20"),
        hf!("-0x1.64a4bd5eca4d7p-23"),
        hf!("0x1.c0acc2502e94ep-25"),
    ];
    let z2 = z * z;
    let mut h = P[21 / 2 + 4];
    for a in [19usize, 17, 15, 13] {
        h = h.mul_add(z2, P[a / 2 + 4]);
    }
    let mut l = 0.0f64;
    for a in [11usize, 9] {
        // (h + l) *= z^2, then += P(degree a).
        let (th, tl) = a_mul(h, z);
        let tl = l.mul_add(z, tl);
        let (hh, ll) = a_mul(th, z);
        l = tl.mul_add(z, ll);
        let (hh, tl) = fasttwosum(P[a / 2 + 4], hh);
        h = hh;
        l += tl;
    }
    for a in [7usize, 5, 3, 1] {
        let (th, tl) = a_mul(h, z);
        let tl = l.mul_add(z, tl);
        let (hh, ll) = a_mul(th, z);
        l = tl.mul_add(z, ll);
        let (hh, tl) = fasttwosum(P[a - 1], hh);
        h = hh;
        l += P[a] + tl;
    }
    let (h, tl) = a_mul(h, z);
    (h, l.mul_add(z, tl))
}

/// Accurate erf(z) for 2^-61 <= z <= 0x1.7afb48dc96626p+2 as a double-double.
#[inline(never)]
fn erf_accurate(z: f64) -> (f64, f64) {
    const EXCEPTIONS: [[f64; 3]; 5] = [
        [
            hf!("0x1.bc466342a2296p-1"),
            hf!("0x1.8f7ab15eb5babp-1"),
            hf!("-0x1.fffffffffffffp-55"),
        ],
        [
            hf!("0x1.589bbd3ae5489p+0"),
            hf!("0x1.e2d7b84ebf6dbp-1"),
            hf!("0x1.fffffffffffffp-55"),
        ],
        [
            hf!("0x1.f9a4a209ca0e4p+0"),
            hf!("0x1.fd542cdc70993p-1"),
            hf!("-0x1.f86f37645446ap-108"),
        ],
        [
            hf!("0x1.6c196b0b4ae04p+1"),
            hf!("0x1.fff8760068eddp-1"),
            hf!("-0x1.6f6f53a83af6bp-111"),
        ],
        [
            hf!("0x1.fd5d9d8c9ef66p-1"),
            hf!("0x1.ae5d17eb4f408p-1"),
            hf!("0x1.03fa708a553b3p-105"),
        ],
    ];
    for e in &EXCEPTIONS {
        if z == e[0] {
            return (e[1], e[2]);
        }
    }
    if z < 0.125 {
        return erf_accurate_tiny(z);
    }
    let v = (8.0 * z).floor();
    let i = (8.0 * z) as usize;
    let z = (z - 0.0625) - 0.125 * v;
    let p = &ERF_C2[i - 1];
    let mut h = p[26];
    for j in (11..=17).rev() {
        h = h.mul_add(z, p[8 + j]);
    }
    let mut l = 0.0f64;
    for j in (8..=10).rev() {
        let (th, tl) = a_mul(h, z);
        let tl = l.mul_add(z, tl);
        let (hh, ll) = two_sum(p[8 + j], th);
        h = hh;
        l = ll + tl;
    }
    for j in (0..=7).rev() {
        let (th, tl) = a_mul(h, z);
        let tl = l.mul_add(z, tl);
        let (hh, ll) = two_sum(p[2 * j], th);
        h = hh;
        l = ll + (p[2 * j + 1] + tl);
    }
    (h, l)
}

/// Correctly rounded `erf`.
pub fn erf(x: f64) -> f64 {
    let z = x.abs();
    let ux = z.to_bits();
    if ux > 0x4017_afb4_8dc9_6626 {
        // |x| > 0x1.7afb48dc96626p+2: erf(x) rounds to ±1.
        let os = 1.0f64.copysign(x);
        if ux > 0x7ff0_0000_0000_0000 {
            return x + x;
        }
        if ux == 0x7ff0_0000_0000_0000 {
            return os;
        }
        return os - hf!("0x1p-54") * os;
    }
    if z < hf!("0x1p-61") {
        // erf(x) ~ 2/sqrt(pi) x; x = -0 must keep its sign.
        if x == 0.0 {
            return x;
        }
        let y = ERF_CH * x;
        // Scale by 2^106 to leave the subnormal range for the residual.
        let sx = x * hf!("0x1p106");
        let (h, l) = a_mul(ERF_CH, sx);
        let mut l = ERF_CL.mul_add(sx, l);
        l += h - y * hf!("0x1p106");
        return l.mul_add(hf!("0x1p-106"), y);
    }
    let (h, l, err) = erf_fast(z);
    let sign = x.to_bits() & (1u64 << 63);
    let u = f64::from_bits(h.to_bits() ^ sign);
    let v = f64::from_bits(l.to_bits() ^ sign);
    let left = u + err.mul_add(-u, v);
    let right = u + err.mul_add(u, v);
    if left == right {
        return left;
    }
    let (h, l) = erf_accurate(z);
    if x >= 0.0 { h + l } else { (-h) + (-l) }
}

// --- erfc (CORE-MATH src/binary64/erfc/erfc.c) -------------------------------
//
// erfc.c also clears a spurious FE_UNDERFLOW raised inside its asymptotic
// fast path; that only affects the flag state, never a returned value, and is
// not reproduced here.

/// `a * (bh + bl)` as a double-double (pow.c `s_mul`).
#[inline(always)]
fn s_mul(a: f64, bh: f64, bl: f64) -> (f64, f64) {
    let (hi, lo) = a_mul(a, bh);
    (hi, a.mul_add(bl, lo))
}

/// `(ah + al) * (bh + bl) - al*bl` (pow.c `d_mul`).
#[inline(always)]
fn d_mul(ah: f64, al: f64, bh: f64, bl: f64) -> (f64, f64) {
    let (hi, lo) = a_mul(ah, bh);
    let lo = ah.mul_add(bl, lo);
    (hi, al.mul_add(bh, lo))
}

/// `a + (bh + bl)` assuming |a| >= |bh| (pow.c `fast_sum`).
#[inline(always)]
fn fast_sum(a: f64, bh: f64, bl: f64) -> (f64, f64) {
    let (hi, lo) = fasttwosum(a, bh);
    (hi, lo + bl)
}

/// exp(zh + zl) for |z| < 0.000130273 (pow.c `q_1`).
#[inline(always)]
fn exp_q1(zh: f64, zl: f64) -> (f64, f64) {
    const Q: [f64; 5] = [
        hf!("0x1p0"),
        hf!("0x1p0"),
        hf!("0x1p-1"),
        hf!("0x1.5555555995d37p-3"),
        hf!("0x1.55555558489dcp-5"),
    ];
    let z = zh + zl;
    let q = Q[4].mul_add(zh, Q[3]);
    let q = q.mul_add(z, Q[2]);
    let (hi, lo) = fasttwosum(Q[1], q * z);
    let (hi, lo) = d_mul(zh, zl, hi, lo);
    fast_sum(Q[0], hi, lo)
}

/// exp(xh + xl) with relative error < 2^-74.139 (pow.c `exp_1`).
#[inline(always)]
fn exp_1(xh: f64, xl: f64) -> (f64, f64) {
    const INVLOG2: f64 = hf!("0x1.71547652b82fep+12");
    const LOG2H: f64 = hf!("0x1.62e42fefa39efp-13");
    const LOG2L: f64 = hf!("0x1.abc9e3b39803fp-68");
    let k = (xh * INVLOG2).round_ties_even();
    let (kh, kl) = s_mul(k, LOG2H, LOG2L);
    let (yh, mut yl) = fasttwosum(xh - kh, xl);
    yl -= kl;
    let kk = k as i64;
    let m = (kk >> 12) + 0x3ff;
    let i2 = ((kk >> 6) & 0x3f) as usize;
    let i1 = (kk & 0x3f) as usize;
    let (hi, lo) = d_mul(EXP_T2[i1][0], EXP_T2[i1][1], EXP_T1[i2][0], EXP_T1[i2][1]);
    let (qh, ql) = exp_q1(yh, yl);
    let (hi, lo) = d_mul(hi, lo, qh, ql);
    let d = f64::from_bits((m as u64) << 52);
    (hi * d, lo * d)
}

/// `2^e * (h + l)` ~ exp(xh + xl) for -742 <= xh + xl <= -2.92, to about
/// 104 bits. Returns `(h, l, e)`.
fn exp_accurate(xh: f64, xl: f64) -> (f64, f64, i32) {
    const INVLOG2: f64 = hf!("0x1.71547652b82fep+0");
    const LOG2H: f64 = hf!("0x1.62e42fefa39efp-1");
    const LOG2L: f64 = hf!("0x1.abc9e3b398p-56");
    const LOG2TINY: f64 = hf!("0x1.f97b57a079a19p-103");
    let e2 = &ERFC_E2;
    let k = (xh * INVLOG2).round_ties_even() as i32;
    let kd = -(k as f64);
    let yh = kd.mul_add(LOG2H, xh);
    let (th, tl) = two_sum(kd * LOG2L, xl);
    let (yh, yl) = fasttwosum(yh, th);
    let yl = kd.mul_add(LOG2TINY, yl + tl);
    let mut h = e2[19 + 8];
    for i in (16..=18).rev() {
        h = h.mul_add(yh, e2[i + 8]);
    }
    let (th, tl) = a_mul(h, yh);
    let tl = h.mul_add(yl, tl);
    let (mut h, mut l) = fasttwosum(e2[15 + 8], th);
    l += tl;
    for i in (8..=14).rev() {
        let (th, tl) = a_mul(h, yh);
        let tl = h.mul_add(yl, tl);
        let tl = l.mul_add(yh, tl);
        let (hh, ll) = fasttwosum(e2[i + 8], th);
        h = hh;
        l = ll + tl;
    }
    for i in (0..=7).rev() {
        let (th, tl) = a_mul(h, yh);
        let tl = h.mul_add(yl, tl);
        let tl = l.mul_add(yh, tl);
        let (hh, ll) = fasttwosum(e2[2 * i], th);
        h = hh;
        l = ll + (tl + e2[2 * i + 1]);
    }
    (h, l, k)
}

/// Fast erfc(x) for 0x1.713786d9c7c09p+1 < x < 0x1.b39dc41e48bfdp+4 via
/// exp(-x^2) p(1/x); returns `(h, l, absolute error bound)`.
#[inline(always)]
fn erfc_asympt_fast(x: f64) -> (f64, f64, f64) {
    if x >= hf!("0x1.9db1bb14e15cap+4") {
        // erfc(x) < 2^-970: leave it to the accurate path.
        return (0.0, 0.0, 1.0);
    }
    let (uh, ul) = a_mul(x, x);
    let (eh, el) = exp_1(-uh, -ul);
    let yh = 1.0 / x;
    let yl = yh * (-x).mul_add(yh, 1.0);
    const THRESHOLD: [f64; 6] = [
        hf!("0x1.d5p-4"),
        hf!("0x1.59da6ca291ba6p-3"),
        hf!("0x1.bcp-3"),
        hf!("0x1.0cp-2"),
        hf!("0x1.38p-2"),
        hf!("0x1.63p-2"),
    ];
    let mut i = 0;
    while i < THRESHOLD.len() - 1 && yh > THRESHOLD[i] {
        i += 1;
    }
    let p = &ERFC_T[i];
    let (uh, ul) = a_mul(yh, yh);
    let ul = (2.0 * yh).mul_add(yl, ul);
    let mut zh = p[12];
    zh = zh.mul_add(uh, p[11]);
    zh = zh.mul_add(uh, p[10]);
    let (h, l) = s_mul(zh, uh, ul);
    let (mut zh, mut zl) = fasttwosum(p[9], h);
    zl += l;
    for j in [15usize, 13, 11, 9, 7, 5, 3] {
        let (h, l) = d_mul(zh, zl, uh, ul);
        let (hh, ll) = fasttwosum(p[j.div_ceil(2)], h);
        zh = hh;
        zl = ll + l;
    }
    let (h, l) = d_mul(zh, zl, uh, ul);
    let (zh, mut zl) = fasttwosum(p[0], h);
    zl += l + p[1];
    let (uh, ul) = d_mul(zh, zl, yh, yl);
    let (h, l) = d_mul(uh, ul, eh, el);
    let err = if h >= hf!("0x1.151b9a3fdd5c9p-955") {
        hf!("0x1.d9p-68") * h
    } else {
        hf!("0x1p-1022")
    };
    (h, l, err)
}

/// Fast erfc(x) for -0x1.7744f8f74e94bp+2 < x < 0x1.b39dc41e48bfdp+4 as
/// `(h, l, absolute error bound)`.
#[inline(always)]
fn erfc_fast(x: f64) -> (f64, f64, f64) {
    if x < 0.0 {
        // erfc(x) = 1 + erf(-x)
        let (h, l, err) = erf_fast(-x);
        let err = err * h;
        let (h, t) = fasttwosum(1.0, h);
        return (h, t + l, err + hf!("0x1.4p-102"));
    }
    if x <= hf!("0x1.713786d9c7c09p+1") {
        let (h, l, err) = erf_fast(x);
        let err = err * h;
        let (h, t) = fasttwosum(1.0, -h);
        let l = t - l;
        if x >= hf!("0x1.e861fbb24c00ap-2") {
            return (h, l, err);
        }
        return (h, l, err + hf!("0x1.4p-104"));
    }
    erfc_asympt_fast(x)
}

/// Accurate erfc(x) for 0x1.b59ffb450828cp+0 < x < 0x1.b39dc41e48bfdp+4.
#[inline(never)]
fn erfc_asympt_accurate(x: f64) -> f64 {
    for e in &ERFC_ASYMPT_EXCEPTIONS {
        if x == e[0] {
            return e[1] + e[2];
        }
    }
    if x == hf!("0x1.a8f7bfbd15495p+4") {
        // Subnormal hard case: 0x1.99ef5883f656cp-1024 - 2^-1076.
        return f64::from_bits(1).mul_add(-0.25, f64::from_bits(0x0006_67bd_620f_d95b));
    }
    let (uh, ul) = a_mul(x, x);
    let (eh, el, e) = exp_accurate(-uh, -ul);
    let yh = 1.0 / x;
    let yl = yh * (-x).mul_add(yh, 1.0);
    const THRESHOLD: [f64; 10] = [
        hf!("0x1.45p-4"),
        hf!("0x1.e0p-4"),
        hf!("0x1.3fp-3"),
        hf!("0x1.95p-3"),
        hf!("0x1.f5p-3"),
        hf!("0x1.31p-2"),
        hf!("0x1.71p-2"),
        hf!("0x1.bcp-2"),
        hf!("0x1.0bp-1"),
        hf!("0x1.3p-1"),
    ];
    let mut i = 0;
    while i < THRESHOLD.len() - 1 && yh > THRESHOLD[i] {
        i += 1;
    }
    let p = &ERFC_TACC[i];
    let (uh, ul) = a_mul(yh, yh);
    let ul = (2.0 * yh).mul_add(yl, ul);
    // p has degree 29 + 2i; its leading coefficient is p[14 + 6 + i].
    let mut zh = p[14 + 6 + i];
    let mut zl = 0.0f64;
    let mut j = 27 + 2 * i;
    while j >= 13 {
        let (h, l) = a_mul(zh, uh);
        let l = zh.mul_add(ul, l);
        let l = zl.mul_add(uh, l);
        let (hh, ll) = two_sum(p[(j - 1) / 2 + 6], h);
        zh = hh;
        zl = ll + l;
        j -= 2;
    }
    for j in [11usize, 9, 7, 5, 3, 1] {
        let (h, l) = a_mul(zh, uh);
        let l = zh.mul_add(ul, l);
        let l = zl.mul_add(uh, l);
        let (hh, ll) = two_sum(p[j - 1], h);
        zh = hh;
        zl = ll + (l + p[j]);
    }
    let (uh, ul) = a_mul(zh, yh);
    let ul = zh.mul_add(yl, ul);
    let ul = zl.mul_add(yh, ul);
    let (uh, ul) = fasttwosum(uh, ul);
    let (h, l) = a_mul(uh, eh);
    let l = uh.mul_add(el, l);
    let l = ul.mul_add(eh, l);
    let mut res = libm::scalbn(h + l, e);
    if res < hf!("0x1p-1022") {
        // Subnormal result: round h + l at the scaled precision directly.
        let mut corr = h - libm::scalbn(res, -e);
        corr += l;
        res += libm::scalbn(corr, e);
    }
    res
}

#[inline(never)]
fn erfc_accurate(x: f64) -> f64 {
    if x < 0.0 {
        for e in &ERFC_NEG_EXCEPTIONS {
            if x == e[0] {
                return e[1] + e[2];
            }
        }
        let (h, l) = erf_accurate(-x);
        let (h, t) = fasttwosum(1.0, h);
        return h + (t + l);
    }
    if x <= hf!("0x1.b59ffb450828cp+0") {
        // erfc(x) >= 2^-6
        for e in &ERFC_POS_EXCEPTIONS {
            if x == e[0] {
                return e[1] + e[2];
            }
        }
        let (h, l) = erf_accurate(x);
        let (h, t) = fasttwosum(1.0, -h);
        return h + (t - l);
    }
    erfc_asympt_accurate(x)
}

/// Correctly rounded `erfc`.
pub fn erfc(x: f64) -> f64 {
    let t = x.to_bits();
    let at = t & 0x7fff_ffff_ffff_ffff;
    if t >= 0x8000_0000_0000_0000 {
        // x = -NaN or x <= 0 (excluding +0)
        if t >= 0xc017_744f_8f74_e94b {
            // NaN or x <= -0x1.7744f8f74e94bp+2: erfc(x) rounds to 2.
            if t >= 0xfff0_0000_0000_0000 {
                if t == 0xfff0_0000_0000_0000 {
                    return 2.0;
                }
                return x + x;
            }
            return 2.0 - hf!("0x1p-54");
        }
        if hf!("-0x1.c5bf891b4ef6ap-54") <= x {
            return (-x).mul_add(hf!("0x1p-54"), 1.0);
        }
    } else {
        // x = +NaN or x >= 0 (excluding -0)
        if at >= 0x403b_39dc_41e4_8bfd {
            // NaN or x >= 0x1.b39dc41e48bfdp+4: erfc(x) < 2^-1075.
            if at >= 0x7ff0_0000_0000_0000 {
                if at == 0x7ff0_0000_0000_0000 {
                    return 0.0;
                }
                return x + x;
            }
            return f64::from_bits(1) * 0.25;
        }
        if x <= hf!("0x1.c5bf891b4ef6ap-55") {
            return (-x).mul_add(hf!("0x1p-54"), 1.0);
        }
    }
    let (h, l, err) = erfc_fast(x);
    let left = h + (l - err);
    let right = h + (l + err);
    if left == right {
        return left;
    }
    erfc_accurate(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hf_parses_exact_literals() {
        assert_eq!(hf!("0x1p+0"), 1.0);
        assert_eq!(hf!("-0x1.8p+1"), -3.0);
        assert_eq!(hf!("0x0p+0").to_bits(), 0);
        assert_eq!(
            hf!("0x1.5555555555555p-2"),
            f64::from_bits(0x3fd5_5555_5555_5555)
        );
        assert_eq!(
            hf!("0x1.62e42fefa3ap-2"),
            f64::from_bits(0x3fd6_2e42_fefa_3a00)
        );
        assert_eq!(
            hf!("0x1.56bb79b254f33p-100"),
            f64::from_bits(0x39b5_6bb7_9b25_4f33)
        );
    }

    /// Deterministic corpus shared with the C program that produced the pinned
    /// hashes: xorshift64*, inputs built from integer bit patterns so C and
    /// Rust generate identical values. Class 0: `±2^[lo,hi) * [1,2)`; class 1:
    /// uniform in (-1, 1); class 2: `1 - u*2^-20`.
    struct Corpus(u64);

    impl Corpus {
        fn new() -> Self {
            Self(0x9e37_79b9_7f4a_7c15)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn sample(&mut self, class: usize, lo: i32, hi: i32) -> f64 {
            let r = self.next_u64();
            match class {
                0 => {
                    let e = (1023 + lo + ((r >> 53) % (hi - lo) as u64) as i32) as u64;
                    f64::from_bits((r << 63) | (e << 52) | ((r >> 1) & MASK52))
                }
                1 => (r >> 11) as f64 * hf!("0x1p-53") * 2.0 - 1.0,
                _ => 1.0 - (r >> 11) as f64 * hf!("0x1p-73"),
            }
        }
    }

    /// FNV-1a over the result bits of `f` on the 1M-input corpus.
    fn corpus_hash(f: impl Fn(f64) -> f64, lo: i32, hi: i32) -> u64 {
        let mut c = Corpus::new();
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for i in 0..1_000_000 {
            let x = c.sample(i % 3, lo, hi);
            h = (h ^ f(x).to_bits()).wrapping_mul(0x100_0000_01b3);
        }
        assert_eq!(
            c.0, 0x5b5c_7615_1d8a_4788,
            "corpus generator drifted from the C original"
        );
        h
    }

    #[test]
    fn atanh_matches_glibc_2_43_on_corpus() {
        // Pinned from glibc 2.43's atanh (this CORE-MATH code), whose results
        // were checked correctly rounded against mpmath. Not a live host
        // comparison because older glibc (the build workers') is not correctly
        // rounded.
        assert_eq!(corpus_hash(atanh, -60, 0), 0x4e4e_3cc8_68bc_d38c);
    }

    #[test]
    fn atanh_hard_and_special_cases() {
        // (input, glibc 2.43 result): the cut-offs and the cases the upstream
        // comments single out (rounding-test failures, refine-path database).
        for (x, want) in [
            (0x3e4d_12ed_0af1_a27f, 0x3e4d_12ed_0af1_a280),
            (0x3fd2_dbb7_b1c9_1363, 0x3fd3_6f33_d51c_264d),
            (0xbfd2_dbb7_b1c9_1363, 0xbfd3_6f33_d51c_264d),
            (0xbfdc_493d_c899_e4a5, 0xbfde_611a_a58a_b608),
            (0x3fd1_10e9_6a6c_2d96, 0x3fd1_7d1e_8a63_711f),
            (0x3fee_bf0b_fefa_727d, 0x3fff_4dc9_45da_98a8),
            (0x3f62_f67d_96be_6eaf, 0x3f62_f67f_cefb_af65),
            (0x3f5c_c709_2205_cfaf, 0x3f5c_c70b_1285_7107),
            (0x3fd0_0000_0000_0000, 0x3fd0_58ae_fa81_1452),
            (0x3fe0_0000_0000_0000, 0x3fe1_93ea_7aad_030b),
            (0x3fef_ffff_ffff_ffff, 0x4032_b708_8723_20e2),
            (0x3fef_ffff_ffff_ff00, 0x402f_e280_4e87_b344),
            (0x3ff0_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0xbff0_0000_0000_0000, 0xfff0_0000_0000_0000),
            (0x4000_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
        ] {
            let got = atanh(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "atanh({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(atanh(f64::NAN).is_nan());
        assert_eq!(atanh(f64::INFINITY).to_bits(), 0xfff8_0000_0000_0000);
    }

    #[test]
    fn asinh_matches_glibc_2_43_on_corpus() {
        assert_eq!(corpus_hash(asinh, -30, 70), 0x6678_0a49_ce1d_22d5);
    }

    #[test]
    fn acosh_matches_glibc_2_43_on_corpus() {
        // Inputs below 1 are folded to 1 + |x| so most land in the domain.
        let map = |x: f64| {
            let a = x.abs();
            if a >= 1.0 { a } else { 1.0 + a }
        };
        assert_eq!(
            corpus_hash(|x| acosh(map(x)), -30, 70),
            0xf070_9603_79c1_a916
        );
    }

    #[test]
    fn asinh_hard_and_special_cases() {
        // (input, glibc 2.43 result): branch cut-offs, database entries and
        // the upstream-documented rounding-test failures.
        for (x, want) in [
            (0x3fd0_0f94_7645_0863u64, 0x3fcf_cb35_067f_343cu64),
            (0xbfd0_0f94_7645_0863, 0xbfcf_cb35_067f_343c),
            (0x4170_fbc6_c02b_1c90, 0x4031_6369_cd53_bb69),
            (0xc09f_ee8f_69c4_cd25, 0xc020_a19a_ebb5_1e90),
            (0x3e57_1374_4912_3ef7, 0x3e57_1374_4912_3ef6),
            (0x3e57_1374_4912_3ef6, 0x3e57_1374_4912_3ef6),
            (0x3fb0_19bc_f56d_16f7, 0x3fb0_1706_93c3_c51b),
            (0x5d3e_ece8_f780_2fb0, 0x4074_5beb_97c2_8a38),
            (0x4330_0000_0000_0000, 0x4042_5e4f_7b27_37fa),
            (0x4190_0000_0000_0000, 0x4032_b708_8723_20e2),
            (0x7fef_ffff_ffff_ffff, 0x4086_33ce_8fb9_f87e),
            (0x3fbb_0000_0000_0000, 0x3fba_f33f_d027_faa7),
            (0x3ffd_4b21_ebf5_42f0, 0x3ff5_d85b_ea38_3b41),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xfff0_0000_0000_0000),
        ] {
            let got = asinh(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "asinh({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(asinh(f64::NAN).is_nan());
    }

    #[test]
    fn acosh_hard_and_special_cases() {
        for (x, want) in [
            (0x3ff5_bff0_41b2_60feu64, 0x3fea_6031_cd5f_93bau64),
            (0x40f3_bf80_0964_8dc0, 0x4027_fce9_5ea5_c653),
            (0x4092_a686_e4b5_67ce, 0x401f_1c92_8e7f_1e65),
            (0x4073_bf80_0964_8dc0, 0x4019_cb8f_1645_b3d1),
            (0x3ff0_0000_0000_0001, 0x3e56_a09e_667f_3bcc),
            (0x3ff1_e83e_425a_ee62, 0x3fde_f248_83d6_bb51),
            (0x3ff1_e83e_425a_ee63, 0x3fde_f248_83d6_bb59),
            (0x3ff0_0a80_0422_847a, 0x3fb2_5391_da7f_5aff),
            (0x405b_f000_0000_0000, 0x4015_a337_7f67_b77e),
            (0x4087_1000_0000_0000, 0x401d_3038_810e_918e),
            (0x40e0_1000_0000_0000, 0x4026_3041_ffa2_68fa),
            (0x41ea_0000_0000_0000, 0x4036_aa8d_3c78_f60b),
            (0x4330_0000_0000_0000, 0x4042_5e4f_7b27_37fa),
            (0x7fef_ffff_ffff_ffff, 0x4086_33ce_8fb9_f87e),
            (0x3ff0_0000_0000_0000, 0x0000_0000_0000_0000),
            (0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0x3fe0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0xbff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0x8000_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000),
        ] {
            let got = acosh(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "acosh({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(acosh(f64::NAN).is_nan());
    }

    #[test]
    fn erf_matches_glibc_2_43_on_corpus() {
        assert_eq!(corpus_hash(erf, -30, 3), 0x9e4b_6e07_7284_febd);
    }

    #[test]
    fn erf_hard_and_special_cases() {
        // (input, glibc 2.43 result): accurate-path exceptions, the 1/16 and
        // 1/8 table boundaries, the tiny-x and saturation cut-offs.
        for (x, want) in [
            (0x3feb_c466_342a_2296u64, 0x3fe8_f7ab_15eb_5babu64),
            (0x3fef_d5d9_d8c9_ef66, 0x3fea_e5d1_7eb4_f408),
            (0x3fbe_f306_7c6c_f276, 0x3fc1_6067_d36b_3d43),
            (0xbf95_2b76_545c_c8ef, 0xbf97_e256_5102_7283),
            (0x3faf_fb7b_4d67_a854, 0x3fb2_054a_731b_0271),
            (0x4017_afb4_8dc9_6626, 0x3fef_ffff_ffff_ffff),
            (0x4017_afb4_8dc9_6627, 0x3ff0_0000_0000_0000),
            (0x4017_9999_9999_999a, 0x3fef_ffff_ffff_ffff),
            (0x3c20_0000_0000_0000, 0x3c22_0dd7_5042_9b6d),
            (0x3c1f_ffff_ffff_ffff, 0x3c22_0dd7_5042_9b6d),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
            (0x8010_0000_0000_0000, 0x8012_0dd7_5042_9b6d),
            (0x3fb0_0000_0000_0000, 0x3fb2_07d4_80e9_0658),
            (0x3fc0_0000_0000_0000, 0x3fc1_f5e1_a35c_3b89),
            (0xbee4_f8b5_88e3_68f1, 0xbee7_a9f0_84b5_e44c),
            (0x7ff0_0000_0000_0000, 0x3ff0_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xbff0_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
        ] {
            let got = erf(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "erf({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(erf(f64::NAN).is_nan());
    }

    #[test]
    fn erfc_matches_glibc_2_43_on_corpus() {
        assert_eq!(corpus_hash(erfc, -30, 5), 0xf56c_08ba_062d_376e);
    }

    #[test]
    fn erfc_hard_and_special_cases() {
        // (input, glibc 2.43 result): every branch cut-off, the subnormal
        // hard case, table exceptions and the asymptotic range.
        for (x, want) in [
            (0x403a_8f7b_fbd1_5495u64, 0x0006_67bd_620f_d95bu64),
            (0xbc9c_5bf8_91b4_ef6b, 0x3ff0_0000_0000_0001),
            (0xbc9c_5bf8_91b4_ef6a, 0x3ff0_0000_0000_0000),
            (0x3c8c_5bf8_91b4_ef6a, 0x3ff0_0000_0000_0000),
            (0x3c8c_5bf8_91b4_ef6b, 0x3fef_ffff_ffff_ffff),
            (0x3ffb_59ff_b450_828c, 0x3f90_0000_0000_0004),
            (0x3ffb_59ff_b450_828d, 0x3f90_0000_0000_0000),
            (0x4007_1378_6d9c_7c09, 0x3f07_ae95_6ac8_3f61),
            (0x4007_1378_6d9c_7c0a, 0x3f07_ae95_6ac8_3f4f),
            (0x4039_db1b_b14e_15ca, 0x034f_ffff_ffff_fef3),
            (0x403a_8b12_fc6e_4892, 0x000f_ffff_ffff_ffe0),
            (0x403b_39dc_41e4_8bfc, 0x0000_0000_0000_0001),
            (0x403b_39dc_41e4_8bfd, 0x0000_0000_0000_0000),
            (0xc017_744f_8f74_e94a, 0x3fff_ffff_ffff_ffff),
            (0xc017_744f_8f74_e94b, 0x4000_0000_0000_0000),
            (0x3fde_861f_bb24_c00a, 0x3fe0_0000_0000_0000),
            (0x3fbd_4af8_adb9_0116, 0x3feb_e2e3_45c3_1801),
            (0xbfff_9a4a_209c_a0e4, 0x3fff_eaa1_66e3_84c9),
            (0x4034_8de4_52fb_1a15, 0x1983_c2a1_2640_45ad),
            (0x3ffb_8940_788b_825d, 0x3f8e_97ea_f108_0bff),
            (0xbff8_0000_0000_0000, 0x3fff_752a_ab89_bd70),
            (0x3fe0_0000_0000_0000, 0x3fde_b021_47ce_245c),
            (0x4008_0000_0000_0000, 0x3ef7_29df_6503_422a),
            (0x4024_0000_0000_0000, 0x36a7_d8a7_f2a8_a2d0),
            (0x403a_0000_0000_0000, 0x02a2_84bf_e1cd_ea24),
            (0x7ff0_0000_0000_0000, 0x0000_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0x4000_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x3ff0_0000_0000_0000),
            (0x0000_0000_0000_0000, 0x3ff0_0000_0000_0000),
        ] {
            let got = erfc(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "erfc({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(erfc(f64::NAN).is_nan());
    }
}
