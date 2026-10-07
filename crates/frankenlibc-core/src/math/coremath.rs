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
use super::gamma_data::{
    LG_ACC_B, LG_ACC_C0, LG_ASYM_C, LG_ASYM_Q, LG_ASYMA_14, LG_ASYMA_48, LG_ASYMA_LOW, LG_CH,
    LG_CL, LG_DB, LG_LOGA_C, LG_LOGA_H1, LG_LOGA_H2, LG_LOGA_R1, LG_LOGA_R2, LG_OFFS, LG_ROOT_C,
    LG_ROOT_PARAMS, LG_SINA_C, LG_SINA_S, LG_STPI, LG_TINY_C0, LG_TINY_Q, LG_UBRD,
};
use super::gamma_data::{
    TG_ACC_CH4, TG_ACC_CH8, TG_ACC_CH16, TG_ACC_CH26, TG_ACC_CH32, TG_ACC_CH64, TG_ACC_CH96,
    TG_ACC_CH128, TG_ACC_CH160, TG_ACC_CL4, TG_ACC_CL8, TG_ACC_CL16, TG_ACC_CL26, TG_ACC_CL32,
    TG_ACC_CL64, TG_ACC_CL96, TG_ACC_CL128, TG_ACC_CL160, TG_ACC0_C, TG_ACC0_CC, TG_ASYM_BIG,
    TG_ASYM_SMALL, TG_DB, TG_E0, TG_E1, TG_EXP_C, TG_LOG_L1, TG_LOG_L2, TG_LOG_R1, TG_LOG_R2,
    TG_MID_C, TG_MID_CC, TG_SMALL_C, TG_SMALL_CC, TG_ST,
};
use super::trig_data::{
    SIN_C2U, SIN_PC, SIN_PS, SIN_S1U, SIN_S2U, SIN_T, SIN_U1, SIN_U2, TRIG_C, TRIG_PC, TRIG_PCFAST,
    TRIG_PS, TRIG_PSFAST, TRIG_S, TRIG_SC, TRIG_T, TRIG_TINV,
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

// --- atan (CORE-MATH src/binary64/atan/atan.c) --------------------------------

/// `(A[j][0], A[j][1])`: tan(pi/256 j) and atan(A[j][0]) - pi/256 j.
const ATAN_A: [[f64; 2]; 129] = [
    [hf!("0x0p+0"), hf!("0x0p+0")],
    [hf!("0x1.9224e047e368ep-7"), hf!("0x1.a3ca6c727c59dp-62")],
    [hf!("0x1.92346247a91fp-6"), hf!("0x1.138b0ef96a186p-64")],
    [hf!("0x1.2dbaae9a05dbp-5"), hf!("0x1.36e7f8a3f5e42p-59")],
    [hf!("0x1.927278a3b1162p-5"), hf!("-0x1.ac986efb92662p-64")],
    [hf!("0x1.f7495ea3f3783p-5"), hf!("0x1.06ec8011ee816p-59")],
    [hf!("0x1.2e239ccff3831p-4"), hf!("-0x1.858437d431332p-58")],
    [hf!("0x1.60b9f7597fdecp-4"), hf!("-0x1.cebd13eb7c513p-60")],
    [hf!("0x1.936bb8c5b2da2p-4"), hf!("-0x1.840cac0d81db5p-58")],
    [hf!("0x1.c63ce377fc802p-4"), hf!("0x1.400b0fdaa109ep-58")],
    [hf!("0x1.f93183a8db9e9p-4"), hf!("0x1.0e04e06c86e72p-59")],
    [hf!("0x1.1626d85a91e7p-3"), hf!("0x1.f7ad829163ca7p-59")],
    [hf!("0x1.2fcac73a6064p-3"), hf!("-0x1.2680735ce2cd8p-58")],
    [hf!("0x1.4986a74cf4e57p-3"), hf!("-0x1.90559690b42e4p-57")],
    [hf!("0x1.635c990ce0d36p-3"), hf!("0x1.91d29110b41aap-58")],
    [hf!("0x1.7d4ec54fb5968p-3"), hf!("-0x1.ea90e2718278p-59")],
    [hf!("0x1.975f5e0553158p-3"), hf!("-0x1.dc82ac14e3e1cp-61")],
    [hf!("0x1.b1909efd8b762p-3"), hf!("-0x1.73a10fd13daafp-58")],
    [hf!("0x1.cbe4ceb4b4cf2p-3"), hf!("-0x1.3a7ffbeabda0bp-57")],
    [hf!("0x1.e65e3f27c9f2ap-3"), hf!("-0x1.db6627a24d523p-57")],
    [hf!("0x1.007fa758626aep-2"), hf!("-0x1.45f97dd3099f6p-57")],
    [hf!("0x1.0de53475f3b3cp-2"), hf!("-0x1.6293f68741816p-57")],
    [hf!("0x1.1b6103d3597e9p-2"), hf!("-0x1.ab240d40633e9p-57")],
    [hf!("0x1.28f459ecad74dp-2"), hf!("-0x1.de34d14e832ep-61")],
    [hf!("0x1.36a08355c63dcp-2"), hf!("0x1.af540d9fb4926p-57")],
    [hf!("0x1.4466d542bac92p-2"), hf!("0x1.da60fdbc82ac4p-57")],
    [hf!("0x1.5248ae1701b17p-2"), hf!("-0x1.92a601170138ap-56")],
    [hf!("0x1.604775fbb27dfp-2"), hf!("-0x1.7f1fca1d5d15bp-57")],
    [hf!("0x1.6e649f7d78649p-2"), hf!("-0x1.4e223ea716c7bp-57")],
    [hf!("0x1.7ca1a832d0f84p-2"), hf!("0x1.b24c824ac51fcp-56")],
    [hf!("0x1.8b00196b3d022p-2"), hf!("0x1.4314cd132ba43p-57")],
    [hf!("0x1.998188e816bfp-2"), hf!("-0x1.11f1e0817879ap-56")],
    [hf!("0x1.a827999fcef32p-2"), hf!("-0x1.c3dea4dbad538p-57")],
    [hf!("0x1.b6f3fc8c61e5bp-2"), hf!("0x1.60d1b780ee3ebp-57")],
    [hf!("0x1.c5e87185e67b6p-2"), hf!("-0x1.ab5edb7dfa545p-59")],
    [hf!("0x1.d506c82a2c8p-2"), hf!("-0x1.8e1437048b5bdp-57")],
    [hf!("0x1.e450e0d273e7ap-2"), hf!("-0x1.06951c97b050fp-56")],
    [hf!("0x1.f3c8ad985d9eep-2"), hf!("-0x1.14af9522ab518p-59")],
    [hf!("0x1.01b819b5a7cf7p-1"), hf!("-0x1.aba0d7d97d1f2p-56")],
    [hf!("0x1.09a4c59bd0d4dp-1"), hf!("0x1.095bc4ebc2c42p-59")],
    [hf!("0x1.11ab7190834ecp-1"), hf!("0x1.798826fa27774p-55")],
    [hf!("0x1.19cd3fe8e405dp-1"), hf!("0x1.008f6258fc98fp-55")],
    [hf!("0x1.220b5ef047825p-1"), hf!("-0x1.462af7ceb7de6p-58")],
    [hf!("0x1.2a6709a74f289p-1"), hf!("-0x1.1184dfd78b472p-56")],
    [hf!("0x1.32e1889047ffdp-1"), hf!("0x1.9141876dc40c5p-56")],
    [hf!("0x1.3b7c3289ed6f3p-1"), hf!("0x1.481c20189726cp-55")],
    [hf!("0x1.44386db9ce5dbp-1"), hf!("0x1.2e851bd025441p-55")],
    [hf!("0x1.4d17b087b265dp-1"), hf!("0x1.13ada9b8bc419p-56")],
    [hf!("0x1.561b82ab7f99p-1"), hf!("-0x1.05b4c3c4cbee8p-55")],
    [hf!("0x1.5f457e4f4812ep-1"), hf!("-0x1.5619249bd96f1p-55")],
    [hf!("0x1.6897514751db6p-1"), hf!("-0x1.b0a0fbcafc671p-57")],
    [hf!("0x1.7212be621be6dp-1"), hf!("-0x1.19ff2dc66da45p-55")],
    [hf!("0x1.7bb99ed2990cfp-1"), hf!("0x1.1320449592d92p-55")],
    [hf!("0x1.858de3b716571p-1"), hf!("-0x1.1fddcd2f3da8ep-55")],
    [hf!("0x1.8f9197bf85eebp-1"), hf!("0x1.d44a42e35cc97p-57")],
    [hf!("0x1.99c6e0f634394p-1"), hf!("-0x1.585a178b4a18dp-56")],
    [hf!("0x1.a43002ae4285p-1"), hf!("0x1.f95a531b3a97p-57")],
    [hf!("0x1.aecf5f9ba35a6p-1"), hf!("-0x1.96c2d43ca3392p-60")],
    [hf!("0x1.b9a77c18c1af2p-1"), hf!("-0x1.a5bed94b05defp-57")],
    [hf!("0x1.c4bb009e77983p-1"), hf!("0x1.54509d2bff511p-59")],
    [hf!("0x1.d00cbc7384d2ep-1"), hf!("-0x1.b4c867cef300cp-57")],
    [hf!("0x1.db9fa89953fcfp-1"), hf!("-0x1.ddfac663d6bc6p-62")],
    [hf!("0x1.e776eafc91706p-1"), hf!("-0x1.a510683ff7cb6p-56")],
    [hf!("0x1.f395d9f0e3c92p-1"), hf!("0x1.4fdcd8e4e871p-59")],
    [hf!("0x1p+0"), hf!("0x0p+0")],
    [hf!("0x1.065c900aaf2d8p+0"), hf!("-0x1.deec7fc9042adp-55")],
    [hf!("0x1.0ce29d0883c99p+0"), hf!("-0x1.395ae45e0657dp-55")],
    [hf!("0x1.139447e6a86eep+0"), hf!("0x1.332cf301a97f3p-55")],
    [hf!("0x1.1a73d55278c4bp+0"), hf!("-0x1.6cc8c4b78213bp-55")],
    [hf!("0x1.2183b0c4573ffp+0"), hf!("0x1.70a90841da57ap-55")],
    [hf!("0x1.28c66fdaf8f09p+0"), hf!("-0x1.ba39bad450eep-57")],
    [hf!("0x1.303ed61109e2p+0"), hf!("-0x1.8692946d9f93cp-55")],
    [hf!("0x1.37efd8d87607ep+0"), hf!("0x1.3b711bf765b58p-57")],
    [hf!("0x1.3fdca42847507p+0"), hf!("0x1.c21387985b081p-56")],
    [hf!("0x1.48089f8bf42ccp+0"), hf!("-0x1.7ddb19d3d0efcp-55")],
    [hf!("0x1.507773c537eadp+0"), hf!("-0x1.f5e354cf971f3p-56")],
    [hf!("0x1.592d11142fa55p+0"), hf!("-0x1.00f0ad675330dp-56")],
    [hf!("0x1.622db63c8ecc2p+0"), hf!("-0x1.2c93f50ab2c0ep-55")],
    [hf!("0x1.6b7df862652p+0"), hf!("0x1.bec391adc37d5p-56")],
    [hf!("0x1.7522cbdd428a8p+0"), hf!("-0x1.9686ddc9ffcf5p-57")],
    [hf!("0x1.7f218e25a7461p+0"), hf!("-0x1.8d16529514246p-56")],
    [hf!("0x1.89801106cc709p+0"), hf!("-0x1.092f51e9c2803p-55")],
    [hf!("0x1.9444a7462122ap+0"), hf!("-0x1.07c06755404c4p-55")],
    [hf!("0x1.9f7632fa9e871p+0"), hf!("0x1.02e0d43abc92bp-55")],
    [hf!("0x1.ab1c35d8a74eap+0"), hf!("0x1.d0184e48af6f7p-58")],
    [hf!("0x1.b73ee3c3ef16ap+0"), hf!("0x1.73be957380bc2p-56")],
    [hf!("0x1.c3e738086bc0fp+0"), hf!("-0x1.02b6e26c84462p-56")],
    [hf!("0x1.d11f0dae40609p+0"), hf!("0x1.25c4f3ffa6e1fp-58")],
    [hf!("0x1.def13b73c1406p+0"), hf!("-0x1.e302db3c6823fp-58")],
    [hf!("0x1.ed69b4153a45dp+0"), hf!("0x1.3207830326c0ep-56")],
    [hf!("0x1.fc95abad6cf4ap+0"), hf!("-0x1.6308cee7927bfp-57")],
    [hf!("0x1.0641e192ceab3p+1"), hf!("-0x1.0147ebf0df4c5p-56")],
    [hf!("0x1.0ea21d716fbf7p+1"), hf!("-0x1.168533cc41d8bp-56")],
    [hf!("0x1.17749711a6679p+1"), hf!("-0x1.52a0b0333e9c5p-57")],
    [hf!("0x1.20c36c6a7f38ep+1"), hf!("0x1.8659eece35395p-57")],
    [hf!("0x1.2a99f50fd4f4fp+1"), hf!("0x1.20fcad18cb36fp-55")],
    [hf!("0x1.3504f333f9de6p+1"), hf!("-0x1.52afdbd5a8c74p-56")],
    [hf!("0x1.4012ce2586a17p+1"), hf!("-0x1.9747a792907d7p-56")],
    [hf!("0x1.4bd3d87fe065p+1"), hf!("0x1.90c59393b52c8p-56")],
    [hf!("0x1.585aa4e1530fap+1"), hf!("0x1.af6934f13a3a8p-56")],
    [hf!("0x1.65bc6cc825147p+1"), hf!("-0x1.8534dcab5ad3ep-59")],
    [hf!("0x1.74118e4b6a7c8p+1"), hf!("-0x1.555aa8bfca9a1p-56")],
    [hf!("0x1.837626d70fdb8p+1"), hf!("-0x1.56b3fee9ca72bp-58")],
    [hf!("0x1.940ad30abc792p+1"), hf!("0x1.4b3fdd4fdc06cp-58")],
    [hf!("0x1.a5f59e90600ddp+1"), hf!("0x1.285d367c55ddcp-57")],
    [hf!("0x1.b9633283b6d14p+1"), hf!("-0x1.8712976f17a16p-59")],
    [hf!("0x1.ce885653127e7p+1"), hf!("-0x1.abe8ab65d49fcp-60")],
    [hf!("0x1.e5a3de972a377p+1"), hf!("0x1.cd9be81ad764bp-58")],
    [hf!("0x1.ff01305ecd8dcp+1"), hf!("0x1.742c2922656fap-59")],
    [hf!("0x1.0d7dc7cff4c9ep+2"), hf!("-0x1.7c842978bee09p-56")],
    [hf!("0x1.1d0143e71565fp+2"), hf!("0x1.7bc7dea7c3c03p-57")],
    [hf!("0x1.2e4ff1626b949p+2"), hf!("0x1.aefbe25b404e9p-59")],
    [hf!("0x1.41bfee2424771p+2"), hf!("-0x1.4bcfaaa95cb2cp-60")],
    [hf!("0x1.57be4eaa5e11bp+2"), hf!("0x1.0fe741e4ec679p-58")],
    [hf!("0x1.70d751908c1b1p+2"), hf!("0x1.fe74a5b0ec709p-58")],
    [hf!("0x1.8dc25c117782bp+2"), hf!("0x1.0ca1c19f710efp-58")],
    [hf!("0x1.af73f4ca3310fp+2"), hf!("0x1.2867b40ba77d6p-58")],
    [hf!("0x1.d7398d15e70dbp+2"), hf!("0x1.0fd4e0d4b1547p-57")],
    [hf!("0x1.0372fb36b87e2p+3"), hf!("0x1.c16c9ecc1621dp-58")],
    [hf!("0x1.208dbdae055efp+3"), hf!("0x1.6b81a36e75e8cp-58")],
    [hf!("0x1.44e6c595afdccp+3"), hf!("-0x1.7c22045771848p-58")],
    [hf!("0x1.7398c57f3f1adp+3"), hf!("0x1.970503be105cp-58")],
    [hf!("0x1.b1d03c03d2f7fp+3"), hf!("-0x1.f299d010aead2p-60")],
    [hf!("0x1.046e9fe60a77ep+4"), hf!("0x1.d2b61deff33ecp-58")],
    [hf!("0x1.45affed201b55p+4"), hf!("0x1.0e84d9567203ap-64")],
    [hf!("0x1.b267195b1ffaep+4"), hf!("-0x1.ad44b44b92653p-64")],
    [hf!("0x1.45e2455e4aaa7p+5"), hf!("-0x1.296d577b5e21dp-60")],
    [hf!("0x1.45eed6854ce99p+6"), hf!("0x1.2db53886013cap-63")],
    [0.0, 0.0],
];

/// Piecewise-quadratic approximation of atan used to pick the `ATAN_A` index.
const ATAN_C: [[u16; 3]; 31] = [
    [419, 81, 0],
    [500, 81, 0],
    [582, 163, 0],
    [745, 163, 0],
    [908, 326, 0],
    [1234, 326, 0],
    [1559, 651, 0],
    [2210, 650, 1],
    [2860, 1299, 3],
    [4156, 1293, 4],
    [5444, 2569, 24],
    [7989, 2520, 32],
    [10476, 4917, 168],
    [15224, 4576, 200],
    [19601, 8341, 838],
    [27105, 6648, 731],
    [33036, 10210, 1998],
    [41266, 6292, 1117],
    [46469, 7926, 2048],
    [52375, 4038, 849],
    [55587, 4591, 1291],
    [58906, 2172, 479],
    [60612, 2390, 688],
    [62325, 1107, 247],
    [63192, 1207, 349],
    [64056, 556, 124],
    [64491, 605, 175],
    [64923, 278, 62],
    [65141, 303, 88],
    [65358, 139, 31],
    [65467, 151, 44],
];

/// atan.c `polydd`: asinh.c's sum steps around the standard `muldd_acc`.
#[inline(always)]
fn polydd_atan(xh: f64, xl: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let mut ch = c[i][0] + l;
    let mut cl = ((c[i][0] - ch) + l) + c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = muldd_acc(xh, xl, ch, cl);
        let th = ch + c[i][0];
        let tl = (c[i][0] - th) + ch;
        ch = th;
        cl += tl + c[i][1];
    }
    (ch, cl)
}

/// Accurate atan for 2^-27 <= |x|, given the fast-path approximation `a`.
#[cold]
#[inline(never)]
fn atan_refine2(x: f64, a: f64) -> f64 {
    const CH: [[f64; 2]; 3] = [
        [hf!("-0x1.5555555555555p-2"), hf!("-0x1.5555555555555p-56")],
        [hf!("0x1.999999999999ap-3"), hf!("-0x1.999999999bcb8p-57")],
        [hf!("-0x1.2492492492492p-3"), hf!("-0x1.249242093c016p-57")],
    ];
    const CL: [f64; 4] = [
        hf!("0x1.c71c71c71c71cp-4"),
        hf!("-0x1.745d1745d1265p-4"),
        hf!("0x1.3b13b115bcbc4p-4"),
        hf!("-0x1.1107c41ad3253p-4"),
    ];
    const DB: [[f64; 3]; 12] = [
        [
            hf!("0x1.0dc89a3b5501p-7"),
            hf!("0x1.0dc70ac228717p-7"),
            hf!("0x1p-61"),
        ],
        [
            hf!("0x1.e3fb41d2d226p-8"),
            hf!("0x1.e3f9013a852f8p-8"),
            hf!("0x1p-62"),
        ],
        [
            hf!("0x1.7ba49f739829fp-1"),
            hf!("0x1.46ac372243536p-1"),
            hf!("0x1p-109"),
        ],
        [
            hf!("0x1.a933fe176b375p-3"),
            hf!("0x1.a33f32ac5ceb5p-3"),
            hf!("-0x1p-112"),
        ],
        [
            hf!("0x1.bb04a79820063p-8"),
            hf!("0x1.bb02ed5c5e956p-8"),
            hf!("-0x1p-115"),
        ],
        [
            hf!("0x1.cd30a9499618bp-8"),
            hf!("0x1.cd2eb65f92a46p-8"),
            hf!("-0x1p-112"),
        ],
        [
            hf!("0x1.f44aa37b8e66bp-7"),
            hf!("0x1.f440b04187c87p-7"),
            hf!("-0x1p-112"),
        ],
        [
            hf!("0x1.fd2ac95e57ef9p-8"),
            hf!("0x1.fd2829febc03ap-8"),
            hf!("-0x1p-112"),
        ],
        [
            hf!("0x1.6419079bbf601p-6"),
            hf!("0x1.640aade8f5427p-6"),
            hf!("0x1p-114"),
        ],
        [
            hf!("0x1.7ba49f739829fp-1"),
            hf!("0x1.46ac372243536p-1"),
            hf!("0x1p-110"),
        ],
        [
            hf!("0x1.d768804487b07p-3"),
            hf!("0x1.cf5676f373ec1p-3"),
            hf!("-0x1p-110"),
        ],
        [
            hf!("0x1.bb04a79820063p-8"),
            hf!("0x1.bb02ed5c5e956p-8"),
            hf!("-0x1p-115"),
        ],
    ];
    let phi = (a.abs() * hf!("0x1.45f306dc9c883p6") + 256.5).to_bits();
    let i = ((phi >> (52 - 8)) & 0xff) as usize; // 0 <= i <= 128
    let (h, hl) = if i == 128 {
        let h = -1.0 / x;
        (h, h.mul_add(x, 1.0) * h)
    } else {
        let ta = ATAN_A[i][0].copysign(x);
        let zta = x * ta;
        let ztal = x.mul_add(ta, -zta);
        let zmta = x - ta;
        let v = 1.0 + zta;
        let d = 1.0 - v;
        let ev = ((d + zta) - ((d + v) - 1.0)) + ztal;
        let r = 1.0 / v;
        let rl = (r.mul_add(-v, 1.0) - ev * r) * r;
        let h = r * zmta;
        (h, r.mul_add(zmta, -h) + rl * zmta)
    };
    let (h2, h2l) = muldd_acc(h, hl, h, hl);
    let h4 = h2 * h2;
    let (h3, h3l) = muldd_acc(h, hl, h2, h2l);
    let fl = h2 * ((CL[0] + h2 * CL[1]) + h4 * (CL[2] + h2 * CL[3]));
    let (f, fl) = polydd_atan(h2, h2l, &CH, fl);
    let (f, fl) = muldd_acc(h3, h3l, f, fl);
    let (ah, al, at) = if i == 0 {
        (h, f, fl)
    } else {
        let df = if i < 128 {
            1.0f64.copysign(x) * ATAN_A[i][1]
        } else {
            0.0
        };
        let id = (i as f64).copysign(x);
        let ah = hf!("0x1.921fb54442dp-7") * id;
        let al = hf!("0x1.8469898cc518p-55") * id;
        let at = hf!("-0x1.fc8f8cbb5bf8p-104") * id;
        let (al, at) = adddd(al, at, df, 0.0);
        let (al, at) = adddd(al, at, h, hl);
        let (al, at) = adddd(al, at, f, fl);
        (ah, al, at)
    };
    let (v0, v2) = fasttwosum(ah, al);
    let (mut v1, v2) = fasttwosum(v2, at);
    let ax = x.abs();
    let t0 = v0.to_bits();
    let t1 = v1.to_bits();
    if (t1.wrapping_add(1) & MASK52) <= 2
        || ((t0 >> 52) & 0x7ff).wrapping_sub((t1 >> 52) & 0x7ff) > 103
    {
        for d in &DB {
            if ax == d[0] {
                return d[1].copysign(x) + 1.0f64.copysign(x) * d[2];
            }
        }
        v1 = nudge_power_of_two(v1, v2).0;
    }
    v1 + v0
}

/// Correctly rounded `atan`.
pub fn atan(x: f64) -> f64 {
    const CH: [f64; 4] = [
        hf!("0x1p+0"),
        hf!("-0x1.555555555552bp-2"),
        hf!("0x1.9999999069c2p-3"),
        hf!("-0x1.248d2c8444ac6p-3"),
    ];
    let t = x.to_bits();
    let at = t & (u64::MAX >> 1);
    if at < 0x3f7b_21c4_75e6_362a {
        // |x| < 0x1.b21c475e6362ap-8
        if at == 0 {
            return x;
        }
        if at < 0x3e40_0000_0000_0000 {
            // |x| < 2^-27
            return hf!("-0x1p-54").mul_add(x, x);
        }
        const CH2: [f64; 4] = [
            hf!("-0x1.5555555555555p-2"),
            hf!("0x1.99999999998c1p-3"),
            hf!("-0x1.249249176aecp-3"),
            hf!("0x1.c711fd121ae8p-4"),
        ];
        let x2 = x * x;
        let x3 = x * x2;
        let x4 = x2 * x2;
        let f = x3 * ((CH2[0] + x2 * CH2[1]) + x4 * (CH2[2] + x2 * CH2[3]));
        let epsp = f * hf!("0x1.6p-50");
        let epsm = f * hf!("0x1.6p-51");
        let ub = (f + epsp) + x;
        let lb = (f - epsm) + x;
        if ub == lb {
            return ub;
        }
        return atan_refine2(x, ub);
    }
    let h;
    let ah;
    let mut al;
    if at > 0x4062_ded8_e34a_9035 {
        // |x| > 0x1.2ded8e34a9035p+7
        ah = hf!("0x1.921fb54442d18p+0").copysign(x);
        al = hf!("0x1.1a62633145c07p-54").copysign(x);
        if at >= 0x434d_0296_7c31_cdb5 {
            // |x| >= 0x1.d02967c31cdb5p+53
            if at > (0x7ffu64 << 52) {
                return x + x;
            }
            return ah + al;
        }
        h = -1.0 / x;
    } else {
        // 0x1.b21c475e6362ap-8 <= |x| <= 0x1.2ded8e34a9035p+7, so 1 <= i <= 30.
        let ci = &ATAN_C[((at >> 51) as i64 - 2030) as usize];
        let u = t & (u64::MAX >> 13);
        let ut = u >> (51 - 16);
        let ut2 = (ut * ut) >> 16;
        let i = (((ci[0] as u64) << 16)
            .wrapping_add(ut.wrapping_mul(ci[1] as u64))
            .wrapping_sub(ut2.wrapping_mul(ci[2] as u64)))
            >> (16 + 9);
        let i = i as usize;
        let sgn = 1.0f64.copysign(x);
        let ta = sgn * ATAN_A[i][0];
        let id = sgn * (i as f64);
        al = sgn * ATAN_A[i][1] + hf!("0x1.8469898cc517p-55") * id;
        h = (x - ta) / (1.0 + x * ta);
        ah = hf!("0x1.921fb54442dp-7") * id;
    }
    let h2 = h * h;
    let h4 = h2 * h2;
    let f = (CH[0] + h2 * CH[1]) + h4 * (CH[2] + h2 * CH[3]);
    al = h.mul_add(f, al);
    let e = h * hf!("0x3.fp-52");
    let ub = (al + e) + ah;
    let lb = (al - e) + ah;
    if ub == lb {
        return ub;
    }
    atan_refine2(x, ub)
}

// --- sin (CORE-MATH src/binary64/sin/sin.c) -----------------------------------

/// Round `(-1)^sbit * r / 2^128` to double; `r` non-zero and not subnormal.
#[inline(always)]
fn u128_tod(r: u128, sbit: usize) -> f64 {
    let h = (r >> 64) as u64;
    let l = r as u64;
    let sh = u64::from(if h != 0 {
        h.leading_zeros()
    } else {
        64 + l.leading_zeros()
    });
    let top = (r >> (75 - sh)) as u64; // upper 53 non-zero bits
    let rbit = (r >> (74 - sh)) & 1; // round bit
    const SGN: [f64; 2] = [hf!("0x1p-53"), hf!("-0x1p-53")];
    let v = f64::from_bits(SGN[sbit].to_bits().wrapping_sub(sh << 52)); // scale by 2^-sh
    let a = top as f64 * v;
    let b = a * if rbit != 0 {
        hf!("0x1p-53")
    } else {
        hf!("0x1p-54")
    };
    a + b
}

/// High 128 bits of the 256-bit product `a * b`, minus the low cross terms'
/// carries (sin.c `mhUU`).
#[inline(always)]
fn mh_uu(a: u128, b: u128) -> u128 {
    let (ah, al) = ((a >> 64) as u64, a as u64);
    let (bh, bl) = ((b >> 64) as u64, b as u64);
    let ahbh = u128::from(ah) * u128::from(bh);
    let ahbl = u128::from(ah) * u128::from(bl);
    let albh = u128::from(al) * u128::from(bh);
    ahbh.wrapping_add(ahbl >> 64).wrapping_add(albh >> 64)
}

/// sin(2 pi r) * 2^128 for 0 <= r < 2^-14 in fixed point (sin.c `evalPS`).
#[inline(always)]
fn sin_eval_ps(u: u128, u2: u128, u2h: u128, u4: u128) -> u128 {
    let ps = &SIN_PS;
    let sh = ps[2].wrapping_sub(ps[3].wrapping_mul(u2h));
    let sh = mh_uu(sh, u4);
    let s = mh_uu(ps[1], u2);
    let s = ps[0].wrapping_sub(s).wrapping_add(sh);
    mh_uu(s, u)
}

/// cos(2 pi r) * 2^128 for 0 <= r < 2^-14 in fixed point (sin.c `evalPC`).
#[inline(always)]
fn sin_eval_pc(u2: u128, u2h: u128, u4: u128) -> u128 {
    let pc = &SIN_PC;
    let sh = pc[3].wrapping_sub(u2h.wrapping_mul(pc[4]));
    let sh = pc[2].wrapping_sub(mh_uu(sh, u2));
    let s = mh_uu(pc[1], u2);
    pc[0].wrapping_sub(s).wrapping_add(mh_uu(sh, u4))
}

/// Argument reduction for |x| >= 2^31: `(k, r)` with
/// x/(2 pi) mod 1 = k/2^15 + r + s, 0 <= r < 2^-15, 0 <= s < 2^-67.988.
#[inline(always)]
fn sin_reduce_large(x: f64) -> (u64, f64) {
    let t = x.to_bits();
    let e = ((t >> 52) & 0x7ff) as i32; // 1054 <= e <= 2046
    let m = (1u64 << 52) | (t & MASK52);
    let i = ((e - 1011) / 64) as usize;
    let f = ((e - 1011) & 0x3f) as u32;
    let tt = &SIN_T;
    let (v0, v1) = if f == 0 {
        (tt[i], tt[i + 1])
    } else {
        (
            (tt[i] << f) | (tt[i + 1] >> (64 - f)),
            (tt[i + 1] << f) | (tt[i + 2] >> (64 - f)),
        )
    };
    let u = u128::from(v1) | (u128::from(v0) << 64);
    let u = u128::from(m).wrapping_mul(u);
    // Round r to nearest: 0x810000000000000 = 2^59 + 2^52.
    const MAGIC: u128 = (1u128 << 112) + 0x0810_0000_0000_0000;
    let u = u.wrapping_add(MAGIC);
    let tf = ((u << 15) >> 75) as u64 as f64; // next 53 bits after the first 15
    ((u >> 113) as u64, tf * hf!("0x1p-68") - hf!("0x1p-16"))
}

/// Accurate-path reduction: `(k, r, neg)` with x/(2 pi) mod 1 =
/// k/2^13 + (-1)^neg r/2^128 + eps, |r/2^128| <= 2^-14.
#[inline(always)]
fn sin_reduce_large_acc(x: f64) -> (u64, u128, bool) {
    let t = x.to_bits();
    let e = ((t >> 52) & 0x7ff) as i32;
    let m = (1u64 << 52) | (t & MASK52);
    let i = -1 + (e - 947) / 64;
    let f = ((e - 1011) & 0x3f) as u32;
    let tt = &SIN_T;
    let at = |j: i32| tt[j as usize];
    let mut v0 = if i >= 0 { at(i) } else { 0 };
    let mut v1 = at(i + 1);
    let mut v2 = at(i + 2);
    if f != 0 {
        v0 = (v0 << f) | (v1 >> (64 - f));
        v1 = (v1 << f) | (v2 >> (64 - f));
        v2 = (v2 << f) | (at(i + 3) >> (64 - f));
    }
    let u = u128::from(v1) | (u128::from(v0) << 64);
    let mut u = u128::from(m).wrapping_mul(u);
    let v = u128::from(m) * u128::from(v2);
    u = u.wrapping_add(v >> 64);
    let mut k = (u >> (128 - 13)) as u64;
    const MASK: u128 = (0x7_ffff_ffff_ffffu128 << 64) | 0xffff_ffff_ffff_ffff;
    u &= MASK; // drop the leading 13 bits
    let neg = (u >> 114) != 0;
    if neg {
        k = (k + 1) & ((1 << 13) - 1);
        u = (MASK + 1).wrapping_sub(u);
    }
    (k, u, neg)
}

/// sin.c `muldd`: `(xh + xl) * (ch + cl)` with the low product folded.
#[inline(always)]
fn muldd_sin(xh: f64, xl: f64, ch: f64, cl: f64) -> (f64, f64) {
    let ahhh = xh * ch;
    (ahhh, (xh * cl + xl * ch) + xh.mul_add(ch, -ahhh))
}

/// sin.c `fastsum`: `(xh + xl) + (yh + yl)` assuming |xh| >= |yh|.
#[inline(always)]
fn fastsum_dd(xh: f64, xl: f64, yh: f64, yl: f64) -> (f64, f64) {
    let (sh, sl) = fasttwosum(xh, yh);
    (sh, (xl + yl) + sl)
}

/// Accurate sin for |x| >= 2^-16 in 128-bit fixed point.
#[cold]
#[inline(never)]
fn sin_large_accurate(x: f64) -> f64 {
    let (k, r, neg) = sin_reduce_large_acc(x);
    // TWOPI/2^128 approximates 2pi/2^3.
    const TWOPI: u128 = (0xc90f_daa2_2168_c234u128 << 64) | 0xc4c6_628b_80dc_1cd1;
    let r = mh_uu(TWOPI, r << 3);
    let u2 = mh_uu(r, r);
    let u4 = mh_uu(u2, u2);
    let u2h = u2 >> 64;
    let mut sbit = usize::from(x <= 0.0) ^ (k >> 12) as usize;
    let i1 = ((k >> 6) & 0x3f) as usize;
    let i2 = (k & 0x3f) as usize;
    let s1 = if i1 <= 32 {
        SIN_S1U[i1]
    } else {
        SIN_S1U[64 - i1]
    };
    let c1 = if i1 <= 32 {
        SIN_S1U[32 - i1]
    } else {
        SIN_S1U[i1 - 32]
    };
    let mut s1u = mh_uu(s1, SIN_C2U[i2]);
    let t = mh_uu(c1, SIN_S2U[i2]);
    s1u = if i1 < 32 {
        s1u.wrapping_add(t)
    } else {
        s1u.wrapping_sub(t)
    };
    let mut c1u = mh_uu(c1, SIN_C2U[i2]);
    let t = mh_uu(s1, SIN_S2U[i2]);
    c1u = if i1 < 32 {
        c1u.wrapping_sub(t)
    } else {
        c1u.wrapping_add(t)
    };
    let sr = sin_eval_ps(r, u2, u2h, u4);
    let cr = sin_eval_pc(u2, u2h, u4);
    let mut s1u = mh_uu(s1u, cr);
    let c1u = mh_uu(c1u, sr);
    if (i1 < 32) ^ neg {
        s1u = s1u.wrapping_add(c1u);
    } else if s1u < c1u {
        s1u = c1u - s1u;
        sbit ^= 1;
    } else {
        s1u -= c1u;
    }
    u128_tod(s1u, sbit)
}

/// Accurate sin for |x| < 2^-16.
#[inline(always)]
fn sin_small_accurate(x: f64) -> f64 {
    const C3H: f64 = hf!("-0x1.5555555555555p-3");
    const C3L: f64 = hf!("-0x1.55554b00de7e8p-57");
    const C5: f64 = hf!("0x1.111111110848p-7");
    let x2h = x * x;
    let x2l = x.mul_add(x, -x2h);
    let mut h = C5 * x2h;
    h += C3L;
    let (h, l) = fasttwosum(C3H, h);
    let (h, l) = muldd_sin(h, l, x2h, x2l);
    let (h, mut l) = muldd_sin(h, l, x, 0.0);
    let (h, t) = fasttwosum(x, h);
    l += t;
    h + l
}

/// sin(j pi / 2^14) as a double-double plus a double cos(j pi / 2^14), from
/// the two-level `SIN_U1`/`SIN_U2` tables.
#[inline(always)]
fn sin_table(j: u64) -> (f64, f64, f64) {
    let i1 = ((j >> 7) & 0x7f) as usize;
    let i2 = (j & 0x7f) as usize;
    let (u1, u2) = (&SIN_U1[i1], &SIN_U2[i2]);
    let (s1h, s1l) = muldd_sin(u1[0], u1[1], u2[2], u2[3]);
    let (s2h, s2l) = muldd_sin(u2[0], u2[1], u1[2], u1[3]);
    let (sh, sl) = fastsum_dd(s1h, s1l, s2h, s2l);
    let ch = u1[2] * u2[2] - u1[0] * u2[0];
    (sh, sl, ch)
}

/// Fast sin for 0x1.7137449123ef6p-26 < |x| < 2^31.
#[inline(always)]
fn sin_moderate(x: f64, sbit: usize) -> f64 {
    const PIH: f64 = hf!("-0x1.921fb54442d18p-13");
    const PIL: f64 = hf!("-0x1.1a62633145c07p-67");
    let ax = x.abs();
    let k = (hf!("0x1.45f306dc9c883p+12") * ax).round_ties_even();
    let rh = k.mul_add(PIH, ax); // exact
    let rl = k * PIL;
    let r = rh + rl;
    let r2 = r * r;
    let j = k as i64;
    let sbit = sbit ^ ((j >> 14) & 1) as usize;
    let (big_sh, big_sl, big_ch) = sin_table(j as u64);
    let sh = r * (1.0 - hf!("0x1.55555553068fp-3") * r2);
    let ch = r2 * (-0.5 + hf!("0x1.55555553bfd3p-5") * r2);
    let fh = big_sh;
    let fl = big_sl + big_sh * ch + big_ch * sh;
    const SGN: [f64; 2] = [1.0, -1.0];
    const EPS: f64 = hf!("0x1.dep-64");
    const EPS2: f64 = hf!("0x1.dep-63");
    let fh = SGN[sbit] * fh;
    let fl = SGN[sbit] * fl - EPS;
    let lb = fh + fl;
    let ub = fh + (fl + EPS2);
    if ub == lb {
        return lb;
    }
    if x.abs() < hf!("0x1p-16") {
        return sin_small_accurate(x);
    }
    sin_large_accurate(x)
}

/// Fast cos for 0x1.6a09e667f3bccp-27 < |x| < 2^31: `sin_moderate`'s
/// computation a quarter turn on. cos(|x|) = sin(|x| + pi/2), and pi/2 is
/// exactly 2^13 steps of its pi/2^14 reduction grid, so only the table index
/// moves: the reduction, the evaluation and the error bound behind the
/// rounding test are sin's, whose analysis covers every index. `None` when
/// the test cannot prove the rounding (the caller's accurate cos decides).
#[inline(always)]
fn cos_moderate(ax: f64) -> Option<f64> {
    const PIH: f64 = hf!("-0x1.921fb54442d18p-13");
    const PIL: f64 = hf!("-0x1.1a62633145c07p-67");
    let k = (hf!("0x1.45f306dc9c883p+12") * ax).round_ties_even();
    let rh = k.mul_add(PIH, ax); // exact
    let rl = k * PIL;
    let r = rh + rl;
    let r2 = r * r;
    let j = k as i64 + (1 << 13);
    let sbit = ((j >> 14) & 1) as usize;
    let (big_sh, big_sl, big_ch) = sin_table(j as u64);
    let sh = r * (1.0 - hf!("0x1.55555553068fp-3") * r2);
    let ch = r2 * (-0.5 + hf!("0x1.55555553bfd3p-5") * r2);
    let fh = big_sh;
    let fl = big_sl + big_sh * ch + big_ch * sh;
    const SGN: [f64; 2] = [1.0, -1.0];
    const EPS: f64 = hf!("0x1.dep-64");
    const EPS2: f64 = hf!("0x1.dep-63");
    let fh = SGN[sbit] * fh;
    let fl = SGN[sbit] * fl - EPS;
    let lb = fh + fl;
    let ub = fh + (fl + EPS2);
    (ub == lb).then_some(lb)
}

/// Fast sin for |x| >= 2^31.
#[inline(never)]
fn sin_large(x: f64) -> f64 {
    let (j, r) = sin_reduce_large(x.abs());
    let r2 = r * r;
    let sbit = usize::from(x <= 0.0) ^ (j >> 14) as usize;
    let (big_sh, big_sl, big_ch) = sin_table(j);
    let sh = r * (hf!("0x1.921fb54442d18p2") - hf!("0x1.4abbcdb6b26d1p5") * r2);
    let ch = r2 * (hf!("-0x1.3bd3cc9be45dep4") + hf!("0x1.03c1eee483083p6") * r2);
    let fh = big_sh;
    let fl = big_sl + big_sh * ch + big_ch * sh;
    const SGN: [f64; 2] = [1.0, -1.0];
    let fh = SGN[sbit] * fh;
    let fl = SGN[sbit] * fl;
    const EPS: f64 = hf!("0x1.01p-63");
    let lb = fh + (fl - EPS);
    let ub = fh + (fl + EPS);
    if lb == ub {
        return lb;
    }
    sin_large_accurate(x)
}

/// Correctly rounded `sin`.
pub fn sin(x: f64) -> f64 {
    let t = x.to_bits();
    let au = t << 1;
    if au <= 0x7cae_26e8_9224_7dec {
        // |x| <= 0x1.7137449123ef6p-26: sin(x) rounds to x - x^3/6 ~ x.
        if au == 0 {
            return x;
        }
        return x.mul_add(hf!("-0x1p-54"), x);
    }
    let e = (t >> 52) & 0x7ff;
    if e < 1054 {
        return sin_moderate(x, (t >> 63) as usize);
    }
    if e == 0x7ff {
        // NaN propagates; ±inf gives the default NaN with FE_INVALID.
        return x * 0.0;
    }
    sin_large(x)
}

// --- cos / tan shared infrastructure (CORE-MATH cos.c, tan.c: dint.h) ---------

/// A 128-bit binary floating-point value (CORE-MATH `dint64_t`):
/// `(-1)^sgn * r/2^128 * 2^ex` with `r` normalised to bit 127 when non-zero.
#[derive(Clone, Copy)]
struct Dint {
    r: u128,
    ex: i64,
    sgn: u64,
}

impl Dint {
    const fn from_parts((hi, lo, ex, sgn): (u64, u64, i64, u64)) -> Self {
        Self {
            r: ((hi as u128) << 64) | lo as u128,
            ex,
            sgn,
        }
    }

    #[inline(always)]
    fn hi(&self) -> u64 {
        (self.r >> 64) as u64
    }

    #[inline(always)]
    fn lo(&self) -> u64 {
        self.r as u64
    }

    #[inline(always)]
    fn set_hi_lo(&mut self, hi: u64, lo: u64) {
        self.r = (u128::from(hi) << 64) | u128::from(lo);
    }
}

/// `dint_tod(ZERO)` is 0.
const DINT_ZERO: Dint = Dint::from_parts((0, 0, -1076, 0));
/// 2^-11.
const DINT_MAGIC: Dint = Dint::from_parts((1 << 63, 0, -10, 0));

/// Compare |a| and |b|: -1, 0 or 1.
#[inline(always)]
fn cmp_dint_abs(a: &Dint, b: &Dint) -> i32 {
    if a.hi() == 0 {
        return if b.hi() == 0 { 0 } else { -1 };
    }
    if b.hi() == 0 {
        return 1;
    }
    match a.ex.cmp(&b.ex).then(a.r.cmp(&b.r)) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// `a + b` with error below 2 ulps (exact in the Sterbenz case).
#[inline(always)]
fn add_dint(a: &Dint, b: &Dint) -> Dint {
    if a.r == 0 {
        return *b;
    }
    let (a, b) = match cmp_dint_abs(a, b) {
        0 => {
            if a.sgn ^ b.sgn != 0 {
                return DINT_ZERO;
            }
            let mut r = *a;
            r.ex += 1;
            return r;
        }
        -1 => (b, a),
        _ => (a, b),
    };
    // |a| > |b|, so a.ex >= b.ex.
    let big_a = a.r;
    let k = (a.ex - b.ex) as u64;
    let big_b = if k < 128 { b.r >> k } else { 0 };
    let mut ex = a.ex;
    let c = if a.sgn ^ b.sgn != 0 {
        let mut c = big_a.wrapping_sub(big_b);
        let ch = (c >> 64) as u64;
        let mut sh = if ch != 0 {
            ch.leading_zeros()
        } else {
            64 + (c as u64).leading_zeros()
        };
        if sh > 0 {
            c = if k == 1 {
                // Sterbenz case: keep the bit B lost to the shift.
                (big_a << sh).wrapping_sub(b.r << (sh - 1))
            } else {
                (big_a << sh).wrapping_sub(big_b << sh)
            };
            ex -= i64::from(sh);
            sh = ((c >> 64) as u64).leading_zeros();
        }
        ex -= i64::from(sh);
        c << sh
    } else {
        let mut c = big_a.wrapping_add(big_b);
        if c < big_a {
            c = (1u128 << 127) | (c >> 1);
            ex += 1;
        }
        c
    };
    Dint {
        r: c,
        ex,
        sgn: a.sgn,
    }
}

/// `a * b` with error below 6 ulps.
#[inline(always)]
fn mul_dint(a: &Dint, b: &Dint) -> Dint {
    let bh = u128::from(b.hi());
    let bl = u128::from(b.lo());
    let m1 = u128::from(a.hi()) * bl;
    let m2 = u128::from(a.lo()) * bh;
    let mut r = u128::from(a.hi()) * bh;
    r += (m1 >> 64) + (m2 >> 64);
    let e = (r >> 127) as u32;
    Dint {
        r: r << (1 - e),
        ex: a.ex + b.ex + i64::from(e) - 1,
        sgn: a.sgn ^ b.sgn,
    }
}

/// `a * b` assuming the low word of `b` is zero; error below 2 ulps.
#[inline(always)]
fn mul_dint_21(a: &Dint, b: &Dint) -> Dint {
    let bh = u128::from(b.hi());
    let hi = u128::from(a.hi()) * bh;
    let lo = u128::from(a.lo()) * bh;
    let r = hi + (lo >> 64);
    let e = (r >> 127) as u32;
    Dint {
        r: r << (1 - e),
        ex: a.ex + b.ex + i64::from(e) - 1,
        sgn: a.sgn ^ b.sgn,
    }
}

/// Convert a non-zero double.
#[inline(always)]
fn dint_fromd(b: f64) -> Dint {
    let u = b.to_bits();
    let e = ((u >> 52) & 0x7ff) as i64;
    let m = (u & MASK52) + if e != 0 { 1 << 52 } else { 0 };
    let e = e - 0x3fe;
    let t = m.leading_zeros();
    Dint {
        r: u128::from(m << t) << 64,
        ex: e - if t > 11 { i64::from(t) - 12 } else { 0 },
        sgn: u64::from(b < 0.0),
    }
}

/// Round to the subnormal precision when the value is below 2^-1022
/// (round-to-nearest; CORE-MATH also handles the directed modes).
#[inline(always)]
fn subnormalize_dint(a: &mut Dint) {
    if a.ex > -1023 {
        return;
    }
    let ex = (-(1011 + a.ex)) as u32;
    let mut hi = a.hi().checked_shr(ex).unwrap_or(0);
    let md = a.hi().checked_shr(ex - 1).unwrap_or(0) & 1;
    let lo = (a.hi() & u64::MAX.checked_shr(ex).unwrap_or(0)) != 0 || a.lo() != 0;
    hi += if lo { md } else { hi & md };
    let mut new_hi = hi.checked_shl(ex).unwrap_or(0);
    if new_hi == 0 {
        a.ex += 1;
        new_hi = 1 << 63;
    }
    a.set_hi_lo(new_hi, 0);
}

/// Round to the nearest double.
#[inline(always)]
fn dint_tod(mut a: Dint) -> f64 {
    subnormalize_dint(&mut a);
    let hi = a.hi();
    let mut r = f64::from_bits((hi >> 11) | (0x3ffu64 << 52));
    let mut rd = 0.0;
    if (hi >> 10) & 1 != 0 {
        rd += hf!("0x1p-53");
    }
    if hi & 0x3ff != 0 || a.lo() != 0 {
        rd += hf!("0x1p-54");
    }
    if a.sgn != 0 {
        rd = -rd;
    }
    r = f64::from_bits(r.to_bits() | (a.sgn << 63));
    r += rd;
    let e = if a.ex > -1022 {
        if a.ex > 1024 {
            if a.ex == 1025 {
                r *= 2.0;
                hf!("0x1p+1023")
            } else {
                r = f64::MAX;
                f64::MAX
            }
        } else {
            f64::from_bits((((a.ex + 1022) & 0x7ff) as u64) << 52)
        }
    } else if a.ex < -1073 {
        if a.ex == -1074 {
            r *= 0.5;
        } else {
            r = f64::from_bits(1);
        }
        f64::from_bits(1)
    } else {
        f64::from_bits(1u64 << (a.ex + 1073))
    };
    r * e
}

/// Shift `x` so that bit 127 of `r` is set (when non-zero).
#[inline(always)]
fn normalize_dint(x: &mut Dint) {
    let (hi, lo) = (x.hi(), x.lo());
    if hi != 0 {
        let cnt = hi.leading_zeros();
        if cnt != 0 {
            x.set_hi_lo((hi << cnt) | (lo >> (64 - cnt)), lo << cnt);
        }
        x.ex -= i64::from(cnt);
    } else if lo != 0 {
        let cnt = lo.leading_zeros();
        x.set_hi_lo(lo << cnt, 0);
        x.ex -= 64 + i64::from(cnt);
    }
}

/// `(a + b, carry)` on 64-bit words.
#[inline(always)]
fn add_carry(a: u64, b: u64) -> (u64, u64) {
    let (s, c) = a.overflowing_add(b);
    (s, u64::from(c))
}

/// X/(2 pi) mod 1 with relative error below 2^-126.67; `x` normalised in
/// and out.
fn trig_reduce(x: &mut Dint) {
    let t = &TRIG_T;
    let e = x.ex;
    let xh = u128::from(x.hi());
    if e <= 1 {
        // |X| < 2: multiply by T[0]/2^64 + T[1]/2^128.
        let u = xh * u128::from(t[1]);
        let tiny = u as u64;
        let lo = (u >> 64) as u64;
        let u = xh * u128::from(t[0]);
        let (lo, carry) = add_carry(lo, u as u64);
        x.set_hi_lo(((u >> 64) as u64) + carry, lo);
        let e0 = x.ex;
        normalize_dint(x);
        let shift = e0 - x.ex;
        if shift != 0 {
            let lo = x.lo() | (tiny >> (64 - shift));
            x.set_hi_lo(x.hi(), lo);
        }
        return;
    }
    // 2 <= e <= 1024
    let i = if e < 127 {
        0
    } else {
        ((e - 127 + 64 - 1) / 64) as usize
    };
    let mut c = [0u64; 5];
    let u = xh * u128::from(t[i + 3]);
    c[0] = u as u64;
    c[1] = (u >> 64) as u64;
    let u = xh * u128::from(t[i + 2]);
    let (s, carry) = add_carry(c[1], u as u64);
    c[1] = s;
    c[2] = ((u >> 64) as u64) + carry;
    let u = xh * u128::from(t[i + 1]);
    let (s, carry) = add_carry(c[2], u as u64);
    c[2] = s;
    c[3] = ((u >> 64) as u64) + carry;
    let u = xh * u128::from(t[i]);
    let (s, carry) = add_carry(c[3], u as u64);
    c[3] = s;
    c[4] = ((u >> 64) as u64).wrapping_add(carry);
    let f = e - 64 * i as i64;
    let (hi, lo, tiny);
    if f < 64 {
        hi = (c[4] << f) | (c[3] >> (64 - f));
        lo = (c[3] << f) | (c[2] >> (64 - f));
        tiny = (c[2] << f) | (c[1] >> (64 - f));
    } else if f == 64 {
        hi = c[3];
        lo = c[2];
        tiny = c[1];
    } else {
        // 65 <= f <= 127: one more term.
        let g = f - 64;
        let u = (xh * u128::from(t[i + 4])) >> 64;
        let (s, carry0) = c[0].overflowing_add(u as u64);
        c[0] = s;
        if carry0 {
            c[1] = c[1].wrapping_add(1);
            if c[1] == 0 {
                c[2] = c[2].wrapping_add(1);
                if c[2] == 0 {
                    c[3] = c[3].wrapping_add(1);
                    if c[3] == 0 {
                        c[4] = c[4].wrapping_add(1);
                    }
                }
            }
        }
        hi = (c[3] << g) | (c[2] >> (64 - g));
        lo = (c[2] << g) | (c[1] >> (64 - g));
        tiny = (c[1] << g) | (c[0] >> (64 - g));
    }
    x.set_hi_lo(hi, lo);
    x.ex = 0;
    normalize_dint(x);
    if x.ex < 0 {
        let lo = x.lo() | (tiny >> (64 + x.ex));
        x.set_hi_lo(x.hi(), lo);
    }
}

/// Split X in [0, 1) as i/2^11 + X' with 0 <= X' < 2^-11 (exact).
#[inline(always)]
fn trig_reduce2(x: &mut Dint) -> u64 {
    if x.ex <= -11 {
        return 0;
    }
    let sh = (64 - 11 - x.ex) as u32;
    let i = x.hi() >> sh;
    x.set_hi_lo(x.hi() & ((1u64 << sh) - 1), x.lo());
    normalize_dint(x);
    i
}

/// `c1/2^64 + c0/2^128` as a double-double.
#[inline(always)]
fn trig_set_dd(mut c1: u64, mut c0: u64) -> (f64, f64) {
    if c1 != 0 {
        let e = u64::from(c1.leading_zeros());
        if e != 0 {
            c1 = (c1 << e) | (c0 >> (64 - e));
            c0 <<= e;
        }
        let f = 0x3fe - e;
        let h = f64::from_bits((f << 52) | ((c1 << 1) >> 12));
        let c0 = (c1 << 53) | (c0 >> 11);
        let l = if c0 != 0 {
            let g = u64::from(c0.leading_zeros());
            let c0 = c0 << g;
            f64::from_bits(((f - 53 - g) << 52) | ((c0 << 1) >> 12))
        } else {
            0.0
        };
        (h, l)
    } else if c0 != 0 {
        let e = u64::from(c0.leading_zeros());
        let f = 0x3fe - 64 - e;
        let c0 = c0 << (e + 1); // most significant bit shifted out
        let h = f64::from_bits((f << 52) | (c0 >> 12));
        let c0 = c0 << 52;
        let l = if c0 != 0 {
            let g = u64::from(c0.leading_zeros());
            let c0 = c0 << (g + 1);
            f64::from_bits(((f - 64 - g) << 52) | (c0 >> 12))
        } else {
            0.0
        };
        (h, l)
    } else {
        (0.0, 0.0)
    }
}

/// For 0x1.6a09e667f3bccp-27 < x: `(i, h, l, err1)` with i/2^11 + h + l ~
/// frac(x/(2 pi)) up to absolute error `err1`.
#[inline(always)]
fn trig_reduce_fast(x: f64) -> (u64, f64, f64, f64) {
    let (h, l, err1);
    if x <= hf!("0x1.921fb54442d17p+2") {
        // x < 2 pi
        const CH: f64 = hf!("0x1.45f306dc9c883p-3");
        const CL: f64 = hf!("-0x1.6b01ec5417056p-57");
        let (hh, ll) = a_mul(CH, x);
        h = hh;
        l = CL.mul_add(x, ll);
        err1 = hf!("0x1.d9p-105") * h;
    } else {
        let tt = &TRIG_T;
        let t = x.to_bits();
        let e = ((t >> 52) & 0x7ff) as i64; // 1025 <= e <= 2046
        let m = (1u64 << 52) | (t & MASK52);
        let mut c = [0u64; 3];
        let shift;
        if e <= 1074 {
            let u = u128::from(m) * u128::from(tt[1]);
            c[0] = u as u64;
            c[1] = (u >> 64) as u64;
            let u = u128::from(m) * u128::from(tt[0]);
            let (s, carry) = add_carry(c[1], u as u64);
            c[1] = s;
            c[2] = ((u >> 64) as u64) + carry;
            shift = 1075 - e; // 1 <= shift <= 50
        } else {
            let i = ((e - 1138 + 63) / 64) as usize;
            let u = u128::from(m) * u128::from(tt[i + 2]);
            c[0] = u as u64;
            c[1] = (u >> 64) as u64;
            let u = u128::from(m) * u128::from(tt[i + 1]);
            let (s, carry) = add_carry(c[1], u as u64);
            c[1] = s;
            c[2] = ((u >> 64) as u64) + carry;
            let u = u128::from(m) * u128::from(tt[i]);
            c[2] = c[2].wrapping_add(u as u64);
            shift = 1139 + ((i as i64) << 6) - e; // 1 <= shift <= 64
        }
        if shift == 64 {
            c[0] = c[1];
            c[1] = c[2];
        } else {
            c[0] = (c[1] << (64 - shift)) | (c[0] >> shift);
            c[1] = (c[2] << (64 - shift)) | (c[1] >> shift);
        }
        let (hh, ll) = trig_set_dd(c[1], c[0]);
        h = hh;
        l = ll;
        err1 = hf!("0x1.01p-76");
    }
    let i = (h * hf!("0x1p11")).floor();
    let h = i.mul_add(hf!("-0x1p-11"), h);
    (i as u64, h, l, err1)
}

/// sin2pi(xh + xl) for 2^-24 <= xh + xl < 2^-11 + 2^-24, given
/// uh + ul ~ (xh + xl)^2; absolute error < 2^-77.09.
#[inline(always)]
fn trig_eval_ps_fast(xh: f64, xl: f64, uh: f64, ul: f64) -> (f64, f64) {
    let p = &TRIG_PSFAST;
    let mut h = p[4];
    h = h.mul_add(uh, p[3]);
    h = h.mul_add(uh, p[2]);
    let (h, mut l) = s_mul(h, uh, ul);
    let (h, t) = fasttwosum(p[0], h);
    l += p[1] + t;
    d_mul_trig(h, l, xh, xl)
}

/// cos2pi(xh + xl) for 2^-24 <= xh + xl < 2^-11 + 2^-24; relative error
/// < 2^-69.96.
#[inline(always)]
fn trig_eval_pc_fast(uh: f64, ul: f64) -> (f64, f64) {
    let p = &TRIG_PCFAST;
    let mut h = p[4];
    h = h.mul_add(uh, p[3]);
    h = h.mul_add(uh, p[2]);
    let (h, mut l) = s_mul(h, uh, ul);
    let (h, t) = fasttwosum(p[0], h);
    l += p[1] + t;
    (h, l)
}

/// sin2pi(X) for 0 <= X < 2^-11, X2 ~ X^2.
#[inline(always)]
fn trig_eval_ps(x: &Dint, x2: &Dint) -> Dint {
    let ps = |k: usize| Dint::from_parts(TRIG_PS[k]);
    let mut y = mul_dint_21(x2, &ps(5));
    y = add_dint(&y, &ps(4));
    for k in [3usize, 2, 1, 0] {
        y = mul_dint(&y, x2);
        y = add_dint(&y, &ps(k));
    }
    mul_dint(&y, x)
}

/// cos2pi(X) for 0 <= X < 2^-11, X2 ~ X^2.
#[inline(always)]
fn trig_eval_pc(x2: &Dint) -> Dint {
    let pc = |k: usize| Dint::from_parts(TRIG_PC[k]);
    let mut y = mul_dint_21(x2, &pc(5));
    y = add_dint(&y, &pc(4));
    for k in [3usize, 2, 1, 0] {
        y = mul_dint(&y, x2);
        y = add_dint(&y, &pc(k));
    }
    y
}

// --- cos (CORE-MATH src/binary64/cos/cos.c) ------------------------------------

/// cos.c `d_mul`: `(ah + al) * (bh + bl) - al*bl`, adding the cross terms
/// in the opposite order to pow.c's.
#[inline(always)]
fn d_mul_trig(ah: f64, al: f64, bh: f64, bl: f64) -> (f64, f64) {
    let (hi, s) = a_mul(ah, bh);
    let t = al.mul_add(bh, s);
    (hi, ah.mul_add(bl, t))
}

/// Fast cos(x) for 0x1.6a09e667f3bccp-27 < x: `(h, l, err)`.
#[inline(always)]
fn cos_fast(x: f64) -> (f64, f64, f64) {
    let (i, mut h, mut l, err1) = trig_reduce_fast(x);
    let mut neg = (i >> 10) & 1;
    let i = i & 0x3ff;
    let mut is_cos = 1 ^ (i >> 9);
    neg ^= i >> 9;
    let mut i = (i & 0x1ff) as usize;
    if i & 0x100 != 0 {
        is_cos ^= 1;
        i = 0x1ff - i;
        h = hf!("0x1p-11") - h;
        l = -l;
    }
    let sc = &TRIG_SC[i];
    h -= sc[0];
    let (uh, ul) = a_mul(h, h);
    let ul = (h + h).mul_add(l, ul);
    let (sh, sl) = trig_eval_ps_fast(h, l, uh, ul);
    let (ch, cl) = trig_eval_pc_fast(uh, ul);
    let err;
    if is_cos == 0 {
        let (sh, sl) = s_mul(sc[2], sh, sl);
        let (ch, cl) = s_mul(sc[1], ch, cl);
        let (hh, ll) = fasttwosum(ch, sh);
        h = hh;
        l = ll + (sl + cl);
        err = hf!("0x1.55p-69");
    } else {
        let (ch, cl) = s_mul(sc[2], ch, cl);
        let (sh, sl) = s_mul(sc[1], sh, sl);
        let (hh, ll) = fasttwosum(ch, -sh);
        h = hh;
        l = ll + (cl - sl);
        err = hf!("0x1.81p-69");
    }
    const SGN: [f64; 2] = [1.0, -1.0];
    (h * SGN[neg as usize], l * SGN[neg as usize], err + err1)
}

/// Accurate cos(x) for 0x1.6a09e667f3bccp-27 < x in 128-bit arithmetic.
#[cold]
#[inline(never)]
fn cos_accurate(x: f64) -> f64 {
    let mut xd = dint_fromd(x);
    trig_reduce(&mut xd);
    let mut neg = false;
    let mut is_cos = true;
    let mut i = trig_reduce2(&mut xd) as usize;
    if i & 0x400 != 0 {
        neg = true;
        i &= 0x3ff;
    }
    if i & 0x200 != 0 {
        neg = !neg;
        is_cos = false;
        i &= 0x1ff;
    }
    if i & 0x100 != 0 {
        is_cos = !is_cos;
        xd.sgn = 1;
        xd = add_dint(&DINT_MAGIC, &xd); // 2^-11 - X
        i = 0x1ff - i;
    }
    let x2 = mul_dint(&xd, &xd);
    let mut u = trig_eval_pc(&x2);
    let mut v = trig_eval_ps(&xd, &x2);
    let s_i = Dint::from_parts(TRIG_S[i]);
    let c_i = Dint::from_parts(TRIG_C[i]);
    if !is_cos {
        u = mul_dint(&s_i, &u);
        v = mul_dint(&c_i, &v);
    } else {
        u = mul_dint(&c_i, &u);
        v = mul_dint(&s_i, &v);
        v.sgn = 1 - v.sgn;
    }
    let mut u = add_dint(&u, &v);
    const ERR: u64 = 41;
    let lo0 = u.lo().wrapping_sub(ERR);
    let hi0 = u.hi().wrapping_sub(u64::from(lo0 > u.lo()));
    let lo1 = u.lo().wrapping_add(ERR);
    let hi1 = u.hi().wrapping_add(u64::from(lo1 < u.lo()));
    if (hi0 >> 10) != (hi1 >> 10) {
        const EXCEPTIONS: [[f64; 3]; 5] = [
            [
                hf!("0x1.8000000000009p-23"),
                hf!("0x1.fffffffffff7p-1"),
                hf!("0x1.b56666666666cp-143"),
            ],
            [
                hf!("0x1.8000000000024p-22"),
                hf!("0x1.ffffffffffdcp-1"),
                hf!("0x1.b56666666667ep-137"),
            ],
            [
                hf!("0x1.800000000009p-21"),
                hf!("0x1.ffffffffff7p-1"),
                hf!("0x1.b5666666666c4p-131"),
            ],
            [
                hf!("0x1.20000000000f3p-20"),
                hf!("0x1.fffffffffebcp-1"),
                hf!("0x1.37642666666fdp-127"),
            ],
            [
                hf!("0x1.800000000024p-20"),
                hf!("0x1.fffffffffdcp-1"),
                hf!("0x1.b5666666667ddp-125"),
            ],
        ];
        for e in &EXCEPTIONS {
            if x.abs() == e[0] {
                return e[1] + e[2];
            }
        }
    }
    if neg {
        u.sgn = 1 - u.sgn;
    }
    dint_tod(u)
}

/// Correctly rounded `cos`.
pub fn cos(x: f64) -> f64 {
    let t = x.to_bits();
    let e = (t >> 52) & 0x7ff;
    if e == 0x7ff {
        // ±inf: the default NaN with FE_INVALID; NaN propagates.
        return x * 0.0;
    }
    let ax = x.abs();
    if ax.to_bits() <= 0x3e46_a09e_667f_3bcc {
        // |x| <= 0x1.6a09e667f3bccp-27: cos(x) rounds to 1.
        return ax.mul_add(hf!("-0x1p-28"), 1.0);
    }
    if e < 1054
        && let Some(r) = cos_moderate(ax)
    {
        return r;
    }
    let (h, l, err) = cos_fast(ax);
    let left = h + (l - err);
    let right = h + (l + err);
    if left == right {
        return left;
    }
    cos_accurate(ax)
}

// --- tan (CORE-MATH src/binary64/tan/tan.c) ------------------------------------

/// 1.
const DINT_ONE: Dint = Dint::from_parts((1 << 63, 0, 1, 0));

/// 1/a for non-zero `a`, relative error below 2^-124.999: three integer
/// Newton steps on a table seed, then one in 128-bit floating point.
#[inline(always)]
fn inv_dint(a: &Dint) -> Dint {
    let h = a.hi();
    let mut t = TRIG_TINV[((h >> 55) & 0xff) as usize];
    let one127 = 1u128 << 127;
    let e = one127.wrapping_sub(u128::from(h) * u128::from(t));
    let e = u128::from(t).wrapping_mul(e >> 55);
    t = t.wrapping_add((e >> 72) as u64);
    let e = one127.wrapping_sub(u128::from(h) * u128::from(t));
    let e = u128::from(t).wrapping_mul(e >> 47);
    t = t.wrapping_add((e >> 80) as u64);
    let e = one127.wrapping_sub(u128::from(h) * u128::from(t));
    let e = u128::from(t).wrapping_mul(e >> 31);
    t = t.wrapping_add((e >> 96) as u64);
    let mut r = Dint {
        r: u128::from(t) << 64,
        ex: 1 - a.ex,
        sgn: 1,
    };
    let q = mul_dint_21(a, &r); // -a*r
    r.sgn = 0;
    let q = add_dint(&DINT_ONE, &q); // 1 - a*r
    let q = mul_dint(&r, &q); // r*(1 - a*r)
    add_dint(&r, &q)
}

/// b/a with relative error below 2^-123.67.
#[inline(always)]
fn div_dint(b: &Dint, a: &Dint) -> Dint {
    let r = inv_dint(a);
    mul_dint(&r, b)
}

/// tan.c `reduce_fast`: `(i, h, l)` with i/2^11 + h + l ~ frac(x/(2 pi))
/// to within 2^-104.815, for 0x1.d12ed0af1a27ep-27 < x.
#[inline(always)]
fn tan_reduce_fast(x: f64) -> (u64, f64, f64) {
    let (h, l);
    if x <= hf!("0x1.921fb54442d17p+2") {
        const CH: f64 = hf!("0x1.45f306dc9c883p-3");
        const CL: f64 = hf!("-0x1.6b01ec5417056p-57");
        let (hh, ll) = a_mul(CH, x);
        h = hh;
        l = CL.mul_add(x, ll);
    } else {
        let tt = &TRIG_T;
        let t = x.to_bits();
        let e = ((t >> 52) & 0x7ff) as i64;
        let m = u128::from((1u64 << 52) | (t & MASK52));
        // m*(w0 + w1/2^64 + w2/2^128) as three words, keeping the carry of
        // the top half of m*w2 into the bottom word.
        let fold = |w0: u64, w1: u64, w2: u64| {
            let v = m * u128::from(w2);
            let u = m * u128::from(w1);
            let c0 = u.wrapping_add(v >> 64) as u64;
            let c1 = ((u >> 64) as u64) + u64::from(c0 < u as u64);
            let u = m * u128::from(w0);
            let (c1, carry) = add_carry(c1, u as u64);
            (c0, c1, ((u >> 64) as u64).wrapping_add(carry))
        };
        let (mut c0, mut c1, mut c2);
        let shift;
        if e <= 1074 {
            // 2^2 <= x < 2^52
            (c0, c1, c2) = fold(tt[0], tt[1], tt[2]);
            shift = 1075 - e; // 1 <= shift <= 50
        } else {
            // 2^52 <= x: only the low word of m*T[i] reaches the fraction.
            let i = ((e - 1138 + 63) / 64) as usize;
            (c0, c1, c2) = fold(tt[i + 1], tt[i + 2], tt[i + 3]);
            c2 = c2.wrapping_add((m * u128::from(tt[i])) as u64);
            shift = 1139 + ((i as i64) << 6) - e; // 1 <= shift <= 64
        }
        if shift == 64 {
            c0 = c1;
            c1 = c2;
        } else {
            c0 = (c1 << (64 - shift)) | (c0 >> shift);
            c1 = (c2 << (64 - shift)) | (c1 >> shift);
        }
        let (hh, ll) = trig_set_dd(c1, c0);
        h = hh;
        l = ll;
    }
    let i = (h * hf!("0x1p11")).floor();
    let h = i.mul_add(hf!("-0x1p-11"), h);
    (i as u64, h, l)
}

/// (bh + bl)/(ah + al) by Karp-Markstein, relative error below 2^-96.99.
#[inline(always)]
fn tan_fast_div(bh: f64, bl: f64, ah: f64, al: f64) -> (f64, f64) {
    let y = 1.0 / ah;
    let h = bh * y;
    let eh = ah.mul_add(-h, bh);
    let el = al.mul_add(-h, bl);
    (h, y * (eh + el))
}

/// Fast tan(x) for |x| > 0x1.d12ed0af1a27ep-27: `(h, l, err)`.
#[inline(always)]
fn tan_fast(x: f64) -> (f64, f64, f64) {
    let mut neg = u64::from(x < 0.0);
    let (i, mut h, mut l) = tan_reduce_fast(x.abs());
    let i = i & 0x3ff;
    let mut is_tan = 1 ^ (i >> 9);
    neg ^= i >> 9;
    let mut i = (i & 0x1ff) as usize;
    if i & 0x100 != 0 {
        is_tan ^= 1;
        i = 0x1ff - i;
        h = hf!("0x1p-11") - h;
        l = -l;
    }
    if i == 0 && h < hf!("0x1p-37") {
        // Too close to a multiple of pi/2 for the fast path's error bound.
        return (h, l, 1.0);
    }
    let sc = &TRIG_SC[i];
    h -= sc[0];
    let (h, l) = fasttwosum(h, l);
    let (uh, ul) = a_mul(h, h);
    let ul = (h + h).mul_add(l, ul);
    let (sh, sl) = trig_eval_ps_fast(h, l, uh, ul);
    let (ch, cl) = trig_eval_pc_fast(uh, ul);
    let (sh0, sl0) = s_mul(sc[2], sh, sl);
    let (ch0, cl0) = s_mul(sc[1], ch, cl);
    let (h1, mut l1) = fasttwosum(ch0, sh0);
    l1 += sl0 + cl0;
    let (ch, cl) = s_mul(sc[2], ch, cl);
    let (sh, sl) = s_mul(sc[1], sh, sl);
    let (h2, mut l2) = fasttwosum(ch, -sh);
    l2 += cl - sl;
    let (h, l) = if is_tan != 0 {
        tan_fast_div(h1, l1, h2, l2)
    } else {
        tan_fast_div(h2, l2, h1, l1)
    };
    const SGN: [f64; 2] = [1.0, -1.0];
    let h = h * SGN[neg as usize];
    let l = l * SGN[neg as usize];
    (h, l, h * hf!("0x1.1ap-66"))
}

/// Accurate tan(x) for |x| > 0x1.d12ed0af1a27ep-27 in 128-bit arithmetic.
#[cold]
#[inline(never)]
fn tan_accurate(x: f64) -> f64 {
    let mut xd = dint_fromd(x.abs());
    trig_reduce(&mut xd);
    let mut is_tan = true;
    let mut neg = x < 0.0;
    let mut i = (trig_reduce2(&mut xd) & 0x3ff) as usize;
    if i & 0x200 != 0 {
        is_tan = false;
        neg = !neg;
        i &= 0x1ff;
    }
    if i & 0x100 != 0 {
        is_tan = !is_tan;
        xd.sgn = 1;
        xd = add_dint(&DINT_MAGIC, &xd); // 2^-11 - X
        i = 0x1ff - i;
    }
    let x2 = mul_dint(&xd, &xd);
    let u = trig_eval_pc(&x2);
    let v = trig_eval_ps(&xd, &x2);
    let s_i = Dint::from_parts(TRIG_S[i]);
    let c_i = Dint::from_parts(TRIG_C[i]);
    let sin = add_dint(&mul_dint(&s_i, &u), &mul_dint(&c_i, &v));
    let mut sv = mul_dint(&s_i, &v);
    sv.sgn = 1 - sv.sgn;
    let cos = add_dint(&mul_dint(&c_i, &u), &sv);
    let mut q = if is_tan {
        div_dint(&sin, &cos)
    } else {
        div_dint(&cos, &sin)
    };
    const ERR: u64 = 86;
    let lo0 = q.lo().wrapping_sub(ERR);
    let hi0 = q.hi().wrapping_sub(u64::from(lo0 > q.lo()));
    let lo1 = q.lo().wrapping_add(ERR);
    let hi1 = q.hi().wrapping_add(u64::from(lo1 < q.lo()));
    if (hi0 >> 10) != (hi1 >> 10) {
        const EXCEPTIONS: [[f64; 3]; 2] = [
            [
                hf!("0x1.dffffffffff1fp-22"),
                hf!("0x1.e000000000151p-22"),
                hf!("0x1.fffffffffffffp-76"),
            ],
            [
                hf!("0x1.dfffffffffc7cp-21"),
                hf!("0x1.e000000000546p-21"),
                hf!("-0x1.658bcedb6e1d4p-147"),
            ],
        ];
        for e in &EXCEPTIONS {
            if x.abs() == e[0] {
                return if x > 0.0 { e[1] + e[2] } else { -e[1] - e[2] };
            }
        }
    }
    if neg {
        q.sgn = 1 - q.sgn;
    }
    dint_tod(q)
}

/// Correctly rounded `tan`.
pub fn tan(x: f64) -> f64 {
    let t = x.to_bits();
    let e = (t >> 52) & 0x7ff;
    if e == 0x7ff {
        // ±inf: the default NaN with FE_INVALID; NaN propagates.
        return x * 0.0;
    }
    if t & 0x7fff_ffff_ffff_ffff <= 0x3e4d_12ed_0af1_a27e {
        // |x| <= 0x1.d12ed0af1a27ep-27: tan(x) rounds to x.
        if x == 0.0 {
            return x;
        }
        return x.mul_add(hf!("0x1p-54"), x);
    }
    let (h, l, err) = tan_fast(x);
    let left = h + (l - err);
    let right = h + (l + err);
    if left == right {
        return left;
    }
    tan_accurate(x)
}

// --- tgamma (CORE-MATH src/binary64/tgamma/tgamma.c) ---------------------------

/// tgamma.c `sumdd`: `(xh + xl) + (yh + yl)` ordering the FastTwoSum by
/// magnitude.
#[inline(always)]
fn sumdd_ordered(xh: f64, xl: f64, yh: f64, yl: f64) -> (f64, f64) {
    let (sh, sl) = if xh.abs() > yh.abs() {
        fasttwosum(xh, yh)
    } else {
        fasttwosum(yh, xh)
    };
    (sh, (xl + yl) + sl)
}

/// tgamma.c `twosum`: FastTwoSum with the operands ordered by magnitude.
#[inline(always)]
fn twosum_ordered(x: f64, y: f64) -> (f64, f64) {
    if x.abs() > y.abs() {
        fasttwosum(x, y)
    } else {
        fasttwosum(y, x)
    }
}

/// tgamma.c `muldd3`: double-double product, normalised.
#[inline(always)]
fn muldd3(xh: f64, xl: f64, yh: f64, yl: f64) -> (f64, f64) {
    let ch = xh * yh;
    let cl1 = xh.mul_add(yh, -ch);
    let tl0 = xl * yl;
    let tl1 = tl0 + xh * yl;
    let cl2 = tl1 + xl * yh;
    let cl3 = cl1 + cl2;
    fasttwosum(ch, cl3)
}

/// tgamma.c `mulddd`: `x * (ch + cl)`.
#[inline(always)]
fn mulddd_tg(x: f64, ch: f64, cl: f64) -> (f64, f64) {
    let ahhh = ch * x;
    (ahhh, cl * x + ch.mul_add(x, -ahhh))
}

/// tgamma.c `polydd`: double-double Horner at `xh + xl`.
#[inline(always)]
fn polydd_tg(xh: f64, xl: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let (mut ch, mut cl) = fasttwosum(c[i][0], l);
    cl += c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = muldd_sin(xh, xl, ch, cl);
        (ch, cl) = fastsum_dd(c[i][0], c[i][1], ch, cl);
    }
    (ch, cl)
}

/// tgamma.c `polyddd`: double-double Horner at the double `x`.
#[inline(always)]
fn polyddd_tg(x: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let (mut ch, mut cl) = fasttwosum(c[i][0], l);
    cl += c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = mulddd_tg(x, ch, cl);
        (ch, cl) = sumdd_ordered(c[i][0], c[i][1], ch, cl);
    }
    (ch, cl)
}

/// tgamma.c `polyd`: Horner on the high parts only.
#[inline(always)]
fn polyd_tg(x: f64, c: &[[f64; 2]]) -> f64 {
    let mut i = c.len() - 1;
    let mut ch = c[i][0];
    while i > 0 {
        i -= 1;
        ch = c[i][0] + x * ch;
    }
    ch
}

/// Split `x` so that ulp(xh) = 2^-25 (exact for |x| <= 2^26).
#[inline(always)]
fn splt(x: f64) -> (f64, f64) {
    const OFF: f64 = hf!("0x1.8p27");
    let xh = (x + OFF) - OFF;
    (xh, x - xh)
}

/// `x * (x0 + x1 + x2)` as a triple `(l0, l1, l2)`.
#[inline(always)]
fn sprod(x: f64, x0: f64, x1: f64, x2: f64) -> (f64, f64, f64) {
    let z0 = x * x0;
    let z0l = x.mul_add(x0, -z0);
    let z1 = x * x1;
    let z2 = x * x2 + x.mul_add(x1, -z1);
    let (z0, e) = splt(z0);
    let (e, z0l) = fasttwosum(e, z0l);
    let (l1, e) = twosum_ordered(e, z1);
    (z0, l1, e + z0l + z2)
}

/// Triple-double polynomial with leading coefficients `ch` and a
/// double-double tail `cl`, at `d` (tgamma.c `poly3`).
fn tg_poly3(d: f64, ch: &[f64], cl: &[[f64; 2]]) -> (f64, f64) {
    let (mut t0, mut t1, mut t2) = (1.0, 0.0, 0.0);
    let mut s0 = ch[0];
    let (mut s1, mut s2) = (0.0, 0.0);
    for &c in &ch[1..] {
        (t0, t1, t2) = sprod(d, t0, t1, t2);
        s0 += t0 * c;
        let (fh, fl) = mulddd_tg(c, t1, t2);
        (s1, s2) = sumdd_ordered(s1, s2, fh, fl);
    }
    let (fh, fl) = polyddd_tg(d, cl, 0.0);
    (s1, s2) = sumdd_ordered(s1, s2, fh, fl);
    let (s0, s1) = fasttwosum(s0, s1);
    let (s1, _) = fasttwosum(s1, s2);
    (s0, s1)
}

/// Raise FE_UNDERFLOW (and FE_INEXACT), as upstream's `raise_underflow`.
#[inline(always)]
fn raise_underflow() {
    let tiny = core::hint::black_box(f64::MIN_POSITIVE);
    let _ = core::hint::black_box(tiny * tiny);
}

/// Accurate tgamma, for inputs whose fast-path rounding test failed.
#[cold]
#[inline(never)]
fn tgamma_accurate(x: f64) -> f64 {
    if x.abs() < 0.25 {
        let c = &TG_ACC0_C;
        let x2 = x * x;
        let x4 = x2 * x2;
        let mut c0 = c[0] + x * c[1] + x2 * (c[2] + x * c[3]);
        let c4 = c[4] + x * c[5] + x2 * (c[6] + x * c[7]);
        c0 += x4 * c4;
        let (ch, cl) = polyddd_tg(x, &TG_ACC0_CC, x * c0);
        let fh = 1.0 / x;
        let dh = fh.mul_add(-x, 1.0);
        let fl = dh * fh;
        let fll = fl.mul_add(-x, dh) * fh;
        let (fl, fll) = sumdd_ordered(fl, fll, ch, cl);
        let (fl, fll) = twosum_ordered(fl, fll);
        let (fh, fl) = fasttwosum(fh, fl);
        let (mut fl, fll) = fasttwosum(fl, fll);
        let (_, et) = fasttwosum(fh, 2.0 * fl);
        if et == 0.0 {
            if 1.0f64.copysign(fl) * 1.0f64.copysign(fll) > 0.0 {
                fl *= 1.0 + hf!("0x1p-50");
            } else {
                fl *= 1.0 - hf!("0x1p-50");
            }
        }
        return fh + fl;
    }
    let ix = x.floor();
    let d = 2.0 * (x - (ix + 0.5));
    let i = ix as i32;
    let (ch, cl, top, mut eoff): (&[f64], &[[f64; 2]], i32, i32) = if i > 159 {
        (&TG_ACC_CH160, &TG_ACC_CL160, 160, 942)
    } else if i > 127 {
        (&TG_ACC_CH128, &TG_ACC_CL128, 128, 713)
    } else if i > 95 {
        (&TG_ACC_CH96, &TG_ACC_CL96, 96, 495)
    } else if i > 63 {
        (&TG_ACC_CH64, &TG_ACC_CL64, 64, 293)
    } else if i > 31 {
        (&TG_ACC_CH32, &TG_ACC_CL32, 32, 115)
    } else if i > 25 {
        (&TG_ACC_CH26, &TG_ACC_CL26, 26, 86)
    } else if i > 15 {
        (&TG_ACC_CH16, &TG_ACC_CL16, 16, 42)
    } else if i > 7 {
        (&TG_ACC_CH8, &TG_ACC_CL8, 8, 14)
    } else {
        (&TG_ACC_CH4, &TG_ACC_CL4, 4, 3)
    };
    let (mut fh, mut fl) = tg_poly3(d, ch, cl);
    let jm = top - i;
    let (mut wh, mut wl) = (1.0, 0.0);
    if jm > 0 {
        // Gamma(x) = Gamma(x + jm) / (x (x+1) ... (x+jm-1))
        let (mut xph, mut xpl) = (x, 0.0);
        wh = xph;
        for _ in 1..jm {
            let l;
            (xph, l) = if xph.abs() > 1.0 {
                fasttwosum(xph, 1.0)
            } else {
                fasttwosum(1.0, xph)
            };
            xpl += l;
            (xph, xpl) = fasttwosum(xph, xpl);
            (wh, wl) = muldd3(xph, xpl, wh, wl);
            if wh.abs() > hf!("0x1p518") {
                wh *= hf!("0x1p-500");
                wl *= hf!("0x1p-500");
                eoff -= 500;
            }
        }
    } else if jm < 0 {
        // Gamma(x) = Gamma(x - |jm|) * (x-1) (x-2) ... (x-|jm|)
        let (mut xph, mut xpl) = (x - 1.0, 0.0);
        wh = xph;
        for _ in 0..(-1 - jm) {
            let l;
            (xph, l) = fasttwosum(xph, -1.0);
            xpl += l;
            (xph, xpl) = fasttwosum(xph, xpl);
            (wh, wl) = muldd3(xph, xpl, wh, wl);
        }
    }
    if jm > 0 {
        let rh = 1.0 / wh;
        let rl = (rh.mul_add(-wh, 1.0) - wl * rh) * rh;
        (fh, fl) = muldd3(fh, fl, rh, rl);
    } else if jm < 0 {
        (fh, fl) = muldd3(fh, fl, wh, wl);
    }
    // Directed-rounding corrections; both are exactly zero to nearest.
    let mut crr = 0.0;
    if jm <= 0 {
        crr = ((hf!("0x1p-54") + hf!("0x1p-107")) - hf!("0x1p-54"))
            + ((hf!("0x1p-53") - hf!("0x1p-107")) - hf!("0x1p-53"));
        fl += fh * (f64::from(jm) * crr);
    } else {
        let op = hf!("0x1p-53") - hf!("0x1p-107");
        let om = hf!("-0x1p-53") + hf!("0x1p-107");
        if op == -om {
            crr = hf!("0x1p-53") - op;
        }
        fl -= fh * (f64::from(jm - 5) * crr * 1.04);
    }
    let eps = hf!("0x1.ep-103") * fh;
    let ub = fh + (fl + eps);
    let lb = fh + (fl - eps);
    let mut res = (fh + fl).to_bits();
    let re = ((res >> 52) & 0x7ff) as i64;
    if re + i64::from(eoff) <= 0 {
        // Subnormal result: round at the subnormal precision.
        res = res.wrapping_sub(((i64::from(eoff) + re - 1) as u64) << 52);
        res &= 0xfffu64 << 52;
        let (h, l) = fasttwosum(f64::from_bits(res), fh);
        fl += l;
        res = (h + fl).to_bits();
        res &= !(0x7ffu64 << 52);
        raise_underflow();
    } else {
        res = res.wrapping_add((eoff as u64) << 52);
    }
    let res = f64::from_bits(res);
    if ub != lb {
        for e in &TG_DB {
            if e[0] == x {
                return e[1] + e[2];
            }
        }
    }
    res
}

/// log(x) as a double-double for x > 0 (tgamma.c `as_logd`).
#[inline(never)]
fn tg_logd(x: f64) -> (f64, f64) {
    let mut t = x.to_bits();
    let e = (t >> 52) as i32 - 0x3ff;
    t &= MASK52;
    let ed = f64::from(e);
    let (i1, i2) = log_table_index(t);
    let tf = f64::from_bits(t | (0x3ffu64 << 52));
    let r = TG_LOG_R1[i1] * TG_LOG_R2[i2];
    let o = r * tf;
    let dxl = r.mul_add(tf, -o);
    let dxh = o - 1.0;
    const C: [f64; 4] = [
        hf!("-0x1.fffffffffffd3p-2"),
        hf!("0x1.55555555543d5p-2"),
        hf!("-0x1.000002bb2d74ep-2"),
        hf!("0x1.999a692c56e4ep-3"),
    ];
    let dx = r.mul_add(tf, -1.0);
    let dx2 = dx * dx;
    let f = dx2 * ((C[0] + dx * C[1]) + dx2 * (C[2] + dx * C[3]));
    let lt = (TG_LOG_L1[i1][1] + TG_LOG_L2[i2][1]) + ed * hf!("0x1.62e42fef8p-1");
    let lh = lt + dxh;
    let mut ll = (lt - lh) + dxh;
    ll += ((TG_LOG_L1[i1][0] + TG_LOG_L2[i2][0]) + hf!("0x1.1cf79abc9e3b4p-36") * ed) + dxl;
    ll += f;
    (lh, ll)
}

/// sin(pi x) as a double-double for 0 <= x < 1 (tgamma.c `as_sinpid`).
#[inline(never)]
fn tg_sinpid(x: f64) -> (f64, f64) {
    let x = (x - 0.5).abs() * 128.0;
    let ix = x.round_ties_even();
    let d = ix - x;
    let d2 = d * d;
    let ky = ix as usize;
    let kx = 64 - ky;
    let (sh, sl) = (TG_ST[kx][1], TG_ST[kx][0]);
    let (ch, cl) = (TG_ST[ky][1], TG_ST[ky][0]);
    const C: [f64; 4] = [
        hf!("-0x1.3bd3cc9be45dep-12"),
        hf!("0x1.03c1f081b5ac4p-26"),
        hf!("-0x1.55d3c7e3bd8bfp-42"),
        hf!("0x1.e1f4826790653p-59"),
    ];
    const C0: f64 = hf!("-0x1.692b66e3cf6e8p-66");
    const S: [f64; 4] = [
        hf!("0x1.921fb54442d18p-6"),
        hf!("-0x1.4abbce625be53p-19"),
        hf!("0x1.466bc67748efcp-34"),
        hf!("-0x1.32d26e446373ap-50"),
    ];
    const S0: f64 = hf!("0x1.1a624b88c9448p-60");
    let p = d2 * (C[1] + d2 * (C[2] + d2 * C[3]));
    let q = d2 * (S[1] + d2 * (S[2] + d2 * S[3]));
    let (qh, mut ql) = fasttwosum(S[0], q);
    ql += S0;
    let (ch, cl) = muldd_sin(qh, ql, ch, cl);
    let (th, mut tl) = fasttwosum(C[0], p);
    tl += C0;
    let (th, tl) = mulddd_tg(d, th, tl);
    let (ph, pl) = muldd_sin(th, tl, sh, sl);
    let (ch, cl) = fastsum_dd(ch, cl, ph, pl);
    let (ch, cl) = mulddd_tg(d, ch, cl);
    fastsum_dd(sh, sl, ch, cl)
}

/// exp(x + l) as `2^e * (h + l)` (tgamma.c `as_expd`).
#[inline(never)]
fn tg_expd(x: f64, l: f64) -> (f64, f64, i32) {
    const LN2H: f64 = hf!("0x1.71547652b82fep+10");
    const LN2L: f64 = hf!("0x1.777d0ffda0d24p-46");
    let (xh, xl) = muldd_sin(x, l, LN2H, LN2L);
    let ix = xh.round_ties_even();
    let (xh, xl) = fasttwosum(xh - ix, xl);
    let k = ix as i32;
    let i0 = ((k >> 5) & 31) as usize;
    let i1 = (k & 31) as usize;
    let e = k >> 10;
    let (rh, rl) = muldd_sin(TG_E0[i0][1], TG_E0[i0][0], TG_E1[i1][1], TG_E1[i1][0]);
    const M: usize = 1;
    let c = &TG_EXP_C;
    let fl = xh * polyd_tg(xh, &c[M..]);
    let (fh, fl) = polydd_tg(xh, xl, &c[..M], fl);
    let (fh, fl) = muldd_sin(xh, xl, fh, fl);
    let (fh, el) = fasttwosum(1.0, fh);
    let fl = fl + el;
    let (rh, rl) = muldd_sin(rh, rl, fh, fl);
    (rh, rl, e)
}

/// log(Gamma(x)) by Stirling's series, for x > 3 (tgamma.c `as_lgamma_asym`).
#[inline(never)]
fn tg_lgamma_asym(xh: f64, xl: f64) -> (f64, f64) {
    let zh = 1.0 / xh;
    let dz = xl * zh;
    let zl = (zh.mul_add(-xh, 1.0) - dz) * zh;
    let (lh, mut ll) = tg_logd(xh);
    ll += dz;
    let (lh0, ll0) = muldd_sin(xh - 0.5, xl, lh - 1.0, ll);
    let (z2h, z2l) = muldd_sin(zh, zl, zh, zl);
    let x2 = z2h * z2h;
    let (lh, ll, fh, fl);
    if xh > 11.5 {
        let c = &TG_ASYM_BIG;
        (lh, ll) = fastsum_dd(lh0, ll0, c[0][0], c[0][1]);
        let (b, q) = (&c[1..2], &c[2..]);
        let q0 = q[0][0] + z2h * q[1][0];
        let q2 = q[2][0] + z2h * q[3][0];
        let q4 = q[4][0] + z2h * q[5][0];
        let tail = z2h * (q0 + x2 * (q2 + x2 * q4));
        (fh, fl) = polydd_tg(z2h, z2l, b, tail);
    } else {
        let c = &TG_ASYM_SMALL;
        (lh, ll) = fastsum_dd(lh0, ll0, c[0][0], c[0][1]);
        let x4 = x2 * x2;
        let (b, q) = (&c[1..3], &c[3..]);
        let mut q0 = q[0][0] + z2h * q[1][0];
        let q2 = q[2][0] + z2h * q[3][0];
        let mut q4 = q[4][0] + z2h * q[5][0];
        let q6 = q[6][0] + z2h * q[7][0];
        let q8 = q[8][0] + z2h * q[9][0];
        q4 += x2 * (q6 + x2 * q8);
        q0 += x2 * q2;
        q0 += x4 * q4;
        (fh, fl) = polydd_tg(z2h, z2l, b, z2h * q0);
    }
    let (fh, fl) = muldd_sin(zh, zl, fh, fl);
    fastsum_dd(lh, ll, fh, fl)
}

/// tgamma's domain-error result: FE_INVALID and glibc's positive quiet NaN
/// (glibc 2.43 returns 0x7ff8000000000000, not the x86 default NaN).
#[inline(never)]
fn tgamma_domain_nan(x: f64) -> f64 {
    let n = (-1.0 - x.abs()).sqrt(); // raises FE_INVALID
    f64::from_bits(n.to_bits() & !(1u64 << 63))
}

/// Correctly rounded `tgamma`.
pub fn tgamma(x: f64) -> f64 {
    let t = x.to_bits();
    let ax = t << 1;
    if ax >= 0x7ffu64 << 53 {
        if ax == 0x7ffu64 << 53 {
            // -inf: domain error; +inf: +inf.
            return if t >> 63 != 0 {
                tgamma_domain_nan(x)
            } else {
                x
            };
        }
        return x + x; // NaN
    }
    let z = x;
    if x.abs() < 0.25 {
        if ax < 0x71e0_0000_0000_0000 {
            // |x| < 2^-112: Gamma(x) ~ 1/x
            if x == f64::from_bits(0x0004_0000_0000_0000) {
                // 2^-1024: avoid the spurious overflow of 1/x.
                return core::hint::black_box(f64::MAX) + hf!("0x1p+970");
            }
            let mut r = 1.0 / x;
            if x == 0.0 {
                return r;
            }
            if r.mul_add(x, -1.0) == 0.0 {
                r -= 0.5; // raise FE_INEXACT for x = 2^k
            }
            return r;
        }
        let c = &TG_SMALL_C;
        let x2 = x * x;
        let x4 = x2 * x2;
        let x8 = x4 * x4;
        let mut c0 = c[0] + x * c[1] + x2 * (c[2] + x * c[3]);
        let c4 = c[4] + x * c[5] + x2 * (c[6] + x * c[7]);
        let mut c8 = c[8] + x * c[9] + x2 * (c[10] + x * c[11]);
        let c12 = c[12] + x * c[13] + x2 * (c[14] + x * c[15]);
        c0 += x4 * c4;
        c8 += x4 * c12;
        let cl = x * (c0 + x8 * c8);
        let (ch, cl) = polyddd_tg(x, &TG_SMALL_CC, cl);
        let fh = 1.0 / z;
        let fl = fh.mul_add(-z, 1.0) * fh;
        let (fh, fl) = fastsum_dd(fh, fl, ch, cl);
        let eps = fh * (3.5e-19 + (x2 * x4) * 4e-15);
        let ub = fh + (fl + eps);
        let lb = fh + (fl - eps);
        if ub != lb {
            return tgamma_accurate(x);
        }
        return ub;
    }
    if x >= hf!("0x1.573fae561f648p+7") {
        let big = core::hint::black_box(hf!("0x1.fp1023"));
        return big + big; // overflow
    }
    let fx = x.floor();
    if fx == x {
        // x integer
        if x == 0.0 {
            return 1.0 / x;
        }
        if x < 0.0 {
            return tgamma_domain_nan(x);
        }
        let k = fx as i64;
        let (mut t0h, mut t0l, mut x0) = (1.0, 0.0, 1.0);
        for _ in 1..k {
            (t0h, t0l) = mulddd_tg(x0, t0h, t0l);
            x0 += 1.0;
        }
        return t0h + t0l;
    }
    if x <= -184.0 {
        // |Gamma(x)| < 2^-1078: underflows to ±0.
        let k = fx as i64; // saturating, as upstream's clamp
        let s = if k & 1 != 0 {
            hf!("-0x1p-1022")
        } else {
            hf!("0x1p-1022")
        };
        return core::hint::black_box(hf!("0x1p-1022")) * s;
    }
    if x < -3.0 {
        // Reflection: Gamma(x) = pi / (sin(pi x) Gamma(1 - x)).
        let (lh, ll) = fasttwosum(-x, 1.0);
        let (lh, ll) = tg_lgamma_asym(lh, ll);
        let (lh, ll, e) = tg_expd(lh, ll);
        let ix = x.floor();
        let dx = x - ix;
        let ip = ix as i32;
        let (sh, sl) = tg_sinpid(dx);
        let (lh, ll) = muldd_sin(sh, sl, lh, ll);
        const PIH: f64 = hf!("0x1.921fb54442d18p+1");
        const PIL: f64 = hf!("0x1.1a62633145c07p-53");
        let rcp = 1.0 / lh;
        let mut rh = rcp * PIH;
        let mut rl = rcp * (PIL - ll * rh - rh.mul_add(lh, -PIH));
        if ip & 1 != 0 {
            rh = -rh;
            rl = -rl;
        }
        let eps = rh * (8.7e-21 - x * 1.46e-22);
        let shift = ((i64::from(e)) << 52) as u64;
        if ip >= -170 {
            let ub = rh + (rl + eps);
            let lb = rh + (rl - eps);
            if ub != lb {
                return tgamma_accurate(x);
            }
            return f64::from_bits(ub.to_bits().wrapping_sub(shift));
        }
        let mut th = rh.to_bits();
        let re = ((th >> 52) & 0x7ff) as i32;
        if re - e <= 0 {
            // Subnormal result.
            th = th.wrapping_add(((e - re + 1) as u64) << 52);
            th &= 0xfffu64 << 52;
            let (h, l) = fasttwosum(f64::from_bits(th), rh);
            rh = h;
            rl += l;
            let ub = rh + (rl + eps);
            let lb = rh + (rl - eps);
            if ub != lb {
                return tgamma_accurate(x);
            }
            let r = f64::from_bits(ub.to_bits() & !(0x7ffu64 << 52));
            raise_underflow();
            return r;
        }
        let ub = rh + (rl + eps);
        let lb = rh + (rl - eps);
        if ub != lb {
            return tgamma_accurate(x);
        }
        return f64::from_bits(ub.to_bits().wrapping_sub(shift));
    }
    if x > 4.0 {
        let (lh, ll) = tg_lgamma_asym(x, 0.0);
        let (lh, ll, e) = tg_expd(lh, ll);
        let eps = lh * (2e-21 + x * 1.84e-22);
        let ub = lh + (ll + eps);
        let lb = lh + (ll - eps);
        if ub != lb {
            return tgamma_accurate(x);
        }
        return f64::from_bits(ub.to_bits().wrapping_add(((i64::from(e)) << 52) as u64));
    }
    // -3 <= x <= 4, |x| >= 1/4: polynomial around 3.5, shifted by the
    // recurrence.
    let c = &TG_MID_C;
    let m = z - 3.5;
    let i = m.round_ties_even();
    let d = z - (i + 3.5);
    let d2 = d * d;
    let d4 = d2 * d2;
    let fl = d
        * ((c[10] + d * c[11])
            + d2 * (c[12] + d * c[13])
            + d4 * ((c[14] + d * c[15]) + d2 * (c[16] + d * c[17])));
    let (fh, fl) = polyddd_tg(d, &TG_MID_CC[..10], fl);
    let jm = i.abs() as i32;
    let (mut wh, mut wl) = (1.0, 0.0);
    let (mut xph, mut xpl) = (z, 0.0);
    if jm != 0 {
        wh = xph;
        for _ in 1..jm {
            let l;
            (xph, l) = if xph.abs() > 1.0 {
                fasttwosum(xph, 1.0)
            } else {
                fasttwosum(1.0, xph)
            };
            xpl += l;
            (wh, wl) = muldd_sin(xph, xpl, wh, wl);
        }
    }
    let rh = 1.0 / wh;
    let rl = (rh.mul_add(-wh, 1.0) - wl * rh) * rh;
    let (fh, fl) = muldd_sin(rh, rl, fh, fl);
    let eps = fh * 1e-21;
    let ub = fh + (fl + eps);
    let lb = fh + (fl - eps);
    if ub != lb {
        return tgamma_accurate(x);
    }
    ub
}

// --- lgamma (CORE-MATH src/binary64/lgamma/lgamma.c) ---------------------------

/// lgamma.c `polydddfst`: double-double Horner at the double `x`, with the
/// unordered FastTwoSum accumulation.
#[inline(always)]
fn polydddfst(x: f64, c: &[[f64; 2]], l: f64) -> (f64, f64) {
    let mut i = c.len() - 1;
    let (mut ch, mut cl) = fasttwosum(c[i][0], l);
    cl += c[i][1];
    while i > 0 {
        i -= 1;
        (ch, cl) = mulddd_tg(x, ch, cl);
        (ch, cl) = fastsum_dd(c[i][0], c[i][1], ch, cl);
    }
    (ch, cl)
}

/// Mantissa bits (exponent field cleared) and unbiased exponent of a positive
/// finite `x`, normalising subnormals (lgamma.c's log reductions).
#[inline(always)]
fn lg_split(x: f64) -> (u64, i32) {
    let mut t = x.to_bits();
    let mut ex = (t >> 52) as i32;
    if ex == 0 {
        let k = t.leading_zeros() as i32;
        t <<= k - 11;
        ex -= k - 12;
    }
    (t & MASK52, ex - 0x3ff)
}

/// log(x) as a double-double for x > 0, subnormals included (lgamma.c
/// `as_logd`; its tables are tgamma.c's).
#[inline(never)]
fn lg_logd(x: f64) -> (f64, f64) {
    let (t, e) = lg_split(x);
    let ed = f64::from(e);
    let (i1, i2) = log_table_index(t);
    let tf = f64::from_bits(t | (0x3ffu64 << 52));
    let r = TG_LOG_R1[i1] * TG_LOG_R2[i2];
    let o = r * tf;
    let dxl = r.mul_add(tf, -o);
    let dxh = o - 1.0;
    const C: [f64; 4] = [
        hf!("-0x1.fffffffffffd3p-2"),
        hf!("0x1.55555555543d5p-2"),
        hf!("-0x1.000002bb2d74ep-2"),
        hf!("0x1.999a692c56e4ep-3"),
    ];
    let dx = r.mul_add(tf, -1.0);
    let dx2 = dx * dx;
    let f = dx2 * ((C[0] + dx * C[1]) + dx2 * (C[2] + dx * C[3]));
    let lt = (TG_LOG_L1[i1][1] + TG_LOG_L2[i2][1]) + ed * hf!("0x1.62e42fef8p-1");
    let lh = lt + dxh;
    let mut ll = (lt - lh) + dxh;
    ll += ((TG_LOG_L1[i1][0] + TG_LOG_L2[i2][0]) + hf!("0x1.1cf79abc9e3b4p-36") * ed) + dxl;
    ll += f;
    (lh, ll)
}

/// log(x) as a triple-double for x > 0 (lgamma.c `as_logd_accurate`).
#[inline(never)]
fn lg_logd_accurate(x: f64) -> (f64, f64, f64) {
    let (t, e) = lg_split(x);
    let ed = f64::from(e);
    let (i1, i2) = log_table_index(t);
    let tf = f64::from_bits(t | (0x3ffu64 << 52));
    let r = LG_LOGA_R1[i1] * LG_LOGA_R2[i2];
    let o = r * tf;
    let dxl = r.mul_add(tf, -o);
    let dxh = o - 1.0;
    let c = &LG_LOGA_C;
    let (dxh, dxl) = fasttwosum(dxh, dxl);
    let fl = dxh * (c[6][0] + dxh * (c[7][0] + dxh * c[8][0]));
    let (fh, fl) = polydd_tg(dxh, dxl, &c[..6], fl);
    let (fh, fl) = muldd_sin(dxh, dxl, fh, fl);
    let (h1, h2) = (&LG_LOGA_H1[i1], &LG_LOGA_H2[i2]);
    let s2 = h1[2] + h2[2];
    let s1 = h1[1] + h2[1];
    let s0 = h1[0] + h2[0];
    let mut l0 = hf!("0x1.62e42fefa38p-1") * ed;
    let l1 = hf!("0x1.ef35793c76p-45") * ed;
    let l2 = hf!("0x1.cc01f97b57a08p-87") * ed;
    l0 += s2;
    let (l1, l2) = sumdd_ordered(l1, l2, s1, s0);
    let (l1, l2) = sumdd_ordered(l1, l2, fh, fl);
    let (l0, l1) = fasttwosum(l0, l1);
    let (l1, l2) = fasttwosum(l1, l2);
    (l0, l1, l2)
}

/// The sin(pi a) / cos(pi a) correction polynomials shared by both lgamma
/// sinpi evaluations.
const LG_SIN_C: [f64; 4] = [
    hf!("-0x1.3bd3cc9be45dep-12"),
    hf!("0x1.03c1f081b5ac4p-26"),
    hf!("-0x1.55d3c7e3bd8bfp-42"),
    hf!("0x1.e1f4826790653p-59"),
];
const LG_SIN_S: [f64; 4] = [
    hf!("0x1.921fb54442d18p-6"),
    hf!("-0x1.4abbce625be53p-19"),
    hf!("0x1.466bc67748efcp-34"),
    hf!("-0x1.32d26e446373ap-50"),
];

/// sin(pi x)/pi as a double-double for 0 <= x < 1 (lgamma.c `as_sinpipid`).
#[inline(never)]
fn lg_sinpipid(x: f64) -> (f64, f64) {
    let x = x - 0.5;
    let ax = x.abs();
    let sx = ax * 128.0;
    let ix = sx.round_ties_even();
    let ky = ix as usize;
    let kx = 64usize.wrapping_sub(ky);
    if kx < 2 {
        // Near x = 0 or 1: sin(pi z)/pi = z (1 + z^2 P(z^2)) with z = 1/2 - |x|.
        const C: [f64; 2] = [hf!("-0x1.a51a6625307d3p+0"), hf!("-0x1.16cc8f2044a4ap-55")];
        const CL: [f64; 3] = [
            hf!("0x1.9f9cb402bc42ap-1"),
            hf!("-0x1.86a8e46ddf78dp-3"),
            hf!("0x1.ac644e7aa33e6p-6"),
        ];
        let z = 0.5 - ax;
        let z2 = z * z;
        let z2l = z.mul_add(z, -z2);
        let fl = z2 * (CL[0] + z2 * (CL[1] + z2 * CL[2]));
        let (fh, mut fl) = fasttwosum(C[0], fl);
        fl += C[1];
        let (fh, fl) = muldd_sin(z2, z2l, fh, fl);
        let (fh, fl) = mulddd_tg(z, fh, fl);
        let (fh, e) = fasttwosum(z, fh);
        return (fh, fl + e);
    }
    let d = ix - sx;
    let d2 = d * d;
    let (sh, sl) = (LG_STPI[kx][1], LG_STPI[kx][0]);
    let (ch, cl) = (LG_STPI[ky][1], LG_STPI[ky][0]);
    const C0: f64 = hf!("-0x1.692b66e3cf6e8p-66");
    const S0: f64 = hf!("0x1.1a624b88c9448p-60");
    let (c, s) = (&LG_SIN_C, &LG_SIN_S);
    let p = d2 * (c[1] + d2 * (c[2] + d2 * c[3]));
    let q = d2 * (s[1] + d2 * (s[2] + d2 * s[3]));
    let (qh, mut ql) = fasttwosum(s[0], q);
    ql += S0;
    let (ch, cl) = muldd_sin(qh, ql, ch, cl);
    let (th, mut tl) = fasttwosum(c[0], p);
    tl += C0;
    let (th, tl) = mulddd_tg(d, th, tl);
    let (ph, pl) = muldd_sin(th, tl, sh, sl);
    let (ch, cl) = fastsum_dd(ch, cl, ph, pl);
    let (ch, cl) = mulddd_tg(d, ch, cl);
    fastsum_dd(sh, sl, ch, cl)
}

/// sin(pi x)/pi to about 106 bits (lgamma.c `as_sinpipid_accurate`).
#[inline(never)]
fn lg_sinpipid_accurate(x: f64) -> (f64, f64) {
    let x = (x - 0.5).abs() * 128.0;
    let ix = x.round_ties_even();
    let d = ix - x;
    let ky = ix as usize;
    let kx = 64 - ky;
    let (sh, sl) = (LG_STPI[kx][1], LG_STPI[kx][0]);
    let (ch, cl) = (LG_STPI[ky][1], LG_STPI[ky][0]);
    let d2h = d * d;
    let d2l = d.mul_add(d, -d2h);
    let (ph, pl) = polydd_tg(d2h, d2l, &LG_SINA_C, 0.0);
    let (qh, ql) = polydd_tg(d2h, d2l, &LG_SINA_S, 0.0);
    let (ph, pl) = mulddd_tg(d, ph, pl);
    let (ph, pl) = muldd_sin(sh, sl, ph, pl);
    let (qh, ql) = muldd_sin(ch, cl, qh, ql);
    let (ch, cl) = fastsum_dd(qh, ql, ph, pl);
    let (ch, cl) = mulddd_tg(d, ch, cl);
    fastsum_dd(sh, sl, ch, cl)
}

/// lgamma(xh + xl) by Stirling's series for large arguments, as a
/// triple-double (lgamma.c `as_lgamma_asym_accurate`).
#[inline(never)]
fn lg_asym_accurate(xh: f64, xl: f64) -> (f64, f64, f64) {
    let (mut l0, mut l1, mut l2) = lg_logd_accurate(xh);
    let (l0x, mut l1x, mut l2x);
    if xh < hf!("0x1p120") {
        let zh = 1.0 / xh;
        let dz = xl * zh;
        let zl = (zh.mul_add(-xh, 1.0) - dz) * zh;
        if xl != 0.0 {
            let (dl1, mut dl2) = mulddd_tg(xl, zh, zh.mul_add(-xh, 1.0) * zh);
            dl2 -= dl1 * dl1 / 2.0;
            (l1, l2) = sumdd_ordered(l1, l2, dl1, dl2);
        }
        let (wh, wl) = if xh.to_bits() >> 52 > 0x3ff + 51 {
            (xh, xl - 0.5)
        } else {
            (xh - 0.5, xl)
        };
        l0 -= 1.0;
        let l0x0 = l0 * wh;
        let l0xl = l0.mul_add(wh, -l0x0);
        l1x = l1 * wh;
        let l1xl = l1.mul_add(wh, -l1x);
        l2x = l2 * wh;
        (l1x, l2x) = sumdd_ordered(l1x, l2x, l0xl, l1xl);
        (l1x, l2x) = sumdd_ordered(l1x, l2x, l0 * wl, l1 * wl);
        let (z2h, z2l) = muldd_sin(zh, zl, zh, zl);
        let c: &[[f64; 2]] = if xh >= 48.0 {
            &LG_ASYMA_48
        } else if xh >= 14.5 {
            &LG_ASYMA_14
        } else {
            &LG_ASYMA_LOW
        };
        (l1x, l2x) = sumdd_ordered(l1x, l2x, c[0][0], c[0][1]);
        let (fh, fl) = polydd_tg(z2h, z2l, &c[1..], 0.0);
        let (fh, fl) = muldd_sin(zh, zl, fh, fl);
        (l1x, l2x) = sumdd_ordered(l1x, l2x, fh, fl);
        let (h, m) = fasttwosum(l0x0, l1x);
        l0x = h;
        (l1x, l2x) = fasttwosum(m, l2x);
    } else {
        let wl = xl - 0.5;
        l0 -= 1.0;
        l0x = l0 * xh;
        let l0xl = l0.mul_add(xh, -l0x);
        l1x = l1 * xh;
        let l1xl = l1.mul_add(xh, -l1x);
        l2x = l2 * xh;
        (l1x, l2x) = sumdd_ordered(l1x, l2x, l0xl, l1xl);
        (l1x, l2x) = sumdd_ordered(l1x, l2x, l0 * wl, l1 * wl);
    }
    (l0x, l1x, l2x)
}

/// Accurate lgamma for inputs whose fast-path rounding test failed.
#[cold]
#[inline(never)]
fn lgamma_accurate(x_in: f64) -> f64 {
    let sx = x_in;
    let mut x = x_in.abs();
    let mut fh;
    let mut fl = 0.0f64;
    let mut fll = 0.0f64;
    // Round-to-nearest probe: both sides round to 1 only to nearest.
    let to_nearest = 1.0 + hf!("0x1p-54") == 1.0 - hf!("0x1p-54");
    if x < hf!("0x1p-100") {
        let (lh, ll, lll) = lg_logd_accurate(x);
        (fh, fl) = fasttwosum(-lh, -ll);
        (fl, fll) = fasttwosum(fl, -lll);
        let (_, e) = fasttwosum(fh, 2.0 * fl);
        if e == 0.0 && to_nearest {
            fl *= 1.0 + hf!("0x1p-52").copysign(fl) * 1.0f64.copysign(fll);
        }
    } else if x < hf!("0x1p-2") {
        (fh, fl) = polydddfst(sx, &LG_ACC_C0, 0.0);
        (fh, fl) = mulddd_tg(sx, fh, fl);
        let (lh, ll, lll) = lg_logd_accurate(x);
        (fh, fl) = sumdd_ordered(fh, fl, -ll, -lll);
        (fh, fll) = twosum_ordered(-lh, fh);
        (fl, fll) = twosum_ordered(fll, fl);
        let (_, e) = fasttwosum(fh, 2.0 * fl);
        if e == 0.0 && to_nearest {
            fl *= 1.0 + hf!("0x1p-52").copysign(fl) * 1.0f64.copysign(fll);
        }
    } else {
        // Add log(y) (a triple-double) to fh + fl + fll.
        let add_log = |fh: &mut f64, fl: &mut f64, fll: &mut f64, y: f64| {
            let (lh, ll, lll) = lg_logd_accurate(y);
            (*fl, *fll) = sumdd_ordered(*fl, *fll, ll, lll);
            let (h, lh2) = twosum_ordered(*fh, lh);
            *fh = h;
            (*fl, *fll) = sumdd_ordered(*fl, *fll, lh2, 0.0);
        };
        if (x - 0.5).abs() < hf!("0x1p-2") {
            (fh, fl) = polydddfst(x - 0.5, &LG_ACC_B, 0.0);
            if sx > 0.0 {
                let (lh, ll, lll) = lg_logd_accurate(x);
                (fl, fll) = sumdd_ordered(fl, 0.0, -ll, -lll);
                let (h, lh2) = twosum_ordered(fh, -lh);
                fh = h;
                (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            }
        } else if (x - 2.5).abs() < hf!("0x1p-2") {
            (fh, fl) = polydddfst(x - 2.5, &LG_ACC_B, 0.0);
            let (lh, ll, lll) = lg_logd_accurate(x - 1.0);
            (fl, fll) = sumdd_ordered(fl, 0.0, ll, lll);
            let (h, lh2) = twosum_ordered(fh, lh);
            fh = h;
            (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            if sx < 0.0 {
                add_log(&mut fh, &mut fl, &mut fll, x);
            }
        } else if (x - 3.5).abs() < hf!("0x1p-2") {
            let (l2h, l2l, l2ll) = lg_logd_accurate(x - 2.0);
            let (l1h, l1l, l1ll) = lg_logd_accurate(x - 1.0);
            let (l1l, l1ll) = sumdd_ordered(l1l, l1ll, l2l, l2ll);
            let (l1h, l2h) = fasttwosum(l1h, l2h);
            let (l1l, l1ll) = sumdd_ordered(l1l, l1ll, l2h, 0.0);
            (fh, fl) = polydddfst(x - 3.5, &LG_ACC_B, 0.0);
            (fl, fll) = sumdd_ordered(fl, 0.0, l1l, l1ll);
            let (h, l1h2) = twosum_ordered(fh, l1h);
            fh = h;
            (fl, fll) = sumdd_ordered(fl, fll, l1h2, 0.0);
            if sx < 0.0 {
                add_log(&mut fh, &mut fl, &mut fll, x);
            }
        } else if (x - 1.0).abs() < hf!("0x1p-2") {
            (fh, fl) = polydddfst(x - 1.0, &LG_ACC_C0, 0.0);
            (fh, fl) = mulddd_tg(x - 1.0, fh, fl);
            if sx < 0.0 {
                let (lh, ll, lll) = lg_logd_accurate(x);
                (fl, fll) = sumdd_ordered(fl, 0.0, ll, lll);
                let (h, lh2) = twosum_ordered(fh, lh);
                fh = h;
                (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            }
        } else if (x - 1.5).abs() < hf!("0x1p-2") {
            (fh, fl) = polydddfst(x - 1.5, &LG_ACC_B, 0.0);
            if sx < 0.0 {
                let (lh, ll, lll) = lg_logd_accurate(x);
                (fl, fll) = sumdd_ordered(fl, 0.0, ll, lll);
                let (h, lh2) = twosum_ordered(fh, lh);
                fh = h;
                (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            }
        } else if (x - 2.0).abs() < hf!("0x1p-2") {
            let (lh, ll, lll) = lg_logd_accurate(x - 1.0);
            (fh, fl) = polydddfst(x - 2.0, &LG_ACC_C0, 0.0);
            (fh, fl) = mulddd_tg(x - 2.0, fh, fl);
            (fl, fll) = sumdd_ordered(fl, 0.0, ll, lll);
            let (h, lh2) = twosum_ordered(fh, lh);
            fh = h;
            (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            if sx < 0.0 {
                add_log(&mut fh, &mut fl, &mut fll, x);
            }
        } else if (x - 3.0).abs() < hf!("0x1p-2") {
            let (l2h, l2l, l2ll) = lg_logd_accurate(x - 2.0);
            let (l1h, l1l, l1ll) = lg_logd_accurate(x - 1.0);
            let (l1l, l1ll) = sumdd_ordered(l1l, l1ll, l2l, l2ll);
            let (l1h, l2h) = fasttwosum(l1h, l2h);
            let (l1l, l1ll) = sumdd_ordered(l1l, l1ll, l2h, 0.0);
            (fh, fl) = polydddfst(x - 3.0, &LG_ACC_C0, 0.0);
            (fh, fl) = mulddd_tg(x - 3.0, fh, fl);
            (fl, fll) = sumdd_ordered(fl, 0.0, l1l, l1ll);
            let (h, l1h2) = twosum_ordered(fh, l1h);
            fh = h;
            (fl, fll) = sumdd_ordered(fl, fll, l1h2, 0.0);
            if sx < 0.0 {
                add_log(&mut fh, &mut fl, &mut fll, x);
            }
        } else {
            // x > 3.75: Stirling's series, on 1 - sx for negative sx.
            if sx < 0.0 {
                (x, fl) = fasttwosum(x, 1.0);
            }
            (fh, fl, fll) = lg_asym_accurate(x, fl);
        }
        if sx < 0.0 {
            // Reflection: lgamma(x) = -lgamma(1-x) - log|sin(pi x)/pi| ... - log|x|
            // folded as upstream.
            let phi = if sx < -0.5 { sx - sx.floor() } else { -sx };
            let (sh, sl) = lg_sinpipid_accurate(phi);
            let (lh, mut ll, lll) = lg_logd_accurate(sh);
            ll += sl / sh + lll;
            (fl, fll) = sumdd_ordered(fl, fll, ll, 0.0);
            let (h, lh2) = twosum_ordered(fh, lh);
            fh = h;
            (fl, fll) = sumdd_ordered(fl, fll, lh2, 0.0);
            fh = -fh;
            fl = -fl;
            fll = -fll;
        }
        (fh, fl) = fasttwosum(fh, fl);
        (fl, fll) = fasttwosum(fl, fll);
        (fh, fl) = fasttwosum(fh, fl);
        (fl, fll) = fasttwosum(fl, fll);
        let (_, e) = fasttwosum(fh, 2.0 * fl);
        if e == 0.0 {
            fl *= 1.0 + hf!("0x1p-26").copysign(fl) * hf!("0x1p-26").copysign(fll);
        }
    }

    // Near the negative-axis roots of lgamma, re-evaluate around the root
    // (bounds, scale and split per root in LG_ROOT_PARAMS).
    if fh.abs() < hf!("0x1.8p-2") {
        for (params, c) in LG_ROOT_PARAMS.iter().zip(LG_ROOT_C.iter()) {
            let &(fb, lo, hi, sc, k, x0) = params;
            if fh.abs() < fb && sx > lo && sx < hi {
                let (zh, mut zl) = fasttwosum(x0[0] + sx, x0[1]);
                zl += x0[2];
                let sh = zh * sc;
                let sl = zl * sc;
                let n = c.len();
                let tail = sh * polyd_tg(sh, &c[n - k..]);
                let (h, l) = polydd_tg(sh, sl, &c[..n - k], tail);
                (fh, fl) = muldd_sin(zh, zl, h, l);
                break;
            }
        }
    }

    let ft = (fl.to_bits().wrapping_add(2) & MASK52) as u32;
    if ft <= 2 {
        for e in &LG_DB {
            if e[0] == sx {
                return e[1] + e[2];
            }
        }
    }
    fh + fl
}

/// Interval index into the [0.5, 8.29541] piecewise polynomials for the
/// top bits `au` of 2|x|.
#[inline(always)]
fn lg_interval(au: u32) -> usize {
    let ou = u64::from(au - LG_UBRD[0]);
    let mut j =
        ((0x1_57ce_d865u64.wrapping_sub(ou * 0x150d)).wrapping_mul(ou) + 0x1280_0000_0000) >> 45;
    if au < LG_UBRD[j as usize] {
        j -= 1;
    }
    j as usize
}

/// The [0.5, 8.29541] piecewise polynomial at offset `z` in interval `j`.
#[inline(always)]
fn lg_piece(j: usize, z: f64) -> (f64, f64) {
    let z2 = z * z;
    let z4 = z2 * z2;
    let q = &LG_CL[j];
    let q0 = q[0] + z * q[1];
    let q2 = q[2] + z * q[3];
    let q4 = q[4] + z * q[5];
    let q6 = q[6] + z * q[7];
    let fl = z * ((q0 + z2 * q2) + z4 * (q4 + z2 * q6));
    polydddfst(z, &LG_CH[j], fl)
}

/// Correctly rounded `lgamma_r`: `(log|Gamma(x)|, sign of Gamma(x))`.
pub fn lgamma_r(x: f64) -> (f64, i32) {
    let t = x.to_bits();
    let nx = t << 1;
    if nx >= 0xfeae_a9b2_4f16_a34c {
        // |x| >= 0x1.006df1bfac84ep+1015 (or inf/NaN)
        if t == 0x7f57_54d9_278b_51a6 {
            return (
                core::hint::black_box(hf!("0x1.ffffffffffffep+1023")) - hf!("0x1p+969"),
                1,
            );
        }
        if t == 0x7f57_54d9_278b_51a7 {
            return (core::hint::black_box(f64::MAX) - hf!("0x1p+969"), 1);
        }
        if nx >= 0x7ffu64 << 53 {
            if nx == 0x7ffu64 << 53 {
                return (x.abs(), 1); // ±inf -> +inf
            }
            return (x + x, 1); // NaN
        }
        if t >> 63 != 0 {
            return (1.0 / core::hint::black_box(0.0), 1); // huge negative integer
        }
        let big = core::hint::black_box(hf!("0x1.fp1023"));
        return (big * big, 1); // overflow
    }
    let fx = x.floor();
    if fx == x {
        if x <= 0.0 {
            // Pole: +inf with FE_DIVBYZERO.
            return (1.0 / core::hint::black_box(0.0), 1 - 2 * (t >> 63) as i32);
        }
        if x == 1.0 || x == 2.0 {
            return (0.0, 1);
        }
    }
    let mut au = (nx >> 38) as u32;
    let (mut fh, mut fl, mut eps);
    let sign;
    if au < LG_UBRD[0] {
        // |x| < 0.5
        sign = 1 - 2 * (t >> 63) as i32;
        let (lh, ll) = lg_logd(x.abs());
        if au < 0x1da_0000 {
            // |x| < 2^-75
            fh = -lh;
            fl = -ll;
            eps = 1.5e-22;
        } else if au < 0x1fd_0000 {
            // |x| < 1/32
            let q = &LG_TINY_Q;
            let z = x;
            let z2 = z * z;
            let z4 = z2 * z2;
            let q0 = q[0] + z * q[1];
            let q2 = q[2] + z * q[3];
            let q4 = q[4] + z * q[5];
            let q6 = q[6] + z * q[7];
            fl = z * ((q0 + z2 * q2) + z4 * (q4 + z2 * q6));
            (fh, fl) = polydddfst(z, &LG_TINY_C0, fl);
            (fh, fl) = mulddd_tg(x, fh, fl);
            (fh, fl) = sumdd_ordered(-lh, -ll, fh, fl);
            eps = 1.5e-22;
        } else {
            // 1/32 <= |x| < 1/2: lgamma(x) = lgamma(1+x) - log|x|, with 1+x in
            // the piecewise range.
            let (tf, xl) = fasttwosum(1.0, x);
            au = (tf.to_bits() >> 37) as u32;
            let j = lg_interval(au);
            let z = (tf - LG_OFFS[j]) + xl;
            (fh, fl) = lg_piece(j, z);
            if j == 4 {
                // the region around the root at 1
                (fh, fl) = mulddd_tg(-x, fh, fl);
            }
            eps = fh.abs() * 8.3e-20;
            (fh, fl) = sumdd_ordered(-lh, -ll, fh, fl);
            eps += lh.abs() * 5e-22;
        }
    } else {
        let ax = x.abs();
        if au >= LG_UBRD[19] {
            // |x| >= 8.29541: Stirling's series.
            let (mut lh, mut ll) = lg_logd(ax);
            lh -= 1.0;
            if au >= 0x219_8000 {
                // x >= 2^52
                if au >= 0x3fa_baa6 {
                    (lh, ll) = fasttwosum(lh, ll);
                }
                let hlh = lh * 0.5;
                (lh, ll) = mulddd_tg(ax, lh, ll);
                ll -= hlh;
            } else {
                (lh, ll) = mulddd_tg(ax - 0.5, lh, ll);
            }
            let (c, q) = (&LG_ASYM_C, &LG_ASYM_Q);
            (lh, ll) = fastsum_dd(lh, ll, c[0][0], c[0][1]);
            if ax < hf!("0x1p100") {
                let zh = 1.0 / ax;
                let zl = zh.mul_add(-ax, 1.0) * zh;
                let z2h = zh * zh;
                let z4h = z2h * z2h;
                let q0 = q[0] + z2h * q[1];
                let q2 = q[2] + z2h * q[3];
                let q4 = q[4];
                fl = z2h * (q0 + z4h * (q2 + z4h * q4));
                (fh, fl) = fasttwosum(c[1][0], fl);
                fl += c[1][1];
                (fh, fl) = muldd_sin(fh, fl, zh, zl);
            } else {
                fh = 0.0;
                fl = 0.0;
            }
            (fh, fl) = fastsum_dd(lh, ll, fh, fl);
            eps = fh.abs() * 4.5e-20;
        } else {
            // x in [0.5, 8.29541]
            let j = lg_interval(au);
            (fh, fl) = lg_piece(j, ax - LG_OFFS[j]);
            if j == 4 {
                (fh, fl) = mulddd_tg(1.0 - ax, fh, fl); // root at 1
            }
            if j == 10 {
                (fh, fl) = mulddd_tg(ax - 2.0, fh, fl); // root at 2
            }
            eps = fh.abs() * 8.7e-20 + 1e-24;
        }
        if t >> 63 != 0 {
            // x < 0: reflection.
            let (sh, sl) = lg_sinpipid(x - x.floor());
            let (sh, sl) = mulddd_tg(-x, sh, sl);
            let (lh, mut ll) = lg_logd(sh);
            ll += sl / sh;
            let (h, l) = sumdd_ordered(fh, fl, lh, ll);
            fh = -h;
            fl = -l;
            eps += lh.abs() * 8e-22;
            let k = fx as i64;
            sign = 1 - 2 * (k & 1) as i32;
        } else {
            sign = 1;
        }
    }
    let ub = fh + (fl + eps);
    let lb = fh + (fl - eps);
    if ub != lb {
        return (lgamma_accurate(x), sign);
    }
    (ub, sign)
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

    #[test]
    fn atan_matches_core_math_on_corpus() {
        // Pinned from the CORE-MATH C original (glibc's atan is not quite
        // correctly rounded: it differs from this on 1206 of these inputs).
        assert_eq!(corpus_hash(atan, -30, 60), 0x0a3d_5099_2cb9_43eb);
    }

    #[test]
    fn atan_hard_and_special_cases() {
        // (input, CORE-MATH result): refine-database entries and every branch
        // cut-off.
        for (x, want) in [
            (0x3f80_dc89_a3b5_5010u64, 0x3f80_dc70_ac22_8717u64),
            (0xbfe7_ba49_f739_829f, 0xbfe4_6ac3_7224_3536),
            (0x3fcd_7688_0448_7b07, 0x3fcc_f567_6f37_3ec1),
            (0x3f7b_21c4_75e6_362a, 0x3f7b_21aa_7472_2c14),
            (0x3f7b_21c4_75e6_3629, 0x3f7b_21aa_7472_2c13),
            (0x3e40_0000_0000_0000, 0x3e40_0000_0000_0000),
            (0x3e3f_ffff_ffff_ffff, 0x3e3f_ffff_ffff_ffff),
            (0x4062_ded8_e34a_9035, 0x3ff9_06d9_8fce_46e2),
            (0x4062_ded8_e34a_9036, 0x3ff9_06d9_8fce_46e2),
            (0x434d_0296_7c31_cdb5, 0x3ff9_21fb_5444_2d18),
            (0x434d_0296_7c31_cdb4, 0x3ff9_21fb_5444_2d18),
            (0x3ff0_0000_0000_0000, 0x3fe9_21fb_5444_2d18),
            (0xbff0_0000_0000_0000, 0xbfe9_21fb_5444_2d18),
            (0x3fe0_0000_0000_0000, 0x3fdd_ac67_0561_bb4f),
            (0x4059_0000_0000_0000, 0x3ff8_f905_eb2d_ef22),
            (0x7e37_e43c_8800_759c, 0x3ff9_21fb_5444_2d18),
            (0x7ff0_0000_0000_0000, 0x3ff9_21fb_5444_2d18),
            (0xfff0_0000_0000_0000, 0xbff9_21fb_5444_2d18),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
        ] {
            let got = atan(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "atan({x:#x}) = {got:#x}, CORE-MATH {want:#x}");
        }
        assert!(atan(f64::NAN).is_nan());
    }

    #[test]
    fn sin_matches_core_math_on_corpus() {
        // Pinned from the CORE-MATH C original (glibc's IBM sin is not quite
        // correctly rounded: it differs from this on 955 of these inputs).
        assert_eq!(corpus_hash(sin, -40, 40), 0x33b8_ebe8_cd05_887b);
    }

    #[test]
    fn sin_hard_and_special_cases() {
        // (input, CORE-MATH result): tiny cut-off, the accurate-path boundary
        // at 2^-16, the large-argument boundary at 2^31, huge arguments.
        for (x, want) in [
            (0x3e57_1374_4912_3ef6u64, 0x3e57_1374_4912_3ef6u64),
            (0x3e57_1374_4912_3ef7, 0x3e57_1374_4912_3ef6),
            (0x3ef0_0000_0000_0000, 0x3eef_ffff_fffa_aaab),
            (0x3eef_ffff_ffff_ffff, 0x3eef_ffff_fffa_aaaa),
            (0x41e0_0000_0000_0000, 0xbfef_14f9_13e9_af98),
            (0x41df_ffff_ffff_ffff, 0xbfef_14f9_325a_7175),
            (0x4480_f0cf_064d_d592, 0xbfeb_453a_b76b_f397),
            (0x4e05_4a9a_d28f_0a25, 0x3fcc_fd76_45fe_82c0),
            (0x4009_21fb_5444_2d18, 0x3ca1_a626_3314_5c07),
            (0xbff0_0000_0000_0000, 0xbfea_ed54_8f09_0cee),
            (0x4059_0000_0000_0000, 0xbfe0_3425_b78c_4db8),
            (0x7e37_e43c_8800_759c, 0xbfea_2c16_b010_e385),
            (0x7fef_ffff_ffff_ffff, 0x3f74_52fc_98b3_4e97),
            (0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
            (0x0010_0000_0000_0000, 0x0010_0000_0000_0000),
        ] {
            let got = sin(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "sin({x:#x}) = {got:#x}, CORE-MATH {want:#x}");
        }
        assert!(sin(f64::NAN).is_nan());
    }

    #[test]
    fn cos_matches_core_math_on_corpus() {
        // Pinned from the CORE-MATH C original (glibc's IBM cos differs from it
        // on 547 of these inputs).
        assert_eq!(corpus_hash(cos, -40, 40), 0x120e_4de5_ef7d_d712);
    }

    #[test]
    fn cos_moderate_agrees_with_the_dint_path_wherever_it_answers() {
        // The quarter-turn fast path may only return a value its rounding
        // test proves; it must then equal what the original cos_fast /
        // cos_accurate chain returns. Random bit patterns over every exponent
        // it serves (2^-27 .. 2^31), plus multiples of pi/2 neighbours.
        let reference = |ax: f64| {
            let (h, l, err) = cos_fast(ax);
            let (left, right) = (h + (l - err), h + (l + err));
            if left == right {
                left
            } else {
                cos_accurate(ax)
            }
        };
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut answered = 0u32;
        for i in 0..300_000u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let exp = 0x3e4 + u64::from(i % 59); // 2^-27 .. 2^31
            let mut ax = f64::from_bits((exp << 52) | (state & MASK52));
            if i % 7 == 0 {
                // Next to k pi/2, where cos is small.
                let k = (state >> 40) % 1_000_000;
                ax = f64::from_bits(
                    (k as f64 * core::f64::consts::FRAC_PI_2)
                        .to_bits()
                        .wrapping_add(state & 3)
                        .wrapping_sub(1),
                );
            }
            if ax.to_bits() <= 0x3e46_a09e_667f_3bcc || ax >= hf!("0x1p31") {
                continue;
            }
            if let Some(fast) = cos_moderate(ax) {
                answered += 1;
                assert_eq!(
                    fast.to_bits(),
                    reference(ax).to_bits(),
                    "cos({:#x})",
                    ax.to_bits()
                );
            }
        }
        assert!(answered > 250_000, "fast path answered only {answered}");
    }

    #[test]
    fn cos_hard_and_special_cases() {
        // (input, CORE-MATH result): the near-1 cut-off, accurate-path
        // exceptions, the 2 pi and 2^52 reduction boundaries, huge arguments.
        for (x, want) in [
            (0x3e46_a09e_667f_3bccu64, 0x3ff0_0000_0000_0000u64),
            (0x3e46_a09e_667f_3bcd, 0x3fef_ffff_ffff_ffff),
            (0x3e88_0000_0000_0009, 0x3fef_ffff_ffff_ff70),
            (0x3eb8_0000_0000_0240, 0x3fef_ffff_ffff_dc00),
            (0x4019_21fb_5444_2d17, 0x3ff0_0000_0000_0000),
            (0x4019_21fb_5444_2d18, 0x3ff0_0000_0000_0000),
            (0x4330_0000_0000_0000, 0xbfdf_1300_d681_503f),
            (0x432f_ffff_ffff_ffff, 0xbf7c_91a4_321f_73c8),
            (0x7fe6_1a3d_b8c8_d129, 0x3ff0_0000_0000_0000),
            (0x7526_ac5b_262c_a1ff, 0x3ff0_0000_0000_0000),
            (0x3ff9_21fb_5444_2d18, 0x3c91_a626_3314_5c07),
            (0xbff0_0000_0000_0000, 0x3fe1_4a28_0fb5_068c),
            (0x4059_0000_0000_0000, 0x3feb_981d_bf66_5fdf),
            (0x4480_f0cf_064d_d592, 0x3fe0_be2c_ef01_c8f4),
            (0x7e37_e43c_8800_759c, 0xbfe2_6990_22ad_c4c1),
            (0x7fef_ffff_ffff_ffff, 0xbfef_ffe6_2ecf_ab75),
            (0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x3ff0_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x3ff0_0000_0000_0000),
        ] {
            let got = cos(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "cos({x:#x}) = {got:#x}, CORE-MATH {want:#x}");
        }
        assert!(cos(f64::NAN).is_nan());
    }

    #[test]
    fn tan_matches_core_math_on_corpus() {
        // Pinned from the CORE-MATH C original (glibc's IBM tan differs from it
        // on 1432 of these inputs).
        assert_eq!(corpus_hash(tan, -40, 40), 0x76f9_8bda_7647_30c5);
    }

    #[test]
    fn tan_hard_and_special_cases() {
        // (input, CORE-MATH result): the tiny cut-off, accurate-path
        // exceptions, near-poles, the 2 pi and 2^52 reduction boundaries and
        // huge arguments.
        for (x, want) in [
            (0x3e4d_12ed_0af1_a27eu64, 0x3e4d_12ed_0af1_a27eu64),
            (0x3e4d_12ed_0af1_a27f, 0x3e4d_12ed_0af1_a280),
            (0x3e9d_ffff_ffff_ff1f, 0x3e9e_0000_0000_0151),
            (0xbead_ffff_ffff_fc7c, 0xbeae_0000_0000_0546),
            (0x4019_21fb_5444_2d17, 0xbcd4_6989_8cc5_1702),
            (0x4019_21fb_5444_2d18, 0xbcb1_a626_3314_5c07),
            (0x4330_0000_0000_0000, 0xbffc_cef2_838d_a5ca),
            (0x432f_ffff_ffff_ffff, 0xc061_ebd0_03c0_5f32),
            (0x7fe6_1a3d_b8c8_d129, 0xbc7d_d15f_96b8_23f2),
            (0x3ff9_21fb_5444_2d18, 0x434d_0296_7c31_cdb5),
            (0xbff9_21fb_5444_2d18, 0xc34d_0296_7c31_cdb5),
            (0x3fe9_21fb_5444_2d18, 0x3fef_ffff_ffff_ffff),
            (0xbff0_0000_0000_0000, 0xbff8_eb24_5cbe_e3a6),
            (0x4059_0000_0000_0000, 0xbfe2_ca74_d62b_5d38),
            (0x4480_f0cf_064d_d592, 0xbffa_0f79_c1b6_b257),
            (0x7e37_e43c_8800_759c, 0x3ff6_be41_1f37_ac77),
            (0x7fef_ffff_ffff_ffff, 0xbf74_530c_fe72_9484),
            (0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000),
            (0x8000_0000_0000_0000, 0x8000_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x0000_0000_0000_0001),
        ] {
            let got = tan(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "tan({x:#x}) = {got:#x}, CORE-MATH {want:#x}");
        }
        assert!(tan(f64::NAN).is_nan());
    }

    #[test]
    fn tgamma_matches_glibc_2_43_on_corpus() {
        assert_eq!(corpus_hash(tgamma, -30, 8), 0x9a7b_1d5e_fde8_4461);
    }

    #[test]
    fn tgamma_hard_and_special_cases() {
        // (input, glibc 2.43 result): database entries, the 2^-1024 / 2^-112 /
        // 1/4 / 4 / -3 / -184 / overflow boundaries, subnormal results, the
        // integer and pole cases and their positive-NaN domain result.
        for (x, want) in [
            (0xc064_8ba8_e27d_09adu64, 0x82f0_b34f_909c_5c92u64),
            (0x4063_a0b3_58e9_e93b, 0x7938_1a5f_a517_374f),
            (0xc013_fc07_c800_57fd, 0xc001_4fd6_b28f_b843),
            (0x3ff0_9ef8_f46e_e74b, 0x3fef_5443_da4b_c3be),
            (0x0004_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0x0008_0000_0000_0000, 0x7fe0_0000_0000_0000),
            (0x0000_0000_0000_0001, 0x7ff0_0000_0000_0000),
            (0x8000_0000_0000_0001, 0xfff0_0000_0000_0000),
            (0x38f0_0000_0000_0000, 0x46f0_0000_0000_0000),
            (0x38ef_ffff_ffff_ffff, 0x46f0_0000_0000_0001),
            (0x3fcf_ffff_ffff_ffff, 0x400d_013f_c47e_eeeb),
            (0x3fd0_0000_0000_0000, 0x400d_013f_c47e_eeea),
            (0xbfd0_0000_0000_0000, 0xc013_9b4e_8b50_f62c),
            (0x4008_0000_0000_0000, 0x4000_0000_0000_0000),
            (0x4010_0000_0000_0000, 0x4018_0000_0000_0000),
            (0x4010_0000_0000_0001, 0x4018_0000_0000_0008),
            (0xc008_0000_0000_0001, 0x42f5_5555_5555_5552),
            (0xc004_0000_0000_0000, 0xbfee_3ff8_12e3_2183),
            (0x4024_0000_0000_0000, 0x4116_2600_0000_0000),
            (0x4065_6000_0000_0000, 0x7fa4_ab78_6441_8639),
            (0x4065_7333_3333_3333, 0x7fec_3ada_dc51_07b1),
            (0x4065_73fa_e561_f648, 0x7ff0_0000_0000_0000),
            (0x4065_73fa_e561_f647, 0x7fef_ffff_ffff_fe51),
            (0xc065_5000_0000_0000, 0x8017_d237_4dfc_da7a),
            (0xc065_7000_0000_0000, 0x0000_238e_e05c_879e),
            (0xc066_f000_0000_0000, 0x0000_0000_0000_0000),
            (0xc067_1000_0000_0000, 0x8000_0000_0000_0000),
            (0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0x0000_0000_0000_0000, 0x7ff0_0000_0000_0000),
            (0x8000_0000_0000_0000, 0xfff0_0000_0000_0000),
            (0xc008_0000_0000_0000, 0x7ff8_0000_0000_0000),
            (0xfe37_e43c_8800_759c, 0x7ff8_0000_0000_0000),
            (0xfff0_0000_0000_0000, 0x7ff8_0000_0000_0000),
            (0xbff0_0000_0000_0000, 0x7ff8_0000_0000_0000),
            (0xc000_0000_0000_0000, 0x7ff8_0000_0000_0000),
        ] {
            let got = tgamma(f64::from_bits(x)).to_bits();
            assert_eq!(got, want, "tgamma({x:#x}) = {got:#x}, glibc 2.43 {want:#x}");
        }
        assert!(tgamma(f64::NAN).is_nan());
    }

    #[test]
    fn lgamma_r_matches_glibc_2_43_on_corpus() {
        // Value and sign hashes of glibc 2.43's lgamma_r on the shared corpus.
        let mut c = Corpus::new();
        let mut hv = 0xcbf2_9ce4_8422_2325u64;
        let mut hs = 0xcbf2_9ce4_8422_2325u64;
        for i in 0..1_000_000 {
            let (y, s) = lgamma_r(c.sample(i % 3, -30, 12));
            hv = (hv ^ y.to_bits()).wrapping_mul(0x100_0000_01b3);
            hs = (hs ^ (i64::from(s) as u64)).wrapping_mul(0x100_0000_01b3);
        }
        assert_eq!(c.0, 0x5b5c_7615_1d8a_4788);
        assert_eq!(hv, 0x2682_ba69_955e_1c4f, "lgamma_r value hash");
        assert_eq!(hs, 0xa36e_ad98_bb06_8eeb, "lgamma_r sign hash");
    }

    #[test]
    fn lgamma_r_hard_and_special_cases() {
        // (input, glibc 2.43 value, glibc sign): database entries, roots near
        // -2.457, the 2^-75 / 1/32 / 1/2 / 8.29541 / 2^52 boundaries, the roots
        // at 1 and 2, poles (+inf with the sign of the zero / -1 for negative
        // integers), huge arguments and infinities.
        for (x, want, sign) in [
            (0xc004_cccc_cccc_cccdu64, 0xbfbe_3602_a772_5dbeu64, -1),
            (0xc021_b649_eb43_16fb, 0xc025_0332_a035_af1f, -1),
            (0xbfd2_6923_ac1f_7c10, 0x3ff7_df2c_32cf_08a3, -1),
            (0xc003_a7fc_9600_f86c, 0x3c90_323b_6d1f_e86d, -1),
            (0xc003_a7ef_9db2_2d0e, 0x3f03_a8ab_4332_558b, -1),
            (0xc006_0000_0000_0000, 0x3f72_61e6_d250_cf63, -1),
            (0xc024_8000_0000_0000, 0xc02c_6872_69b1_e743, -1),
            (0x3af0_0000_0000_0000, 0x404b_b9d3_beb8_c86b, 1),
            (0xbaf0_0000_0000_0000, 0x404b_b9d3_beb8_c86b, -1),
            (0x0000_0000_0000_0001, 0x4087_4385_446d_71c3, 1),
            (0x3f9e_b851_eb85_1eb8, 0x400b_eb75_f03c_93c6, 1),
            (0x3fd0_0000_0000_0000, 0x3ff4_9bbd_81c1_6efb, 1),
            (0x3fe0_0000_0000_0000, 0x3fe2_50d0_48e7_a1bd, 1),
            (0x3fe8_0000_0000_0000, 0x3fca_051c_3726_09ee, 1),
            (0x3ff0_0000_0000_0000, 0x0000_0000_0000_0000, 1),
            (0x4000_0000_0000_0000, 0x0000_0000_0000_0000, 1),
            (0x3ff0_0000_0006_df38, 0xbdcf_bb96_c643_47a7, 1),
            (0x3fff_ffff_e528_0d65, 0xbe66_b2b4_05fa_85a3, 1),
            (0x4008_0000_0000_0000, 0x3fe6_2e42_fefa_39ef, 1),
            (0x400c_0000_0000_0000, 0x3ff3_3730_1897_0a36, 1),
            (0x4020_973f_fac1_d29e, 0x4022_40af_32c9_d778, 1),
            (0x4020_9999_9999_999a, 0x4022_4583_3c3f_2ade, 1),
            (0x4059_0000_0000_0000, 0x4076_7225_b487_9462, 1),
            (0x4330_0000_0000_0000, 0x4381_8596_6f2b_4f12, 1),
            (0x43b0_0000_0000_0000, 0x4404_4b5e_cf0a_9650, 1),
            (0x7f60_06df_1bfa_c84e, 0x7ff0_0000_0000_0000, 1),
            (0x7fef_ffff_ffff_ffff, 0x7ff0_0000_0000_0000, 1),
            (0xffef_ffff_ffff_ffff, 0x7ff0_0000_0000_0000, 1),
            (0x7f57_54c0_0000_0000, 0x7fef_ffdd_7354_aa33, 1),
            (0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 1),
            (0xfff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 1),
            (0x0000_0000_0000_0000, 0x7ff0_0000_0000_0000, 1),
            (0x8000_0000_0000_0000, 0x7ff0_0000_0000_0000, -1),
            (0xbff0_0000_0000_0000, 0x7ff0_0000_0000_0000, -1),
            (0xc000_0000_0000_0000, 0x7ff0_0000_0000_0000, -1),
            (0xfe37_e43c_8800_759c, 0x7ff0_0000_0000_0000, -1),
            (0xbfe0_0000_0000_0000, 0x3ff4_3f89_a3f0_edd6, -1),
            (0xc00c_0000_0000_0000, 0xbff4_f1b0_fe64_a5d8, 1),
            (0xc065_4999_9999_999a, 0xc086_1610_f60c_1060, -1),
        ] {
            let (got, s) = lgamma_r(f64::from_bits(x));
            assert_eq!(
                (got.to_bits(), s),
                (want, sign),
                "lgamma_r({x:#x}) = ({:#x}, {s}), glibc 2.43 ({want:#x}, {sign})",
                got.to_bits()
            );
        }
        assert!(lgamma_r(f64::NAN).0.is_nan());
    }
}
