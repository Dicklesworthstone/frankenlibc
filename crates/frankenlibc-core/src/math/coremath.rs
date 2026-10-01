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
//! Constants keep the upstream C99 hex-float spelling through [`hf`], which is
//! evaluated at compile time and rejects any literal that is not exactly a
//! normal binary64 value, so the tables can be diffed against upstream.
//!
//! The C sources were verified correctly rounded both with and without FMA
//! contraction, so only the explicit `__builtin_fma` calls are kept as
//! `mul_add`; every other operation is a plain IEEE operation.

const MASK52: u64 = u64::MAX >> 12;

/// Parse a C99 hex-float literal (`[-]0x<hex>[.<hex>]p<[+-]dec>`) at compile time.
const fn hf(s: &str) -> f64 {
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

const ATANH_B: [(u16, i16); 32] = [
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

const ATANH_R1: [f64; 33] = [
    hf("0x1p+0"),
    hf("0x1.f5076p-1"),
    hf("0x1.ea4bp-1"),
    hf("0x1.dfc98p-1"),
    hf("0x1.d5818p-1"),
    hf("0x1.cb72p-1"),
    hf("0x1.c199cp-1"),
    hf("0x1.b7f76p-1"),
    hf("0x1.ae8ap-1"),
    hf("0x1.a5504p-1"),
    hf("0x1.9c492p-1"),
    hf("0x1.93738p-1"),
    hf("0x1.8ace6p-1"),
    hf("0x1.8258ap-1"),
    hf("0x1.7a114p-1"),
    hf("0x1.71f76p-1"),
    hf("0x1.6a09ep-1"),
    hf("0x1.6247ep-1"),
    hf("0x1.5ab08p-1"),
    hf("0x1.5342cp-1"),
    hf("0x1.4bfdap-1"),
    hf("0x1.44e08p-1"),
    hf("0x1.3dea6p-1"),
    hf("0x1.371a8p-1"),
    hf("0x1.306fep-1"),
    hf("0x1.29e9ep-1"),
    hf("0x1.2387ap-1"),
    hf("0x1.1d488p-1"),
    hf("0x1.172b8p-1"),
    hf("0x1.11302p-1"),
    hf("0x1.0b558p-1"),
    hf("0x1.059bp-1"),
    hf("0x1p-1"),
];

const ATANH_R2: [f64; 33] = [
    hf("0x1p+0"),
    hf("0x1.ffa74p-1"),
    hf("0x1.ff4eap-1"),
    hf("0x1.fef62p-1"),
    hf("0x1.fe9dap-1"),
    hf("0x1.fe452p-1"),
    hf("0x1.fdeccp-1"),
    hf("0x1.fd946p-1"),
    hf("0x1.fd3c2p-1"),
    hf("0x1.fce3ep-1"),
    hf("0x1.fc8bcp-1"),
    hf("0x1.fc33ap-1"),
    hf("0x1.fbdbap-1"),
    hf("0x1.fb83ap-1"),
    hf("0x1.fb2bcp-1"),
    hf("0x1.fad3ep-1"),
    hf("0x1.fa7c2p-1"),
    hf("0x1.fa246p-1"),
    hf("0x1.f9ccap-1"),
    hf("0x1.f975p-1"),
    hf("0x1.f91d8p-1"),
    hf("0x1.f8c6p-1"),
    hf("0x1.f86e8p-1"),
    hf("0x1.f8172p-1"),
    hf("0x1.f7bfep-1"),
    hf("0x1.f768ap-1"),
    hf("0x1.f7116p-1"),
    hf("0x1.f6ba4p-1"),
    hf("0x1.f6632p-1"),
    hf("0x1.f60c2p-1"),
    hf("0x1.f5b52p-1"),
    hf("0x1.f55e4p-1"),
    hf("0x1.f5076p-1"),
];

/// `(low, high)` parts of -log(r1[i]).
const ATANH_L1: [[f64; 2]; 33] = [
    [hf("0x0p+0"), hf("0x0p+0")],
    [hf("-0x1.532c1269e2038p-27"), hf("0x1.62e5p-7")],
    [hf("0x1.ce42d81b54e84p-27"), hf("0x1.62e3cp-6")],
    [hf("-0x1.25826f815ec3dp-26"), hf("0x1.0a2acp-5")],
    [hf("0x1.0db1b1e7cee11p-26"), hf("0x1.62e4ap-5")],
    [hf("-0x1.1f3a8c6c95003p-26"), hf("0x1.bb9dcp-5")],
    [hf("-0x1.774cd4fb8c30dp-26"), hf("0x1.0a2b2p-4")],
    [hf("0x1.452e56c030a0ap-29"), hf("0x1.3687fp-4")],
    [hf("0x1.6b63c4966a79ap-28"), hf("0x1.62e41p-4")],
    [hf("-0x1.b20a21ccb525ep-28"), hf("0x1.8f40ap-4")],
    [hf("0x1.4006cfb3d8f85p-26"), hf("0x1.bb9d1p-4")],
    [hf("-0x1.cdb026b310c41p-26"), hf("0x1.e7f9bp-4")],
    [hf("-0x1.69124fdc0f16dp-26"), hf("0x1.0a2b08p-3")],
    [hf("-0x1.084656cdc2727p-26"), hf("0x1.205958p-3")],
    [hf("-0x1.376fa8b0357fdp-26"), hf("0x1.3687cp-3")],
    [hf("0x1.e56ae55a47b4ap-28"), hf("0x1.4cb5e8p-3")],
    [hf("0x1.070ff8834eeb4p-26"), hf("0x1.62e44p-3")],
    [hf("0x1.623516109f4fep-26"), hf("0x1.79129p-3")],
    [hf("-0x1.ec656b95fbdacp-29"), hf("0x1.8f40bp-3")],
    [hf("0x1.f0ca2e729f51p-28"), hf("0x1.a56ed8p-3")],
    [hf("-0x1.7d260a858354ap-26"), hf("0x1.bb9d68p-3")],
    [hf("0x1.e7279075503d3p-27"), hf("0x1.d1cb9p-3")],
    [hf("0x1.39e1a0a503873p-27"), hf("0x1.e7f9dp-3")],
    [hf("0x1.cd86d7b87c3d6p-26"), hf("0x1.fe27d8p-3")],
    [hf("0x1.060ab88de341ep-26"), hf("0x1.0a2b24p-2")],
    [hf("0x1.20a860d3f939p-28"), hf("0x1.154244p-2")],
    [hf("-0x1.dacee95fc2f1p-27"), hf("0x1.205974p-2")],
    [hf("0x1.45de3a86e0acap-26"), hf("0x1.2b707p-2")],
    [hf("0x1.c164cbfb991afp-27"), hf("0x1.3687bp-2")],
    [hf("0x1.d3f66b24225efp-26"), hf("0x1.419ec4p-2")],
    [hf("0x1.fc023efa144bap-26"), hf("0x1.4cb5f8p-2")],
    [hf("0x1.086a8af6f26cp-28"), hf("0x1.57cd28p-2")],
    [hf("-0x1.05c610ca86c39p-30"), hf("0x1.62e43p-2")],
];

/// `(low, high)` parts of -log(r2[i]).
const ATANH_L2: [[f64; 2]; 33] = [
    [hf("0x0p+0"), hf("0x0p+0")],
    [hf("-0x1.37e152a129e4ep-28"), hf("0x1.632p-12")],
    [hf("-0x1.3f6c916b8be9cp-26"), hf("0x1.63p-11")],
    [hf("0x1.20505936739d5p-26"), hf("0x1.0a24p-10")],
    [hf("-0x1.23e2e8cb541bap-26"), hf("0x1.62dcp-10")],
    [hf("-0x1.acb7983ac4f5ep-32"), hf("0x1.bbap-10")],
    [hf("0x1.6f7c7689c63aep-28"), hf("0x1.0a2ap-9")],
    [hf("0x1.f5ca695b4c58bp-30"), hf("0x1.368cp-9")],
    [hf("-0x1.c6c18bd953226p-27"), hf("0x1.62e6p-9")],
    [hf("0x1.7a516c34846bdp-26"), hf("0x1.8f46p-9")],
    [hf("-0x1.f3b83dd8b853p-27"), hf("0x1.bbap-9")],
    [hf("-0x1.c3459046e4e57p-31"), hf("0x1.e8p-9")],
    [hf("0x1.b5c7e34cb79f6p-38"), hf("0x1.0a2cp-8")],
    [hf("-0x1.2487e9af9a692p-27"), hf("0x1.205cp-8")],
    [hf("0x1.f21bbc4ad79cep-26"), hf("0x1.3687p-8")],
    [hf("-0x1.550ffc857b731p-29"), hf("0x1.4cb7p-8")],
    [hf("0x1.87458ec1b7b34p-27"), hf("0x1.62e2p-8")],
    [hf("0x1.103d4fe83ee81p-26"), hf("0x1.7911p-8")],
    [hf("0x1.810483d3b398cp-27"), hf("0x1.8f44p-8")],
    [hf("-0x1.2085cb340608ep-27"), hf("0x1.a573p-8")],
    [hf("0x1.12698a119c42fp-26"), hf("0x1.bb9dp-8")],
    [hf("-0x1.edb8c172b4c33p-26"), hf("0x1.d1ccp-8")],
    [hf("-0x1.8b55b87a5e238p-26"), hf("0x1.e7fep-8")],
    [hf("0x1.be5e17763f78ap-26"), hf("0x1.fe2bp-8")],
    [hf("-0x1.c2d496790073ep-30"), hf("0x1.0a2a8p-7")],
    [hf("0x1.6542f523abeecp-26"), hf("0x1.1541p-7")],
    [hf("-0x1.b7fdbe5b193f8p-26"), hf("0x1.205ap-7")],
    [hf("0x1.fa4d42fe30c7cp-26"), hf("0x1.2b7p-7")],
    [hf("0x1.0d46ad04adc86p-26"), hf("0x1.36888p-7")],
    [hf("-0x1.1c22d02d17c4cp-26"), hf("0x1.419fp-7")],
    [hf("0x1.a7d1e330dcccep-30"), hf("0x1.4cb7p-7")],
    [hf("0x1.187025e656ba3p-31"), hf("0x1.57cdp-7")],
    [hf("-0x1.532c1269e2038p-27"), hf("0x1.62e5p-7")],
];

/// Accurate path for |x| < 1/4: odd series of atanh in double-double.
#[inline(never)]
fn atanh_zero(x: f64) -> f64 {
    const CH: [[f64; 2]; 13] = [
        [hf("0x1.5555555555555p-2"), hf("0x1.5555555555555p-56")],
        [hf("0x1.999999999999ap-3"), hf("-0x1.999999999611cp-57")],
        [hf("0x1.2492492492492p-3"), hf("0x1.2492490f76b25p-57")],
        [hf("0x1.c71c71c71c71cp-4"), hf("0x1.c71cd5c38a112p-58")],
        [hf("0x1.745d1745d1746p-4"), hf("-0x1.7556c4165f4cap-59")],
        [hf("0x1.3b13b13b13b14p-4"), hf("-0x1.b893c3b36052ep-59")],
        [hf("0x1.1111111111105p-4"), hf("0x1.4e1afd723ed1fp-59")],
        [hf("0x1.e1e1e1e1e2678p-5"), hf("-0x1.f86ea96fb1435p-59")],
        [hf("0x1.af286bc9f90ccp-5"), hf("0x1.1e51a6e54fde9p-60")],
        [hf("0x1.8618618c779b6p-5"), hf("-0x1.ab913de95c3bfp-61")],
        [hf("0x1.642c84aa383ebp-5"), hf("0x1.632e747641b12p-59")],
        [hf("0x1.47ae2d205013cp-5"), hf("-0x1.0c9617e7bcff2p-60")],
        [hf("0x1.2f664d60473f9p-5"), hf("0x1.3adb3e2b7f35ep-61")],
    ];
    const CL: [f64; 5] = [
        hf("0x1.1a9a91fd692afp-5"),
        hf("0x1.06dfbb35e7f44p-5"),
        hf("0x1.037bed4d7588fp-5"),
        hf("0x1.5aca6d6d720d6p-6"),
        hf("0x1.99ea5700d53a5p-5"),
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
        hf("0x1.2dbb7b1c91363p-2"),
        hf("0x1.36f33d51c264dp-2"),
        hf("0x1p-56"),
    ],
    [
        hf("0x1.c493dc899e4a5p-2"),
        hf("0x1.e611aa58ab608p-2"),
        hf("-0x1p-56"),
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

const ATANH_T1: [f64; 17] = [
    hf("0x1p+0"),
    hf("0x1.ea4afap-1"),
    hf("0x1.d5818ep-1"),
    hf("0x1.c199bep-1"),
    hf("0x1.ae89f98p-1"),
    hf("0x1.9c4918p-1"),
    hf("0x1.8ace54p-1"),
    hf("0x1.7a1147p-1"),
    hf("0x1.6a09e68p-1"),
    hf("0x1.5ab07ep-1"),
    hf("0x1.4bfdad8p-1"),
    hf("0x1.3dea65p-1"),
    hf("0x1.306fe08p-1"),
    hf("0x1.2387a7p-1"),
    hf("0x1.172b84p-1"),
    hf("0x1.0b5587p-1"),
    hf("0x1p-1"),
];
const ATANH_T2: [f64; 16] = [
    hf("0x1p+0"),
    hf("0x1.fe9d968p-1"),
    hf("0x1.fd3c228p-1"),
    hf("0x1.fbdba38p-1"),
    hf("0x1.fa7c18p-1"),
    hf("0x1.f91d8p-1"),
    hf("0x1.f7bfdbp-1"),
    hf("0x1.f663278p-1"),
    hf("0x1.f507658p-1"),
    hf("0x1.f3ac948p-1"),
    hf("0x1.f252b38p-1"),
    hf("0x1.f0f9c2p-1"),
    hf("0x1.efa1bfp-1"),
    hf("0x1.ee4aaap-1"),
    hf("0x1.ecf483p-1"),
    hf("0x1.eb9f488p-1"),
];
const ATANH_T3: [f64; 16] = [
    hf("0x1p+0"),
    hf("0x1.ffe9d2p-1"),
    hf("0x1.ffd3a58p-1"),
    hf("0x1.ffbd798p-1"),
    hf("0x1.ffa74e8p-1"),
    hf("0x1.ff91248p-1"),
    hf("0x1.ff7afb8p-1"),
    hf("0x1.ff64d38p-1"),
    hf("0x1.ff4eac8p-1"),
    hf("0x1.ff38868p-1"),
    hf("0x1.ff22618p-1"),
    hf("0x1.ff0c3dp-1"),
    hf("0x1.fef61ap-1"),
    hf("0x1.fedff78p-1"),
    hf("0x1.fec9d68p-1"),
    hf("0x1.feb3b6p-1"),
];
const ATANH_T4: [f64; 16] = [
    hf("0x1p+0"),
    hf("0x1.fffe9dp-1"),
    hf("0x1.fffd3ap-1"),
    hf("0x1.fffbd78p-1"),
    hf("0x1.fffa748p-1"),
    hf("0x1.fff9118p-1"),
    hf("0x1.fff7ae8p-1"),
    hf("0x1.fff64cp-1"),
    hf("0x1.fff4e9p-1"),
    hf("0x1.fff386p-1"),
    hf("0x1.fff2238p-1"),
    hf("0x1.fff0c08p-1"),
    hf("0x1.ffef5d8p-1"),
    hf("0x1.ffedfa8p-1"),
    hf("0x1.ffec98p-1"),
    hf("0x1.ffeb35p-1"),
];

/// Triple-double -log(t1[i]), -log(t2[i]), -log(t3[i]), -log(t4[i]).
const ATANH_LL: [[[f64; 3]; 17]; 4] = [
    [
        [hf("0x0p+0"), hf("0x0p+0"), hf("0x0p+0")],
        [
            hf("0x1.62e432b24p-6"),
            hf("-0x1.745af34bb54b8p-42"),
            hf("-0x1.17e3ec05cde7p-97"),
        ],
        [
            hf("0x1.62e42e4a8p-5"),
            hf("0x1.111a4eadf312p-44"),
            hf("0x1.cff3027abb119p-93"),
        ],
        [
            hf("0x1.0a2b233f1p-4"),
            hf("-0x1.88ac4ec78af8p-42"),
            hf("0x1.4fa087ca75dfdp-93"),
        ],
        [
            hf("0x1.62e43056cp-4"),
            hf("0x1.6bd65e8b0b7p-46"),
            hf("-0x1.b18e160362c24p-95"),
        ],
        [
            hf("0x1.bb9d3cbd6p-4"),
            hf("0x1.de14aa55ec2bp-42"),
            hf("-0x1.c6ac3f1862a6bp-94"),
        ],
        [
            hf("0x1.0a2b244dap-3"),
            hf("0x1.94def487fea7p-42"),
            hf("-0x1.dead1a4581acfp-94"),
        ],
        [
            hf("0x1.3687aa9b78p-3"),
            hf("0x1.9cec9a50db22p-43"),
            hf("0x1.34a70684f8e0ep-93"),
        ],
        [
            hf("0x1.62e42fabap-3"),
            hf("-0x1.d69047a3aebp-44"),
            hf("-0x1.4e061f79144e2p-95"),
        ],
        [
            hf("0x1.8f40b56d28p-3"),
            hf("0x1.de7d755fd2e2p-42"),
            hf("0x1.bdc7ecf001489p-94"),
        ],
        [
            hf("0x1.bb9d3b61fp-3"),
            hf("0x1.c14f1445b12p-46"),
            hf("0x1.a1d78cbdc5b58p-93"),
        ],
        [
            hf("0x1.e7f9c11f08p-3"),
            hf("-0x1.6e3e0000dae7p-43"),
            hf("0x1.6a4559fadde98p-94"),
        ],
        [
            hf("0x1.0a2b242ec4p-2"),
            hf("0x1.bb7cf852a5fe8p-42"),
            hf("0x1.a6aef11ee43bdp-93"),
        ],
        [
            hf("0x1.205966c764p-2"),
            hf("0x1.ad3a5f214294p-45"),
            hf("0x1.5cc344fa10652p-93"),
        ],
        [
            hf("0x1.3687a98aacp-2"),
            hf("0x1.1623671842fp-45"),
            hf("-0x1.0b428fe1f9e43p-94"),
        ],
        [
            hf("0x1.4cb5ec93f4p-2"),
            hf("0x1.3d50980ea513p-42"),
            hf("0x1.67f0ea083b1c4p-93"),
        ],
        [
            hf("0x1.62e42fefa4p-2"),
            hf("-0x1.8432a1b0e264p-44"),
            hf("0x1.803f2f6af40f3p-93"),
        ],
    ],
    [
        [hf("0x0p+0"), hf("0x0p+0"), hf("0x0p+0")],
        [
            hf("0x1.62e462b4p-10"),
            hf("0x1.061d003b97318p-42"),
            hf("0x1.d7faee66a2e1ep-93"),
        ],
        [
            hf("0x1.62e44c92p-9"),
            hf("0x1.95a7bff5e239p-42"),
            hf("-0x1.f7e788a87135p-95"),
        ],
        [
            hf("0x1.0a2b1e33p-8"),
            hf("0x1.2a3a1a65aa3ap-43"),
            hf("-0x1.54599c9605442p-93"),
        ],
        [
            hf("0x1.62e4367cp-8"),
            hf("-0x1.4a995b6d9ddcp-45"),
            hf("-0x1.56bb79b254f33p-100"),
        ],
        [
            hf("0x1.bb9d449ap-8"),
            hf("0x1.8a119c42e9bcp-42"),
            hf("-0x1.8ecf7d8d661f1p-93"),
        ],
        [
            hf("0x1.0a2b1f19p-7"),
            hf("0x1.8863771bd10a8p-42"),
            hf("0x1.e9731de7f0155p-94"),
        ],
        [
            hf("0x1.3687ad11p-7"),
            hf("0x1.e026a347ca1c8p-42"),
            hf("0x1.fadc62522444dp-97"),
        ],
        [
            hf("0x1.62e436f28p-7"),
            hf("0x1.25b84f71b70b8p-42"),
            hf("-0x1.fcb3f98612d27p-96"),
        ],
        [
            hf("0x1.8f40b7b38p-7"),
            hf("-0x1.62a0a4fd4758p-43"),
            hf("0x1.3cb3c35d9f6a1p-93"),
        ],
        [
            hf("0x1.bb9d3abbp-7"),
            hf("-0x1.0ec48f94d786p-42"),
            hf("-0x1.6b47d410e4cc7p-93"),
        ],
        [
            hf("0x1.e7f9bb23p-7"),
            hf("0x1.e4415cbc97ap-43"),
            hf("-0x1.3729fdb677231p-93"),
        ],
        [
            hf("0x1.0a2b22478p-6"),
            hf("-0x1.cb73f4505b03p-42"),
            hf("-0x1.1b3b3a3bc370ap-93"),
        ],
        [
            hf("0x1.2059691e8p-6"),
            hf("-0x1.abcc3412f264p-43"),
            hf("-0x1.fe6e998e48673p-95"),
        ],
        [
            hf("0x1.3687a768p-6"),
            hf("-0x1.43901e5c97a9p-42"),
            hf("0x1.b54cdd52a5d88p-96"),
        ],
        [
            hf("0x1.4cb5eb5d8p-6"),
            hf("-0x1.8f106f00f13b8p-42"),
            hf("-0x1.8f793f5fce148p-93"),
        ],
        [
            hf("0x1.62e432b24p-6"),
            hf("-0x1.745af34bb54b8p-42"),
            hf("-0x1.17e3ec05cde7p-97"),
        ],
    ],
    [
        [hf("0x0p+0"), hf("0x0p+0"), hf("0x0p+0")],
        [
            hf("0x1.62e7bp-14"),
            hf("-0x1.868625640a68p-44"),
            hf("-0x1.34bf0db910f65p-93"),
        ],
        [
            hf("0x1.62e35f6p-13"),
            hf("-0x1.2ee3d96b696ap-43"),
            hf("0x1.a2948cd558655p-94"),
        ],
        [
            hf("0x1.0a2b4b2p-12"),
            hf("0x1.53edbcf1165p-47"),
            hf("-0x1.cfc26ccf6d0e4p-97"),
        ],
        [
            hf("0x1.62e4be1p-12"),
            hf("0x1.783e334614p-52"),
            hf("-0x1.04b96da30e63ap-93"),
        ],
        [
            hf("0x1.bb9e085p-12"),
            hf("-0x1.60785f20acb2p-43"),
            hf("-0x1.f33369bf7dff1p-96"),
        ],
        [
            hf("0x1.0a2b94dp-11"),
            hf("0x1.fd4b3a273353p-42"),
            hf("-0x1.685a35575eff1p-96"),
        ],
        [
            hf("0x1.368810f8p-11"),
            hf("0x1.7ded26dc813p-47"),
            hf("-0x1.4c4d1abca79bfp-96"),
        ],
        [
            hf("0x1.62e47878p-11"),
            hf("0x1.7d2bee9a1f63p-42"),
            hf("0x1.860233b7ad13p-93"),
        ],
        [
            hf("0x1.8f40cb48p-11"),
            hf("-0x1.af034eaf471cp-42"),
            hf("0x1.ae748822d57b7p-94"),
        ],
        [
            hf("0x1.bb9d094p-11"),
            hf("-0x1.7a223013a20fp-42"),
            hf("-0x1.1e499087075b6p-93"),
        ],
        [
            hf("0x1.e7fa32c8p-11"),
            hf("-0x1.b2e67b1b59bdp-43"),
            hf("-0x1.54a41eda30fa6p-93"),
        ],
        [
            hf("0x1.0a2b237p-10"),
            hf("-0x1.7ad97ff4ac7ap-44"),
            hf("0x1.f932da91371ddp-93"),
        ],
        [
            hf("0x1.2059a338p-10"),
            hf("-0x1.96422d90df4p-44"),
            hf("-0x1.90800fbbf2ed3p-94"),
        ],
        [
            hf("0x1.36879824p-10"),
            hf("0x1.0f9054001812p-44"),
            hf("0x1.9567e01e48f9ap-93"),
        ],
        [
            hf("0x1.4cb602cp-10"),
            hf("-0x1.0d709a5ec0b5p-43"),
            hf("0x1.253dfd44635d2p-94"),
        ],
        [
            hf("0x1.62e462b4p-10"),
            hf("0x1.061d003b97318p-42"),
            hf("0x1.d7faee66a2e1ep-93"),
        ],
    ],
    [
        [hf("0x0p+0"), hf("0x0p+0"), hf("0x0p+0")],
        [
            hf("0x1.63007cp-18"),
            hf("-0x1.db0e38e5aaaap-43"),
            hf("0x1.259a7b94815b9p-93"),
        ],
        [
            hf("0x1.6300f6p-17"),
            hf("0x1.2b1c75580438p-44"),
            hf("0x1.78cabba01e3e4p-93"),
        ],
        [
            hf("0x1.0a2115p-16"),
            hf("-0x1.5ff223730759p-42"),
            hf("0x1.8074feacfe49dp-95"),
        ],
        [
            hf("0x1.62e1ecp-16"),
            hf("-0x1.85d6f6487ce4p-45"),
            hf("0x1.05485074b9276p-93"),
        ],
        [
            hf("0x1.bba301p-16"),
            hf("-0x1.af5d58a7c921p-43"),
            hf("-0x1.30a8c0fd2ff5fp-93"),
        ],
        [
            hf("0x1.0a32298p-15"),
            hf("0x1.590faa0883bdp-43"),
            hf("0x1.95e9bda999947p-93"),
        ],
        [
            hf("0x1.3682f1p-15"),
            hf("0x1.f0224376efaf8p-42"),
            hf("-0x1.5843c0db50d1p-93"),
        ],
        [
            hf("0x1.62e3d8p-15"),
            hf("-0x1.142c13daed4ap-43"),
            hf("0x1.c68a61183ce87p-93"),
        ],
        [
            hf("0x1.8f44dd8p-15"),
            hf("-0x1.aa489f399931p-43"),
            hf("0x1.11c5c376854eap-94"),
        ],
        [
            hf("0x1.bb9601p-15"),
            hf("0x1.9904d8b6a3638p-42"),
            hf("0x1.8c89554493c8fp-93"),
        ],
        [
            hf("0x1.e7f744p-15"),
            hf("0x1.5785ddbe7cba8p-42"),
            hf("0x1.e7ff3cde7d70cp-94"),
        ],
        [
            hf("0x1.0a2c53p-14"),
            hf("-0x1.6d9e8780d0d5p-43"),
            hf("0x1.ad9c178106693p-94"),
        ],
        [
            hf("0x1.205d134p-14"),
            hf("-0x1.214a2e893fccp-43"),
            hf("0x1.548a9500c9822p-93"),
        ],
        [
            hf("0x1.3685e28p-14"),
            hf("0x1.e23588646103p-43"),
            hf("0x1.2a97b26da2d88p-94"),
        ],
        [
            hf("0x1.4cb6c18p-14"),
            hf("0x1.2b7cfcea9e0d8p-42"),
            hf("-0x1.5095048a6b824p-93"),
        ],
        [
            hf("0x1.62e7bp-14"),
            hf("-0x1.868625640a68p-44"),
            hf("-0x1.34bf0db910f65p-93"),
        ],
    ],
];

/// Accurate path for |x| >= 1/4: log(zh + zl) in triple-double, where
/// `a` ~ log2(zh + zl) selects the table indices.
#[inline(never)]
fn atanh_refine(x: f64, zh: f64, zl: f64, a: f64) -> f64 {
    const CH: [[f64; 2]; 3] = [
        [hf("0x1p-1"), hf("0x1.24b67ee516e3bp-111")],
        [hf("-0x1p-2"), hf("-0x1.932ce43199a8dp-110")],
        [hf("0x1.5555555555555p-3"), hf("0x1.55540c15cf91fp-57")],
    ];
    const CL: [f64; 3] = [
        hf("-0x1p-3"),
        hf("0x1.9999999a0754fp-4"),
        hf("-0x1.55555555c3157p-4"),
    ];
    const L20: f64 = hf("0x1.62e42fefa3ap-2");
    const L21: f64 = hf("-0x1.0ca86c3898dp-50");
    const L22: f64 = hf("0x1.f97b57a079ap-104");

    let mut t = zh.to_bits();
    let e = (t >> 52) as i32 - 0x3ff;
    t &= MASK52;
    t |= 0x3ffu64 << 52;
    let tf = f64::from_bits(t);
    let ed = e as f64;
    let v = (a - ed + hf("0x1.00008p+0")).to_bits();
    let i = v.wrapping_sub(0x3ffu64 << 52) >> (52 - 16);
    let i1 = (i >> 12) as usize;
    let i2 = ((i >> 8) & 0xf) as usize;
    let i3 = ((i >> 4) & 0xf) as usize;
    let i4 = (i & 0xf) as usize;
    let el2 = L22 * ed;
    let el1 = L21 * ed;
    let el0 = L20 * ed;
    let ll = &ATANH_LL;
    let l0 = ll[0][i1][0] + ll[1][i2][0] + (ll[2][i3][0] + ll[3][i4][0]) + el0;
    let l1 = ll[0][i1][1] + ll[1][i2][1] + (ll[2][i3][1] + ll[3][i4][1]);
    let l2 = ll[0][i1][2] + ll[1][i2][2] + (ll[2][i3][2] + ll[3][i4][2]);
    let t12 = ATANH_T1[i1] * ATANH_T2[i2];
    let t34 = ATANH_T3[i3] * ATANH_T4[i4];
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
            return x.mul_add(hf("0x1p-55"), x);
        }
        const C: [f64; 9] = [
            hf("0x1.999999999999ap-3"),
            hf("0x1.2492492492244p-3"),
            hf("0x1.c71c71c79715fp-4"),
            hf("0x1.745d16f777723p-4"),
            hf("0x1.3b13ca4174634p-4"),
            hf("0x1.110c9724989bdp-4"),
            hf("0x1.e2d17608a5b2ep-5"),
            hf("0x1.a0b56308cba0bp-5"),
            hf("0x1.fb6341208ad2ep-5"),
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
        let t = x2.mul_add(p, hf("0x1.5555555555555p-56"));
        let (ph, pl) = fasttwosum(hf("0x1.5555555555555p-2"), t);
        let (ph, mut pl) = muldd(ph, pl, x3, dx3);
        let (ph, tl) = fasttwosum(x, ph);
        pl += tl;
        let eps = x * (x4 * hf("0x1.dp-53") + hf("0x1p-103"));
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
        hf("-0x1p+0"),
        hf("0x1.555555555553p+0"),
        hf("-0x1.fffffffffffap+0"),
        hf("0x1.99999e33a6366p+1"),
        hf("-0x1.555559ef9525fp+2"),
    ];
    let mut t = th.to_bits();
    let e = (t >> 52) as i32 - 0x3ff;
    t &= MASK52;
    let ed = e as f64;
    let i = (t >> (52 - 5)) as usize;
    let d = (t & (u64::MAX >> 17)) as i64;
    let (c0, c1) = ATANH_B[i];
    let j = t
        .wrapping_add((c0 as u64) << 33)
        .wrapping_add((c1 as i64).wrapping_mul(d >> 16) as u64)
        >> (52 - 10);
    t |= 0x3ffu64 << 52;
    let tf = f64::from_bits(t);
    let i1 = (j >> 5) as usize;
    let i2 = (j & 0x1f) as usize;
    let r = (0.5 * ATANH_R1[i1]) * ATANH_R2[i2];
    let dx = r.mul_add(tf, -0.5);
    let dx2 = dx * dx;
    let rx = r * tf;
    let dxl = r.mul_add(tf, -rx);
    let f = dx2 * ((C[0] + dx * C[1]) + dx2 * (C[2] + dx * C[3] + dx2 * C[4]));
    const L2H: f64 = hf("0x1.62e42fefa3ap-2");
    const L2L: f64 = hf("-0x1.0ca86c3898dp-50");
    let lh = (ATANH_L1[i1][1] + ATANH_L2[i2][1]) + L2H * ed;
    let (mut lh, mut ll) = fasttwosum(lh, rx - 0.5);
    ll += L2L * ed + (ATANH_L1[i1][0] + ATANH_L2[i2][0]) + dxl + 0.5 * tl / th;
    ll += f;
    let sgn = 1.0f64.copysign(x);
    lh *= sgn;
    ll *= sgn;
    let eps = 38e-24 + dx2 * hf("0x1p-49");
    let lb = lh + (ll - eps);
    let ub = lh + (ll + eps);
    if lb == ub {
        return lb;
    }
    let (th, tl) = fasttwosum(th, tl);
    atanh_refine(x, th, tl, hf("0x1.71547652b82fep+1") * (lh + ll).abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hf_parses_exact_literals() {
        assert_eq!(hf("0x1p+0"), 1.0);
        assert_eq!(hf("-0x1.8p+1"), -3.0);
        assert_eq!(hf("0x0p+0").to_bits(), 0);
        assert_eq!(
            hf("0x1.5555555555555p-2"),
            f64::from_bits(0x3fd5_5555_5555_5555)
        );
        assert_eq!(
            hf("0x1.62e42fefa3ap-2"),
            f64::from_bits(0x3fd6_2e42_fefa_3a00)
        );
        assert_eq!(
            hf("0x1.56bb79b254f33p-100"),
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
                1 => (r >> 11) as f64 * hf("0x1p-53") * 2.0 - 1.0,
                _ => 1.0 - (r >> 11) as f64 * hf("0x1p-73"),
            }
        }
    }

    /// FNV-1a over the result bits of `f` on the 1M-input corpus.
    fn corpus_hash(f: fn(f64) -> f64, lo: i32, hi: i32) -> u64 {
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
}
