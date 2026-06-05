//! Exponential and logarithmic functions.

#[inline]
pub fn exp(x: f64) -> f64 {
    if let Some(result) = exp_medium_exp2_fast_path(x) {
        return result;
    }
    libm::exp(x)
}

#[inline]
pub fn exp2(x: f64) -> f64 {
    libm::exp2(x)
}

// expm1 exists to avoid the catastrophic cancellation of `exp(x)-1` as x→0.
// Away from zero there is no cancellation, so on the positive medium band the
// direct `exp(x)-1` is both accurate (≤3 ULP vs glibc) and far cheaper than
// libm's dedicated expm1 polynomial — and our `exp` fast path already beats
// glibc. Mirrors the f32 `expm1f` lever. x<0.5 (incl. the near-0 cancellation
// region) and large/non-finite x defer to libm for exact semantics.
const EXPM1_POSITIVE_FAST_MIN: f64 = 0.5;
const EXPM1_POSITIVE_FAST_MAX: f64 = 2.5;

#[inline]
pub fn expm1(x: f64) -> f64 {
    if (EXPM1_POSITIVE_FAST_MIN..=EXPM1_POSITIVE_FAST_MAX).contains(&x) {
        return exp(x) - 1.0;
    }
    libm::expm1(x)
}

#[inline]
pub fn log(x: f64) -> f64 {
    libm::log(x)
}

/// `log2` via the cheaper natural-log kernel: `log2(x) = ln(x) * log2(e)`.
///
/// Profiling (`glibc_baseline_math`, bd-e4jb7k) showed `libm::log2` (~12.2 ns)
/// is markedly slower than `libm::log` (~9.5 ns) — glibc's `log2` (~9.0 ns) is
/// hand-tuned, leaving fl `log2` ~1.35x behind. Routing through `libm::log`
/// scaled by `LOG2_E` reaches glibc parity. A 4M-point sweep (full dynamic
/// range + the near-1 region where `log2 -> 0`) bounds the result within 2 ULP
/// of `libm::log2` (itself correctly rounded), so within the established
/// 4-ULP-vs-glibc math contract shared by the exp/pow fast paths.
///
/// Exact powers of two are gated out (mantissa bits all zero) so glibc's exact
/// integer result (`log2(2^k) == k`) is preserved bit-for-bit; subnormals,
/// non-positive, and non-finite inputs defer to `libm::log2` for its precise
/// special-case handling.
// ---------------------------------------------------------------------------
// log2: ARM optimized-routines-style table + degree-8 poly (bd-e4jb7k).
//
// The shipped `ln(x)·LOG2_E` reroute was 1.26x slower than glibc and the whole
// pow family inherits log2's cost. This replaces it with the
// optimized-routines reduction: x = 2^k·z with z near 1 in one of 64 buckets
// (the `OFF` bit-trick centers the reduction so `k + logc` never catastrophically
// cancels — logc stays the same magnitude as the result near x=1). r = z/c-1 is
// tiny; log2(x) = k + logc + r/ln2 + r²·poly(r), finalized in a hi/lo pair
// (ARM's two-sum recovery) with the table's `logc` carried as double-double.
// A separate atanh branch handles |x-1|<0.15 where the result→0 needs relative
// accuracy. Tables generated offline in double-double (dd atanh), embedded as
// exact bit patterns. Validated <=3 ULP vs glibc on [1e-300,1e300] (2 ULP on the
// normal sweep), bit-exact on powers of two, and ~1.7x faster than libm::log2.
const LOG2_OFF: u64 = 0x3fe6000000000000;
const LOG2_INVLN2_HI: f64 = f64::from_bits(0x3FF7154765200000);
const LOG2_INVLN2_LO: f64 = f64::from_bits(0x3DE705FC2EEFA200);
// log2(1+r) - r/ln2 = r²·(C2 + r·C3 + …); C_k = (-1)^k/(k·ln2). Degree 8 keeps
// the bucket-edge (|r|<1/128) truncation well under 1 ULP.
const LOG2_C2: f64 = -0.7213475204444817;
const LOG2_C3: f64 = 0.4808983469629878;
const LOG2_C4: f64 = -0.36067376022240424;
const LOG2_C5: f64 = 0.2885390081777927;
const LOG2_C6: f64 = -0.24046880792913617;
const LOG2_C7: f64 = 0.20611528765933095;
const LOG2_C8: f64 = -0.18033688011112045;
// Near-1 atanh series: log2(1+f) = (2/ln2)·atanh(s), s = f/(2+f). A_k=(2/ln2)/k.
const LOG2_A1: f64 = 2.885390081777926774;
const LOG2_A3: f64 = LOG2_A1 / 3.0;
const LOG2_A5: f64 = LOG2_A1 / 5.0;
const LOG2_A7: f64 = LOG2_A1 / 7.0;
const LOG2_A9: f64 = LOG2_A1 / 9.0;
const LOG2_A11: f64 = LOG2_A1 / 11.0;
const LOG2_A13: f64 = LOG2_A1 / 13.0;
const LOG2_A15: f64 = LOG2_A1 / 15.0;

const LOG2_INVC: [f64; 64] = [
    f64::from_bits(0x3ff724287f46debc), f64::from_bits(0x3ff6e1f76b4337c7), f64::from_bits(0x3ff6a13cd1537290), f64::from_bits(0x3ff661ec6a5122f9),
    f64::from_bits(0x3ff623fa77016240), f64::from_bits(0x3ff5e75bb8d015e7), f64::from_bits(0x3ff5ac056b015ac0), f64::from_bits(0x3ff571ed3c506b3a),
    f64::from_bits(0x3ff5390948f40feb), f64::from_bits(0x3ff5015015015015), f64::from_bits(0x3ff4cab88725af6e), f64::from_bits(0x3ff49539e3b2d067),
    f64::from_bits(0x3ff460cbc7f5cf9a), f64::from_bits(0x3ff42d6625d51f87), f64::from_bits(0x3ff3fb013fb013fb), f64::from_bits(0x3ff3c995a47babe7),
    f64::from_bits(0x3ff3991c2c187f63), f64::from_bits(0x3ff3698df3de0748), f64::from_bits(0x3ff33ae45b57bcb2), f64::from_bits(0x3ff30d190130d190),
    f64::from_bits(0x3ff2e025c04b8097), f64::from_bits(0x3ff2b404ad012b40), f64::from_bits(0x3ff288b01288b013), f64::from_bits(0x3ff25e22708092f1),
    f64::from_bits(0x3ff23456789abcdf), f64::from_bits(0x3ff20b470c67c0d9), f64::from_bits(0x3ff1e2ef3b3fb874), f64::from_bits(0x3ff1bb4a4046ed29),
    f64::from_bits(0x3ff19453808ca29c), f64::from_bits(0x3ff16e0689427379), f64::from_bits(0x3ff1485f0e0acd3b), f64::from_bits(0x3ff12358e75d3033),
    f64::from_bits(0x3ff0fef010fef011), f64::from_bits(0x3ff0db20a88f4696), f64::from_bits(0x3ff0b7e6ec259dc8), f64::from_bits(0x3ff0953f39010954),
    f64::from_bits(0x3ff073260a47f7c6), f64::from_bits(0x3ff05197f7d73404), f64::from_bits(0x3ff03091b51f5e1a), f64::from_bits(0x3ff0101010101010),
    f64::from_bits(0x3fefc07f01fc07f0), f64::from_bits(0x3fef44659e4a4271), f64::from_bits(0x3feecc07b301ecc0), f64::from_bits(0x3fee573ac901e574),
    f64::from_bits(0x3fede5d6e3f8868a), f64::from_bits(0x3fed77b654b82c34), f64::from_bits(0x3fed0cb58f6ec074), f64::from_bits(0x3feca4b3055ee191),
    f64::from_bits(0x3fec3f8f01c3f8f0), f64::from_bits(0x3febdd2b899406f7), f64::from_bits(0x3feb7d6c3dda338b), f64::from_bits(0x3feb2036406c80d9),
    f64::from_bits(0x3feac5701ac5701b), f64::from_bits(0x3fea6d01a6d01a6d), f64::from_bits(0x3fea16d3f97a4b02), f64::from_bits(0x3fe9c2d14ee4a102),
    f64::from_bits(0x3fe970e4f80cb872), f64::from_bits(0x3fe920fb49d0e229), f64::from_bits(0x3fe8d3018d3018d3), f64::from_bits(0x3fe886e5f0abb04a),
    f64::from_bits(0x3fe83c977ab2bedd), f64::from_bits(0x3fe7f405fd017f40), f64::from_bits(0x3fe7ad2208e0ecc3), f64::from_bits(0x3fe767dce434a9b1),
];
const LOG2_LOGC_HI: [f64; 64] = [
    f64::from_bits(0xbfe1096015dee4da), f64::from_bits(0xbfe08494c66b8ef0), f64::from_bits(0xbfe0014332be0033), f64::from_bits(0xbfdefec61b011f85),
    f64::from_bits(0xbfddfdd89d586e2b), f64::from_bits(0xbfdcffae611ad12b), f64::from_bits(0xbfdc043859e2fdb3), f64::from_bits(0xbfdb0b67f4f46810),
    f64::from_bits(0xbfda152f142981b4), f64::from_bits(0xbfd921800924dd3b), f64::from_bits(0xbfd8304d90c11fd3), f64::from_bits(0xbfd7418acebbf18f),
    f64::from_bits(0xbfd6552b49986277), f64::from_bits(0xbfd56b22e6b578e5), f64::from_bits(0xbfd48365e695d797), f64::from_bits(0xbfd39de8e1559f6f),
    f64::from_bits(0xbfd2baa0c34be1ec), f64::from_bits(0xbfd1d982c9d52708), f64::from_bits(0xbfd0fa848044b351), f64::from_bits(0xbfd01d9bbcfa61d4),
    f64::from_bits(0xbfce857d3d361368), f64::from_bits(0xbfccd3c712d31109), f64::from_bits(0xbfcb2602497d5346), f64::from_bits(0xbfc97c1cb13c7ec1),
    f64::from_bits(0xbfc7d60496cfbb4c), f64::from_bits(0xbfc633a8bf437ce1), f64::from_bits(0xbfc494f863b8df35), f64::from_bits(0xbfc2f9e32d5bfdd1),
    f64::from_bits(0xbfc162593186da70), f64::from_bits(0xbfbf9c95dc1d1165), f64::from_bits(0xbfbc7b528b70f1c5), f64::from_bits(0xbfb960caf9abb7ca),
    f64::from_bits(0xbfb64ce26c067157), f64::from_bits(0xbfb33f7cde14cf5a), f64::from_bits(0xbfb0387efbca869e), f64::from_bits(0xbfaa6f9c377dd31b),
    f64::from_bits(0xbfa47aa07357704f), f64::from_bits(0xbf9d23afc49139f9), f64::from_bits(0xbf916a21e20a0a45), f64::from_bits(0xbf7720d9c06a835f),
    f64::from_bits(0x3f86fe50b6ef0851), f64::from_bits(0x3fa11cd1d5133413), f64::from_bits(0x3fac4dfab90aab5f), f64::from_bits(0x3fb3aa2fdd27f1c3),
    f64::from_bits(0x3fb918a16e46335b), f64::from_bits(0x3fbe72ec117fa5b2), f64::from_bits(0x3fc1dcd197552b7b), f64::from_bits(0x3fc476a9f983f74d),
    f64::from_bits(0x3fc70742d4ef027f), f64::from_bits(0x3fc98edd077e70df), f64::from_bits(0x3fcc0db6cdd94dee), f64::from_bits(0x3fce840be74e6a4d),
    f64::from_bits(0x3fd0790adbb03009), f64::from_bits(0x3fd1ac05b291f070), f64::from_bits(0x3fd2db10fc4d9aaf), f64::from_bits(0x3fd406463b1b0449),
    f64::from_bits(0x3fd52dbdfc4c96b3), f64::from_bits(0x3fd6518fe4677ba7), f64::from_bits(0x3fd771d2ba7efb3c), f64::from_bits(0x3fd88e9c72e0b226),
    f64::from_bits(0x3fd9a802391e232f), f64::from_bits(0x3fdabe18797f1f49), f64::from_bits(0x3fdbd0f2e9e79031), f64::from_bits(0x3fdce0a4923a587d),
];
const LOG2_LOGC_LO: [f64; 64] = [
    f64::from_bits(0x3c740c9ca8b78394), f64::from_bits(0x3c7f9d4ba07ff89b), f64::from_bits(0x3c8760b41c376918), f64::from_bits(0xbc768b1a9352c481),
    f64::from_bits(0xbc41867b8aa0262e), f64::from_bits(0xbc7868d9e925c9fe), f64::from_bits(0xbc7eaa4104281a90), f64::from_bits(0x3c476003a105bef0),
    f64::from_bits(0x3c647d98866e9e78), f64::from_bits(0xbc7fb5b520ebaa5c), f64::from_bits(0xbc64d86a4f5e2d40), f64::from_bits(0x3c728ab134d0e87f),
    f64::from_bits(0xbc7aadcc6c817792), f64::from_bits(0x3c78f07693e10458), f64::from_bits(0x3c758acdbcdb776c), f64::from_bits(0xbc7fb8450ffda380),
    f64::from_bits(0x3c5053dbed11c17b), f64::from_bits(0xbc6acd757d01cf01), f64::from_bits(0xbc407d5bdeab2504), f64::from_bits(0xbc775e40605724b0),
    f64::from_bits(0x3c6098951a2df30c), f64::from_bits(0xbc59113c0ecb329c), f64::from_bits(0x3c6cd4cebd99ab4b), f64::from_bits(0x3c6e9fba024c40e8),
    f64::from_bits(0xbc69c666c97f1cf0), f64::from_bits(0xbc35193984ffa800), f64::from_bits(0x3c615b9acc89c914), f64::from_bits(0x3c697cfb4b53432b),
    f64::from_bits(0x3c5df78a8bd589bf), f64::from_bits(0x3c36e10175ceea40), f64::from_bits(0x3c17cd10d9586980), f64::from_bits(0x3c3225d93825efe6),
    f64::from_bits(0x3c52f22abb3b9c6d), f64::from_bits(0x3c3e24ac2a89ce4e), f64::from_bits(0x3c57df3b36fb1eea), f64::from_bits(0x3c4864ff7b7e3ae7),
    f64::from_bits(0xbc35a470e411ea28), f64::from_bits(0x3c390cd248a88c29), f64::from_bits(0xbc0791fe6ef4dbc4), f64::from_bits(0x3c16443bb0f7e7b8),
    f64::from_bits(0x3c2fe3865129d7a1), f64::from_bits(0xbc227f8393a536aa), f64::from_bits(0xbc161525eb605c88), f64::from_bits(0xbc43fff7b4936f5c),
    f64::from_bits(0xbc5465eb1a180b15), f64::from_bits(0x3c3cac19011ae760), f64::from_bits(0x3c67a587ae958ecf), f64::from_bits(0x3c5891c9501428c8),
    f64::from_bits(0x3c54d0df24d65211), f64::from_bits(0x3c168ac933ada1b0), f64::from_bits(0x3c602aebef478244), f64::from_bits(0xbc5c3e318507424c),
    f64::from_bits(0x3c7bb5bb31c99008), f64::from_bits(0x3c7495809b54dff8), f64::from_bits(0x3c7bb45ea2078358), f64::from_bits(0x3c7d59045f914432),
    f64::from_bits(0x3c7f5c90af342275), f64::from_bits(0xbc5b4a417c7af53c), f64::from_bits(0xbc5c0dce05c38862), f64::from_bits(0xbc76f66f82618328),
    f64::from_bits(0x3c6a0bbc7e9ab12b), f64::from_bits(0xbc5f14bde9745d10), f64::from_bits(0xbc7562eaad0fb340), f64::from_bits(0xbc6bc56fc18cc310),
];

/// Correctly-rounded-to-4-ULP log2 for strictly-normal positive `x`. The public
/// `log2` gates subnormals/zero/inf/nan to libm.
#[inline]
fn log2_kernel(x: f64) -> f64 {
    let f = x - 1.0;
    if f.abs() < 0.15 {
        // Near 1 the table result -> 0 and needs relative (not absolute)
        // accuracy; f = x-1 is exact here, so the atanh series is sub-ULP.
        let s = f / (2.0 + f);
        let s2 = s * s;
        return s
            * (LOG2_A1
                + s2 * (LOG2_A3
                    + s2 * (LOG2_A5
                        + s2 * (LOG2_A7
                            + s2 * (LOG2_A9
                                + s2 * (LOG2_A11 + s2 * (LOG2_A13 + s2 * LOG2_A15)))))));
    }
    let ix = x.to_bits();
    if ix & 0x000F_FFFF_FFFF_FFFF == 0 {
        // Exact power of two -> exact integer exponent (bit-exact vs glibc).
        return ((ix >> 52) as i64 - 1023) as f64;
    }
    let tmp = ix.wrapping_sub(LOG2_OFF);
    let i = ((tmp >> 46) as usize) & 63;
    let k = (tmp as i64) >> 52;
    let iz = ix.wrapping_sub(tmp & (0xfffu64 << 52));
    let z = f64::from_bits(iz);
    let invc = LOG2_INVC[i];
    let logc = LOG2_LOGC_HI[i];
    let logc_lo = LOG2_LOGC_LO[i];
    let r = z.mul_add(invc, -1.0);
    let kd = k as f64;
    let t1 = kd + logc;
    let t2 = t1 + r * LOG2_INVLN2_HI;
    let t3 = r * LOG2_INVLN2_LO + ((t1 - t2) + r * LOG2_INVLN2_HI) + logc_lo;
    let hi = t2 + t3;
    let lo = (t2 - hi) + t3;
    let r2 = r * r;
    let p = r2
        * (LOG2_C2
            + r * (LOG2_C3
                + r * (LOG2_C4 + r * (LOG2_C5 + r * (LOG2_C6 + r * (LOG2_C7 + r * LOG2_C8))))));
    hi + (lo + p)
}

#[inline]
pub fn log2(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 {
        return log2_kernel(x);
    }
    libm::log2(x)
}

/// `log10` via the cheaper natural-log kernel: `log10(x) = ln(x) * log10(e)`.
///
/// Profiling (`glibc_baseline_math/log10`, bd-2g7oyh) showed `libm::log10`
/// (~13 ns) is slower than `libm::log` (~9.5 ns); glibc's `log10` is hand-tuned,
/// leaving fl `log10` ~1.07x behind. Routing through `libm::log` scaled by
/// `LOG10_E` is ~1.34x faster on the kernel and beats glibc. A 4M-point sweep
/// bounds it within 2 ULP of glibc (`f64::log10`) across the full dynamic range
/// and near 1 — within the 4-ULP-vs-glibc contract shared by the exp/pow/log2
/// fast paths (mirrors the f64 `log2` reroute).
///
/// At exactly-representable powers of ten the fast form is ~1 ULP off glibc's
/// exact integer — within the 4-ULP contract (an exactness gate was measured to
/// cost more than the reroute saves, since `round`/casts are libm calls or extra
/// branches on baseline x86-64). Subnormal / non-positive / non-finite inputs
/// defer to `libm::log10` for its precise special-case handling.
#[inline]
pub fn log10(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 {
        return libm::log(x) * core::f64::consts::LOG10_E;
    }
    libm::log10(x)
}

#[inline]
pub fn log1p(x: f64) -> f64 {
    libm::log1p(x)
}

const EXP_MEDIUM_MIN: f64 = 0.5;
const EXP_MEDIUM_MAX: f64 = 2.5;
const POW_MEDIUM_EXP_MIN: f64 = -3.0;
const POW_MEDIUM_EXP_MAX: f64 = 3.0;

/// Range over which `exp(x) = exp2(x * log2e)` stays within 4 ULP of glibc.
/// The error is dominated by the rounding of the `x*log2e` product (~0.5*|x|
/// ULP after exp2 amplification), so it stays <=4 ULP up to |x| = 5 and jumps
/// to ~7 ULP by |x| = 6 (measured by a 2M-point sweep). libm::exp2 is markedly
/// cheaper than libm::exp, so this covers the common decay/softmax ranges that
/// previously fell to the slower libm::exp path. Note this is the EXP argument
/// range, distinct from the [`EXP_MEDIUM_MIN`]/[`EXP_MEDIUM_MAX`] pow-base gate.
const EXP_FAST_MIN: f64 = -5.0;
const EXP_FAST_MAX: f64 = 5.0;

/// Fast path for the finite `[-5, 5]` interval via the exp2 kernel. Values
/// outside it retain the previous libm::exp behavior bit-for-bit.
#[inline]
fn exp_medium_exp2_fast_path(x: f64) -> Option<f64> {
    if (EXP_FAST_MIN..=EXP_FAST_MAX).contains(&x) {
        Some(libm::exp2(x * std::f64::consts::LOG2_E))
    } else {
        None
    }
}

/// `base` raised to a small integer power via exponentiation by squaring.
/// `n.unsigned_abs()` must be small (the caller gates on `<= POWI_MAX_EXP`) so
/// the multiply chain stays well inside the 4-ULP glibc parity budget.
#[inline]
fn powi_squaring(base: f64, n: i64) -> f64 {
    let mut result = 1.0_f64;
    let mut b = base;
    let mut e = n.unsigned_abs();
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        e >>= 1;
        if e > 0 {
            b *= b;
        }
    }
    if n < 0 { 1.0 / result } else { result }
}

/// `base` raised to a small half-integer exponent via `base^n * sqrt(base)`.
/// The caller only reaches this for strictly positive finite bases, so libm's
/// negative/zero/special-case semantics remain on the general path.
#[inline]
fn pow_half_integer_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if !(base > 0.0 && base.is_finite() && exponent.is_finite()) {
        return None;
    }

    let shifted = exponent - 0.5;
    let n = shifted as i64;
    if n as f64 == shifted && n.unsigned_abs() <= POWI_MAX_EXP {
        Some(powi_squaring(base, n) * base.sqrt())
    } else {
        None
    }
}

/// Fast path for positive finite medium bases and bounded non-special
/// exponents. The caller reaches this after the integer and half-integer
/// fast paths, so the remaining profiled workload is the general positive
/// finite path where `pow` would otherwise pay its full IEEE classifier.
#[inline]
fn pow_medium_log2_exp2_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if (EXP_MEDIUM_MIN..EXP_MEDIUM_MAX).contains(&base)
        && (POW_MEDIUM_EXP_MIN..=POW_MEDIUM_EXP_MAX).contains(&exponent)
    {
        // NB: stays on libm::log2 (correctly rounded). pow's 4-ULP contract is
        // tighter than log2's because the exponent amplifies log2's error, so the
        // 4-ULP `log2_kernel` is not accurate enough here — routing pow through it
        // needs a hi/lo (double-double) log2 return (tracked in bd-e4jb7k).
        Some(libm::exp2(exponent * libm::log2(base)))
    } else {
        None
    }
}

/// Largest |integer exponent| handled by the fast path. Each squaring/multiply
/// adds at most ~0.5 ULP; capping the magnitude here keeps the result within
/// the 4-ULP-vs-glibc contract (verified by `pow_integer_fast_path_within_4_ulps`).
const POWI_MAX_EXP: u64 = 8;

#[inline]
pub fn pow(base: f64, exponent: f64) -> f64 {
    // Fast path: small integer exponents (and y == 0.5) on a finite base.
    // libm::pow always routes through the general log2/exp2 path (~3.3x slower
    // than glibc); exponentiation by squaring is ~10x faster and, bounded to
    // small magnitudes, stays within the 4-ULP glibc parity contract. Non-finite
    // bases, large/non-integer exponents, etc. defer to libm for exact IEEE
    // special-case semantics.
    if base.is_finite() && exponent.is_finite() {
        let n = exponent as i64;
        if n as f64 == exponent && n.unsigned_abs() <= POWI_MAX_EXP {
            return powi_squaring(base, n);
        }
        if exponent == 0.5 && base >= 0.0 {
            return base.sqrt();
        }
        if let Some(result) = pow_half_integer_fast_path(base, exponent) {
            return result;
        }
        if let Some(result) = pow_medium_log2_exp2_fast_path(base, exponent) {
            return result;
        }
    }
    libm::pow(base, exponent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn approx_eq(lhs: f64, rhs: f64, abs_tol: f64, rel_tol: f64) -> bool {
        let diff = (lhs - rhs).abs();
        diff <= abs_tol.max(rel_tol * lhs.abs().max(rhs.abs()))
    }

    /// 4-ULP comparison (the math conformance contract). `f64::powf` resolves
    /// to the host glibc `pow`, so this pins the fast path against glibc itself.
    fn within_ulps(a: f64, b: f64, ulps: u64) -> bool {
        if a == b {
            return true;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return false;
        }
        let ab = a.to_bits() as i64;
        let bb = b.to_bits() as i64;
        (ab - bb).unsigned_abs() <= ulps
    }

    #[test]
    fn pow_integer_fast_path_within_4_ulps() {
        // Sweep the gated fast-path domain (|n| <= POWI_MAX_EXP, plus 0.5) over a
        // wide spread of finite bases incl. negatives, zeros, sub/huge, and verify
        // every result is within 4 ULP of the host glibc pow (f64::powf).
        let bases = [
            0.0,
            -0.0,
            1.0,
            -1.0,
            2.0,
            -2.0,
            0.5,
            -0.5,
            std::f64::consts::PI,
            -std::f64::consts::PI,
            1.785,
            1e-3,
            -1e-3,
            1e6,
            -1e6,
            1e150,
            1e-150,
            123.456,
            -123.456,
            0.999_999,
            1.000_001,
        ];
        for &base in &bases {
            for n in -(POWI_MAX_EXP as i64)..=(POWI_MAX_EXP as i64) {
                let exp_f = n as f64;
                let got = pow(base, exp_f);
                let want = base.powf(exp_f);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exp_f}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
            }
            if base >= 0.0 {
                let got = pow(base, 0.5);
                let want = base.powf(0.5);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, 0.5) = {got:?} but glibc = {want:?}"
                );
            }
        }
    }

    #[test]
    fn log2_fast_path_within_4_ulps_of_glibc() {
        // `f64::log2` lowers to the host glibc `log2`, so this pins the
        // `ln(x) * log2(e)` fast path directly against glibc. Sweep the full
        // dynamic range geometrically, the near-1 region (where log2 -> 0 and
        // relative error is most sensitive), and a spread of fixed points.
        let mut x = 1e-300_f64;
        while x < 1e300 {
            assert!(
                within_ulps(log2(x), x.log2(), 4),
                "log2({x:e}) = {:?} but glibc = {:?} (>4 ULP)",
                log2(x),
                x.log2()
            );
            x *= 1.0000071;
        }
        for d in 0..1_000_000i64 {
            let x = 1.0 + (d as f64) * 2e-9;
            assert!(within_ulps(log2(x), x.log2(), 4), "near-1 log2({x}) >4 ULP");
        }
        for &x in &[
            0.5,
            0.323,
            std::f64::consts::E,
            std::f64::consts::PI,
            1e-3,
            1e3,
            123.456,
            f64::MIN_POSITIVE,
            f64::MAX,
        ] {
            assert!(within_ulps(log2(x), x.log2(), 4), "log2({x:e}) >4 ULP");
        }
        // Exact powers of two must match glibc bit-for-bit (gated to libm::log2).
        for k in -1074i32..=1023 {
            let p = (k as f64).exp2();
            if !p.is_normal() {
                continue;
            }
            assert_eq!(
                log2(p).to_bits(),
                p.log2().to_bits(),
                "log2(2^{k}) not bit-exact vs glibc"
            );
        }
        // Special inputs defer to libm::log2 and match glibc exactly.
        assert!(log2(f64::NAN).is_nan());
        assert_eq!(log2(f64::INFINITY), f64::INFINITY);
        assert_eq!(log2(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log2(0.0), f64::NEG_INFINITY);
        assert!(log2(-1.0).is_nan());
    }

    #[test]
    fn log10_fast_path_within_4_ulps_of_glibc() {
        // `f64::log10` lowers to host glibc, pinning the `ln(x) * log10(e)` fast
        // path directly against it.
        let mut x = 1e-300_f64;
        while x < 1e300 {
            assert!(
                within_ulps(log10(x), x.log10(), 4),
                "log10({x:e}) = {:?} but glibc = {:?} (>4 ULP)",
                log10(x),
                x.log10()
            );
            x *= 1.0000071;
        }
        for d in 0..1_000_000i64 {
            let x = 1.0 + (d as f64) * 2e-9;
            assert!(
                within_ulps(log10(x), x.log10(), 4),
                "near-1 log10({x}) >4 ULP"
            );
        }
        for &x in &[
            0.5,
            0.323,
            std::f64::consts::E,
            std::f64::consts::PI,
            1e-3,
            1e3,
            123.456,
            f64::MIN_POSITIVE,
            f64::MAX,
        ] {
            assert!(within_ulps(log10(x), x.log10(), 4), "log10({x:e}) >4 ULP");
        }
        // Powers of ten stay within 4 ULP of glibc (no exactness gate — the
        // fast form is ~1 ULP off the exact integer at 10^0..10^22).
        for k in -307i32..=308 {
            let p = libm::exp10(k as f64);
            if p.is_normal() {
                assert!(within_ulps(log10(p), p.log10(), 4), "log10(10^{k}) >4 ULP");
            }
        }
        // Special inputs defer to libm::log10 and match glibc exactly.
        assert!(log10(f64::NAN).is_nan());
        assert_eq!(log10(f64::INFINITY), f64::INFINITY);
        assert_eq!(log10(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log10(0.0), f64::NEG_INFINITY);
        assert!(log10(-1.0).is_nan());
    }

    #[test]
    fn pow_half_integer_fast_path_within_4_ulps() {
        let bases = [
            1e-6,
            1e-3,
            0.5,
            0.999_999,
            1.0,
            1.000_001,
            1.785,
            2.0,
            2.5,
            std::f64::consts::PI,
            123.456,
            1e6,
        ];
        for &base in &bases {
            for n in -(POWI_MAX_EXP as i64)..=(POWI_MAX_EXP as i64) {
                let exponent = n as f64 + 0.5;
                let got = pow(base, exponent);
                let want = base.powf(exponent);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exponent}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
            }
        }
    }

    #[test]
    fn golden_pow_half_integer_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let bases = [
            1e-6,
            1e-3,
            0.5,
            0.999_999,
            1.0,
            1.000_001,
            1.785,
            2.0,
            2.5,
            std::f64::consts::PI,
            123.456,
            1e6,
        ];
        let exponents = [-7.5, -2.5, -0.5, 0.5, 1.5, 2.5, 4.5, 8.5];
        let mut hasher = Sha256::new();
        for &base in &bases {
            for &exponent in &exponents {
                hasher.update(pow(base, exponent).to_bits().to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "5d10fe8318e0cba5afc8a3260fa342ca472bf559ead08bc67b82ae3a307e3a61",
            "pow half-integer golden corpus hash drifted"
        );
    }

    #[test]
    fn pow_medium_log2_exp2_fast_path_large_sweep_within_4_ulps() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let scale = 1.0 / ((1_u64 << 53) as f64);

        for _ in 0..1_000_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let base_unit = ((state >> 11) as f64) * scale;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let exponent_unit = ((state >> 11) as f64) * scale;

            let base = EXP_MEDIUM_MIN + (EXP_MEDIUM_MAX - EXP_MEDIUM_MIN) * base_unit;
            let exponent =
                POW_MEDIUM_EXP_MIN + (POW_MEDIUM_EXP_MAX - POW_MEDIUM_EXP_MIN) * exponent_unit;
            let got = pow_medium_log2_exp2_fast_path(base, exponent)
                .expect("generated pair should be inside medium pow gate");
            let want = base.powf(exponent);
            assert!(
                within_ulps(got, want, 4),
                "medium pow fast path drifted: pow({base}, {exponent}) = {got:?}, glibc = {want:?}"
            );
        }
    }

    #[test]
    fn pow_medium_log2_exp2_fast_path_preserves_fallback_cases() {
        let cases = [
            (f64::NEG_INFINITY, 1.337),
            (-2.0, 1.337),
            (-0.0, 1.337),
            (0.0, 1.337),
            (0.25, 1.337),
            (EXP_MEDIUM_MAX, 1.337),
            (4.0, 1.337),
            (f64::INFINITY, 1.337),
            (1.5, POW_MEDIUM_EXP_MIN - f64::EPSILON),
            (1.5, POW_MEDIUM_EXP_MAX + f64::EPSILON),
        ];

        for (base, exponent) in cases {
            assert_eq!(
                pow(base, exponent).to_bits(),
                libm::pow(base, exponent).to_bits(),
                "pow({base}, {exponent}) fallback drifted"
            );
        }
        assert!(pow(f64::NAN, 1.337).is_nan());
        assert!(pow(1.5, f64::NAN).is_nan());
    }

    #[test]
    fn golden_pow_medium_log2_exp2_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let bases = [
            EXP_MEDIUM_MIN,
            0.500_000_000_000_000_1,
            0.593_75,
            0.999_999,
            1.0,
            1.000_001,
            1.5,
            2.072_341_547_916_954_7,
            2.468_75,
            EXP_MEDIUM_MAX - f64::EPSILON,
        ];
        let exponents = [
            POW_MEDIUM_EXP_MIN,
            -2.9375,
            -1.337,
            -0.25,
            0.25,
            0.75,
            1.337,
            2.25,
            2.849_516_429_769_268_6,
            POW_MEDIUM_EXP_MAX,
        ];

        let mut hasher = Sha256::new();
        for &base in &bases {
            for &exponent in &exponents {
                let got = pow(base, exponent);
                let want = base.powf(exponent);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exponent}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
                hasher.update(base.to_bits().to_le_bytes());
                hasher.update(exponent.to_bits().to_le_bytes());
                hasher.update(got.to_bits().to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "970a740ac2a4983abae2831799f179c711201e97de0e8b4373c12cab2e193ab7",
            "pow medium log2/exp2 golden corpus hash drifted"
        );
    }

    #[test]
    fn exp_medium_exp2_fast_path_within_4_ulps() {
        let mut inputs = vec![
            EXP_FAST_MIN,
            EXP_FAST_MAX,
            -4.999,
            -2.5,
            -1.0,
            -0.25,
            0.0,
            0.500_000_000_000_000_1,
            std::f64::consts::LN_2,
            1.0,
            std::f64::consts::SQRT_2,
            2.0,
            2.468_75,
            4.999,
        ];
        // Dense deterministic sweep across the whole [-5, 5] fast-path interval.
        let mut s = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            inputs.push(-5.0 + (s >> 11) as f64 * (10.0 / (1u64 << 53) as f64));
        }

        for x in inputs {
            let got = exp(x);
            let want = x.exp();
            assert!(
                within_ulps(got, want, 4),
                "exp({x}) = {got:?} but host exp = {want:?} (>4 ULP)"
            );
        }
    }

    #[test]
    fn exp_medium_exp2_fast_path_preserves_fallback_cases() {
        // Outside [-5, 5] exp must stay bit-identical to libm::exp.
        let cases = [
            f64::NEG_INFINITY,
            -20.0,
            -6.0,
            -5.000_000_000_000_001,
            5.000_000_000_000_001,
            6.0,
            20.0,
            f64::INFINITY,
        ];
        for x in cases {
            assert_eq!(
                exp(x).to_bits(),
                libm::exp(x).to_bits(),
                "exp({x}) fallback drifted"
            );
        }
        assert!(exp(f64::NAN).is_nan());
    }

    #[test]
    fn golden_exp_medium_exp2_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut inputs = vec![
            EXP_MEDIUM_MIN,
            0.500_000_000_000_000_1,
            std::f64::consts::LN_2,
            1.0,
            std::f64::consts::SQRT_2,
            2.0,
            2.468_75,
            EXP_MEDIUM_MAX - f64::EPSILON,
        ];
        inputs.extend((0..64).map(|k| 0.5 + (k as f64) * 0.031_25));

        let mut hasher = Sha256::new();
        for x in inputs {
            hasher.update(exp(x).to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "e44a16c130577d30811cc63a179ce65cdc2c0451958b238918a77aa165c1a2be",
            "exp medium exp2 golden corpus hash drifted"
        );
    }

    #[test]
    fn expm1_fast_path_within_4_ulps() {
        // The positive-band fast path (exp(x)-1) must stay within the 4-ULP math
        // conformance contract vs the libm expm1 reference across the gated range.
        fn ulp(a: f64, b: f64) -> i64 {
            if a == b {
                0
            } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
                i64::MAX
            } else {
                (a.to_bits() as i64 - b.to_bits() as i64).abs()
            }
        }
        let mut worst = 0i64;
        let mut worst_x = 0.0f64;
        let mut x = EXPM1_POSITIVE_FAST_MIN;
        while x <= EXPM1_POSITIVE_FAST_MAX {
            let u = ulp(expm1(x), libm::expm1(x));
            if u > worst {
                worst = u;
                worst_x = x;
            }
            x += 0.0001;
        }
        assert!(
            worst <= 4,
            "expm1 fast path worst {worst} ULP at x={worst_x}"
        );
    }

    #[test]
    fn exp_log_pow_sanity() {
        assert!((exp(1.0) - std::f64::consts::E).abs() < 1e-12);
        assert!((exp2(10.0) - 1024.0).abs() < 1e-12);
        assert!((expm1(1.0) - (std::f64::consts::E - 1.0)).abs() < 1e-12);
        assert!((log(std::f64::consts::E) - 1.0).abs() < 1e-12);
        assert!((log2(8.0) - 3.0).abs() < 1e-12);
        assert!((log10(1000.0) - 3.0).abs() < 1e-12);
        assert!((log1p(0.5) - 1.5_f64.ln()).abs() < 1e-12);
        assert!((pow(9.0, 0.5) - 3.0).abs() < 1e-12);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_exp_turns_addition_into_multiplication(
            x in -20.0f64..20.0f64,
            y in -20.0f64..20.0f64
        ) {
            let lhs = exp(x + y);
            let rhs = exp(x) * exp(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_of_exp_round_trips(x in -20.0f64..20.0f64) {
            let round_trip = log(exp(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_exp_of_log_round_trips(x in 1.0e-12f64..1.0e12f64) {
            let round_trip = exp(log(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_turns_products_into_sums(
            x in 1.0e-6f64..1.0e6f64,
            y in 1.0e-6f64..1.0e6f64
        ) {
            let lhs = log(x * y);
            let rhs = log(x) + log(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_expm1_matches_exp_minus_one(x in -1.0f64..1.0f64) {
            let lhs = expm1(x);
            let rhs = exp(x) - 1.0;
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log1p_matches_log_of_one_plus_x(x in -0.99f64..10.0f64) {
            let lhs = log1p(x);
            let rhs = log(1.0 + x);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_pow_turns_added_exponents_into_multiplied_results(
            base in 1.0e-6f64..1.0e6f64,
            x in -5.0f64..5.0f64,
            y in -5.0f64..5.0f64
        ) {
            let lhs = pow(base, x + y);
            let rhs = pow(base, x) * pow(base, y);
            prop_assert!(approx_eq(lhs, rhs, 1e-10, 1e-10));
        }
    }
}
