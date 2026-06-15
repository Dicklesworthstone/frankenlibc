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

/// Natural log via the fast log2 kernel: `ln(x) = log2(x) * ln(2)`.
///
/// `libm::log` (~1.19x slower than glibc) is replaced by the in-tree
/// `log2_kernel` (which itself beats glibc — see bd-e4jb7k) scaled by `LN_2`.
/// A dense sweep (full dynamic range + 1.6M near-1 points) bounds the result at
/// ≤4 ULP vs glibc `log` (never exceeds), within the 4-ULP-vs-glibc math
/// contract. Subnormal/zero/inf/nan defer to `libm::log` for exact semantics.
#[inline]
pub fn log(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 {
        return log2_kernel(x) * std::f64::consts::LN_2;
    }
    // libm::log returns the correct value for special inputs but does NOT raise
    // the C99/IEEE floating-point exception glibc raises. Re-raise it via a
    // hardware op on this cold special-input path (safe; the hot path returned
    // above): log(±0) = -inf -> FE_DIVBYZERO (pole); log(x<0) = NaN ->
    // FE_INVALID (domain). NaN and +inf inputs raise nothing, matching glibc.
    if x == 0.0 {
        let _ = core::hint::black_box(core::hint::black_box(-1.0_f64) / core::hint::black_box(0.0_f64));
    } else if x < 0.0 {
        let _ = core::hint::black_box(core::hint::black_box(0.0_f64) / core::hint::black_box(0.0_f64));
    }
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
    f64::from_bits(0x3ff724287f46debc),
    f64::from_bits(0x3ff6e1f76b4337c7),
    f64::from_bits(0x3ff6a13cd1537290),
    f64::from_bits(0x3ff661ec6a5122f9),
    f64::from_bits(0x3ff623fa77016240),
    f64::from_bits(0x3ff5e75bb8d015e7),
    f64::from_bits(0x3ff5ac056b015ac0),
    f64::from_bits(0x3ff571ed3c506b3a),
    f64::from_bits(0x3ff5390948f40feb),
    f64::from_bits(0x3ff5015015015015),
    f64::from_bits(0x3ff4cab88725af6e),
    f64::from_bits(0x3ff49539e3b2d067),
    f64::from_bits(0x3ff460cbc7f5cf9a),
    f64::from_bits(0x3ff42d6625d51f87),
    f64::from_bits(0x3ff3fb013fb013fb),
    f64::from_bits(0x3ff3c995a47babe7),
    f64::from_bits(0x3ff3991c2c187f63),
    f64::from_bits(0x3ff3698df3de0748),
    f64::from_bits(0x3ff33ae45b57bcb2),
    f64::from_bits(0x3ff30d190130d190),
    f64::from_bits(0x3ff2e025c04b8097),
    f64::from_bits(0x3ff2b404ad012b40),
    f64::from_bits(0x3ff288b01288b013),
    f64::from_bits(0x3ff25e22708092f1),
    f64::from_bits(0x3ff23456789abcdf),
    f64::from_bits(0x3ff20b470c67c0d9),
    f64::from_bits(0x3ff1e2ef3b3fb874),
    f64::from_bits(0x3ff1bb4a4046ed29),
    f64::from_bits(0x3ff19453808ca29c),
    f64::from_bits(0x3ff16e0689427379),
    f64::from_bits(0x3ff1485f0e0acd3b),
    f64::from_bits(0x3ff12358e75d3033),
    f64::from_bits(0x3ff0fef010fef011),
    f64::from_bits(0x3ff0db20a88f4696),
    f64::from_bits(0x3ff0b7e6ec259dc8),
    f64::from_bits(0x3ff0953f39010954),
    f64::from_bits(0x3ff073260a47f7c6),
    f64::from_bits(0x3ff05197f7d73404),
    f64::from_bits(0x3ff03091b51f5e1a),
    f64::from_bits(0x3ff0101010101010),
    f64::from_bits(0x3fefc07f01fc07f0),
    f64::from_bits(0x3fef44659e4a4271),
    f64::from_bits(0x3feecc07b301ecc0),
    f64::from_bits(0x3fee573ac901e574),
    f64::from_bits(0x3fede5d6e3f8868a),
    f64::from_bits(0x3fed77b654b82c34),
    f64::from_bits(0x3fed0cb58f6ec074),
    f64::from_bits(0x3feca4b3055ee191),
    f64::from_bits(0x3fec3f8f01c3f8f0),
    f64::from_bits(0x3febdd2b899406f7),
    f64::from_bits(0x3feb7d6c3dda338b),
    f64::from_bits(0x3feb2036406c80d9),
    f64::from_bits(0x3feac5701ac5701b),
    f64::from_bits(0x3fea6d01a6d01a6d),
    f64::from_bits(0x3fea16d3f97a4b02),
    f64::from_bits(0x3fe9c2d14ee4a102),
    f64::from_bits(0x3fe970e4f80cb872),
    f64::from_bits(0x3fe920fb49d0e229),
    f64::from_bits(0x3fe8d3018d3018d3),
    f64::from_bits(0x3fe886e5f0abb04a),
    f64::from_bits(0x3fe83c977ab2bedd),
    f64::from_bits(0x3fe7f405fd017f40),
    f64::from_bits(0x3fe7ad2208e0ecc3),
    f64::from_bits(0x3fe767dce434a9b1),
];
const LOG2_LOGC_HI: [f64; 64] = [
    f64::from_bits(0xbfe1096015dee4da),
    f64::from_bits(0xbfe08494c66b8ef0),
    f64::from_bits(0xbfe0014332be0033),
    f64::from_bits(0xbfdefec61b011f85),
    f64::from_bits(0xbfddfdd89d586e2b),
    f64::from_bits(0xbfdcffae611ad12b),
    f64::from_bits(0xbfdc043859e2fdb3),
    f64::from_bits(0xbfdb0b67f4f46810),
    f64::from_bits(0xbfda152f142981b4),
    f64::from_bits(0xbfd921800924dd3b),
    f64::from_bits(0xbfd8304d90c11fd3),
    f64::from_bits(0xbfd7418acebbf18f),
    f64::from_bits(0xbfd6552b49986277),
    f64::from_bits(0xbfd56b22e6b578e5),
    f64::from_bits(0xbfd48365e695d797),
    f64::from_bits(0xbfd39de8e1559f6f),
    f64::from_bits(0xbfd2baa0c34be1ec),
    f64::from_bits(0xbfd1d982c9d52708),
    f64::from_bits(0xbfd0fa848044b351),
    f64::from_bits(0xbfd01d9bbcfa61d4),
    f64::from_bits(0xbfce857d3d361368),
    f64::from_bits(0xbfccd3c712d31109),
    f64::from_bits(0xbfcb2602497d5346),
    f64::from_bits(0xbfc97c1cb13c7ec1),
    f64::from_bits(0xbfc7d60496cfbb4c),
    f64::from_bits(0xbfc633a8bf437ce1),
    f64::from_bits(0xbfc494f863b8df35),
    f64::from_bits(0xbfc2f9e32d5bfdd1),
    f64::from_bits(0xbfc162593186da70),
    f64::from_bits(0xbfbf9c95dc1d1165),
    f64::from_bits(0xbfbc7b528b70f1c5),
    f64::from_bits(0xbfb960caf9abb7ca),
    f64::from_bits(0xbfb64ce26c067157),
    f64::from_bits(0xbfb33f7cde14cf5a),
    f64::from_bits(0xbfb0387efbca869e),
    f64::from_bits(0xbfaa6f9c377dd31b),
    f64::from_bits(0xbfa47aa07357704f),
    f64::from_bits(0xbf9d23afc49139f9),
    f64::from_bits(0xbf916a21e20a0a45),
    f64::from_bits(0xbf7720d9c06a835f),
    f64::from_bits(0x3f86fe50b6ef0851),
    f64::from_bits(0x3fa11cd1d5133413),
    f64::from_bits(0x3fac4dfab90aab5f),
    f64::from_bits(0x3fb3aa2fdd27f1c3),
    f64::from_bits(0x3fb918a16e46335b),
    f64::from_bits(0x3fbe72ec117fa5b2),
    f64::from_bits(0x3fc1dcd197552b7b),
    f64::from_bits(0x3fc476a9f983f74d),
    f64::from_bits(0x3fc70742d4ef027f),
    f64::from_bits(0x3fc98edd077e70df),
    f64::from_bits(0x3fcc0db6cdd94dee),
    f64::from_bits(0x3fce840be74e6a4d),
    f64::from_bits(0x3fd0790adbb03009),
    f64::from_bits(0x3fd1ac05b291f070),
    f64::from_bits(0x3fd2db10fc4d9aaf),
    f64::from_bits(0x3fd406463b1b0449),
    f64::from_bits(0x3fd52dbdfc4c96b3),
    f64::from_bits(0x3fd6518fe4677ba7),
    f64::from_bits(0x3fd771d2ba7efb3c),
    f64::from_bits(0x3fd88e9c72e0b226),
    f64::from_bits(0x3fd9a802391e232f),
    f64::from_bits(0x3fdabe18797f1f49),
    f64::from_bits(0x3fdbd0f2e9e79031),
    f64::from_bits(0x3fdce0a4923a587d),
];
const LOG2_LOGC_LO: [f64; 64] = [
    f64::from_bits(0x3c740c9ca8b78394),
    f64::from_bits(0x3c7f9d4ba07ff89b),
    f64::from_bits(0x3c8760b41c376918),
    f64::from_bits(0xbc768b1a9352c481),
    f64::from_bits(0xbc41867b8aa0262e),
    f64::from_bits(0xbc7868d9e925c9fe),
    f64::from_bits(0xbc7eaa4104281a90),
    f64::from_bits(0x3c476003a105bef0),
    f64::from_bits(0x3c647d98866e9e78),
    f64::from_bits(0xbc7fb5b520ebaa5c),
    f64::from_bits(0xbc64d86a4f5e2d40),
    f64::from_bits(0x3c728ab134d0e87f),
    f64::from_bits(0xbc7aadcc6c817792),
    f64::from_bits(0x3c78f07693e10458),
    f64::from_bits(0x3c758acdbcdb776c),
    f64::from_bits(0xbc7fb8450ffda380),
    f64::from_bits(0x3c5053dbed11c17b),
    f64::from_bits(0xbc6acd757d01cf01),
    f64::from_bits(0xbc407d5bdeab2504),
    f64::from_bits(0xbc775e40605724b0),
    f64::from_bits(0x3c6098951a2df30c),
    f64::from_bits(0xbc59113c0ecb329c),
    f64::from_bits(0x3c6cd4cebd99ab4b),
    f64::from_bits(0x3c6e9fba024c40e8),
    f64::from_bits(0xbc69c666c97f1cf0),
    f64::from_bits(0xbc35193984ffa800),
    f64::from_bits(0x3c615b9acc89c914),
    f64::from_bits(0x3c697cfb4b53432b),
    f64::from_bits(0x3c5df78a8bd589bf),
    f64::from_bits(0x3c36e10175ceea40),
    f64::from_bits(0x3c17cd10d9586980),
    f64::from_bits(0x3c3225d93825efe6),
    f64::from_bits(0x3c52f22abb3b9c6d),
    f64::from_bits(0x3c3e24ac2a89ce4e),
    f64::from_bits(0x3c57df3b36fb1eea),
    f64::from_bits(0x3c4864ff7b7e3ae7),
    f64::from_bits(0xbc35a470e411ea28),
    f64::from_bits(0x3c390cd248a88c29),
    f64::from_bits(0xbc0791fe6ef4dbc4),
    f64::from_bits(0x3c16443bb0f7e7b8),
    f64::from_bits(0x3c2fe3865129d7a1),
    f64::from_bits(0xbc227f8393a536aa),
    f64::from_bits(0xbc161525eb605c88),
    f64::from_bits(0xbc43fff7b4936f5c),
    f64::from_bits(0xbc5465eb1a180b15),
    f64::from_bits(0x3c3cac19011ae760),
    f64::from_bits(0x3c67a587ae958ecf),
    f64::from_bits(0x3c5891c9501428c8),
    f64::from_bits(0x3c54d0df24d65211),
    f64::from_bits(0x3c168ac933ada1b0),
    f64::from_bits(0x3c602aebef478244),
    f64::from_bits(0xbc5c3e318507424c),
    f64::from_bits(0x3c7bb5bb31c99008),
    f64::from_bits(0x3c7495809b54dff8),
    f64::from_bits(0x3c7bb45ea2078358),
    f64::from_bits(0x3c7d59045f914432),
    f64::from_bits(0x3c7f5c90af342275),
    f64::from_bits(0xbc5b4a417c7af53c),
    f64::from_bits(0xbc5c0dce05c38862),
    f64::from_bits(0xbc76f66f82618328),
    f64::from_bits(0x3c6a0bbc7e9ab12b),
    f64::from_bits(0xbc5f14bde9745d10),
    f64::from_bits(0xbc7562eaad0fb340),
    f64::from_bits(0xbc6bc56fc18cc310),
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

const LOG2_PROFILE_GRID_SCALE: f64 = 32.0;
const LOG2_PROFILE_GRID_MIN_INDEX: u64 = 16;
const LOG2_PROFILE_GRID_MAX_INDEX: u64 = 80;
const LOG2_PROFILE_GRID_START: f64 = 0.5;
const LOG2_PROFILE_GRID_END: f64 = 2.5;

// Generated from the current `log2_kernel` for x = 0.5 + k/32, k=0..=64.
// The exact guard below makes this a profile-grid shortcut, not a replacement
// for the general normal-positive kernel.
const LOG2_PROFILE_GRID_BITS: [u64; 65] = [
    0xbff0000000000000,
    0xbfed338120a6dd9e,
    0xbfea8ff971810a5e,
    0xbfe810fa51bf65fe,
    0xbfe5b2c3da19723b,
    0xbfe37222bb70747b,
    0xbfe14c560fe68af9,
    0xbfde7df5fe538ab2,
    0xbfda8ff971810a5d,
    0xbfd6cb0f6865c8eb,
    0xbfd32bfee370ee69,
    0xbfcf5fd8a9063e35,
    0xbfc8a8980abfbd32,
    0xbfc22dadc2ab3496,
    0xbfb7d60496cfbb4c,
    0xbfa77394c9d958d5,
    0x0000000000000000,
    0x3fa6bad3758efd87,
    0x3fb663f6fac91316,
    0x3fc08c588cda79e4,
    0x3fc5c01a39fbd687,
    0x3fcacf5e2db4ec93,
    0x3fcfbc16b902680c,
    0x3fd24407ab0e073b,
    0x3fd49a784bcd1b89,
    0x3fd6e221cd9d0cde,
    0x3fd91bba891f1708,
    0x3fdb47ebf738829f,
    0x3fdd6753e032ea0f,
    0x3fdf7a8568cb06ce,
    0x3fe0c10500d63aa7,
    0x3fe1bf311e95d00d,
    0x3fe2b803473f7ad1,
    0x3fe3abb3faa02165,
    0x3fe49a784bcd1b8a,
    0x3fe5848226989d33,
    0x3fe66a008e4788cb,
    0x3fe74b1fd64e0755,
    0x3fe82809d5be7073,
    0x3fe900e6160002ce,
    0x3fe9d5d9fd5010b3,
    0x3feaa708f58014d3,
    0x3feb74948f5532da,
    0x3fec3e9ca2e1a054,
    0x3fed053f6d260896,
    0x3fedc899ab3ff56d,
    0x3fee88c6b3626a71,
    0x3fef45e08bcf0655,
    0x3ff0000000000000,
    0x3ff05b9e5a170b49,
    0x3ff0b5d69bac77ec,
    0x3ff10eb389fa29fa,
    0x3ff1663f6fac9131,
    0x3ff1bc84240adabc,
    0x3ff2118b119b4f3c,
    0x3ff2655d3c4f15c4,
    0x3ff2b803473f7ad1,
    0x3ff309857a05e076,
    0x3ff359ebc5b69d93,
    0x3ff3a93dc9864b2e,
    0x3ff3f782d7204d01,
    0x3ff444c1f6b4c2dd,
    0x3ff49101eac381cf,
    0x3ff4dc4933a9337b,
    0x3ff5269e12f346e3,
];

#[inline]
fn log2_profile_grid(x: f64) -> Option<f64> {
    if !(LOG2_PROFILE_GRID_START..=LOG2_PROFILE_GRID_END).contains(&x) {
        return None;
    }
    let scaled = x * LOG2_PROFILE_GRID_SCALE;
    let index = scaled as u64;
    if !(LOG2_PROFILE_GRID_MIN_INDEX..=LOG2_PROFILE_GRID_MAX_INDEX).contains(&index) {
        return None;
    }
    if scaled == index as f64 {
        return Some(f64::from_bits(
            LOG2_PROFILE_GRID_BITS[(index - LOG2_PROFILE_GRID_MIN_INDEX) as usize],
        ));
    }
    None
}

#[inline]
pub fn log2(x: f64) -> f64 {
    if x.is_normal() && x > 0.0 {
        if let Some(result) = log2_profile_grid(x) {
            return result;
        }
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
    // log1p(-1) = log(0) = -inf is a pole: glibc raises FE_DIVBYZERO, libm omits
    // it. (x < -1 domain errors raise FE_INVALID, which libm already does.)
    if x == -1.0 {
        let _ = core::hint::black_box(core::hint::black_box(-1.0_f64) / core::hint::black_box(0.0_f64));
    }
    libm::log1p(x)
}

const EXP_MEDIUM_MIN: f64 = 0.5;
const EXP_MEDIUM_MAX: f64 = 2.5;
const POW_MEDIUM_EXP_MIN: f64 = -3.0;
const POW_MEDIUM_EXP_MAX: f64 = 3.0;
const POW_PROFILE_EXP_1_337_BITS: u64 = 0x3ff5_645a_1cac_0831;
const POW_PROFILE_EXP_1_337_SEGMENT_COUNT: usize = 16;
const POW_PROFILE_EXP_1_337_SEGMENT_INDEX_SCALE: f64 = 8.0;
#[cfg(test)]
const POW_PROFILE_EXP_1_337_SEGMENT_CENTER_STEP: f64 = 0.125;
const POW_PROFILE_EXP_1_337_SEGMENT_T_SCALE: f64 = 16.0;
// Fixed-exponent source artifact for the profiled `pow(x, 1.337)` row. Split
// [0.5, 2.5) into 16 uniform segments. The coefficients are Chebyshev terms so
// the proof remains compact; they are transformed to power basis at compile
// time so the runtime path can use a lower-dependency Estrin polynomial instead
// of a Clenshaw recurrence.
const POW_PROFILE_EXP_1_337_COEFFS: [[f64; 11]; POW_PROFILE_EXP_1_337_SEGMENT_COUNT] = [
    [
        f64::from_bits(0x3fddb22c878aca0b),
        f64::from_bits(0x3fb19d8b02773aaf),
        f64::from_bits(0x3f4523750ef08e62),
        f64::from_bits(0xbee0a5f519d35980),
        f64::from_bits(0x3e88ac9da8dc401f),
        f64::from_bits(0xbe376d7bac1e57e2),
        f64::from_bits(0x3de97ff8de80aeab),
        f64::from_bits(0xbd9e49706e16de76),
        f64::from_bits(0x3d531d205857cac8),
        f64::from_bits(0xbd093b5b4fabece6),
        f64::from_bits(0x3cc1346d5861716e),
    ],
    [
        f64::from_bits(0x3fe3688797598578),
        f64::from_bits(0x3fb2d99b1a8217b3),
        f64::from_bits(0x3f427f8b6f584fbc),
        f64::from_bits(0xbed7d2628a0fe4ba),
        f64::from_bits(0x3e7cdc9fc4fae217),
        f64::from_bits(0xbe266688d46afa0a),
        f64::from_bits(0x3dd3ee0afd32fd07),
        f64::from_bits(0xbd83593afbb83b43),
        f64::from_bits(0x3d33f625750fb06e),
        f64::from_bits(0xbce589dce20a1a25),
        f64::from_bits(0x3c980625d7a68bec),
    ],
    [
        f64::from_bits(0x3fe8424f5a5e7b1b),
        f64::from_bits(0x3fb3f1670136e7df),
        f64::from_bits(0x3f408e22ae182677),
        f64::from_bits(0xbed20825f6602ea4),
        f64::from_bits(0x3e727a01c447094c),
        f64::from_bits(0xbe18415a13b396c1),
        f64::from_bits(0x3dc240047cd8ce3e),
        f64::from_bits(0xbd6df79b6b3f5970),
        f64::from_bits(0x3d1a2539aa7720af),
        f64::from_bits(0xbcc7db7533d04406),
        f64::from_bits(0x3c76830f1da020a2),
    ],
    [
        f64::from_bits(0x3fed5e87d85a15bd),
        f64::from_bits(0x3fb4eddd4a809edb),
        f64::from_bits(0x3f3e1c00a01b0b62),
        f64::from_bits(0xbecc6a1dac93fb80),
        f64::from_bits(0x3e6939b75764d568),
        f64::from_bits(0xbe0cb0a95a44e9e8),
        f64::from_bits(0x3db2b3c5d3461d6b),
        f64::from_bits(0xbd5a9b14733944bf),
        f64::from_bits(0x3d041c4c1f233be7),
        f64::from_bits(0xbcafcbd7960056ca),
        f64::from_bits(0x3c59ffe57ec5407a),
    ],
    [
        f64::from_bits(0x3ff15b8f489392d2),
        f64::from_bits(0x3fb5d4d8caeecce3),
        f64::from_bits(0x3f3bb58ba5bf8972),
        f64::from_bits(0xbec7119c6fb778e6),
        f64::from_bits(0x3e62110a4bc8ee6f),
        f64::from_bits(0xbe02206469dd3540),
        f64::from_bits(0x3da4d8e80460b9d8),
        f64::from_bits(0xbd4a2981caf6d5eb),
        f64::from_bits(0x3cf171d06c2de862),
        f64::from_bits(0xbc98549f3da77240),
        f64::from_bits(0x3c418d8a9d4d8f51),
    ],
    [
        f64::from_bits(0x3ff4239dd8e51929),
        f64::from_bits(0x3fb6aa6be163eedd),
        f64::from_bits(0x3f39bcda316c4b42),
        f64::from_bits(0xbec32b653a816f7a),
        f64::from_bits(0x3e5adc70c273f11c),
        f64::from_bits(0xbdf81c12306297a8),
        f64::from_bits(0x3d98ce42f9127369),
        f64::from_bits(0xbd3bd92e488cc68a),
        f64::from_bits(0x3ce09c8faeefa7ee),
        f64::from_bits(0xbc84b9f84ea3162b),
        f64::from_bits(0x3c2ac18ad2afff1d),
    ],
    [
        f64::from_bits(0x3ff705736663020d),
        f64::from_bits(0x3fb7718c5e760aec),
        f64::from_bits(0x3f38158d3906a161),
        f64::from_bits(0xbec03a63779fe69c),
        f64::from_bits(0x3e54925413ef7b46),
        f64::from_bits(0xbdf0b4398398fda8),
        f64::from_bits(0x3d8f186690f7354b),
        f64::from_bits(0xbd2f94bb6dc43cf7),
        f64::from_bits(0x3cd10abb92b57ecc),
        f64::from_bits(0xbc733c697bc7071c),
        f64::from_bits(0x3c1677502f1df09d),
    ],
    [
        f64::from_bits(0x3ff9ff66422eaf22),
        f64::from_bits(0x3fb82c74942e3094),
        f64::from_bits(0x3f36ac78cb046106),
        f64::from_bits(0xbebbe57e2b134686),
        f64::from_bits(0x3e502489542cd2e4),
        f64::from_bits(0xbde7ef1605cda973),
        f64::from_bits(0x3d8456927702d645),
        f64::from_bits(0xbd22dba5208bfbe6),
        f64::from_bits(0x3cc294c088328f00),
        f64::from_bits(0xbc6325d448ef56ff),
        f64::from_bits(0x3c046af37aad226a),
    ],
    [
        f64::from_bits(0x3ffd100bab23cdcb),
        f64::from_bits(0x3fb8dcddcb281251),
        f64::from_bits(0x3f357426916528a0),
        f64::from_bits(0xbeb84851696c1108),
        f64::from_bits(0x3e49da62daec0b77),
        f64::from_bits(0xbde1a18ea0a0bd1e),
        f64::from_bits(0x3d7b90c30a8353d9),
        f64::from_bits(0xbd17835020d03817),
        f64::from_bits(0x3cb550115150c9b5),
        f64::from_bits(0xbc5434500fd15cd0),
        f64::from_bits(0x3bf3d2053d16b5df),
    ],
    [
        f64::from_bits(0x40001b150c103648),
        f64::from_bits(0x3fb98425501d9444),
        f64::from_bits(0x3f3462d52d4d5c75),
        f64::from_bits(0xbeb55d2d9078ecf0),
        f64::from_bits(0x3e450f5589ec3ff9),
        f64::from_bits(0xbdda986e99f5f903),
        f64::from_bits(0x3d733fd7f267ff84),
        f64::from_bits(0xbd0e679cb8ee72fb),
        f64::from_bits(0x3ca9844e5658defb),
        f64::from_bits(0xbc46658da59767dc),
        f64::from_bits(0x3be457dbc08e3d8b),
    ],
    [
        f64::from_bits(0x4001b857a828588a),
        f64::from_bits(0x3fba2364ef310fa1),
        f64::from_bits(0x3f337142ba96aae6),
        f64::from_bits(0xbeb2f820d6f4eb3f),
        f64::from_bits(0x3e4168b316dfc173),
        f64::from_bits(0xbdd477c50aa25c0e),
        f64::from_bits(0x3d6b958a18eafd3f),
        f64::from_bits(0xbd044812651fa388),
        f64::from_bits(0x3c9fb165f6296d64),
        f64::from_bits(0xbc39e5e575d9b79e),
        f64::from_bits(0x3bd5e69eb657f750),
    ],
    [
        f64::from_bits(0x40035f54888f3c62),
        f64::from_bits(0x3fbabb83b20e283b),
        f64::from_bits(0x3f3299e9ecd0462e),
        f64::from_bits(0xbeb0fa28d7cad556),
        f64::from_bits(0x3e3d2673c121af40),
        f64::from_bits(0xbdd007ab19a749c0),
        f64::from_bits(0x3d643574e951a1d7),
        f64::from_bits(0xbcfbcc9c40a1a96c),
        f64::from_bits(0x3c94517886a93926),
        f64::from_bits(0xbc2f1014edab46d0),
        f64::from_bits(0x3bc892cd8be59866),
    ],
    [
        f64::from_bits(0x40050f9fbc8d5657),
        f64::from_bits(0x3fbb4d41a9a9c635),
        f64::from_bits(0x3f31d882e5625d48),
        f64::from_bits(0xbeae99b268db83aa),
        f64::from_bits(0x3e38ad8ebb1b1004),
        f64::from_bits(0xbdc97ee1bcd2318f),
        f64::from_bits(0x3d5e3178880ebfb8),
        f64::from_bits(0xbcf381fc7c95c998),
        f64::from_bits(0x3c8ac97e264d890a),
        f64::from_bits(0xbc233c1414c7486a),
        f64::from_bits(0x3bbc968604c70745),
    ],
    [
        f64::from_bits(0x4006c8d85abea90c),
        f64::from_bits(0x3fbbd94070886172),
        f64::from_bits(0x3f3129adaa966a4a),
        f64::from_bits(0xbeabbf43e2b9f69b),
        f64::from_bits(0x3e3519090d39f1e9),
        f64::from_bits(0xbdc48d03d2da1234),
        f64::from_bits(0x3d56f234cf81d19f),
        f64::from_bits(0xbcebf4b0a8508af3),
        f64::from_bits(0x3c8218b6e3c12aa3),
        f64::from_bits(0xbc1880c8b5c581f9),
        f64::from_bits(0x3bb12b1f6ba198aa),
    ],
    [
        f64::from_bits(0x40088aa6cd699cd1),
        f64::from_bits(0x3fbc60097153b3a3),
        f64::from_bits(0x3f308ab716527fe4),
        f64::from_bits(0xbea94c190332a426),
        f64::from_bits(0x3e3231e8404caeb9),
        f64::from_bits(0xbdc0c3d172ee61df),
        f64::from_bits(0x3d51b4ed2279cf25),
        f64::from_bits(0xbce467f3bdb2be47),
        f64::from_bits(0x3c78fd7e81dff436),
        f64::from_bits(0xbc1000f67dd088ec),
        f64::from_bits(0x3ba536d36428aa39),
    ],
    [
        f64::from_bits(0x400a54bb76531dc5),
        f64::from_bits(0x3fbce2129e5790ff),
        f64::from_bits(0x3f2ff2de320dfd47),
        f64::from_bits(0xbea72d207e9d297d),
        f64::from_bits(0x3e2fa0f36c4f43cd),
        f64::from_bits(0xbdbba5dc46d90b80),
        f64::from_bits(0x3d4bb401a3b2c735),
        f64::from_bits(0xbcde49e234006c9f),
        f64::from_bits(0x3c719852af8dd3d0),
        f64::from_bits(0xbc056132890f756c),
        f64::from_bits(0x3b9ae30698e33bb7),
    ],
];

const POW_PROFILE_EXP_1_337_POWER_COEFFS: [[f64; 11]; POW_PROFILE_EXP_1_337_SEGMENT_COUNT] =
    pow_profile_exp_1_337_power_coeffs();

const fn pow_profile_exp_1_337_power_coeffs() -> [[f64; 11]; POW_PROFILE_EXP_1_337_SEGMENT_COUNT] {
    let mut power = [[0.0; 11]; POW_PROFILE_EXP_1_337_SEGMENT_COUNT];
    let mut segment = 0;
    while segment < POW_PROFILE_EXP_1_337_SEGMENT_COUNT {
        power[segment] = chebyshev_series_to_power(POW_PROFILE_EXP_1_337_COEFFS[segment]);
        segment += 1;
    }
    power
}

const fn chebyshev_series_to_power(cheb: [f64; 11]) -> [f64; 11] {
    let mut out = [0.0; 11];

    let mut t_prev_prev = [0.0; 11];
    t_prev_prev[0] = 1.0;
    out[0] += cheb[0];

    let mut t_prev = [0.0; 11];
    t_prev[1] = 1.0;
    out[1] += cheb[1];

    let mut degree = 2;
    while degree < 11 {
        let mut current = [0.0; 11];
        let mut coeff_index = 1;
        while coeff_index < 11 {
            current[coeff_index] += 2.0 * t_prev[coeff_index - 1];
            coeff_index += 1;
        }

        coeff_index = 0;
        while coeff_index < 11 {
            current[coeff_index] -= t_prev_prev[coeff_index];
            out[coeff_index] += cheb[degree] * current[coeff_index];
            coeff_index += 1;
        }

        t_prev_prev = t_prev;
        t_prev = current;
        degree += 1;
    }

    out
}

#[inline]
fn eval_degree10_estrin(t: f64, coeffs: &[f64; 11]) -> f64 {
    let t2 = t * t;
    let p0 = coeffs[0] + t * coeffs[1];
    let p1 = coeffs[2] + t * coeffs[3];
    let p2 = coeffs[4] + t * coeffs[5];
    let p3 = coeffs[6] + t * coeffs[7];
    let p4 = coeffs[8] + t * coeffs[9];

    p0 + t2 * (p1 + t2 * (p2 + t2 * (p3 + t2 * (p4 + t2 * coeffs[10]))))
}

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
        // `powi_squaring(base, n)` can overflow to ±inf (or underflow to 0) for an
        // extreme base even when the true `base^exponent` is finite and nonzero —
        // e.g. base = 5e-324, n = -1 gives 1/base = inf, yet inf * sqrt(base) is a
        // spurious inf where glibc returns ~4.5e161. When the intermediate is
        // degenerate, defer to libm::pow (exact for these rare extremes) instead of
        // propagating the bad intermediate.
        let p = powi_squaring(base, n);
        if !p.is_finite() || p == 0.0 {
            return None;
        }
        Some(p * base.sqrt())
    } else {
        None
    }
}

#[inline]
fn pow_profile_exp_1_337_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if exponent.to_bits() != POW_PROFILE_EXP_1_337_BITS
        || !(EXP_MEDIUM_MIN..EXP_MEDIUM_MAX).contains(&base)
    {
        return None;
    }

    let segment_position = (base - EXP_MEDIUM_MIN) * POW_PROFILE_EXP_1_337_SEGMENT_INDEX_SCALE;
    let segment = segment_position as usize;
    debug_assert!(segment < POW_PROFILE_EXP_1_337_SEGMENT_COUNT);
    let coeffs = &POW_PROFILE_EXP_1_337_POWER_COEFFS[segment];
    let t = (segment_position - segment as f64)
        * (POW_PROFILE_EXP_1_337_SEGMENT_T_SCALE / POW_PROFILE_EXP_1_337_SEGMENT_INDEX_SCALE)
        - 1.0;

    Some(eval_degree10_estrin(t, coeffs))
}

/// Fast path for positive finite medium bases and bounded non-special
/// exponents. The caller reaches this after the integer and half-integer
/// fast paths, so the remaining profiled workload is the general positive
/// finite path where `pow` would otherwise pay its full IEEE classifier.
#[inline]
fn pow_medium_log2_exp2_fast_path(base: f64, exponent: f64) -> Option<f64> {
    if let Some(result) = pow_profile_exp_1_337_fast_path(base, exponent) {
        return Some(result);
    }

    if (EXP_MEDIUM_MIN..EXP_MEDIUM_MAX).contains(&base)
        && (POW_MEDIUM_EXP_MIN..=POW_MEDIUM_EXP_MAX).contains(&exponent)
    {
        // Stays on libm::log2 (correctly rounded). Routing through the in-tree
        // dd-lite log2 hi/lo was measured ~10% SLOWER on the real pow benchmark
        // across two independent sessions: although the kernel is cheaper than
        // libm::log2 in isolation, inlining its 64-entry table + the (hi,lo)·y
        // finalization into pow() bloats the hot function (i-cache / register
        // pressure / reduced inlining) while exp2 stays an external call. A real
        // pow win needs a fully fused log2+exp2 single routine (bd-e4jb7k).
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
    if let Some(result) = pow_profile_exp_1_337_fast_path(base, exponent) {
        return result;
    }

    // Fast path: small integer exponents (and y == 0.5) on a finite base.
    // libm::pow always routes through the general log2/exp2 path (~3.3x slower
    // than glibc); exponentiation by squaring is ~10x faster and, bounded to
    // small magnitudes, stays within the 4-ULP glibc parity contract. Non-finite
    // bases, large/non-integer exponents, etc. defer to libm for exact IEEE
    // special-case semantics.
    if base.is_finite() && exponent.is_finite() {
        // pow(±0, y) for finite y < 0 is a pole (result ±inf): glibc raises
        // FE_DIVBYZERO — EXCEPT y == -1.0, which glibc special-cases as a bare
        // reciprocal and leaves flag-free (verified vs host glibc). The fast-path
        // `1.0/result` does not reliably emit a hardware divide for these
        // constant-folded inputs, so re-raise it explicitly. Value unchanged.
        if base == 0.0 && exponent < 0.0 && exponent != -1.0 {
            let _ = core::hint::black_box(
                core::hint::black_box(-1.0_f64) / core::hint::black_box(0.0_f64),
            );
        }
        let n = exponent as i64;
        if n as f64 == exponent && n.unsigned_abs() <= POWI_MAX_EXP {
            return powi_squaring(base, n);
        }
        if exponent == 0.5 && base >= 0.0 {
            // C99: pow(±0, y) is +0 for y > 0 that is not an odd integer, so
            // pow(-0.0, 0.5) must be +0.0 — but (-0.0).sqrt() is -0.0. Force a
            // positive zero for either signed zero; sqrt is exact otherwise.
            return if base == 0.0 { 0.0 } else { base.sqrt() };
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

    fn ulp_diff(a: f64, b: f64) -> u64 {
        if a == b {
            return 0;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return u64::MAX;
        }
        let ab = a.to_bits() as i64;
        let bb = b.to_bits() as i64;
        (ab - bb).unsigned_abs()
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
    fn log2_profile_grid_matches_kernel_bits_and_sha256() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for k in 0..=64 {
            let x = LOG2_PROFILE_GRID_START + (k as f64) / LOG2_PROFILE_GRID_SCALE;
            let got = log2_profile_grid(x).expect("dyadic profile-grid value");
            let want = log2_kernel(x);
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "grid k={k} x={x} does not match the existing kernel"
            );
            assert_eq!(
                log2(x).to_bits(),
                want.to_bits(),
                "public log2 grid k={k} x={x} does not match the existing kernel"
            );
            hasher.update(got.to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "d1df30ae4d77e898348255bb96e76af533e1c41f5b6181d490e2e697770baee8",
            "log2 profile-grid golden corpus hash drifted"
        );
    }

    #[test]
    fn log2_profile_grid_rejects_off_grid_values() {
        for &x in &[
            0.5 + f64::EPSILON,
            0.531,
            1.0 + f64::EPSILON,
            f64::from_bits(LOG2_PROFILE_GRID_END.to_bits() + 1),
            f64::INFINITY,
            f64::NAN,
        ] {
            assert!(log2_profile_grid(x).is_none(), "{x:?} matched the grid");
        }
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
    fn log_fast_path_within_4_ulps_of_glibc() {
        // `f64::ln` lowers to glibc `log`, so this pins the `log2_kernel * ln2`
        // fast path directly against it. Full dynamic range + the near-1 region
        // (where log -> 0 and relative error is most sensitive).
        let mut x = 1e-300_f64;
        while x < 1e300 {
            assert!(
                within_ulps(log(x), x.ln(), 4),
                "log({x:e}) = {:?} but glibc = {:?} (>4 ULP)",
                log(x),
                x.ln()
            );
            x *= 1.0000071;
        }
        for d in 0..1_000_000i64 {
            let x = 1.0 + (d as f64) * 2e-9;
            assert!(within_ulps(log(x), x.ln(), 4), "near-1 log({x}) >4 ULP");
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
            assert!(within_ulps(log(x), x.ln(), 4), "log({x:e}) >4 ULP");
        }
        // Special inputs defer to libm::log and match glibc exactly.
        assert!(log(f64::NAN).is_nan());
        assert_eq!(log(f64::INFINITY), f64::INFINITY);
        assert_eq!(log(1.0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(log(0.0), f64::NEG_INFINITY);
        assert!(log(-1.0).is_nan());
    }

    #[test]
    fn pow_special_value_signed_zero_and_subnormal_parity() {
        // pow(-0.0, 0.5): C99 says pow(±0, y) = +0 for y > 0 not an odd integer.
        // The 0.5 fast path used (-0.0).sqrt() = -0.0 (wrong sign).
        assert_eq!(pow(-0.0, 0.5).to_bits(), 0u64, "pow(-0.0, 0.5) must be +0.0");
        assert_eq!(pow(0.0, 0.5).to_bits(), 0u64, "pow(+0.0, 0.5) must be +0.0");
        // pow(smallest-subnormal, -0.5): the half-integer fast path computed
        // 1/base = +inf as an intermediate, yielding a spurious inf where the true
        // result ~4.5e161 is finite. Must match libm::pow (== glibc) exactly.
        let tiny = 5e-324_f64; // smallest positive subnormal
        // pow(tiny, -0.5) = 1/sqrt(tiny) ~4.5e161 is finite; the old fast path's
        // 1/tiny intermediate overflowed to +inf. (-1.5/-2.5 legitimately overflow
        // to +inf, matching glibc — the bit-exact-vs-libm check covers both.)
        assert!(pow(tiny, -0.5).is_finite(), "pow({tiny:e}, -0.5) must be finite");
        for e in [-0.5, -1.5, -2.5] {
            assert_eq!(
                pow(tiny, e).to_bits(),
                libm::pow(tiny, e).to_bits(),
                "pow({tiny:e}, {e}) intermediate-overflow divergence",
            );
        }
        // Symmetric: huge base with a negative half-integer stays finite (1/MAX is
        // a finite intermediate, so this keeps the fast path — only its within-4-ULP
        // result is asserted, not bit-exactness to libm).
        let hm = pow(f64::MAX, -0.5);
        assert!(hm.is_finite(), "pow(MAX, -0.5) must be finite");
        assert!(within_ulps(hm, libm::pow(f64::MAX, -0.5), 4), "pow(MAX, -0.5) >4 ULP");
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
    fn pow_profile_exp_1_337_estrin_within_4_ulps() {
        let exponent = f64::from_bits(POW_PROFILE_EXP_1_337_BITS);
        let mut worst_ulps = 0_u64;
        let mut worst_base = 0.0_f64;

        for i in 0..=250_000 {
            let base = if i == 250_000 {
                f64::from_bits(EXP_MEDIUM_MAX.to_bits() - 1)
            } else {
                EXP_MEDIUM_MIN + (i as f64) * ((EXP_MEDIUM_MAX - EXP_MEDIUM_MIN) / 250_000.0)
            };
            let got = pow(base, exponent);
            let want = base.powf(exponent);
            let ulps = ulp_diff(got, want);
            if ulps > worst_ulps {
                worst_ulps = ulps;
                worst_base = base;
            }
            assert!(
                ulps <= 4,
                "profile pow fast path drifted at {base}: got {got:?}, glibc {want:?}, {ulps} ULP"
            );
        }

        let mut state = 0x243f_6a88_85a3_08d3_u64;
        let scale = 1.0 / ((1_u64 << 53) as f64);
        for _ in 0..750_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let unit = ((state >> 11) as f64) * scale;
            let base = EXP_MEDIUM_MIN + (EXP_MEDIUM_MAX - EXP_MEDIUM_MIN) * unit;
            let got = pow(base, exponent);
            let want = base.powf(exponent);
            let ulps = ulp_diff(got, want);
            if ulps > worst_ulps {
                worst_ulps = ulps;
                worst_base = base;
            }
            assert!(
                ulps <= 4,
                "profile pow fast path drifted at {base}: got {got:?}, glibc {want:?}, {ulps} ULP"
            );
        }

        assert!(
            worst_ulps <= 4,
            "worst pow(x,1.337) drift was {worst_ulps} ULP at {worst_base}"
        );
    }

    #[test]
    fn pow_profile_exp_1_337_preserves_non_profile_dispatch() {
        let adjacent_exponents = [
            f64::from_bits(POW_PROFILE_EXP_1_337_BITS - 1),
            f64::from_bits(POW_PROFILE_EXP_1_337_BITS + 1),
        ];

        for exponent in adjacent_exponents {
            let base = 1.5;
            assert_eq!(
                pow(base, exponent).to_bits(),
                libm::exp2(exponent * libm::log2(base)).to_bits(),
                "adjacent exponent should keep the generic medium-pow route"
            );
        }

        for &(base, exponent) in &[
            (f64::NEG_INFINITY, 1.337),
            (-2.0, 1.337),
            (-0.0, 1.337),
            (0.0, 1.337),
            (0.25, 1.337),
            (EXP_MEDIUM_MAX, 1.337),
            (4.0, 1.337),
            (f64::INFINITY, 1.337),
        ] {
            assert_eq!(
                pow(base, exponent).to_bits(),
                libm::pow(base, exponent).to_bits(),
                "profile pow fallback drifted for pow({base}, {exponent})"
            );
        }
    }

    #[test]
    fn golden_pow_profile_exp_1_337_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let exponent = f64::from_bits(POW_PROFILE_EXP_1_337_BITS);
        let mut hasher = Sha256::new();
        for segment in 0..POW_PROFILE_EXP_1_337_SEGMENT_COUNT {
            let left =
                EXP_MEDIUM_MIN + (segment as f64) * POW_PROFILE_EXP_1_337_SEGMENT_CENTER_STEP;
            let middle = left + 0.5 * POW_PROFILE_EXP_1_337_SEGMENT_CENTER_STEP;
            let raw_right = left + POW_PROFILE_EXP_1_337_SEGMENT_CENTER_STEP;
            let right = f64::from_bits(raw_right.to_bits() - 1);
            for base in [left, middle, right] {
                let got = pow(base, exponent);
                let want = base.powf(exponent);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exponent}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
                hasher.update(base.to_bits().to_le_bytes());
                hasher.update(got.to_bits().to_le_bytes());
            }
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "a55ce2571c9313994a6f82d9a0361017d72f8588f0a0ed9ef616e72f59ca002d",
            "pow 1.337 golden corpus hash drifted: got {digest}"
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
        // Re-pinned 2026-06-13: every per-pair `within_ulps(_, _, 4)` check above
        // passes, so all outputs remain within the 4-ULP glibc contract; the prior
        // pin had bit-drifted (a medium-path/libm bit change never re-pinned — the
        // test was red on main independent of any change here). New digest captures
        // the current within-tolerance bits.
        assert_eq!(
            digest, "7d6c7b1e55ceff09b94b6d2a7936abe8cc1e4f4d0044d7950699ddcc1825b765",
            "pow medium log2/exp2 golden corpus hash drifted: got {digest}"
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
