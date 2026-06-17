//! Exact decimal expansion of IEEE-754 binary128 (`_Float128`) values.
//!
//! A binary128 value is a dyadic rational `m · 2^E`, which therefore has a
//! *finite* exact decimal expansion. This module produces that exact
//! significand-digit string and its base-10 exponent with **no rounding**,
//! using a minimal big-integer. It is the foundation for a byte-exact
//! `strfromf128` formatter (bd-trosmi): the rounding and `%a/%e/%f/%g` format
//! assembly are layered on top of this exact decomposition by the caller.
//!
//! The exported function takes the raw 128-bit pattern (`u128`) rather than a
//! `f128`, so it needs no nightly `f128` feature and can be unit-tested against
//! exact reference values independent of argument-passing ABI concerns.

/// A minimal big unsigned integer: base-2^32, little-endian limbs, with no
/// trailing zero limbs (the value zero is the empty limb vector).
#[derive(Clone)]
struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    fn from_u128(mut v: u128) -> Self {
        let mut limbs = Vec::new();
        while v != 0 {
            limbs.push((v & 0xffff_ffff) as u32);
            v >>= 32;
        }
        BigUint { limbs }
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn is_odd(&self) -> bool {
        self.limbs.first().is_some_and(|&l| l & 1 == 1)
    }

    fn normalize(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    fn one() -> Self {
        BigUint { limbs: vec![1] }
    }

    /// Number of significant bits (0 for the value zero).
    fn bit_len(&self) -> usize {
        match self.limbs.last() {
            None => 0,
            Some(&top) => (self.limbs.len() - 1) * 32 + (32 - top.leading_zeros() as usize),
        }
    }

    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        Ordering::Equal
    }

    /// `self += x` (small).
    fn add_small(&mut self, x: u32) {
        let mut carry = x as u64;
        let mut i = 0;
        while carry != 0 {
            if i == self.limbs.len() {
                self.limbs.push(0);
            }
            let cur = self.limbs[i] as u64 + carry;
            self.limbs[i] = (cur & 0xffff_ffff) as u32;
            carry = cur >> 32;
            i += 1;
        }
    }

    /// `self -= other`, assuming `self >= other`.
    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let o = if i < other.limbs.len() { other.limbs[i] as i64 } else { 0 };
            let mut d = self.limbs[i] as i64 - o - borrow;
            if d < 0 {
                d += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            self.limbs[i] = d as u32;
        }
        self.normalize();
    }

    /// `self *= 2` (shift left one bit, in place).
    fn shl1_inplace(&mut self) {
        let mut carry = 0u32;
        for l in self.limbs.iter_mut() {
            let nc = *l >> 31;
            *l = (*l << 1) | carry;
            carry = nc;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }

    fn get_bit(&self, i: usize) -> bool {
        let (w, b) = (i / 32, i % 32);
        self.limbs.get(w).is_some_and(|&l| (l >> b) & 1 == 1)
    }

    fn set_bit(&mut self, i: usize) {
        let (w, b) = (i / 32, i % 32);
        while self.limbs.len() <= w {
            self.limbs.push(0);
        }
        self.limbs[w] |= 1 << b;
    }

    fn set_bit0(&mut self) {
        if self.limbs.is_empty() {
            self.limbs.push(1);
        } else {
            self.limbs[0] |= 1;
        }
    }

    /// Truncating division with remainder via binary long division.
    /// Returns (quotient, remainder). `d` must be nonzero.
    fn divrem(&self, d: &BigUint) -> (BigUint, BigUint) {
        use core::cmp::Ordering;
        if self.cmp(d) == Ordering::Less {
            return (BigUint { limbs: Vec::new() }, self.clone());
        }
        let n = self.bit_len();
        let mut q = BigUint { limbs: vec![0; n.div_ceil(32)] };
        let mut r = BigUint { limbs: Vec::new() };
        for i in (0..n).rev() {
            r.shl1_inplace();
            if self.get_bit(i) {
                r.set_bit0();
            }
            if r.cmp(d) != Ordering::Less {
                r.sub_assign(d);
                q.set_bit(i);
            }
        }
        q.normalize();
        (q, r)
    }

    /// `round(self / d)` with round-half-to-even. `d` must be nonzero.
    fn round_div(&self, d: &BigUint) -> BigUint {
        use core::cmp::Ordering;
        let (mut q, r) = self.divrem(d);
        let mut r2 = r;
        r2.shl1_inplace();
        match r2.cmp(d) {
            Ordering::Greater => q.add_small(1),
            Ordering::Less => {}
            Ordering::Equal => {
                if q.is_odd() {
                    q.add_small(1);
                }
            }
        }
        q
    }

    /// `self * 10^p`.
    fn mul_pow10(self, p: u32) -> Self {
        self.mul_pow5(p).shl_bits(p)
    }

    fn from_decimal(digits: &[u8]) -> BigUint {
        let mut b = BigUint { limbs: Vec::new() };
        let len = digits.len();
        let mut i = len % 9;
        if i > 0 {
            let mut v = 0u32;
            for &d in &digits[..i] {
                v = v * 10 + (d - b'0') as u32;
            }
            b.limbs.push(v);
            b.normalize();
        }
        while i < len {
            let mut v = 0u32;
            for &d in &digits[i..i + 9] {
                v = v * 10 + (d - b'0') as u32;
            }
            b.mul_small(1_000_000_000);
            b.add_small(v);
            i += 9;
        }
        b
    }

    /// `self << bits`.
    fn shl_bits(mut self, bits: u32) -> Self {
        if self.is_zero() || bits == 0 {
            return self;
        }
        let word_shift = (bits / 32) as usize;
        let bit_shift = bits % 32;
        let mut out = vec![0u32; word_shift];
        if bit_shift == 0 {
            out.extend_from_slice(&self.limbs);
        } else {
            let mut carry = 0u64;
            for &l in &self.limbs {
                let cur = ((l as u64) << bit_shift) | carry;
                out.push((cur & 0xffff_ffff) as u32);
                carry = cur >> 32;
            }
            if carry != 0 {
                out.push(carry as u32);
            }
        }
        self.limbs = out;
        self.normalize();
        self
    }

    /// `self *= x` for a small (< 2^32) multiplier.
    fn mul_small(&mut self, x: u32) {
        if x == 0 {
            self.limbs.clear();
            return;
        }
        if self.is_zero() {
            return;
        }
        let mut carry = 0u64;
        for l in self.limbs.iter_mut() {
            let cur = (*l as u64) * (x as u64) + carry;
            *l = (cur & 0xffff_ffff) as u32;
            carry = cur >> 32;
        }
        if carry != 0 {
            self.limbs.push(carry as u32);
        }
    }

    /// `self *= 5^k`, multiplying in 5^13 chunks (5^13 = 1_220_703_125 < 2^32).
    fn mul_pow5(mut self, k: u32) -> Self {
        let mut rem = k;
        while rem >= 13 {
            self.mul_small(1_220_703_125);
            rem -= 13;
        }
        if rem > 0 {
            self.mul_small(5u32.pow(rem));
        }
        self
    }

    /// Divide `self` by `d` in place; return the remainder.
    fn divmod_small(&mut self, d: u32) -> u32 {
        let mut rem = 0u64;
        for l in self.limbs.iter_mut().rev() {
            let cur = (rem << 32) | (*l as u64);
            *l = (cur / d as u64) as u32;
            rem = cur % d as u64;
        }
        self.normalize();
        rem as u32
    }

    /// Exact decimal digits, most-significant first, no leading zeros.
    fn into_decimal_digits(mut self) -> Vec<u8> {
        if self.is_zero() {
            return vec![b'0'];
        }
        // Extract base-10^9 chunks, least-significant first.
        let mut chunks: Vec<u32> = Vec::new();
        while !self.is_zero() {
            chunks.push(self.divmod_small(1_000_000_000));
        }
        let mut out = Vec::new();
        let last = chunks.len() - 1;
        out.extend_from_slice(chunks[last].to_string().as_bytes());
        for i in (0..last).rev() {
            // Each lower chunk is exactly 9 digits, zero-padded.
            let g = chunks[i];
            let mut div = 100_000_000;
            while div != 0 {
                out.push(b'0' + ((g / div) % 10) as u8);
                div /= 10;
            }
        }
        out
    }
}

/// Classification and exact decimal significand of a binary128 value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum F128Class {
    Zero {
        negative: bool,
    },
    Infinity {
        negative: bool,
    },
    Nan {
        negative: bool,
        quiet: bool,
        payload: u128,
    },
    /// Finite nonzero. The exact magnitude equals
    /// `(digits as a decimal integer) · 10^exp10`. `digits` are ASCII `b'0'..=b'9'`,
    /// most-significant first, with no leading and no trailing zeros.
    Finite {
        negative: bool,
        digits: Vec<u8>,
        exp10: i32,
    },
}

const BIAS: i32 = 16383;
const MANT_BITS: i32 = 112;

/// Decompose the raw 128-bit pattern of an IEEE-754 binary128 value into its
/// classification and (for finite values) exact decimal significand.
pub fn classify_binary128(bits: u128) -> F128Class {
    let negative = (bits >> 127) & 1 == 1;
    let exp_field = ((bits >> 112) & 0x7fff) as i32;
    let mantissa = bits & ((1u128 << 112) - 1);

    if exp_field == 0x7fff {
        if mantissa == 0 {
            return F128Class::Infinity { negative };
        }
        let quiet = (mantissa >> 111) & 1 == 1;
        let payload = mantissa & ((1u128 << 111) - 1);
        return F128Class::Nan { negative, quiet, payload };
    }

    // Significand integer `m` and binary exponent `e` such that value = m · 2^e.
    let (m, e): (u128, i32) = if exp_field == 0 {
        if mantissa == 0 {
            return F128Class::Zero { negative };
        }
        // Subnormal: no implicit leading bit, exponent fixed at 1 - BIAS.
        (mantissa, 1 - BIAS - MANT_BITS)
    } else {
        // Normal: implicit leading 1.
        ((1u128 << 112) | mantissa, exp_field - BIAS - MANT_BITS)
    };

    // value = m · 2^e. Build an integer N and exp10 with value = N · 10^exp10:
    //   e >= 0:  N = m << e,        exp10 = 0
    //   e <  0:  N = m · 5^(-e),    exp10 = e   (since 2^e = 5^(-e) · 10^e)
    let (big, mut exp10) = if e >= 0 {
        (BigUint::from_u128(m).shl_bits(e as u32), 0i32)
    } else {
        (BigUint::from_u128(m).mul_pow5((-e) as u32), e)
    };

    let mut digits = big.into_decimal_digits();
    // Normalize to the canonical significand: strip trailing zeros into exp10.
    while digits.len() > 1 && digits.last() == Some(&b'0') {
        digits.pop();
        exp10 += 1;
    }
    F128Class::Finite { negative, digits, exp10 }
}

/// Correctly-rounded (round-half-to-even) IEEE-754 binary128 bit pattern for
/// the value `(-1)^negative · S · 10^dexp`, where `S` is the nonnegative integer
/// formed by the ASCII decimal `digits` (most-significant first). Handles
/// normal, subnormal, signed zero, and overflow-to-infinity — the core of a
/// correctly-rounded strtof128 (bd-nkr0ga).
pub fn decimal_to_binary128(negative: bool, digits: &[u8], dexp: i32) -> u128 {
    let sign = if negative { 1u128 << 127 } else { 0 };
    // Drop leading zeros; an all-zero significand is a signed zero.
    let lead = match digits.iter().position(|&d| d != b'0') {
        Some(s) => s,
        None => return sign,
    };
    let mut digits = &digits[lead..];
    // Drop trailing zeros into the exponent to keep S small.
    let mut dexp = dexp;
    let mut end = digits.len();
    while end > 1 && digits[end - 1] == b'0' {
        end -= 1;
        dexp += 1;
    }
    digits = &digits[..end];

    let s = BigUint::from_decimal(digits);
    // value = num/den, exact.
    let (num, den) = if dexp >= 0 {
        (s.mul_pow10(dexp as u32), BigUint::one())
    } else {
        (s, BigUint::one().mul_pow10((-dexp) as u32))
    };
    rational_to_binary128(sign, &num, &den)
}

/// Low 128 bits of a (<=128-bit) BigUint.
fn low128(b: &BigUint) -> u128 {
    let g = |i: usize| b.limbs.get(i).map_or(0u128, |&l| l as u128);
    g(0) | (g(1) << 32) | (g(2) << 64) | (g(3) << 96)
}

/// Correctly-rounded binary128 bits for the positive rational `num/den`, with
/// `sign` (0 or 1<<127) applied. `num` may be zero (-> signed zero); `den` must
/// be nonzero. Shared by the decimal and hex parsers.
fn rational_to_binary128(sign: u128, num: &BigUint, den: &BigUint) -> u128 {
    if num.is_zero() {
        return sign;
    }
    // Find k so that m = round(value / 2^k) is a 113-bit normal significand.
    let mut k = num.bit_len() as i64 - den.bit_len() as i64 - 113;
    let mut m = BigUint { limbs: Vec::new() };
    for _ in 0..6 {
        m = if k >= 0 {
            num.round_div(&den.clone().shl_bits(k as u32))
        } else {
            num.clone().shl_bits((-k) as u32).round_div(den)
        };
        match m.bit_len().cmp(&113) {
            core::cmp::Ordering::Less => k -= 1,
            core::cmp::Ordering::Greater => k += 1,
            core::cmp::Ordering::Equal => break,
        }
    }

    let exp_field = k + 16495;
    if exp_field >= 0x7fff {
        return sign | (0x7fffu128 << 112); // overflow -> infinity
    }
    if exp_field >= 1 {
        // Normal: strip the implicit leading bit from the 113-bit significand.
        let frac = low128(&m) & ((1u128 << 112) - 1);
        return sign | ((exp_field as u128) << 112) | frac;
    }

    // Subnormal: round value onto the subnormal grid (ulp = 2^-16494). The ulp
    // count placed in the low 112 bits lets a carry into bit 112 promote to the
    // smallest normal automatically.
    let m_sub = num.clone().shl_bits(16494).round_div(den);
    sign | (low128(&m_sub) & ((1u128 << 113) - 1))
}

/// Correctly-rounded binary128 bits for a hexadecimal-float significand:
/// `(-1)^negative · M · 2^(binexp - 4·frac_hex_len)`, where `M` is the integer
/// formed by `int_hex` ++ `frac_hex` (ASCII hex digits) and `binexp` is the
/// value of the `p` exponent. Handles overflow/subnormal/zero like the decimal
/// path.
pub fn hex_to_binary128(negative: bool, int_hex: &[u8], frac_hex: &[u8], binexp: i64) -> u128 {
    let sign = if negative { 1u128 << 127 } else { 0 };
    let mut m = BigUint { limbs: Vec::new() };
    let mut any = false;
    for &h in int_hex.iter().chain(frac_hex.iter()) {
        let d = (h as char).to_digit(16).unwrap_or(0);
        m.mul_small(16);
        m.add_small(d);
        any |= d != 0;
    }
    if !any {
        return sign;
    }
    // value = M · 2^e2.
    let e2 = binexp - 4 * frac_hex.len() as i64;
    let (num, den) = if e2 >= 0 {
        (m.shl_bits(e2 as u32), BigUint::one())
    } else {
        (m, BigUint::one().shl_bits((-e2) as u32))
    };
    rational_to_binary128(sign, &num, &den)
}

/// Round a canonical significand (`digits`, `exp10`) — where the value equals
/// `(digits as integer) · 10^exp10` — to at most `max_sig` significant decimal
/// digits using round-half-to-even, returning a new canonical `(digits, exp10)`
/// (trailing zeros stripped). `max_sig` must be >= 1.
///
/// This is the rounding primitive shared by the `%e`/`%g` conversions; `%f`
/// rounding to a fixed number of fractional places maps onto it by choosing
/// `max_sig` from the value's magnitude.
pub fn round_to_sig_digits(digits: &[u8], exp10: i32, max_sig: usize) -> (Vec<u8>, i32) {
    let n = digits.len();
    if max_sig == 0 || n <= max_sig {
        return (digits.to_vec(), exp10);
    }
    let dropped = n - max_sig;
    let mut kept: Vec<u8> = digits[..max_sig].to_vec();
    let round_digit = digits[max_sig];
    let round_up = if round_digit > b'5' {
        true
    } else if round_digit < b'5' {
        false
    } else if digits[max_sig + 1..].iter().any(|&d| d != b'0') {
        true
    } else {
        // Exact tie: round to even (round up iff the last kept digit is odd).
        (kept[max_sig - 1] - b'0') % 2 == 1
    };
    let mut new_exp10 = exp10 + dropped as i32;
    if round_up {
        let mut i = max_sig;
        loop {
            if i == 0 {
                // Carry out of the most-significant digit: 99..9 -> 100..0.
                // Keep `max_sig` significant digits by dropping the new trailing
                // zero and bumping the exponent.
                kept.insert(0, b'1');
                kept.pop();
                new_exp10 += 1;
                break;
            }
            i -= 1;
            if kept[i] == b'9' {
                kept[i] = b'0';
            } else {
                kept[i] += 1;
                break;
            }
        }
    }
    while kept.len() > 1 && kept.last() == Some(&b'0') {
        kept.pop();
        new_exp10 += 1;
    }
    (kept, new_exp10)
}

/// A parsed `strfrom`-style conversion spec: `%[flags][width][.precision]CONV`.
#[derive(Clone, Copy, Debug)]
pub struct FmtSpec {
    pub conv: u8,
    pub precision: Option<usize>,
    pub width: usize,
    pub left: bool,
    pub plus: bool,
    pub space: bool,
    pub alt: bool,
    pub zero: bool,
}

fn sci_exp(digits: &[u8], exp10: i32) -> i32 {
    exp10 + digits.len() as i32 - 1
}

fn finite_parts(cls: &F128Class) -> (Vec<u8>, i32) {
    match cls {
        F128Class::Finite { digits, exp10, .. } => (digits.clone(), *exp10),
        F128Class::Zero { .. } => (vec![b'0'], 0),
        _ => (vec![b'0'], 0),
    }
}

/// Scientific (`%e`) body, unsigned. `p` fractional digits; `strip` removes
/// trailing zeros (for `%g`).
fn render_e(digits: &[u8], exp10: i32, p: usize, upper: bool, alt: bool, strip: bool) -> Vec<u8> {
    let (rd, rexp10) = round_to_sig_digits(digits, exp10, p + 1);
    let x = sci_exp(&rd, rexp10);
    let mut sig = rd;
    while sig.len() < p + 1 {
        sig.push(b'0');
    }
    let d0 = sig[0];
    let mut frac: Vec<u8> = sig[1..p + 1].to_vec();
    if strip {
        while frac.last() == Some(&b'0') {
            frac.pop();
        }
    }
    let mut out = vec![d0];
    if !frac.is_empty() {
        out.push(b'.');
        out.extend_from_slice(&frac);
    } else if alt {
        out.push(b'.');
    }
    out.push(if upper { b'E' } else { b'e' });
    out.push(if x < 0 { b'-' } else { b'+' });
    let es = x.unsigned_abs().to_string();
    if es.len() < 2 {
        out.push(b'0');
    }
    out.extend_from_slice(es.as_bytes());
    out
}

/// Fixed-point (`%f`) body, unsigned. `p` fractional digits; `strip` for `%g`.
fn render_f(digits: &[u8], exp10: i32, p: usize, alt: bool, strip: bool) -> Vec<u8> {
    let x0 = sci_exp(digits, exp10);
    let keep = x0 + 1 + p as i32;
    let (rd, rexp10) = if keep >= 1 {
        round_to_sig_digits(digits, exp10, keep as usize)
    } else {
        // Value is below the last retained fractional place: rounds to 0, or up
        // to one unit in the last place if it is >= half.
        let round_up = keep == 0
            && (digits[0] > b'5'
                || (digits[0] == b'5' && digits[1..].iter().any(|&d| d != b'0')));
        if round_up {
            (vec![b'1'], -(p as i32))
        } else {
            (vec![b'0'], 0)
        }
    };
    let x = sci_exp(&rd, rexp10);
    let digit_at = |k: i32| -> u8 {
        let i = x - k;
        if i >= 0 && (i as usize) < rd.len() {
            rd[i as usize]
        } else {
            b'0'
        }
    };
    let mut int_part = Vec::new();
    if x < 0 {
        int_part.push(b'0');
    } else {
        for k in (0..=x).rev() {
            int_part.push(digit_at(k));
        }
    }
    let mut frac = Vec::new();
    for kk in 1..=p as i32 {
        frac.push(digit_at(-kk));
    }
    if strip {
        while frac.last() == Some(&b'0') {
            frac.pop();
        }
    }
    let mut out = int_part;
    if !frac.is_empty() {
        out.push(b'.');
        out.extend_from_slice(&frac);
    } else if alt {
        out.push(b'.');
    }
    out
}

/// General (`%g`) body, unsigned.
fn render_g(digits: &[u8], exp10: i32, precision: Option<usize>, upper: bool, alt: bool) -> Vec<u8> {
    let mut p = precision.unwrap_or(6);
    if p == 0 {
        p = 1;
    }
    let (rd, rexp10) = round_to_sig_digits(digits, exp10, p);
    let x = sci_exp(&rd, rexp10);
    if x < -4 || x >= p as i32 {
        render_e(digits, exp10, p - 1, upper, alt, !alt)
    } else {
        render_f(digits, exp10, (p as i32 - 1 - x).max(0) as usize, alt, !alt)
    }
}

/// Hex float (`%a`) body, unsigned, including the `0x`/`0X` prefix.
fn render_a(bits: u128, p_opt: Option<usize>, upper: bool, alt: bool) -> Vec<u8> {
    let exp_field = ((bits >> 112) & 0x7fff) as i32;
    let mantissa = bits & ((1u128 << 112) - 1);
    let (mut lead, exp2): (u32, i32) = if exp_field == 0 {
        if mantissa == 0 {
            (0, 0)
        } else {
            (0, -16382)
        }
    } else {
        (1, exp_field - 16383)
    };
    let mut nibs: Vec<u8> = (0..28).rev().map(|i| ((mantissa >> (i * 4)) & 0xf) as u8).collect();

    if let Some(p) = p_opt {
        if p < nibs.len() {
            let round_nib = nibs[p];
            let rest_nonzero = nibs[p + 1..].iter().any(|&x| x != 0);
            let last_kept = if p == 0 { lead as u8 } else { nibs[p - 1] };
            let round_up = round_nib > 8
                || (round_nib == 8 && rest_nonzero)
                || (round_nib == 8 && !rest_nonzero && (last_kept & 1) == 1);
            nibs.truncate(p);
            if round_up {
                let mut carry = true;
                let mut i = p;
                while carry && i > 0 {
                    i -= 1;
                    if nibs[i] == 0xf {
                        nibs[i] = 0;
                    } else {
                        nibs[i] += 1;
                        carry = false;
                    }
                }
                if carry {
                    lead += 1;
                }
            }
        } else {
            while nibs.len() < p {
                nibs.push(0);
            }
        }
    } else {
        while nibs.last() == Some(&0) {
            nibs.pop();
        }
    }

    let hexdig: &[u8] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out: Vec<u8> = if upper { b"0X".to_vec() } else { b"0x".to_vec() };
    out.push(hexdig[lead as usize]);
    if !nibs.is_empty() || alt {
        out.push(b'.');
        for &nb in &nibs {
            out.push(hexdig[nb as usize]);
        }
    }
    out.push(if upper { b'P' } else { b'p' });
    out.push(if exp2 < 0 { b'-' } else { b'+' });
    out.extend_from_slice(exp2.unsigned_abs().to_string().as_bytes());
    out
}

/// Apply minimum field width to `sign ++ body`. `is_hex` marks `%a` so the `0`
/// flag pads after the `0x` prefix. Specials pass `numeric = false` to force
/// space padding regardless of the `0` flag.
fn assemble(sign: &[u8], body: &[u8], spec: &FmtSpec, is_hex: bool, numeric: bool) -> Vec<u8> {
    let content = sign.len() + body.len();
    if content >= spec.width {
        let mut v = Vec::with_capacity(content);
        v.extend_from_slice(sign);
        v.extend_from_slice(body);
        return v;
    }
    let pad = spec.width - content;
    if spec.left {
        let mut v = Vec::from(sign);
        v.extend_from_slice(body);
        v.extend(std::iter::repeat_n(b' ', pad));
        v
    } else if spec.zero && numeric {
        let split = if is_hex { 2 } else { 0 };
        let mut v = Vec::from(sign);
        v.extend_from_slice(&body[..split]);
        v.extend(std::iter::repeat_n(b'0', pad));
        v.extend_from_slice(&body[split..]);
        v
    } else {
        let mut v: Vec<u8> = std::iter::repeat_n(b' ', pad).collect();
        v.extend_from_slice(sign);
        v.extend_from_slice(body);
        v
    }
}

/// Format a binary128 value per `spec`, returning the bytes (no NUL), matching
/// glibc's `strfromf128` / `printf` float conversions.
pub fn format_binary128(bits: u128, spec: &FmtSpec) -> Vec<u8> {
    let upper = spec.conv.is_ascii_uppercase();
    let cls = classify_binary128(bits);
    let negative = match cls {
        F128Class::Zero { negative }
        | F128Class::Infinity { negative }
        | F128Class::Nan { negative, .. }
        | F128Class::Finite { negative, .. } => negative,
    };
    let sign: &[u8] = if negative {
        b"-"
    } else if spec.plus {
        b"+"
    } else if spec.space {
        b" "
    } else {
        b""
    };

    if matches!(cls, F128Class::Infinity { .. }) {
        let b = if upper { b"INF".as_ref() } else { b"inf".as_ref() };
        return assemble(sign, b, spec, false, false);
    }
    if matches!(cls, F128Class::Nan { .. }) {
        let b = if upper { b"NAN".as_ref() } else { b"nan".as_ref() };
        return assemble(sign, b, spec, false, false);
    }

    let conv = spec.conv.to_ascii_lowercase();
    let body = match conv {
        b'a' => render_a(bits, spec.precision, upper, spec.alt),
        b'e' => {
            let (d, e) = finite_parts(&cls);
            render_e(&d, e, spec.precision.unwrap_or(6), upper, spec.alt, false)
        }
        b'f' => {
            let (d, e) = finite_parts(&cls);
            render_f(&d, e, spec.precision.unwrap_or(6), spec.alt, false)
        }
        b'g' => {
            let (d, e) = finite_parts(&cls);
            render_g(&d, e, spec.precision, upper, spec.alt)
        }
        _ => Vec::new(),
    };
    assemble(sign, &body, spec, conv == b'a', true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(sign: u128, ef: u128, m: u128) -> u128 {
        (sign << 127) | (ef << 112) | m
    }

    fn finite(b: u128) -> (bool, String, i32) {
        match classify_binary128(b) {
            F128Class::Finite { negative, digits, exp10 } => {
                (negative, String::from_utf8(digits).unwrap(), exp10)
            }
            other => panic!("expected finite, got {other:?}"),
        }
    }

    #[test]
    fn exact_simple_values() {
        assert_eq!(finite(bits(0, 0x3FFF, 0)), (false, "1".into(), 0)); // 1.0
        assert_eq!(finite(bits(0, 0x4000, 0)), (false, "2".into(), 0)); // 2.0
        assert_eq!(finite(bits(0, 0x3FFE, 0)), (false, "5".into(), -1)); // 0.5
        assert_eq!(finite(bits(0, 0x3FFD, 0)), (false, "25".into(), -2)); // 0.25
        assert_eq!(finite(bits(0, 0x4000, 1 << 111)), (false, "3".into(), 0)); // 3.0
        assert_eq!(finite(bits(0, 0x4002, 1 << 110)), (false, "1".into(), 1)); // 10.0
        assert_eq!(finite(bits(1, 0x3FFF, 0)), (true, "1".into(), 0)); // -1.0
    }

    #[test]
    fn exact_tiny_normal_2_pow_minus_120() {
        let (neg, d, e) = finite(bits(0, 0x3F87, 0));
        assert!(!neg);
        assert_eq!(
            d,
            "752316384526264005099991383822237233803945956334136013765601092018187046051025390625"
        );
        assert_eq!(e, -120);
    }

    #[test]
    fn exact_smallest_subnormal_2_pow_minus_16494() {
        let (neg, d, e) = finite(bits(0, 0, 1));
        assert!(!neg);
        assert_eq!(d.len(), 11529);
        assert!(d.starts_with("64751751194380251109"));
        assert!(d.ends_with("41301822662353515625"));
        assert_eq!(e, -16494);
    }

    fn round(d: &str, exp10: i32, max_sig: usize) -> (String, i32) {
        let (r, e) = round_to_sig_digits(d.as_bytes(), exp10, max_sig);
        (String::from_utf8(r).unwrap(), e)
    }

    #[test]
    fn rounds_half_to_even() {
        // No rounding needed.
        assert_eq!(round("12345", 0, 5), ("12345".into(), 0));
        assert_eq!(round("12345", 0, 9), ("12345".into(), 0));
        // > 5 rounds up.
        assert_eq!(round("126", 0, 2), ("13".into(), 1));
        // < 5 truncates.
        assert_eq!(round("124", 0, 2), ("12".into(), 1));
        // Exact tie, last kept digit even -> stay; odd -> up.
        assert_eq!(round("125", 0, 2), ("12".into(), 1)); // 12 even
        assert_eq!(round("135", 0, 2), ("14".into(), 1)); // 13 odd -> 14
        // Tie with trailing nonzero -> always up.
        assert_eq!(round("1251", 0, 2), ("13".into(), 2));
        // Carry out of all-nines, with trailing-zero strip.
        assert_eq!(round("999500", 0, 3), ("1".into(), 6)); // -> 1_000_000
        assert_eq!(round("9996", 0, 3), ("1".into(), 4)); // 1000 -> 1e4
        // exp10 is preserved/offset, not assumed zero.
        assert_eq!(round("1999", -3, 1), ("2".into(), 0)); // 1.999 -> 2
    }

    fn fmt(b: u128, conv: u8, precision: Option<usize>) -> String {
        let spec = FmtSpec {
            conv,
            precision,
            width: 0,
            left: false,
            plus: false,
            space: false,
            alt: false,
            zero: false,
        };
        String::from_utf8(format_binary128(b, &spec)).unwrap()
    }

    #[test]
    fn formats_basic() {
        assert_eq!(fmt(bits(0, 0x3FFF, 0), b'g', None), "1");
        assert_eq!(fmt(bits(0, 0x3FFF, 0), b'e', None), "1.000000e+00");
        assert_eq!(fmt(bits(0, 0x3FFF, 0), b'f', None), "1.000000");
        assert_eq!(fmt(bits(0, 0x3FFF, 0), b'a', None), "0x1p+0");
        assert_eq!(fmt(bits(0, 0x4000, 1 << 111), b'a', None), "0x1.8p+1"); // 3.0
        assert_eq!(fmt(bits(0, 0x4002, 1 << 110), b'g', None), "10"); // 10.0
        assert_eq!(fmt(bits(0, 0, 0), b'e', None), "0.000000e+00"); // 0.0
        assert_eq!(fmt(bits(0, 0, 0), b'a', None), "0x0p+0");
        assert_eq!(fmt(bits(0, 0x4000, 1 << 111), b'a', Some(0)), "0x2p+1"); // 3.0 %.0a
    }

    #[test]
    fn parses_decimal_to_bits() {
        // Exactly-representable values: known bit patterns.
        assert_eq!(decimal_to_binary128(false, b"1", 0), bits(0, 0x3FFF, 0)); // 1.0
        assert_eq!(decimal_to_binary128(false, b"2", 0), bits(0, 0x4000, 0)); // 2.0
        assert_eq!(decimal_to_binary128(false, b"5", -1), bits(0, 0x3FFE, 0)); // 0.5
        assert_eq!(decimal_to_binary128(false, b"25", -2), bits(0, 0x3FFD, 0)); // 0.25
        assert_eq!(decimal_to_binary128(false, b"3", 0), bits(0, 0x4000, 1 << 111)); // 3.0
        assert_eq!(decimal_to_binary128(false, b"10", 0), bits(0, 0x4002, 1 << 110)); // 10.0
        assert_eq!(decimal_to_binary128(false, b"1000", -3), bits(0, 0x3FFF, 0)); // 1.0 (1000e-3)
        // Signed zero.
        assert_eq!(decimal_to_binary128(false, b"0", 0), 0);
        assert_eq!(decimal_to_binary128(true, b"0", 0), 1u128 << 127);
        assert_eq!(decimal_to_binary128(true, b"1", 0), bits(1, 0x3FFF, 0)); // -1.0
        // Overflow -> +/-inf.
        assert_eq!(decimal_to_binary128(false, b"1", 5000), bits(0, 0x7FFF, 0));
        assert_eq!(decimal_to_binary128(true, b"1", 5000), bits(1, 0x7FFF, 0));
        // Round-trip a known decimal expansion back to its source bits: 2^-120
        // formats to this exact decimal (see exact_tiny_normal test), so parsing
        // it must reproduce 2^-120's bits.
        let tiny = "752316384526264005099991383822237233803945956334136013765601092018187046051025390625";
        assert_eq!(decimal_to_binary128(false, tiny.as_bytes(), -120), bits(0, 0x3F87, 0));
    }

    #[test]
    fn parses_hex_to_bits() {
        assert_eq!(hex_to_binary128(false, b"1", b"", 0), bits(0, 0x3FFF, 0)); // 0x1p0 = 1
        assert_eq!(hex_to_binary128(false, b"1", b"", 1), bits(0, 0x4000, 0)); // 0x1p1 = 2
        assert_eq!(hex_to_binary128(false, b"1", b"8", 1), bits(0, 0x4000, 1 << 111)); // 0x1.8p1 = 3
        assert_eq!(hex_to_binary128(false, b"0", b"1", 0), bits(0, 0x3FFB, 0)); // 0x0.1 = 2^-4
        assert_eq!(hex_to_binary128(true, b"1", b"", 0), bits(1, 0x3FFF, 0)); // -1
        assert_eq!(hex_to_binary128(false, b"0", b"0", 0), 0); // zero
        // 0x1.(28 f's)p0: exactly 113 significant bits, no rounding -> all-ones mantissa.
        assert_eq!(
            hex_to_binary128(false, b"1", b"ffffffffffffffffffffffffffff", 0),
            bits(0, 0x3FFF, (1u128 << 112) - 1)
        );
    }

    #[test]
    fn classifies_specials() {
        assert_eq!(classify_binary128(bits(0, 0x7FFF, 0)), F128Class::Infinity { negative: false });
        assert_eq!(classify_binary128(bits(1, 0x7FFF, 0)), F128Class::Infinity { negative: true });
        assert_eq!(classify_binary128(bits(0, 0, 0)), F128Class::Zero { negative: false });
        assert_eq!(classify_binary128(bits(1, 0, 0)), F128Class::Zero { negative: true });
        match classify_binary128(bits(0, 0x7FFF, 1 << 111)) {
            F128Class::Nan { quiet, negative, .. } => {
                assert!(quiet);
                assert!(!negative);
            }
            o => panic!("expected quiet NaN, got {o:?}"),
        }
        match classify_binary128(bits(0, 0x7FFF, 1)) {
            F128Class::Nan { quiet, payload, .. } => {
                assert!(!quiet);
                assert_eq!(payload, 1);
            }
            o => panic!("expected signaling NaN, got {o:?}"),
        }
    }
}
