//! Research harness for bd-e4jb7k (the pow gap = log2 being 1.47x slower than
//! glibc). Offline generator + validator for a table-driven log2 with
//! double-double `logc` produced via the atanh series (cancellation-free,
//! unlike a naive `c - exp2(log2(c))`). Oracle = std f64 methods (system glibc
//! libm). `#[ignore]`d (runs multi-million-point sweeps); run explicitly:
//!   cargo test --release -p frankenlibc-core --test zzz_log2_gen -- --ignored --nocapture
//!
//! FINDINGS (2026-06-05): the atanh-dd generation yields `logc_hi` matching the
//! glibc oracle to 0 ULP — so the TABLE is exact. But the round-once dd
//! accumulation kernel measures ~12.7 ns/op, SLOWER than libm::log2 (~11.8 ns)
//! and far above glibc's hand-scheduled ~8 ns: the dd two_sums needed to reach
//! 0.5-ULP add more ops than glibc's asm. Closing the gap needs fewer-op
//! instruction scheduling (asm-class), not a better algorithm — the table+poly
//! algorithm here is already glibc's. Kept as the starting point if a future
//! attempt finds a lower-op accurate accumulation.

const N: usize = 128;

// ln(2) and 1/ln(2) as double-double constants.
const LN2_HI: f64 = 0.6931471805599453;
const LN2_LO: f64 = 2.3190468138462996e-17;

#[inline]
fn two_sum(a: f64, b: f64) -> (f64, f64) {
    let s = a + b;
    let bb = s - a;
    (s, (a - (s - bb)) + (b - bb))
}
#[inline]
fn two_prod(a: f64, b: f64) -> (f64, f64) {
    let p = a * b;
    (p, a.mul_add(b, -p))
}
#[inline]
fn dd_add(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let (s, e) = two_sum(a.0, b.0);
    let e = e + (a.1 + b.1);
    let (s2, e2) = two_sum(s, e);
    (s2, e2)
}
#[inline]
fn dd_mul(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let (p, e) = two_prod(a.0, b.0);
    let e = e + (a.0 * b.1 + a.1 * b.0);
    let (s, e2) = two_sum(p, e);
    (s, e2)
}
#[inline]
fn dd_div(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    let q0 = a.0 / b.0;
    let r = dd_add(a, (-(dd_mul((q0, 0.0), b).0), -(dd_mul((q0, 0.0), b).1)));
    let q1 = r.0 / b.0;
    two_sum(q0, q1)
}

// log2(c) as double-double via ln(c) = 2*atanh((c-1)/(c+1)), then / ln2.
fn log2_dd(c: f64) -> (f64, f64) {
    // s = (c-1)/(c+1) in dd (c exact, c-1 & c+1 exact for our grid).
    let num = (c - 1.0, 0.0);
    let den = (c + 1.0, 0.0);
    let s = dd_div(num, den);
    let s2 = dd_mul(s, s);
    // atanh(s) = s + s^3/3 + s^5/5 + ... ; accumulate in dd.
    let mut term = s; // s^(2k+1)
    let mut sum = s;
    let mut k = 1u32;
    loop {
        term = dd_mul(term, s2); // *= s^2
        k += 2;
        let add = dd_mul(term, (1.0 / k as f64, 0.0));
        sum = dd_add(sum, add);
        // term magnitude shrinks ~ s^2 (<1/9); stop when negligible vs result.
        if term.0.abs() < 1e-40 || k > 99 {
            break;
        }
    }
    let lnc = dd_mul(sum, (2.0, 0.0)); // ln(c)
    // log2(c) = ln(c) / ln2.
    dd_div(lnc, (LN2_HI, LN2_LO))
}

#[test]
#[ignore = "research harness for bd-e4jb7k; runs multi-million-point sweeps"]
fn zzz_log2_gen_validate() {
    use std::hint::black_box;
    use std::time::Instant;

    // Build tables: grid c = 1 + k/128, invc = 1/c, logc = dd log2(c).
    let mut invc = [0.0f64; N + 1];
    let mut logc_hi = [0.0f64; N + 1];
    let mut logc_lo = [0.0f64; N + 1];
    for k in 0..=N {
        let c = 1.0 + (k as f64) / (N as f64);
        invc[k] = 1.0 / c;
        let (hi, lo) = log2_dd(c);
        logc_hi[k] = hi;
        logc_lo[k] = lo;
    }
    // Sanity: logc_hi must match the oracle log2(c) to <=1 ULP.
    let mut maxtab = 0i64;
    for k in 0..=N {
        let c = 1.0 + (k as f64) / (N as f64);
        let d = (logc_hi[k].to_bits() as i64 - c.log2().to_bits() as i64).abs();
        if d > maxtab {
            maxtab = d;
        }
    }
    eprintln!("GEN logc_hi vs oracle max_ulp = {maxtab}");

    // Degree-6 Taylor of log2(1+r) = (r - r^2/2 + ... - r^6/6)/ln2.
    let il = 1.0 / LN2_HI;
    let (c1, c2, c3, c4, c5, c6) = (il, -il / 2.0, il / 3.0, -il / 4.0, il / 5.0, -il / 6.0);

    let log2_fast = |x: f64| -> f64 {
        let bits = x.to_bits();
        let e = (((bits >> 52) & 0x7ff) as i64 - 1023) as f64;
        let m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
        let k = ((m - 1.0) * N as f64).round() as usize;
        let r = m.mul_add(invc[k], -1.0);
        let poly = r * c6
            .mul_add(r, c5)
            .mul_add(r, c4)
            .mul_add(r, c3)
            .mul_add(r, c2)
            .mul_add(r, c1);
        // Round-once accumulation: (logc_hi + poly) + e, errors folded in.
        let (s1, e1) = two_sum(logc_hi[k], poly);
        let (s2, e2) = two_sum(e, s1);
        s2 + ((e1 + e2) + logc_lo[k])
    };

    // ULP helpers (total-order, valid across signs).
    let key = |f: f64| -> i128 {
        let b = f.to_bits();
        (if b & (1 << 63) != 0 {
            !b
        } else {
            b | (1 << 63)
        }) as i128
    };
    let ulp = |g: f64, w: f64| -> f64 {
        if g == w {
            0.0
        } else {
            (key(g) - key(w)).unsigned_abs() as f64
        }
    };

    // (1) standalone single-f64 log2 ULP vs glibc, AWAY from x=1 (ill-conditioned).
    let mut maxlog2 = 0.0f64;
    let mut s = 0x1234_5678_9abc_def1u64;
    for _ in 0..2_000_000 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let x = 0.5 + (s >> 11) as f64 * (2.0 / (1u64 << 53) as f64); // [0.5,2.5)
        if (x - 1.0).abs() < 0.05 {
            continue; // skip near-1 (log2->0, ULP ill-conditioned)
        }
        let u = ulp(log2_fast(x), x.log2());
        if u > maxlog2 {
            maxlog2 = u;
        }
    }
    eprintln!("GEN log2_fast single-f64 max_ulp (|x-1|>0.05) = {maxlog2}");

    // (2) pow composition vs glibc powf: exp2(y*log2(x)). The real contract.
    let mut maxpow = 0.0f64;
    let mut over4 = 0u64;
    let mut s = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..3_000_000 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bx = 0.5 + (s >> 11) as f64 * (2.0 / (1u64 << 53) as f64);
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let ey = -3.0 + (s >> 11) as f64 * (6.0 / (1u64 << 53) as f64);
        let got = (ey * log2_fast(bx)).exp2();
        let want = bx.powf(ey);
        let u = ulp(got, want);
        if u > maxpow {
            maxpow = u;
        }
        if u > 4.0 {
            over4 += 1;
        }
    }
    eprintln!("GEN pow(simple-compose) max_ulp = {maxpow}, over_4ulp = {over4}");

    // (3) timing of log2_fast.
    let xs: Vec<f64> = (0..1024)
        .map(|i| 0.5 + (i as f64) * (2.0 / 1024.0))
        .collect();
    for _ in 0..50 {
        let mut a = 0.0;
        for &x in &xs {
            a += log2_fast(black_box(x));
        }
        black_box(a);
    }
    let t0 = Instant::now();
    let mut a = 0.0;
    for _ in 0..4000 {
        for &x in &xs {
            a += log2_fast(black_box(x));
        }
    }
    black_box(a);
    eprintln!(
        "GEN log2_fast = {:.2} ns/op",
        t0.elapsed().as_nanos() as f64 / (4000.0 * xs.len() as f64)
    );
}
