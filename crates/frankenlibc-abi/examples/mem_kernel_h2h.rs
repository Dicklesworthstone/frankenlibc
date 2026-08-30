//! Head-to-head for `frankenlibc-core`'s memory-scan kernels against the live host glibc,
//! run entirely in ONE process so both arms share the CPU, the caches and the invocation.
//!
//! Method notes that make the numbers admissible:
//!
//! * The incumbent is opened with `dlmopen(LM_ID_NEWLM, "libc.so.6")`, so it is the real
//!   shipped glibc in its own link-map namespace rather than anything this crate provides.
//!   The arms are asserted to be different code by pointer; a self-compare would report a
//!   meaningless 1.0.
//! * **Order-balanced rounds.** Earlier versions timed a fixed `[fl, glibc, glibc]` triple
//!   every round, which put `fl` permanently in the coldest slot. That showed up as A/A nulls
//!   stuck near 0.90 for the shortest ops, and it biased in two directions at once: `fl` in
//!   position 1 inflated the numerator while `glibc` in position 2 inflated the denominator.
//!   Two mitigations were tried and neither fixed it -- per-round warmup (nulls unchanged at
//!   0.900-0.929) and a 400 ms clock spin-up (helped once, did not reproduce). Rounds now
//!   alternate `[fl, glibc, glibc]` and `[glibc, fl, glibc]`, so across a round pair `fl` and
//!   the denominator each average position 1.5 and the slot advantage cancels instead of
//!   being absorbed by whichever arm always ran first.
//! * The A/A null is the fastest glibc round over the fastest glibc round of the other slot --
//!   the same loop against itself, and the noise floor for the moment the run happened.
//! * A ratio is **withheld** unless its null lands inside `ADMISSIBLE`. A figure on the page
//!   gets quoted downstream; a caveat beside it does not travel. The withheld number is shown
//!   in parentheses so nobody re-derives it by accident, but it is not formatted as a result.
//! * The **ELF sha256 is computed from inside the running process** (`/proc/self/exe`).
//! * Conformance is checked before timing, and `memcmp` gets an exhaustive ordering sweep,
//!   because it returns an ORDER: a resolver that picks the right panel but the wrong byte
//!   still returns the right sign whenever the two candidates happen to order the same way.
//! * All output goes to **stderr** so `rch exec` returns it.

use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 25;
const WARMUP: usize = 3;
const ADMISSIBLE: (f64, f64) = (0.97, 1.03);

type MemchrFn = unsafe extern "C" fn(*const u8, i32, usize) -> *const u8;
type MemcmpFn = unsafe extern "C" fn(*const u8, *const u8, usize) -> i32;
type MemmemFn = unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> *const u8;

fn sha256_self() -> String {
    use sha2::{Digest, Sha256};
    match std::fs::read("/proc/self/exe") {
        Ok(bytes) => {
            let mut h = Sha256::new();
            h.update(&bytes);
            h.finalize().iter().map(|b| format!("{b:02x}")).collect()
        }
        Err(_) => "<unreadable>".to_string(),
    }
}

/// Fastest round observed.
///
/// The estimator of choice once the harness had to survive a contended worker. Every source
/// of interference here -- another tenant on the core, a migration, an interrupt, the clock
/// not yet at its ceiling -- can only ADD time to a loop; none can make the code faster than
/// it is. So the minimum over rounds is the closest thing to the uncontended cost, while the
/// median drags in whatever the machine was doing during the middle rounds. The median-based
/// version resolved n <= 64 on roughly one run in five; this is the change that was supposed
/// to need fewer clean rounds rather than a quieter machine.
fn fastest(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::INFINITY, f64::min)
}

/// Bootstrap percentile CI for the MEDIAN of a set of per-round ratios.
///
/// The point estimate this harness reports is fastest-of-rounds, for the reason argued above,
/// and a minimum has no useful sampling distribution -- resampling it just re-finds the same
/// smallest observation. So the interval is computed for the median of the per-round ratios
/// instead: it answers "how much of this number is the sample I happened to draw", which is
/// the question an A/A null is being asked, while the minimum answers "what is the
/// uncontended cost". Both are reported; neither is derived from the other.
///
/// Resampling is seeded deterministically from the round count, so two runs of the same build
/// produce the same interval and a moved bound means the timings moved, not the dice.
fn bootstrap_median_ci(ratios: &[f64]) -> (f64, f64) {
    const RESAMPLES: usize = 2000;
    let n = ratios.len();
    if n == 0 {
        return (f64::NAN, f64::NAN);
    }
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ (n as u64);
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut medians = Vec::with_capacity(RESAMPLES);
    let mut draw = vec![0.0f64; n];
    for _ in 0..RESAMPLES {
        for slot in draw.iter_mut() {
            *slot = ratios[(next() % n as u64) as usize];
        }
        draw.sort_by(|a, b| a.partial_cmp(b).unwrap());
        medians.push(if n % 2 == 1 {
            draw[n / 2]
        } else {
            0.5 * (draw[n / 2 - 1] + draw[n / 2])
        });
    }
    medians.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let lo = medians[(0.025 * RESAMPLES as f64) as usize];
    let hi = medians[((0.975 * RESAMPLES as f64) as usize).min(RESAMPLES - 1)];
    (lo, hi)
}

#[inline]
fn timed(iters: usize, mut body: impl FnMut()) -> f64 {
    let t = Instant::now();
    for _ in 0..iters {
        body();
    }
    t.elapsed().as_nanos() as f64 / iters as f64
}

/// Runs the order-balanced round schedule and reports, withholding unresolvable rows.
fn measure(op: &str, n: usize, iters: usize, mut fl: impl FnMut(), mut gl: impl FnMut()) {
    let (mut fls, mut gls, mut aas) = (Vec::new(), Vec::new(), Vec::new());
    for round in 0..(ROUNDS + WARMUP) {
        // Alternate which arm takes the cold slot. Even: [fl, gl, gl]. Odd: [gl, fl, gl].
        let (f, g, a) = if round % 2 == 0 {
            let f = timed(iters, &mut fl);
            let g = timed(iters, &mut gl);
            let a = timed(iters, &mut gl);
            (f, g, a)
        } else {
            let g = timed(iters, &mut gl);
            let f = timed(iters, &mut fl);
            let a = timed(iters, &mut gl);
            (f, g, a)
        };
        if round >= WARMUP {
            fls.push(f);
            gls.push(g);
            aas.push(a);
        }
    }
    // Ratio of fastest-observed per arm. Per-round pairing was what the median form needed to
    // keep drift common-mode; the minimum does not need it, because drift and interference
    // both only push a round upward and the minimum ignores them by construction.
    let (fl_best, gl_best, aa_best) = (fastest(&fls), fastest(&gls), fastest(&aas));
    let (r, null) = (fl_best / gl_best, aa_best / gl_best);
    // Per-round ratios feed the interval; the fastest-of-rounds pair above feeds the estimate.
    let null_rounds: Vec<f64> = aas.iter().zip(&gls).map(|(a, g)| a / g).collect();
    let eff_rounds: Vec<f64> = fls.iter().zip(&gls).map(|(f, g)| f / g).collect();
    let (nlo, nhi) = bootstrap_median_ci(&null_rounds);
    let (elo, ehi) = bootstrap_median_ci(&eff_rounds);
    if (ADMISSIBLE.0..=ADMISSIBLE.1).contains(&null) {
        eprintln!(
            "{op:<10} n={n:<6} fl={:8.2}ns glibc={:8.2}ns  fl/glibc={r:6.3}x  A/A_null={null:.3} \
             null_medCI=[{nlo:.3},{nhi:.3}] effect_medCI=[{elo:.3},{ehi:.3}]",
            fl_best,
            gl_best,
        );
    } else {
        eprintln!(
            "{op:<10} n={n:<6} UNRESOLVED: A/A_null={null:.3} outside {:.2}..{:.2} (would have read {r:.3}x)",
            ADMISSIBLE.0, ADMISSIBLE.1,
        );
    }
}

fn main() {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");

        eprintln!("SELF_ELF_SHA256={}", sha256_self());
        eprintln!("INCUMBENT=libc.so.6 via dlmopen(LM_ID_NEWLM)");
        eprintln!(
            "SCHEDULE=order-balanced [fl,gl,gl]/[gl,fl,gl], {ROUNDS} timed rounds after {WARMUP} warmup"
        );

        let gl_memchr: MemchrFn = std::mem::transmute(libc::dlsym(h, c"memchr".as_ptr()));
        let gl_memrchr: MemchrFn = std::mem::transmute(libc::dlsym(h, c"memrchr".as_ptr()));
        let gl_memcmp: MemcmpFn = std::mem::transmute(libc::dlsym(h, c"memcmp".as_ptr()));
        let gl_memmem: MemmemFn = std::mem::transmute(libc::dlsym(h, c"memmem".as_ptr()));
        assert!(
            gl_memchr as usize != frankenlibc_core::string::mem::memchr as usize,
            "arms identical"
        );

        // Spin the core to its steady clock before any timing. memchr is measured first and
        // was absorbing the process-start ramp: its nulls sat at 0.952 while every later op
        // read 1.000, which is position-in-the-RUN, not a property of memchr.
        {
            let spin = Instant::now();
            let mut acc = 0u64;
            while spin.elapsed().as_millis() < 600 {
                for i in 0..10_000u64 {
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
                }
            }
            black_box(acc);
            eprintln!("SPINUP_MS=600\n");
        }

        // `memcmp` returns an ORDER: sweep every length, every difference position and the
        // byte pairs where a signed/unsigned confusion shows up, against live glibc's sign.
        {
            let (mut checks, mut bad) = (0usize, 0usize);
            for len in 0..=300usize {
                for pos in 0..len {
                    for &(x, y) in &[(b'a', b'b'), (b'b', b'a'), (0u8, 255u8), (255u8, 0u8)] {
                        let mut p = vec![b'k'; len];
                        let mut q = vec![b'k'; len];
                        p[pos] = x;
                        q[pos] = y;
                        let fl = match frankenlibc_core::string::mem::memcmp(&p, &q, len) {
                            core::cmp::Ordering::Less => -1,
                            core::cmp::Ordering::Equal => 0,
                            core::cmp::Ordering::Greater => 1,
                        };
                        let gl = gl_memcmp(p.as_ptr(), q.as_ptr(), len).signum();
                        checks += 1;
                        if fl != gl {
                            bad += 1;
                            if bad <= 5 {
                                eprintln!(
                                    "MEMCMP ORDER MISMATCH len={len} pos={pos} ({x},{y}) fl={fl} glibc={gl}"
                                );
                            }
                        }
                    }
                }
            }
            eprintln!(
                "MEMCMP_ORDER_SWEEP checks={checks} mismatches={bad} verdict={}\n",
                if bad == 0 { "PASS" } else { "FAIL" }
            );
        }

        // memrchr returns the LAST occurrence: sweep every length and every needle position,
        // plus a second needle earlier in the buffer so a resolver that returns the FIRST
        // match instead of the last cannot pass. Reverse index arithmetic is exactly where an
        // off-by-one hides, and this tier resolves from the mask's high bit.
        {
            let (mut checks, mut bad) = (0usize, 0usize);
            for len in 1..=200usize {
                for pos in 0..len {
                    let mut buf = vec![b'k'; len];
                    buf[pos] = b'z';
                    if pos > 0 { buf[0] = b'z'; }
                    let fl = frankenlibc_core::string::mem::memrchr(&buf, b'z', len);
                    let raw = gl_memrchr(buf.as_ptr(), b'z' as i32, len);
                    let gl = (!raw.is_null()).then(|| raw as usize - buf.as_ptr() as usize);
                    checks += 1;
                    if fl != gl {
                        bad += 1;
                        if bad <= 5 {
                            eprintln!("MEMRCHR MISMATCH len={len} pos={pos} fl={fl:?} glibc={gl:?}");
                        }
                    }
                }
            }
            eprintln!(
                "MEMRCHR_INDEX_SWEEP checks={checks} mismatches={bad} verdict={}\n",
                if bad == 0 { "PASS" } else { "FAIL" }
            );
        }

        // memchr returns the FIRST occurrence: the mirror sweep, with the decoy planted at the
        // LAST index instead of the first, so a resolver that returns the last match cannot
        // pass. The sub-panel dispatch resolves 16..=31 from two overlapping 16-byte windows
        // and argues the trailing mask needs no masking step; if that argument is wrong it is
        // wrong somewhere in 16..=31 with a match in the overlap, which this covers densely.
        {
            let (mut checks, mut bad) = (0usize, 0usize);
            for len in 1..=200usize {
                for pos in 0..len {
                    let mut buf = vec![b'k'; len];
                    buf[pos] = b'z';
                    if pos < len - 1 { buf[len - 1] = b'z'; }
                    let fl = frankenlibc_core::string::mem::memchr(&buf, b'z', len);
                    let raw = gl_memchr(buf.as_ptr(), b'z' as i32, len);
                    let gl = (!raw.is_null()).then(|| raw as usize - buf.as_ptr() as usize);
                    checks += 1;
                    if fl != gl {
                        bad += 1;
                        if bad <= 5 {
                            eprintln!("MEMCHR MISMATCH len={len} pos={pos} fl={fl:?} glibc={gl:?}");
                        }
                    }
                }
            }
            // A needle that is absent entirely must return None at every length, including the
            // 16..=31 two-window range where an unmasked trailing read could invent a hit.
            for len in 0..=200usize {
                let buf = vec![b'k'; len];
                let fl = frankenlibc_core::string::mem::memchr(&buf, b'z', len);
                let raw = gl_memchr(buf.as_ptr(), b'z' as i32, len);
                let gl = (!raw.is_null()).then(|| raw as usize - buf.as_ptr() as usize);
                checks += 1;
                if fl != gl {
                    bad += 1;
                    eprintln!("MEMCHR ABSENT MISMATCH len={len} fl={fl:?} glibc={gl:?}");
                }
            }
            eprintln!(
                "MEMCHR_INDEX_SWEEP checks={checks} mismatches={bad} verdict={}\n",
                if bad == 0 { "PASS" } else { "FAIL" }
            );
        }

        for &n in &[8usize, 16, 32, 64, 128, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[n - 1] = b'z';
            let fl_hit = frankenlibc_core::string::mem::memchr(&buf, b'z', n);
            let gl_raw = gl_memchr(buf.as_ptr(), b'z' as i32, n);
            let gl_hit = (!gl_raw.is_null()).then(|| gl_raw as usize - buf.as_ptr() as usize);
            if fl_hit != gl_hit {
                eprintln!("memchr     n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_hit:?}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            measure(
                "memchr",
                n,
                iters,
                || {
                    black_box(frankenlibc_core::string::mem::memchr(
                        black_box(&buf),
                        black_box(b'z'),
                        black_box(n),
                    ));
                },
                || {
                    black_box(gl_memchr(
                        black_box(buf.as_ptr()),
                        black_box(b'z' as i32),
                        black_box(n),
                    ));
                },
            );
        }
        eprintln!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[0] = b'z';
            let fl_hit = frankenlibc_core::string::mem::memrchr(&buf, b'z', n);
            let gl_raw = gl_memrchr(buf.as_ptr(), b'z' as i32, n);
            let gl_hit = (!gl_raw.is_null()).then(|| gl_raw as usize - buf.as_ptr() as usize);
            if fl_hit != gl_hit {
                eprintln!("memrchr    n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_hit:?}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            measure(
                "memrchr",
                n,
                iters,
                || {
                    black_box(frankenlibc_core::string::mem::memrchr(
                        black_box(&buf),
                        black_box(b'z'),
                        black_box(n),
                    ));
                },
                || {
                    black_box(gl_memrchr(
                        black_box(buf.as_ptr()),
                        black_box(b'z' as i32),
                        black_box(n),
                    ));
                },
            );
        }
        eprintln!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let a = vec![b'q'; n];
            let mut b = vec![b'q'; n];
            b[n - 1] = b'r';
            let iters = (1 << 22) / n.max(8);
            measure(
                "memcmp",
                n,
                iters,
                || {
                    black_box(frankenlibc_core::string::mem::memcmp(
                        black_box(&a),
                        black_box(&b),
                        black_box(n),
                    ));
                },
                || {
                    black_box(gl_memcmp(
                        black_box(a.as_ptr()),
                        black_box(b.as_ptr()),
                        black_box(n),
                    ));
                },
            );
        }
        eprintln!();

        for &n in &[256usize, 4096] {
            let mut hay = vec![b'a'; n];
            let needle = b"needle";
            hay[n - 6..].copy_from_slice(needle);
            let fl_hit = frankenlibc_core::string::mem::memmem(&hay, n, needle, needle.len());
            let gl_raw = gl_memmem(hay.as_ptr(), n, needle.as_ptr(), needle.len());
            let gl_hit = (!gl_raw.is_null()).then(|| gl_raw as usize - hay.as_ptr() as usize);
            if fl_hit != gl_hit {
                eprintln!("memmem     n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_hit:?}");
                continue;
            }
            let iters = (1 << 20) / n.max(8);
            measure(
                "memmem",
                n,
                iters,
                || {
                    black_box(frankenlibc_core::string::mem::memmem(
                        black_box(&hay),
                        black_box(n),
                        black_box(needle),
                        black_box(needle.len()),
                    ));
                },
                || {
                    black_box(gl_memmem(
                        black_box(hay.as_ptr()),
                        black_box(n),
                        black_box(needle.as_ptr()),
                        black_box(needle.len()),
                    ));
                },
            );
        }
    }
}
