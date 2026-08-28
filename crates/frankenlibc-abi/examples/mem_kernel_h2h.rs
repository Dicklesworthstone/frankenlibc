//! Head-to-head for `frankenlibc-core`'s memory-scan kernels against the live host glibc,
//! run entirely in ONE process so both arms share the CPU, the caches and the invocation.
//!
//! Method notes that make the numbers admissible:
//!
//! * The incumbent is opened with `dlmopen(LM_ID_NEWLM, "libc.so.6")`, so it is the real
//!   shipped glibc in its own link-map namespace rather than anything this crate provides.
//!   The two arms are asserted to be different code by comparing the resolved pointer
//!   against the fl-side one; a self-compare would report a meaningless 1.0.
//! * Every op reports an **A/A null**: the glibc arm timed twice, back to back, under the
//!   identical loop. That is the noise floor for this host at this moment, and a ratio that
//!   is not close to 1.0 invalidates the paired fl/glibc figure printed beside it.
//! * The **ELF sha256 is computed from inside the running process** (`/proc/self/exe`), so
//!   the reported identity is the binary that actually produced the numbers.
//! * Results are the **median of `ROUNDS` interleaved rounds**, alternating arms within each
//!   round, so a monotonic drift in clock speed lands on both arms rather than on whichever
//!   ran second.
//! * Conformance is checked before timing: if the two arms disagree on an answer the op is
//!   reported as MISMATCH and no ratio is printed, because timing two functions that compute
//!   different things is not a comparison.

use std::hint::black_box;
use std::time::Instant;

const ROUNDS: usize = 25;

/// Untimed rounds per arm before the first timed one.
///
/// Without this the harness reported memchr A/A nulls clustered at 0.887-0.927 -- always
/// below 1.0, never above, across every small size and several runs. Random noise has no
/// sign. Each round is an interleaved triple `[fl, glibc, glibc]` and the null is the second
/// glibc over the first, so 0.90 means the REPEAT loop is ~10% faster than the one right
/// before it: a position effect (branch history, i-cache) that recurs every round, so a
/// median over 25 rounds does not remove it. It biases in both directions at once -- `fl`
/// runs first and coldest, inflating the numerator; `glibc` runs second and still not warm,
/// inflating the denominator -- which is why the affected sizes had to be withheld rather
/// than corrected. Warming both arms first moves that cost out of the measurement.
const WARMUP: usize = 3;

/// A paired round is [fl, glibc, glibc]; the ratio is taken PER ROUND and the median of the
/// per-round ratios is reported. Taking a ratio of medians instead lets a clock ramp that
/// happened between the two medians masquerade as a speed difference, which is exactly what
/// the first run of this harness showed: A/A nulls from 0.78 to 1.47 on a shared worker.
/// Pairing inside the round makes drift common-mode, and the reported A/A null is then the
/// median of per-round glibc-vs-glibc ratios -- a real noise floor for the same loop.

type MemchrFn = unsafe extern "C" fn(*const u8, i32, usize) -> *const u8;
type MemrchrFn = unsafe extern "C" fn(*const u8, i32, usize) -> *const u8;
type MemcmpFn = unsafe extern "C" fn(*const u8, *const u8, usize) -> i32;
type MemmemFn =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> *const u8;

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

/// Median of the per-round nanosecond figures.
fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// Reports the median of the PER-ROUND ratios, and the A/A null the same way.
///
/// `ADMISSIBLE` is the band the A/A null must fall inside for the paired figure to mean
/// anything; outside it the row is printed with a `SUSPECT` marker rather than quietly
/// standing next to the trustworthy ones.
const ADMISSIBLE: (f64, f64) = (0.97, 1.03);

fn report(op: &str, n: usize, fls: &[f64], gls: &[f64], aas: &[f64]) {
    let ratios: Vec<f64> = fls.iter().zip(gls).map(|(f, g)| f / g).collect();
    let nulls: Vec<f64> = aas.iter().zip(gls).map(|(a, g)| a / g).collect();
    let (r, null) = (median(ratios), median(nulls));
    // A ratio is only printed when the null says the instrument could resolve it. Outside the
    // band the row prints UNRESOLVED and withholds the number entirely, rather than printing
    // it next to a caveat -- a figure on the page gets quoted, a caveat does not travel with
    // it. Two hypotheses for the out-of-band nulls were tested and neither fixed them (see
    // WARMUP and the spin-up block), and the offset reproduces at ~0.90 run after run, so at
    // those sizes this harness is resolving arm POSITION rather than code and has no business
    // reporting a speed.
    if (ADMISSIBLE.0..=ADMISSIBLE.1).contains(&null) {
        eprintln!(
            "{op:<10} n={n:<6} fl={:8.2}ns glibc={:8.2}ns  fl/glibc={r:6.3}x  A/A_null={null:.3}",
            median(fls.to_vec()),
            median(gls.to_vec()),
        );
    } else {
        eprintln!(
            "{op:<10} n={n:<6} UNRESOLVED on this host: A/A_null={null:.3} outside {:.2}..{:.2} \
             (would have read {r:.3}x)",
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
        let phase: Option<unsafe extern "C" fn() -> i32> = {
            let p = libc::dlsym(libc::RTLD_DEFAULT, c"__frankenlibc_runtime_phase".as_ptr());
            if p.is_null() { None } else { Some(std::mem::transmute(p)) }
        };
        // Stated, not assumed: an example links fl as an rlib rather than loading it as the
        // process libc, so the ABI entrypoints are NOT at PHASE=2 here. These figures are for
        // the CORE kernels, which is what this harness compares.
        eprintln!(
            "RUNTIME_PHASE={} (example links fl as an rlib; core kernels under test)",
            phase.map_or(-1, |f| f())
        );
        eprintln!("INCUMBENT=libc.so.6 via dlmopen(LM_ID_NEWLM)");

        // GLOBAL SPIN-UP before any timing.
        //
        // Per-round warmup did NOT fix the memchr A/A nulls -- they stayed at 0.900/0.901/
        // 0.900/0.929, refuting the branch-history explanation. What the data actually shows
        // is positional in the RUN, not the round: memchr is measured first and its nulls are
        // worst at the sizes with the most iterations, while every op measured later comes
        // back at 1.000. That is the CPU ramping its clock during the opening block, which
        // makes each successive loop faster and drives the null BELOW 1. Burning a fixed
        // slice of wall time here lets the core reach its steady frequency before the first
        // timed loop, so the ramp stops landing on whichever op happens to go first.
        {
            let spin = Instant::now();
            let mut acc = 0u64;
            while spin.elapsed().as_millis() < 400 {
                for i in 0..10_000u64 {
                    acc = acc.wrapping_mul(6364136223846793005).wrapping_add(i);
                }
            }
            black_box(acc);
            eprintln!("SPINUP_MS=400 (clock allowed to reach steady state before timing)\n");
        }

        let gl_memchr: MemchrFn =
            std::mem::transmute(libc::dlsym(h, c"memchr".as_ptr()));
        let gl_memrchr: MemrchrFn =
            std::mem::transmute(libc::dlsym(h, c"memrchr".as_ptr()));
        let gl_memcmp: MemcmpFn =
            std::mem::transmute(libc::dlsym(h, c"memcmp".as_ptr()));
        let gl_memmem: MemmemFn =
            std::mem::transmute(libc::dlsym(h, c"memmem".as_ptr()));
        assert!(
            gl_memchr as usize != frankenlibc_core::string::mem::memchr as usize,
            "arms identical"
        );

        // EXHAUSTIVE ORDERING SWEEP before any timing. `memcmp` returns an ORDER, not a
        // bool, so a resolver that finds the right panel but the wrong byte within it still
        // returns the right sign most of the time -- it only breaks when the two differing
        // bytes order oppositely to the first one. This sweeps every length 0..=300 and every
        // difference position within it, in BOTH directions (a<b and a>b), and checks the
        // sign against live glibc. 
        {
            let mut checks = 0usize;
            let mut bad = 0usize;
            for len in 0..=300usize {
                for pos in 0..len {
                    for &(x, y) in &[(b'a', b'b'), (b'b', b'a'), (0u8, 255u8), (255u8, 0u8)] {
                        let mut p = vec![b'k'; len];
                        let mut q = vec![b'k'; len];
                        p[pos] = x;
                        q[pos] = y;
                        let fl = frankenlibc_core::string::mem::memcmp(&p, &q, len);
                        let gl = gl_memcmp(p.as_ptr(), q.as_ptr(), len).signum();
                        let fl_sign = match fl {
                            core::cmp::Ordering::Less => -1,
                            core::cmp::Ordering::Equal => 0,
                            core::cmp::Ordering::Greater => 1,
                        };
                        checks += 1;
                        if fl_sign != gl {
                            bad += 1;
                            if bad <= 5 {
                                eprintln!(
                                    "MEMCMP ORDER MISMATCH len={len} pos={pos} bytes=({x},{y}) fl={fl_sign} glibc={gl}"
                                );
                            }
                        }
                    }
                }
            }
            eprintln!("MEMCMP_ORDER_SWEEP checks={checks} mismatches={bad} verdict={}\n",
                     if bad == 0 { "PASS" } else { "FAIL" });
        }

        // buffers: needle at the very end so both arms scan the whole length
        for &n in &[8usize, 16, 32, 64, 128, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[n - 1] = b'z';

            // conformance before timing
            let fl_hit = frankenlibc_core::string::mem::memchr(&buf, b'z', n);
            let gl_hit = gl_memchr(buf.as_ptr(), b'z' as i32, n);
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - buf.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                eprintln!("memchr          n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }

            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for round in 0..(ROUNDS + WARMUP) {
                let warm = round < WARMUP;
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memchr(
                        black_box(&buf),
                        black_box(b'z'),
                        black_box(n),
                    ));
                }
                if !warm { fls.push(t.elapsed().as_nanos() as f64 / iters as f64); }

                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                if !warm { gls.push(t.elapsed().as_nanos() as f64 / iters as f64); }

                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                if !warm { aas.push(t.elapsed().as_nanos() as f64 / iters as f64); }
            }
            report("memchr", n, &fls, &gls, &aas);
        }
        eprintln!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let mut buf = vec![b'a'; n];
            buf[0] = b'z';
            let fl_hit = frankenlibc_core::string::mem::memrchr(&buf, b'z', n);
            let gl_hit = gl_memrchr(buf.as_ptr(), b'z' as i32, n);
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - buf.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                eprintln!("memrchr         n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for round in 0..(ROUNDS + WARMUP) {
                let warm = round < WARMUP;
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memrchr(
                        black_box(&buf), black_box(b'z'), black_box(n),
                    ));
                }
                if !warm { fls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memrchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                if !warm { gls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memrchr(black_box(buf.as_ptr()), black_box(b'z' as i32), black_box(n)));
                }
                if !warm { aas.push(t.elapsed().as_nanos() as f64 / iters as f64); }
            }
            report("memrchr", n, &fls, &gls, &aas);
        }
        eprintln!();

        for &n in &[8usize, 16, 64, 256, 1024] {
            let a = vec![b'q'; n];
            let mut b = vec![b'q'; n];
            b[n - 1] = b'r';
            let fl_ord = frankenlibc_core::string::mem::memcmp(&a, &b, n);
            let gl_ord = gl_memcmp(a.as_ptr(), b.as_ptr(), n);
            let agree = matches!(
                (fl_ord, gl_ord.signum()),
                (core::cmp::Ordering::Less, -1)
                    | (core::cmp::Ordering::Equal, 0)
                    | (core::cmp::Ordering::Greater, 1)
            );
            if !agree {
                eprintln!("memcmp          n={n:<6} MISMATCH fl={fl_ord:?} glibc={gl_ord}");
                continue;
            }
            let iters = (1 << 22) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for round in 0..(ROUNDS + WARMUP) {
                let warm = round < WARMUP;
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memcmp(
                        black_box(&a), black_box(&b), black_box(n),
                    ));
                }
                if !warm { fls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memcmp(black_box(a.as_ptr()), black_box(b.as_ptr()), black_box(n)));
                }
                if !warm { gls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memcmp(black_box(a.as_ptr()), black_box(b.as_ptr()), black_box(n)));
                }
                if !warm { aas.push(t.elapsed().as_nanos() as f64 / iters as f64); }
            }
            report("memcmp", n, &fls, &gls, &aas);
        }
        eprintln!();

        // memmem: fl already measured far ahead on Ir; confirm on wall time
        for &n in &[256usize, 4096] {
            let mut hay = vec![b'a'; n];
            let needle = b"needle";
            hay[n - 6..].copy_from_slice(needle);
            let fl_hit = frankenlibc_core::string::mem::memmem(&hay, n, needle, needle.len());
            let gl_hit = gl_memmem(hay.as_ptr(), n, needle.as_ptr(), needle.len());
            let gl_idx = if gl_hit.is_null() {
                None
            } else {
                Some(gl_hit as usize - hay.as_ptr() as usize)
            };
            if fl_hit != gl_idx {
                eprintln!("memmem          n={n:<6} MISMATCH fl={fl_hit:?} glibc={gl_idx:?}");
                continue;
            }
            let iters = (1 << 20) / n.max(8);
            let (mut fls, mut gls, mut aas) = (vec![], vec![], vec![]);
            for round in 0..(ROUNDS + WARMUP) {
                let warm = round < WARMUP;
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(frankenlibc_core::string::mem::memmem(
                        black_box(&hay), black_box(n), black_box(needle), black_box(needle.len()),
                    ));
                }
                if !warm { fls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memmem(
                        black_box(hay.as_ptr()), black_box(n),
                        black_box(needle.as_ptr()), black_box(needle.len()),
                    ));
                }
                if !warm { gls.push(t.elapsed().as_nanos() as f64 / iters as f64); }
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(gl_memmem(
                        black_box(hay.as_ptr()), black_box(n),
                        black_box(needle.as_ptr()), black_box(needle.len()),
                    ));
                }
                if !warm { aas.push(t.elapsed().as_nanos() as f64 / iters as f64); }
            }
            report("memmem", n, &fls, &gls, &aas);
        }
    }
}
