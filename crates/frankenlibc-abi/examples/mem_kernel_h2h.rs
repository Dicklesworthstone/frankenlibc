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
//! * The A/A null is the median of per-round glibc-vs-glibc ratios -- the same loop against
//!   itself, and the noise floor for the moment the run happened.
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

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
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
    let ratios: Vec<f64> = fls.iter().zip(&gls).map(|(f, g)| f / g).collect();
    let nulls: Vec<f64> = aas.iter().zip(&gls).map(|(a, g)| a / g).collect();
    let (r, null) = (median(ratios), median(nulls));
    if (ADMISSIBLE.0..=ADMISSIBLE.1).contains(&null) {
        eprintln!(
            "{op:<10} n={n:<6} fl={:8.2}ns glibc={:8.2}ns  fl/glibc={r:6.3}x  A/A_null={null:.3}",
            median(fls),
            median(gls),
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
