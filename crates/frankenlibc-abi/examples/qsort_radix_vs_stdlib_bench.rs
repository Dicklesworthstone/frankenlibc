// Does the shipped ASCENDING integer radix lane (widths 2/4/8, num>threshold)
// beat the stdlib fixed-width fallback it preempts? The radix lane's shipped wins
// were measured vs glibc / the in-house pdqsort_recurse, NOT vs `std_sort_unstable_
// fixed_width` (a `[u8;N]` stdlib pdqsort, added later, which runs when the radix
// lane is skipped). Isolate the two on the SAME data with the SAME extern-"C"
// comparator (both pay realistic FFI: radix ~n verify calls, stdlib ~n log n).
//
//   radix  = __bench_integer_radix_attempt (the lane alone, must commit)
//   stdlib = as_chunks_mut::<N>().sort_unstable_by(extern-C cmp)  (the fallback)
//   glibc  = libc::qsort
// radix/stdlib > 1 ⇒ radix slower than the fallback ⇒ narrow/remove it.
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

fn lcg(s: &mut u64) -> u64 {
    *s = s
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *s >> 1
}

extern "C" fn gl_cmp_i16(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i16)).cmp(&*(b as *const i16)) as i32 }
}
extern "C" fn gl_cmp_i32(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i32)).cmp(&*(b as *const i32)) as i32 }
}
extern "C" fn gl_cmp_i64(a: *const c_void, b: *const c_void) -> i32 {
    unsafe { (*(a as *const i64)).cmp(&*(b as *const i64)) as i32 }
}

fn make(n: usize, width: usize, dist: &str) -> Vec<u8> {
    let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ (n as u64) ^ ((width as u64) << 40);
    let mut out = Vec::with_capacity(n * width);
    for i in 0..n {
        let v: i64 = match dist {
            "rand" => lcg(&mut s) as i64,
            "sorted" => i as i64,
            "reverse" => (n - i) as i64,
            "dups" => (lcg(&mut s) % 16) as i64,
            // Realistic partially-ordered data: ascending with ~1% of positions
            // perturbed by a bounded jitter (append log, timestamps, mostly-sorted
            // ids). pdqsort exploits the runs; LSD radix cannot.
            "nearly" => {
                if lcg(&mut s) % 100 == 0 {
                    i as i64 + (lcg(&mut s) % 64) as i64 - 32
                } else {
                    i as i64
                }
            }
            _ => unreachable!(),
        };
        out.extend_from_slice(&v.to_ne_bytes()[..width]);
    }
    out
}

// Run `f` `k` times and return the fastest per-op ns (min = the least
// interfered-with run — the closest estimate of true compute cost on a shared box).
fn best_of<F: FnMut()>(k: usize, iters: usize, reset: f64, mut f: F) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..k {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let ns = t.elapsed().as_nanos() as f64 / iters as f64 - reset;
        if ns < best {
            best = ns;
        }
    }
    best.max(0.0)
}

fn stdlib_sort(buf: &mut [u8], width: usize, cmp: fn(&[u8], &[u8]) -> i32) {
    macro_rules! s {
        ($n:literal) => {{
            let (c, _) = buf.as_chunks_mut::<$n>();
            c.sort_unstable_by(|a, b| cmp(&a[..], &b[..]).cmp(&0));
        }};
    }
    match width {
        2 => s!(2),
        4 => s!(4),
        8 => s!(8),
        _ => unreachable!(),
    }
}

fn bench(
    n: usize,
    width: usize,
    dist: &str,
    fl_cmp: fn(&[u8], &[u8]) -> i32,
    gl_cmp: extern "C" fn(*const c_void, *const c_void) -> i32,
) {
    let pristine = make(n, width, dist);
    {
        let mut r = pristine.clone();
        let committed =
            frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(&mut r, width, &fl_cmp);
        assert!(committed, "radix did not commit w{width} {dist} n={n}");
        let mut sb = pristine.clone();
        stdlib_sort(&mut sb, width, fl_cmp);
        assert_eq!(r, sb, "radix vs stdlib mismatch w{width} {dist} n={n}");
        // The DEPLOYED full-qsort path (incl. the already-ordered commit-lane, which
        // commits sorted input as-is and reverses descending input) must match the
        // reference sort byte-for-byte — the load-bearing check for the commit-lane.
        let mut qf = pristine.clone();
        frankenlibc_core::stdlib::qsort(&mut qf, width, fl_cmp);
        assert_eq!(qf, sb, "qsort(full) vs reference mismatch w{width} {dist} n={n}");
    }

    let iters = (120_000_000usize / (n * width)).max(60);
    const K: usize = 6; // min-of-K per arm to reject transient interference
    let mut buf = pristine.clone();

    // Reset (memcpy) baseline, also min-of-K, subtracted from every arm.
    let reset = {
        let mut best = f64::INFINITY;
        for _ in 0..K {
            let t = Instant::now();
            for _ in 0..iters {
                buf.copy_from_slice(&pristine);
                black_box(&buf);
            }
            let ns = t.elapsed().as_nanos() as f64 / iters as f64;
            if ns < best {
                best = ns;
            }
        }
        best
    };

    let radix = best_of(K, iters, reset, || {
        buf.copy_from_slice(&pristine);
        black_box(frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(
            black_box(&mut buf),
            width,
            &fl_cmp,
        ));
    });
    let stdlib = best_of(K, iters, reset, || {
        buf.copy_from_slice(&pristine);
        stdlib_sort(black_box(&mut buf), width, fl_cmp);
        black_box(&buf);
    });
    let gl = best_of(K, iters, reset, || {
        buf.copy_from_slice(&pristine);
        unsafe { libc::qsort(black_box(buf.as_mut_ptr()) as *mut c_void, n, width, Some(gl_cmp)) };
        black_box(&buf);
    });
    // Full deployed qsort path (INCLUDES the new already-ordered guard): the metric
    // that actually ships. On sorted input it should now route to pdqsort (≈ stdlib)
    // instead of radix; on random it should still ≈ radix.
    let qfull = best_of(K, iters, reset, || {
        buf.copy_from_slice(&pristine);
        frankenlibc_core::stdlib::qsort(black_box(&mut buf), width, fl_cmp);
        black_box(&buf);
    });

    let verdict = if radix / stdlib > 1.10 {
        "RADIX-LOSES"
    } else if radix / stdlib < 0.90 {
        "radix-wins"
    } else {
        "~parity"
    };
    println!(
        "RADIXvsSTDLIB w{width} {dist:>7} n={n:>6} radix={radix:>9.0} stdlib={stdlib:>9.0} qfull={qfull:>9.0} glibc={gl:>9.0}  \
         radix/stdlib={:.2}x  qfull/stdlib={:.2}x  {verdict}",
        radix / stdlib,
        qfull / stdlib,
    );
}

// The deployed `compare` closure is exactly this: hand the two element pointers to
// the caller's extern-"C" comparator. NO Rust-side from_ne_bytes/try_into (that
// bounds-check + panic path inflates the arm making more comparisons and does not
// exist in the real lib). Both radix-verify and stdlib pay this identical cost.
fn cmp16(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i16(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}
fn cmp32(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i32(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}
fn cmp64(a: &[u8], b: &[u8]) -> i32 {
    gl_cmp_i64(a.as_ptr() as *const c_void, b.as_ptr() as *const c_void)
}

fn main() {
    let widths: [(usize, fn(&[u8], &[u8]) -> i32, extern "C" fn(*const c_void, *const c_void) -> i32); 3] =
        [(2, cmp16, gl_cmp_i16), (4, cmp32, gl_cmp_i32), (8, cmp64, gl_cmp_i64)];
    for (w, fl, gl) in widths {
        for &dist in &["rand", "dups", "nearly", "sorted"] {
            for &n in &[16384usize, 262144] {
                bench(n, w, dist, fl, gl);
            }
        }
    }
}
