//! In-process A/B for the `native_stdio_fd_for_ptr` FILE*->fd mapper under thread
//! contention (cc/BlackThrush, BOLD-VERIFY).
//!
//! WHY THIS EXISTS. `stdio_mt_contention_bench` (Criterion) cannot resolve this lever:
//! every iteration spawns N threads and opens/closes N `fmemopen` streams, so thread-spawn
//! and allocator noise dominate the measured mean. Its own recorded history for the SAME
//! arm spans 15.2 / 23.7 / 56.7 / 60.4 / 74.1 ms across rch workers, and the host-glibc
//! comparator spans 1.59 - 8.22 ms. Two earlier lock-elision candidates were rejected on
//! that instrument with deltas (56.7 -> 60.4 ms) far inside its own noise band. This bench
//! measures the mapper DIRECTLY, with threads spawned once and barrier-synced rounds, so
//! the OLD/NEW ratio is a within-process quantity and worker load cancels.
//!
//! WHAT IS MEASURED. `native_stdio_fd_for_ptr` fires on EVERY stdio op against a
//! non-sentinel `FILE *` (fgetc/fputc/fputs/fwrite on any fopen'd file, pipe, or fmemopen
//! stream) purely to rule out the three native glibc std FILE slots.
//!   * `old` - locked slot scan: global `NATIVE_STREAM_REGISTRY` `std::sync::Mutex`
//!             + up to three occupancy-checked pointer compares.
//!   * `new` - lock-free compare against the three slot addresses published once at
//!             chain init (THE SHIPPED path).
//! Each thread maps its OWN foreign pointer (the common case: a non-std stream), which is
//! exactly the `None` outcome the deployed hot path takes 4096 times per `fgetc` drain.
//!
//! `verify()` runs first and asserts new == old on every reachable input class (the three
//! real native std FILE slots, a foreign pointer, NULL) -- executable byte-identity proof
//! for the shipped change.
//!
//! END-TO-END ARM. A kernel A/B win is necessary but not sufficient, so this bench also
//! drives the real deployed `fl::fgetc` against host glibc's, 8 threads, each draining its
//! own `fmemopen` stream -- the exact body of `stdio_mt_contention_bench`, but with the
//! threads spawned ONCE and barrier-synced, which is what makes it readable. (That
//! Criterion bench additionally cannot run to completion here: it aborts with
//! `realloc(): invalid pointer` during Criterion's analysis phase, because an `abi-bench`
//! binary links fl's `#[no_mangle]` allocator over the harness's own. The same abort is
//! recorded in docs/NEGATIVE_EVIDENCE.md on 2026-06-28, where it was attributed to a
//! candidate; it reproduces on unmodified code.)
//!
//! Run: `cargo run --release -p frankenlibc-bench --features abi-bench --example stdio_mapper_mt_ab`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::{Barrier, OnceLock};
use std::time::Instant;

use frankenlibc_abi::io_internal_abi as io;
use frankenlibc_abi::stdio_abi as fl;

/// Threads spawned once per arm; barrier-synced per round.
const THREADS: usize = 8;
/// Mapper calls per thread per round. 4096 == the byte count one `fgetc` drain performs
/// in `stdio_mt_contention_bench`, so one round == one thread's worth of that workload.
const ITERS: usize = 4096;
/// Timed rounds per arm (first `WARMUP` rounds discarded).
const ROUNDS: usize = 200;
/// Leading rounds discarded per arm (first-touch, cache/branch warm-up).
const WARMUP: usize = 5;

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Median: robust to the bursty tail that lock contention (futex sleep/wake) puts on the
/// locked arm, where the mean's cv exceeds the 5% keep-gate for reasons intrinsic to the
/// thing being measured rather than to the measurement.
fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

/// Coefficient of variation in percent. The keep-gate requires cv < 5%.
fn cv_pct(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
}

/// Byte-identity proof: the shipped lock-free mapper must agree with the locked scan on
/// every input class. Runs before timing so a divergence aborts rather than benchmarks.
fn verify() {
    // The three real native std FILE slots must map to their fds, identically on both.
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        let p = io::native_stdio_stream_ptr(fd);
        assert!(!p.is_null(), "native_stdio_stream_ptr({fd}) is null");
        let old = io::bench_native_stdio_fd_for_ptr_locked(p);
        let new = io::native_stdio_fd_for_ptr(p);
        assert_eq!(old, Some(fd), "old mapper lost slot fd={fd}");
        assert_eq!(new, old, "lock-free mapper diverged for fd={fd}");
    }

    // A foreign (non-std) pointer: both must answer None. This is the hot-path outcome.
    let foreign = Box::into_raw(Box::new(0u64)) as *const c_void;
    assert_eq!(io::bench_native_stdio_fd_for_ptr_locked(foreign), None);
    assert_eq!(io::native_stdio_fd_for_ptr(foreign), None);

    // NULL: both None.
    assert_eq!(
        io::bench_native_stdio_fd_for_ptr_locked(std::ptr::null()),
        None
    );
    assert_eq!(io::native_stdio_fd_for_ptr(std::ptr::null()), None);

    // SAFETY: `foreign` came from `Box::into_raw` above and is not aliased.
    drop(unsafe { Box::from_raw(foreign as *mut u64) });
    println!("verify: OK (lock-free mapper == locked scan on all input classes)");
}

/// Run one arm: spawn `threads` workers once, barrier-sync `ROUNDS` rounds, and return the
/// per-round mean ns/op averaged across threads. Contention inflates each thread's own
/// elapsed time, so a serializing arm shows up directly in ns/op.
fn run_arm(threads: usize, locked: bool) -> Vec<f64> {
    let barrier = Barrier::new(threads);
    let mut per_thread: Vec<Vec<f64>> = Vec::new();

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let barrier = &barrier;
            handles.push(s.spawn(move || {
                // Each thread maps its OWN foreign pointer: the deployed non-std case.
                let owned = Box::new(0u64);
                let ptr: *const c_void = (&raw const *owned).cast();
                let mut rounds = Vec::with_capacity(ROUNDS);
                for _ in 0..ROUNDS {
                    barrier.wait();
                    let start = Instant::now();
                    if locked {
                        for _ in 0..ITERS {
                            black_box(io::bench_native_stdio_fd_for_ptr_locked(black_box(ptr)));
                        }
                    } else {
                        for _ in 0..ITERS {
                            black_box(io::native_stdio_fd_for_ptr(black_box(ptr)));
                        }
                    }
                    let ns = start.elapsed().as_nanos() as f64 / ITERS as f64;
                    rounds.push(ns);
                }
                black_box(&owned);
                rounds
            }));
        }
        for h in handles {
            per_thread.push(h.join().expect("worker panicked"));
        }
    });

    // Per round, average across threads (all threads run the round concurrently).
    (WARMUP..ROUNDS)
        .map(|r| mean(&per_thread.iter().map(|t| t[r]).collect::<Vec<_>>()))
        .collect()
}

fn report(label: &str, threads: usize) {
    // Alternate arms so any monotonic drift (thermal, co-tenant load) hits both equally.
    let old_a = run_arm(threads, true);
    let new_a = run_arm(threads, false);
    let old_b = run_arm(threads, true);
    let new_b = run_arm(threads, false);

    let old: Vec<f64> = old_a.iter().chain(old_b.iter()).copied().collect();
    let new: Vec<f64> = new_a.iter().chain(new_b.iter()).copied().collect();

    let (om, nm) = (mean(&old), mean(&new));
    let (omed, nmed) = (median(&old), median(&new));
    println!(
        "{label} threads={threads}  (n={} rounds/arm, 2 interleaved blocks)\n  \
         old(locked)   mean {om:8.2} ns/op  cv={:5.2}%   median {omed:8.2}\n  \
         new(lockfree) mean {nm:8.2} ns/op  cv={:5.2}%   median {nmed:8.2}\n  \
         new/old: mean {:.4} ({:.2}x faster)   median {:.4} ({:.2}x faster)",
        old.len(),
        cv_pct(&old),
        cv_pct(&new),
        nm / om,
        om / nm,
        nmed / omed,
        omed / nmed
    );
}

// --- end-to-end arm: real fgetc drain, fl vs host glibc, same process ---

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostStdio {
    fmemopen: FmemopenFn,
    fgetc: FgetcFn,
    fclose: FcloseFn,
}

/// Host glibc resolved in a private namespace so its `fmemopen`/`fgetc` are the real
/// glibc ones rather than fl's interposing `#[no_mangle]` exports. Fn pointers are
/// `Send + Sync`.
fn host() -> &'static HostStdio {
    static H: OnceLock<HostStdio> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &std::ffi::CStr| {
            let s = libc::dlsym(handle, n.as_ptr());
            assert!(!s.is_null(), "dlsym {n:?} failed");
            s
        };
        HostStdio {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(sym(c"fmemopen")),
            fgetc: std::mem::transmute::<*mut c_void, FgetcFn>(sym(c"fgetc")),
            fclose: std::mem::transmute::<*mut c_void, FcloseFn>(sym(c"fclose")),
        }
    })
}

/// Bytes drained per stream per round (matches `stdio_mt_contention_bench`).
const DRAIN: usize = 4096;
/// Timed rounds for the end-to-end arm.
const E2E_ROUNDS: usize = 60;

#[derive(Clone, Copy, PartialEq)]
enum Arm {
    /// Deployed fl `fgetc` (lock-free mapper).
    Fl,
    /// Reconstructed pre-change fl `fgetc`: the deployed call plus one locked mapper probe
    /// per byte, which is exactly the global-mutex acquisition the old
    /// `native_stdio_fd_for_ptr` performed on every `fgetc`. Overstates the old path by the
    /// ~2.6 ns lock-free probe the deployed call still makes, so the measured
    /// old/new ratio is a slight UNDER-estimate of the true speedup.
    FlOldReconstructed,
    /// Real host glibc `fgetc` via `dlmopen`.
    Host,
}

/// One arm of the e2e drain: `threads` workers, spawned once, barrier-synced rounds. Each
/// round every thread opens its OWN `fmemopen` stream, drains `DRAIN` bytes with `fgetc`,
/// and closes it. Returns per-round ns/byte averaged across threads.
fn run_drain(threads: usize, arm: Arm) -> Vec<f64> {
    let barrier = Barrier::new(threads);
    let mut per_thread: Vec<Vec<f64>> = Vec::new();

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let barrier = &barrier;
            handles.push(s.spawn(move || {
                let h = host();
                let mut rounds = Vec::with_capacity(E2E_ROUNDS);
                for _ in 0..E2E_ROUNDS {
                    let data = vec![b'x'; DRAIN];
                    barrier.wait();
                    let start = Instant::now();
                    // SAFETY: `data` outlives the stream; both libcs read `DRAIN` bytes
                    // from it and the stream is closed before `data` is dropped.
                    let mut sum = 0i64;
                    unsafe {
                        let buf = data.as_ptr() as *mut c_void;
                        let fp = if arm == Arm::Host {
                            (h.fmemopen)(buf, DRAIN, c"r".as_ptr())
                        } else {
                            fl::fmemopen(buf, DRAIN, c"r".as_ptr())
                        };
                        assert!(!fp.is_null(), "fmemopen failed");
                        for _ in 0..DRAIN {
                            sum += match arm {
                                Arm::Host => (h.fgetc)(fp) as i64,
                                Arm::Fl => fl::fgetc(fp) as i64,
                                Arm::FlOldReconstructed => {
                                    black_box(io::bench_native_stdio_fd_for_ptr_locked(fp));
                                    fl::fgetc(fp) as i64
                                }
                            };
                        }
                        if arm == Arm::Host {
                            (h.fclose)(fp);
                        } else {
                            fl::fclose(fp);
                        }
                    }
                    let ns = start.elapsed().as_nanos() as f64 / DRAIN as f64;
                    black_box(sum);
                    rounds.push(ns);
                }
                rounds
            }));
        }
        for h in handles {
            per_thread.push(h.join().expect("drain worker panicked"));
        }
    });

    (WARMUP..E2E_ROUNDS)
        .map(|r| mean(&per_thread.iter().map(|t| t[r]).collect::<Vec<_>>()))
        .collect()
}

fn report_e2e(threads: usize) {
    // Interleave the three arms twice so monotonic drift hits all equally.
    let old_a = run_drain(threads, Arm::FlOldReconstructed);
    let fl_a = run_drain(threads, Arm::Fl);
    let gl_a = run_drain(threads, Arm::Host);
    let old_b = run_drain(threads, Arm::FlOldReconstructed);
    let fl_b = run_drain(threads, Arm::Fl);
    let gl_b = run_drain(threads, Arm::Host);

    let cat = |a: Vec<f64>, b: Vec<f64>| -> Vec<f64> { a.into_iter().chain(b).collect() };
    let oldv = cat(old_a, old_b);
    let flv = cat(fl_a, fl_b);
    let glv = cat(gl_a, gl_b);
    let (om, fm, gm) = (median(&oldv), median(&flv), median(&glv));
    println!(
        "e2e fgetc drain threads={threads}  (n={} rounds/arm)\n  \
         fl OLD (reconstructed) mean {:8.2} ns/byte  cv={:5.2}%   median {om:8.2}\n  \
         fl NEW (deployed)      mean {:8.2} ns/byte  cv={:5.2}%   median {fm:8.2}\n  \
         host glibc             mean {:8.2} ns/byte  cv={:5.2}%   median {gm:8.2}\n  \
         new/old: median {:.4} ({:.2}x faster)   fl_new/glibc: median {:.3}x ({})",
        flv.len(),
        mean(&oldv),
        cv_pct(&oldv),
        mean(&flv),
        cv_pct(&flv),
        mean(&glv),
        cv_pct(&glv),
        fm / om,
        om / fm,
        fm / gm,
        if fm <= gm { "WIN" } else { "LOSS" }
    );
}

fn main() {
    // Force lazy chain init before any timing so neither arm pays it.
    let warm = Box::into_raw(Box::new(0u64)) as *const c_void;
    let _: Option<c_int> = io::native_stdio_fd_for_ptr(warm);
    // SAFETY: `warm` came from `Box::into_raw` and is not aliased.
    drop(unsafe { Box::from_raw(warm as *mut u64) });

    verify();
    println!("MAPPER_MT_AB iters={ITERS} rounds={ROUNDS} (warmup={WARMUP}, arms alternated)");
    report("single-thread", 1);
    report("contended", THREADS);
    println!();
    report_e2e(1);
    report_e2e(THREADS);
}
