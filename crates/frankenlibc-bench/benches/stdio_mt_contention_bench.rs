//! Multi-threaded stdio contention benchmark: frankenlibc vs host glibc
//! (cc/BlackThrush, BOLD-VERIFY). The single-threaded benches cannot show the two
//! things this campaign's stdio work is really about:
//!   1. The bd-hqo6b6 gap: fl serializes ALL stdio on the GLOBAL `registry()` Mutex,
//!      so concurrent ops on DIFFERENT streams contend; glibc uses per-FILE locking
//!      and scales. This quantifies the architectural target.
//!   2. The MT value of the shipped lock-removal guards (is_cookie_stream,
//!      sync_memstream/sync_fmemopen, observe/decide membrane fast-paths): each
//!      removes a GLOBAL serialization point, so under contention fewer global-lock
//!      round-trips per op should help even where single-thread microbenches showed
//!      ~0-gain.
//!
//! Design: N threads, each opens its OWN `fmemopen` read stream IN-THREAD (no
//! cross-thread pointer passing → no Send/Sync gymnastics) and drains it with
//! `fgetc`. `thread::scope` joins all before the timed iteration returns. glibc is
//! resolved via `dlmopen(LM_ID_NEWLM)`; each thread uses glibc's own `fmemopen`.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench stdio_mt_contention_bench --features abi-bench`
//!
//! FIRST RUN (cc, 2026-06-27, rch remote ovh-a, sample-size 20 / measure 2s, on
//! current main = the LANDED parking_lot registry swap a564ca8ae): 8-thread
//! `stdio_mt_contention_8t` fl 56.7 ms vs host glibc 6.61 ms => 8.6x LOSS.
//! This quantifies the bd-hqo6b6 architectural target: even with the parking_lot
//! lock swap deployed, fl still serializes ALL stdio on the single global
//! `registry()` Mutex, so 8 threads draining 8 *independent* `fmemopen` streams
//! contend on one lock while glibc's per-FILE locking scales. The lock-IMPL swap
//! (std::sync::Mutex -> parking_lot) cannot close this gap because the
//! bottleneck is the single global serialization POINT, not per-acquire cost;
//! the real fix is per-FILE locking (Arc<Mutex<StdioStream>> resolved outside the
//! registry lock). Recorded so the contention gap is never re-measured blind.

use std::ffi::{c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use frankenlibc_abi::stdio_abi as fl;
use sha2::{Digest, Sha256};

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FreadFn = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostStdio {
    fmemopen: FmemopenFn,
    fgetc: FgetcFn,
    fread: FreadFn,
    fclose: FcloseFn,
}

// fn pointers are Send + Sync, so the resolved table is safe to share across threads.
fn host() -> &'static HostStdio {
    static H: OnceLock<HostStdio> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let s = libc::dlsym(handle, n.as_ptr().cast());
            assert!(!s.is_null(), "dlsym failed");
            s
        };
        HostStdio {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(sym(b"fmemopen\0")),
            fgetc: std::mem::transmute::<*mut c_void, FgetcFn>(sym(b"fgetc\0")),
            fread: std::mem::transmute::<*mut c_void, FreadFn>(sym(b"fread\0")),
            fclose: std::mem::transmute::<*mut c_void, FcloseFn>(sym(b"fclose\0")),
        }
    })
}

const N: usize = 4096; // bytes drained per stream per thread
const CHUNK: usize = 64; // fread element size ⇒ N/CHUNK = 64 fread calls per stream
const PAIRED_ROUNDS: usize = 21;
const PAIRED_ITERS: u64 = 1;
const BOOTSTRAP_RESAMPLES: usize = 4096;

/// SHA-256 of this executable, reported from inside the measured process.
fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".into();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".into();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest_hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest_hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    format!("{} ({} bytes) {}", digest_hex, bytes.len(), path.display())
}

#[derive(Debug)]
struct PairedStats {
    p50_a_ns: f64,
    p50_b_ns: f64,
    ratio_p50: f64,
    ratio_cv_pct: f64,
    ratio_mad: f64,
    ratio_ci95_low: f64,
    ratio_ci95_high: f64,
    checksum: u64,
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted[sorted.len() / 2]
}

fn coefficient_of_variation_pct(values: &[f64]) -> f64 {
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    if values.len() < 2 || mean == 0.0 {
        return 0.0;
    }
    let variance = values
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / (values.len() - 1) as f64;
    100.0 * variance.sqrt() / mean
}

fn median_absolute_deviation(values: &[f64], center: f64) -> f64 {
    let deviations = values
        .iter()
        .map(|value| (value - center).abs())
        .collect::<Vec<_>>();
    median(&deviations)
}

fn bootstrap_median_ci95(values: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ values.len() as u64;
    let mut resampled_medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; values.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = values[(state as usize) % values.len()];
        }
        resampled_medians.push(median(&resample));
    }
    resampled_medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (resampled_medians[low], resampled_medians[high])
}

fn time_arm(iters: u64, arm: &mut impl FnMut() -> u64) -> (f64, u64) {
    let start = Instant::now();
    let mut checksum = 0u64;
    for iteration in 0..iters {
        checksum =
            checksum.rotate_left(11) ^ black_box(arm()) ^ iteration.wrapping_mul(0x9e37_79b9);
    }
    (
        start.elapsed().as_nanos() as f64 / iters.max(1) as f64,
        black_box(checksum),
    )
}

/// Time both arms back-to-back in every round, alternating their order.
///
/// The decision statistic is the median of the per-round A/B ratios. CV is
/// descriptive provenance only; the bootstrap interval on the median is the
/// acceptance instrument.
fn paired(
    rounds: usize,
    iters: u64,
    mut arm_a: impl FnMut() -> u64,
    mut arm_b: impl FnMut() -> u64,
) -> PairedStats {
    let mut samples_a = Vec::with_capacity(rounds);
    let mut samples_b = Vec::with_capacity(rounds);
    let mut ratios = Vec::with_capacity(rounds);
    let mut checksum = 0u64;

    for round in 0..rounds {
        let ((elapsed_a, checksum_a), (elapsed_b, checksum_b)) = if round.is_multiple_of(2) {
            (time_arm(iters, &mut arm_a), time_arm(iters, &mut arm_b))
        } else {
            let b = time_arm(iters, &mut arm_b);
            let a = time_arm(iters, &mut arm_a);
            (a, b)
        };
        samples_a.push(elapsed_a);
        samples_b.push(elapsed_b);
        ratios.push(elapsed_a / elapsed_b.max(f64::MIN_POSITIVE));
        checksum = checksum.rotate_left(7) ^ checksum_a ^ checksum_b.rotate_left(1);
    }

    let ratio_p50 = median(&ratios);
    let (ratio_ci95_low, ratio_ci95_high) = bootstrap_median_ci95(&ratios);
    PairedStats {
        p50_a_ns: median(&samples_a),
        p50_b_ns: median(&samples_b),
        ratio_p50,
        ratio_cv_pct: coefficient_of_variation_pct(&ratios),
        ratio_mad: median_absolute_deviation(&ratios, ratio_p50),
        ratio_ci95_low,
        ratio_ci95_high,
        checksum: black_box(checksum),
    }
}

fn claim_clears_null_with_2x_margin(null: &PairedStats, claim_ratio: f64) -> bool {
    let null_half_width = (1.0 - null.ratio_ci95_low)
        .abs()
        .max((null.ratio_ci95_high - 1.0).abs());
    (claim_ratio - 1.0).abs() > 2.0 * null_half_width
}

fn report_pair(kind: &str, workload: &str, threads: usize, stats: &PairedStats) {
    println!(
        "BENCH_CONTRACT kind={kind} workload={workload} threads={threads} rounds={PAIRED_ROUNDS} \
         iters={PAIRED_ITERS} p50_a_ns={:.1} p50_b_ns={:.1} ratio_median={:.6} \
         ratio_ci95=[{:.6},{:.6}] ratio_cv_pct={:.3} ratio_mad={:.6} checksum={}",
        stats.p50_a_ns,
        stats.p50_b_ns,
        stats.ratio_p50,
        stats.ratio_ci95_low,
        stats.ratio_ci95_high,
        stats.ratio_cv_pct,
        stats.ratio_mad,
        stats.checksum,
    );
}

/// One workload iteration: `nthreads` threads, each opens its OWN fmemopen stream and
/// drains N bytes via fgetc, then closes. Concurrent ops on DIFFERENT streams contend on
/// fl's single global registry lock; glibc's per-FILE locking scales.
fn fl_workload(nthreads: usize) -> u64 {
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(nthreads);
        for _ in 0..nthreads {
            handles.push(s.spawn(|| {
                let data = vec![b'x'; N];
                let fp = unsafe { fl::fmemopen(data.as_ptr() as *mut c_void, N, c"r".as_ptr()) };
                let mut sum = 0i64;
                for _ in 0..N {
                    sum += unsafe { fl::fgetc(fp) } as i64;
                }
                unsafe { fl::fclose(fp) };
                black_box(sum);
                black_box(data.as_ptr());
                sum as u64
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("FrankenLibC workload thread failed"))
            .fold(0u64, u64::wrapping_add)
    })
}

fn glibc_workload(nthreads: usize, h: &'static HostStdio) -> u64 {
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(nthreads);
        for _ in 0..nthreads {
            handles.push(s.spawn(|| {
                let data = vec![b'x'; N];
                let fp = unsafe { (h.fmemopen)(data.as_ptr() as *mut c_void, N, c"r".as_ptr()) };
                let mut sum = 0i64;
                for _ in 0..N {
                    sum += unsafe { (h.fgetc)(fp) } as i64;
                }
                unsafe { (h.fclose)(fp) };
                black_box(sum);
                black_box(data.as_ptr());
                sum as u64
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("host glibc workload thread failed"))
            .fold(0u64, u64::wrapping_add)
    })
}

/// `fread` variant: each thread opens its OWN fmemopen read stream and drains N bytes via
/// `N/CHUNK` calls to `fread(buf, 1, CHUNK, fp)`. Exposes the fmemopen `fread` per-op floor
/// (`canonical_stream_id` lock + `decide` + map lock per call) the pointer-keyed cursor cache
/// removes.
fn fl_fread_workload(nthreads: usize) -> u64 {
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(nthreads);
        for _ in 0..nthreads {
            handles.push(s.spawn(|| {
                let data = vec![b'x'; N];
                let fp = unsafe { fl::fmemopen(data.as_ptr() as *mut c_void, N, c"r".as_ptr()) };
                let mut buf = [0u8; CHUNK];
                let mut got = 0usize;
                for _ in 0..(N / CHUNK) {
                    got += unsafe { fl::fread(buf.as_mut_ptr() as *mut c_void, 1, CHUNK, fp) };
                }
                unsafe { fl::fclose(fp) };
                black_box(got);
                black_box(buf);
                black_box(data.as_ptr());
                got as u64
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("FrankenLibC fread workload thread failed")
            })
            .fold(0u64, u64::wrapping_add)
    })
}

fn glibc_fread_workload(nthreads: usize, h: &'static HostStdio) -> u64 {
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(nthreads);
        for _ in 0..nthreads {
            handles.push(s.spawn(|| {
                let data = vec![b'x'; N];
                let fp = unsafe { (h.fmemopen)(data.as_ptr() as *mut c_void, N, c"r".as_ptr()) };
                let mut buf = [0u8; CHUNK];
                let mut got = 0usize;
                for _ in 0..(N / CHUNK) {
                    got += unsafe { (h.fread)(buf.as_mut_ptr() as *mut c_void, 1, CHUNK, fp) };
                }
                unsafe { (h.fclose)(fp) };
                black_box(got);
                black_box(buf);
                black_box(data.as_ptr());
                got as u64
            }));
        }
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("host glibc fread workload thread failed")
            })
            .fold(0u64, u64::wrapping_add)
    })
}

fn main() {
    println!("bench_elf_sha256={}", self_identity());
    let maxt: usize = std::thread::available_parallelism()
        .map(|n| n.get().min(8))
        .unwrap_or(4);
    let h = host();
    // Measure at 1 thread (isolates per-op overhead, NO lock contention) and at max
    // threads (adds contention). The delta between the two ratios is the registry-lock
    // contention the sharding swing would target.
    for &nthreads in &[1usize, maxt] {
        for _ in 0..8 {
            black_box(fl_workload(nthreads));
            black_box(glibc_workload(nthreads, h));
        }
        let null = paired(
            PAIRED_ROUNDS,
            PAIRED_ITERS,
            || fl_workload(nthreads),
            || fl_workload(nthreads),
        );
        let real = paired(
            PAIRED_ROUNDS,
            PAIRED_ITERS,
            || fl_workload(nthreads),
            || glibc_workload(nthreads, h),
        );
        report_pair("null", "fgetc", nthreads, &null);
        report_pair("real", "fgetc", nthreads, &real);
        println!(
            "STDIO_MT_GATE workload=fgetc threads={nthreads} ratio_fl_over_glibc={:.6} \
             decidable_2x_margin={}",
            real.ratio_p50,
            claim_clears_null_with_2x_margin(&null, real.ratio_p50),
        );
    }
    // fread arm: same fmemopen streams, drained via N/CHUNK fread calls instead of N fgetc.
    for &nthreads in &[1usize, maxt] {
        for _ in 0..8 {
            black_box(fl_fread_workload(nthreads));
            black_box(glibc_fread_workload(nthreads, h));
        }
        let null = paired(
            PAIRED_ROUNDS,
            PAIRED_ITERS,
            || fl_fread_workload(nthreads),
            || fl_fread_workload(nthreads),
        );
        let real = paired(
            PAIRED_ROUNDS,
            PAIRED_ITERS,
            || fl_fread_workload(nthreads),
            || glibc_fread_workload(nthreads, h),
        );
        report_pair("null", "fread", nthreads, &null);
        report_pair("real", "fread", nthreads, &real);
        println!(
            "STDIO_MT_GATE workload=fread threads={nthreads} ratio_fl_over_glibc={:.6} \
             decidable_2x_margin={}",
            real.ratio_p50,
            claim_clears_null_with_2x_margin(&null, real.ratio_p50),
        );
    }
}
