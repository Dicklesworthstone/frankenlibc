//! Same-worker interleaved profile for the read-only `textdomain(NULL)` query.
//!
//! The deployed FrankenLibC symbol and host glibc are timed together. Two
//! source-identical FrankenLibC arms form the mandatory NULL control.

use std::ffi::c_char;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::locale_abi;
use sha2::{Digest, Sha256};

const SAMPLES: usize = 45;
const WARMUP: usize = 4;
const REPS: usize = 2_000_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;

type TextdomainFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

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

fn median(xs: &[f64]) -> f64 {
    let mut values = xs.to_vec();
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let avg = mean(xs);
    let variance = xs
        .iter()
        .map(|value| (value - avg) * (value - avg))
        .sum::<f64>()
        / xs.len() as f64;
    100.0 * variance.sqrt() / avg
}

fn median_absolute_deviation(xs: &[f64], center: f64) -> f64 {
    median(
        &xs.iter()
            .map(|value| (value - center).abs())
            .collect::<Vec<_>>(),
    )
}

fn bootstrap_median_ci95(xs: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ xs.len() as u64;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; xs.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = xs[(state as usize) % xs.len()];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

#[inline(never)]
fn run_frankenlibc() -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            locale_abi::textdomain(black_box(std::ptr::null()))
        }) as usize);
    }
    black_box(total)
}

#[inline(never)]
fn run_host(host: TextdomainFn) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total =
            total.wrapping_add(black_box(unsafe { host(black_box(std::ptr::null())) }) as usize);
    }
    black_box(total)
}

fn timed(f: impl FnOnce() -> usize) -> Duration {
    let start = Instant::now();
    black_box(f());
    start.elapsed()
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null());
    let host: TextdomainFn = unsafe {
        let symbol = libc::dlsym(handle, c"textdomain".as_ptr());
        assert!(!symbol.is_null());
        std::mem::transmute(symbol)
    };

    let fl_ptr = unsafe { locale_abi::textdomain(std::ptr::null()) };
    let host_ptr = unsafe { host(std::ptr::null()) };
    assert!(!fl_ptr.is_null());
    assert!(!host_ptr.is_null());
    assert_eq!(unsafe { std::ffi::CStr::from_ptr(fl_ptr) }, unsafe {
        std::ffi::CStr::from_ptr(host_ptr)
    });
    println!("verify: OK (FrankenLibC and host glibc query the same default domain)");

    let mut deployed = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (deployed_elapsed, host_elapsed, null_a_elapsed, null_b_elapsed) = if sample % 2 == 0 {
            let na = timed(run_frankenlibc);
            let host_t = timed(|| run_host(host));
            let deployed_t = timed(run_frankenlibc);
            let nb = timed(run_frankenlibc);
            (deployed_t, host_t, na, nb)
        } else {
            let nb = timed(run_frankenlibc);
            let deployed_t = timed(run_frankenlibc);
            let host_t = timed(|| run_host(host));
            let na = timed(run_frankenlibc);
            (deployed_t, host_t, na, nb)
        };

        if sample >= WARMUP {
            let scale = REPS as f64;
            deployed.push(deployed_elapsed.as_nanos() as f64 / scale);
            glibc.push(host_elapsed.as_nanos() as f64 / scale);
            null_a.push(null_a_elapsed.as_nanos() as f64 / scale);
            null_b.push(null_b_elapsed.as_nanos() as f64 / scale);
        }
    }

    let host_paired: Vec<f64> = deployed
        .iter()
        .zip(&glibc)
        .map(|(fl_ns, host_ns)| fl_ns / host_ns)
        .collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(&null_a)
        .map(|(b_ns, a_ns)| b_ns / a_ns)
        .collect();

    let effect_median = median(&host_paired);
    let null_median = median(&null_paired);
    let (effect_ci_low, effect_ci_high) = bootstrap_median_ci95(&host_paired);
    let (null_ci_low, null_ci_high) = bootstrap_median_ci95(&null_paired);
    let null_half_width = (1.0 - null_ci_low).abs().max((null_ci_high - 1.0).abs());
    let effect_clears_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let effect_ci_excludes_one = effect_ci_high < 1.0 || effect_ci_low > 1.0;
    let comparison = if effect_clears_null && effect_ci_excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if effect_clears_null && effect_ci_excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "TEXTDOMAIN_QUERY_BASELINE samples={} reps/arm={REPS} (interleaved, order alternated)",
        deployed.len()
    );
    println!(
        "  deployed FrankenLibC median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&deployed),
        mean(&deployed),
        cv_pct(&deployed)
    );
    println!(
        "  host glibc           median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&glibc),
        mean(&glibc),
        cv_pct(&glibc)
    );
    println!(
        "TEXTDOMAIN_BENCH_CONTRACT kind=null_fl_fl ratio_median={null_median:.6} \
         ratio_ci95=[{null_ci_low:.6},{null_ci_high:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6}",
        cv_pct(&null_paired),
        median_absolute_deviation(&null_paired, null_median),
    );
    println!(
        "TEXTDOMAIN_BENCH_CONTRACT kind=fl_glibc ratio_median={effect_median:.6} \
         ratio_ci95=[{effect_ci_low:.6},{effect_ci_high:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6} null_half_width={null_half_width:.6} \
         clears_2x_null={} comparison={comparison}",
        cv_pct(&host_paired),
        median_absolute_deviation(&host_paired, effect_median),
        effect_clears_null,
    );
}
