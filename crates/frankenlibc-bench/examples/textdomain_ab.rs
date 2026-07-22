//! Same-worker interleaved profile for the read-only `textdomain(NULL)` query.
//!
//! The deployed FrankenLibC symbol and host glibc are timed together. Two
//! source-identical FrankenLibC arms form the mandatory NULL control.

use std::ffi::c_char;
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::locale_abi;

const SAMPLES: usize = 80;
const WARMUP: usize = 16;
const REPS: usize = 25_000_000;

type TextdomainFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

fn median(xs: &[f64]) -> f64 {
    let mut values = xs.to_vec();
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
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
        "  NULL deployed/deployed: median {:.4}  cv={:.2}%  arms cv={:.2}%/{:.2}%",
        median(&null_paired),
        cv_pct(&null_paired),
        cv_pct(&null_a),
        cv_pct(&null_b)
    );
    println!(
        "  PAIRED deployed/glibc: median {:.4}  cv={:.2}%  verdict={}",
        median(&host_paired),
        cv_pct(&host_paired),
        if median(&host_paired) <= 1.0 {
            "WIN"
        } else {
            "LOSS"
        }
    );
}
