//! Same-worker, paired `%B` strftime profiler against host glibc.
//!
//! The source-identical FL/FL null control is measured once per paired sample and
//! assigned opposite labels on alternating samples. The FL/glibc pair is likewise
//! order-alternated, so worker drift cannot systematically favor an arm.
//!
//! The decision instrument is a bootstrap 95% CI on the median paired ratio.
//! CV is reported as provenance only and is never used as a gate.

use std::ffi::c_char;
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use sha2::{Digest, Sha256};

const SAMPLES: usize = 45;
const WARMUP: usize = 4;
const REPS: usize = 250_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;

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
fn run_fl(out: *mut c_char, fmt: *const c_char, tm: *const libc::tm) -> usize {
    use frankenlibc_abi::time_abi as fl;
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            fl::strftime(black_box(out), 64, black_box(fmt), black_box(tm))
        }));
    }
    black_box(total)
}

#[inline(never)]
fn run_host(host: StrftimeFn, out: *mut c_char, fmt: *const c_char, tm: *const libc::tm) -> usize {
    let mut total = 0usize;
    for _ in 0..REPS {
        total = total.wrapping_add(black_box(unsafe {
            host(black_box(out), 64, black_box(fmt), black_box(tm))
        }));
    }
    black_box(total)
}

fn verify(host: StrftimeFn, fmt: *const c_char) {
    use frankenlibc_abi::time_abi as fl;
    for month in 0..=11 {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_mon = month;
        for capacity in 1usize..=64 {
            let mut a = [0x55 as c_char; 64];
            let mut b = [0x55 as c_char; 64];
            let fl_n = unsafe { fl::strftime(a.as_mut_ptr(), capacity, fmt, &tm) };
            let host_n = unsafe { host(b.as_mut_ptr(), capacity, fmt, &tm) };
            assert_eq!(
                fl_n, host_n,
                "length mismatch for tm_mon={month}, cap={capacity}"
            );
            if fl_n != 0 {
                assert_eq!(
                    &a[..=fl_n],
                    &b[..=host_n],
                    "output mismatch for tm_mon={month}, cap={capacity}"
                );
            }
        }
    }
    println!("verify: OK (FL == host glibc for tm_mon 0..=11 and capacity 1..=64)");
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    let h = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!h.is_null());
    unsafe {
        let sl: unsafe extern "C" fn(i32, *const c_char) -> *mut c_char =
            std::mem::transmute(libc::dlsym(h, b"setlocale\0".as_ptr().cast()));
        sl(6, b"C\0".as_ptr().cast());
    }
    let host: StrftimeFn = unsafe {
        let symbol = libc::dlsym(h, b"strftime\0".as_ptr().cast());
        assert!(!symbol.is_null());
        std::mem::transmute(symbol)
    };
    let fmt = c"%B";
    verify(host, fmt.as_ptr());

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_mon = 8;
    let tm_ptr = &tm;
    let mut fl_out = [0 as c_char; 64];
    let mut host_out = [0 as c_char; 64];
    let mut fl = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_a = Vec::with_capacity(SAMPLES - WARMUP);
    let mut null_b = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let (null_a_elapsed, null_b_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            (start.elapsed(), b)
        };
        let (fl_elapsed, host_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_host(host, host_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_host(host, host_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(fl_out.as_mut_ptr(), fmt.as_ptr(), tm_ptr));
            (start.elapsed(), b)
        };

        if sample >= WARMUP {
            let scale = REPS as f64;
            fl.push(fl_elapsed.as_nanos() as f64 / scale);
            glibc.push(host_elapsed.as_nanos() as f64 / scale);
            null_a.push(null_a_elapsed.as_nanos() as f64 / scale);
            null_b.push(null_b_elapsed.as_nanos() as f64 / scale);
        }
    }

    let paired: Vec<f64> = fl
        .iter()
        .zip(&glibc)
        .map(|(fl_ns, host_ns)| fl_ns / host_ns)
        .collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(&null_a)
        .map(|(b_ns, a_ns)| b_ns / a_ns)
        .collect();

    let paired_median = median(&paired);
    let null_median = median(&null_paired);
    let (paired_ci_low, paired_ci_high) = bootstrap_median_ci95(&paired);
    let (null_ci_low, null_ci_high) = bootstrap_median_ci95(&null_paired);
    let null_half_width = (1.0 - null_ci_low).abs().max((null_ci_high - 1.0).abs());
    let effect_clears_null = (paired_median - 1.0).abs() > 2.0 * null_half_width;
    let paired_ci_excludes_one = paired_ci_high < 1.0 || paired_ci_low > 1.0;
    let verdict = if effect_clears_null && paired_ci_excludes_one && paired_median < 1.0 {
        "KEEP"
    } else if effect_clears_null && paired_ci_excludes_one {
        "REJECT"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "STRFTIME_FULL_MONTH_AB samples={} reps/arm={REPS} (interleaved, order alternated)",
        fl.len()
    );
    println!(
        "  frankenlibc median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&fl),
        mean(&fl),
        cv_pct(&fl)
    );
    println!(
        "  host glibc  median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&glibc),
        mean(&glibc),
        cv_pct(&glibc)
    );
    println!(
        "STRFTIME_BENCH_CONTRACT kind=null_fl_fl ratio_median={null_median:.6} \
         ratio_ci95=[{null_ci_low:.6},{null_ci_high:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6}",
        cv_pct(&null_paired),
        median_absolute_deviation(&null_paired, null_median),
    );
    println!(
        "STRFTIME_BENCH_CONTRACT kind=fl_glibc ratio_median={paired_median:.6} \
         ratio_ci95=[{paired_ci_low:.6},{paired_ci_high:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6} null_half_width={null_half_width:.6} \
         clears_2x_null={} verdict={verdict}",
        cv_pct(&paired),
        median_absolute_deviation(&paired, paired_median),
        effect_clears_null,
    );
}
