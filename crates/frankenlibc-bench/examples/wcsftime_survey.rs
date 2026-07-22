//! Same-worker, truly interleaved `%j` strftime profiler against host glibc.
//!
//! The source-identical FL/FL null control is measured once per paired sample and
//! assigned opposite labels on alternating samples. The FL/glibc pair is likewise
//! order-alternated, so worker drift cannot systematically favor an arm.
//!
//! Reusable profiler: `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> rch exec -- \
//!       cargo run -j4 --profile release -p frankenlibc-bench \
//!       --features abi-bench --example wcsftime_survey`

use std::ffi::c_char;
use std::hint::black_box;
use std::time::Instant;

const SAMPLES: usize = 80;
const WARMUP: usize = 16;
const REPS: usize = 2_500_000;

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;

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
    for yday in [0, 1, 8, 9, 98, 99, 364, 365] {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_yday = yday;
        for capacity in [1usize, 2, 3, 4, 5, 64] {
            let mut a = [0x55 as c_char; 64];
            let mut b = [0x55 as c_char; 64];
            let fl_n = unsafe { fl::strftime(a.as_mut_ptr(), capacity, fmt, &tm) };
            let host_n = unsafe { host(b.as_mut_ptr(), capacity, fmt, &tm) };
            assert_eq!(
                fl_n, host_n,
                "length mismatch for tm_yday={yday}, cap={capacity}"
            );
            if fl_n != 0 {
                assert_eq!(
                    &a[..=fl_n],
                    &b[..=host_n],
                    "output mismatch for tm_yday={yday}, cap={capacity}"
                );
            }
        }
    }
    println!("verify: OK (FL == host glibc for valid %j day-of-year and fit boundaries)");
}

fn main() {
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
    let fmt = c"%j";
    verify(host, fmt.as_ptr());

    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_yday = 172;
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
    println!(
        "STRFTIME_YDAY_AB samples={} reps/arm={REPS} (interleaved, order alternated)",
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
        "  NULL FL/FL: median {:.4}  cv={:.2}%  arms cv={:.2}%/{:.2}%",
        median(&null_paired),
        cv_pct(&null_paired),
        cv_pct(&null_a),
        cv_pct(&null_b)
    );
    println!(
        "  PAIRED FL/glibc: median {:.4}  cv={:.2}%  verdict={}",
        median(&paired),
        cv_pct(&paired),
        if median(&paired) <= 1.0 {
            "WIN"
        } else {
            "LOSS"
        }
    );
}
