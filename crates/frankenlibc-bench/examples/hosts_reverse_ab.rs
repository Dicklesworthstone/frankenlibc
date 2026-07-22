//! Truly-interleaved paired A/B for the reverse `/etc/hosts` lookup (cc_fl/BlackThrush, bd-d8vabn).
//!
//! Substrate v2: criterion group members run SEQUENTIALLY, so registering ORIG and CAND side by
//! side does not cancel worker/thermal drift. Here the two arms alternate **within one measured
//! routine** — one call of each per paired sample, order swapped every sample — so drift lands on
//! both and the per-sample ratio cancels it. Host glibc is a third interleaved arm, resolved via
//! `dlmopen(LM_ID_NEWLM)` so it cannot bind our own `#[no_mangle]` `gethostbyaddr`.
//!
//! black_box discipline: every input is fed through `black_box` and every result consumed through
//! it, so no arm can be dead-code-eliminated. `verify()` asserts fl == host glibc on the resolved
//! canonical name before any timing — a DCE'd arm cannot satisfy that.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> rch exec -- cargo bench -j4 --profile release \
//!       -p frankenlibc-bench --features abi-bench --bench hosts_reverse_ab -- --noplot`

use std::ffi::{CStr, c_int, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const SAMPLES: usize = 80;
const WARMUP: usize = 16;
const REPS: usize = 50_000;

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

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
}

/// 127.0.0.1 in network order, as `gethostbyaddr` expects.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

/// Consume the resolved hostent so nothing can be elided.
unsafe fn consume(h: *mut c_void) -> u8 {
    assert!(!h.is_null(), "gethostbyaddr returned NULL");
    let hp = h.cast::<libc::hostent>();
    let name = unsafe { CStr::from_ptr((*hp).h_name) };
    black_box(name.to_bytes().first().copied().unwrap_or(0))
}

/// CAND: the deployed, allocation-free reverse walk.
#[inline(never)]
fn cand() -> u8 {
    let mut acc = 0u8;
    for _ in 0..REPS {
        let h = unsafe {
            fl::gethostbyaddr(
                black_box(LOOPBACK.as_ptr()).cast::<c_void>(),
                black_box(4 as libc::socklen_t),
                black_box(libc::AF_INET),
            )
        };
        acc = acc.wrapping_add(unsafe { consume(h) });
    }
    black_box(acc)
}

/// ORIG: reconstructs the removed per-call work in-process — a clone of the whole `/etc/hosts`
/// plus `reverse_lookup_hosts`, which `parse_hosts_line`-allocates every line — then runs the
/// deployed call. It OVERSTATES ORIG by the deployed borrowed walk, so the ratio is an
/// UNDER-estimate of the speedup.
#[inline(never)]
fn orig() -> u8 {
    let mut acc = 0u8;
    for _ in 0..REPS {
        fl::bench_legacy_reverse_hosts_scan(black_box(b"127.0.0.1"));
        let h = unsafe {
            fl::gethostbyaddr(
                black_box(LOOPBACK.as_ptr()).cast::<c_void>(),
                black_box(4 as libc::socklen_t),
                black_box(libc::AF_INET),
            )
        };
        acc = acc.wrapping_add(unsafe { consume(h) });
    }
    black_box(acc)
}

type GetHostByAddr =
    unsafe extern "C" fn(*const c_void, libc::socklen_t, c_int) -> *mut libc::hostent;

fn host_gethostbyaddr() -> GetHostByAddr {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let s = libc::dlsym(handle, c"gethostbyaddr".as_ptr());
        assert!(!s.is_null(), "dlsym gethostbyaddr failed");
        std::mem::transmute::<*mut c_void, GetHostByAddr>(s)
    }
}

#[inline(never)]
fn host(f: GetHostByAddr) -> u8 {
    let mut acc = 0u8;
    for _ in 0..REPS {
        let h = unsafe {
            f(
                black_box(LOOPBACK.as_ptr()).cast::<c_void>(),
                black_box(4 as libc::socklen_t),
                black_box(libc::AF_INET),
            )
        };
        assert!(!h.is_null(), "host gethostbyaddr returned NULL");
        let name = unsafe { CStr::from_ptr((*h).h_name) };
        acc = acc.wrapping_add(black_box(name.to_bytes().first().copied().unwrap_or(0)));
    }
    black_box(acc)
}

fn verify(hf: GetHostByAddr) {
    let fl_h = unsafe {
        fl::gethostbyaddr(
            LOOPBACK.as_ptr().cast::<c_void>(),
            4 as libc::socklen_t,
            libc::AF_INET,
        )
    };
    assert!(!fl_h.is_null(), "fl gethostbyaddr(127.0.0.1) returned NULL");
    let fl_name = unsafe { CStr::from_ptr((*fl_h.cast::<libc::hostent>()).h_name) };

    let h_h = unsafe {
        hf(
            LOOPBACK.as_ptr().cast::<c_void>(),
            4 as libc::socklen_t,
            libc::AF_INET,
        )
    };
    assert!(!h_h.is_null(), "host gethostbyaddr returned NULL");
    let h_name = unsafe { CStr::from_ptr((*h_h).h_name) };

    assert_eq!(fl_name, h_name, "fl vs host glibc canonical name mismatch");
    println!("verify: OK (fl == host glibc for gethostbyaddr(127.0.0.1): {fl_name:?})");
}

fn main() {
    let hf = host_gethostbyaddr();
    verify(hf);

    let mut o = Vec::with_capacity(SAMPLES);
    let mut c = Vec::with_capacity(SAMPLES);
    let mut g = Vec::with_capacity(SAMPLES);
    let mut null_a = Vec::with_capacity(SAMPLES);
    let mut null_b = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        let (t_null_a, t_null_b) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(cand());
            let a = s.elapsed();
            let s = Instant::now();
            black_box(cand());
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(cand());
            let b = s.elapsed();
            let s = Instant::now();
            black_box(cand());
            let a = s.elapsed();
            (a, b)
        };
        let (t_o, t_c) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(orig());
            let a = s.elapsed();
            let s = Instant::now();
            black_box(cand());
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(cand());
            let b = s.elapsed();
            let s = Instant::now();
            black_box(orig());
            let a = s.elapsed();
            (a, b)
        };
        let s = Instant::now();
        black_box(host(hf));
        let t_g = s.elapsed();

        if i >= WARMUP {
            o.push(t_o.as_nanos() as f64 / REPS as f64);
            c.push(t_c.as_nanos() as f64 / REPS as f64);
            g.push(t_g.as_nanos() as f64 / REPS as f64);
            null_a.push(t_null_a.as_nanos() as f64 / REPS as f64);
            null_b.push(t_null_b.as_nanos() as f64 / REPS as f64);
        }
    }

    let paired: Vec<f64> = c.iter().zip(o.iter()).map(|(cc, oo)| cc / oo).collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(null_a.iter())
        .map(|(bb, aa)| bb / aa)
        .collect();

    println!(
        "HOSTS_REVERSE_AB samples={} reps/arm={REPS} (interleaved, order alternated)",
        o.len()
    );
    println!(
        "  orig(clone+parse) median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&o),
        mean(&o),
        cv_pct(&o)
    );
    println!(
        "  cand(borrow+scan)  median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&c),
        mean(&c),
        cv_pct(&c)
    );
    println!(
        "  host glibc         median {:8.2} ns/call  mean {:8.2}  cv={:5.2}%",
        median(&g),
        mean(&g),
        cv_pct(&g)
    );
    println!(
        "  NULL cand/cand: median {:.4}  cv={:.2}%  arms cv={:.2}%/{:.2}%",
        median(&null_paired),
        cv_pct(&null_paired),
        cv_pct(&null_a),
        cv_pct(&null_b)
    );
    println!(
        "  PAIRED cand/orig: median {:.4} ({:.2}x faster)  cv={:.2}%",
        median(&paired),
        1.0 / median(&paired),
        cv_pct(&paired)
    );
    println!(
        "  cand/glibc: median {:.3}x ({})",
        median(&c) / median(&g),
        if median(&c) <= median(&g) {
            "WIN"
        } else {
            "LOSS"
        }
    );
}
