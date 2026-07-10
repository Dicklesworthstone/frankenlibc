//! Truly-interleaved paired A/B for the reverse-lookup IPv4 text formatter (cc_fl, bd-ld0i35).
//!
//! `gethostbyaddr`, `_gethtbyaddr` and the reentrant reverse fill each did `ip.to_string()` per
//! call: one `String` heap allocation through the interposed allocator plus `core::fmt` machinery.
//! `write_ipv4_text` writes `a.b.c.d` into a 15-byte stack buffer instead.
//!
//! TWO SCALES, because the end-to-end effect is small and the primitive is not:
//!   KERNEL  — `to_string()` vs `write_ipv4_text()` directly. Resolves the primitive cleanly.
//!   DEPLOYED — `gethostbyaddr` with vs without the reconstructed `String` allocation. This is a
//!              3-5% effect and may sit below the paired sampler's resolution; reported honestly
//!              either way rather than dressed up.
//!
//! Substrate v2: arms alternate WITHIN one measured routine, order swapped every sample (criterion
//! group members run sequentially and would not cancel drift). Every input goes through `black_box`
//! and every result is consumed through `black_box`. `verify()` asserts the formatter is
//! byte-identical to `Ipv4Addr::to_string()` on edge cases before any timing, so a
//! dead-code-eliminated arm cannot pass.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example ip_fmt_ab`

use std::ffi::{CStr, c_int, c_void};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const KERNEL_SAMPLES: usize = 400;
const KERNEL_REPS: usize = 20_000;
const DEPLOYED_SAMPLES: usize = 2000;
const DEPLOYED_REPS: usize = 20;
const WARMUP: usize = 50;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
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

// --- kernel arms -----------------------------------------------------------------

#[inline(never)]
fn kernel_orig(octets: [u8; 4]) -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        fl::bench_legacy_ip_to_string(black_box(octets));
        acc = acc.wrapping_add(1);
    }
    black_box(acc)
}

#[inline(never)]
fn kernel_cand(octets: [u8; 4]) -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        acc = acc.wrapping_add(black_box(fl::bench_write_ipv4_text(black_box(octets))) as u64);
    }
    black_box(acc)
}

// --- deployed arms ---------------------------------------------------------------

#[inline(never)]
unsafe fn consume(h: *mut c_void) -> u8 {
    assert!(!h.is_null(), "gethostbyaddr returned NULL");
    let name = unsafe { CStr::from_ptr((*h.cast::<libc::hostent>()).h_name) };
    black_box(name.to_bytes().first().copied().unwrap_or(0))
}

#[inline(never)]
fn deployed_cand() -> u8 {
    let mut acc = 0u8;
    for _ in 0..DEPLOYED_REPS {
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

#[inline(never)]
fn deployed_orig() -> u8 {
    let mut acc = 0u8;
    for _ in 0..DEPLOYED_REPS {
        // Reconstruct the removed per-call String allocation, then run the deployed path.
        fl::bench_legacy_ip_to_string(black_box(LOOPBACK));
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

fn verify() {
    for octets in [
        [0, 0, 0, 0],
        [1, 2, 3, 4],
        [127, 0, 0, 1],
        [10, 0, 0, 255],
        [255, 255, 255, 255],
        [9, 99, 100, 199],
    ] {
        let ours = fl::bench_ipv4_text_owned(octets);
        let std_ = Ipv4Addr::from(octets).to_string();
        assert_eq!(
            ours,
            std_.as_bytes(),
            "write_ipv4_text != Ipv4Addr::to_string() for {octets:?}"
        );
    }
    let h = unsafe {
        fl::gethostbyaddr(
            LOOPBACK.as_ptr().cast::<c_void>(),
            4 as libc::socklen_t,
            libc::AF_INET,
        )
    };
    assert!(
        !h.is_null(),
        "fl gethostbyaddr(127.0.0.1) NULL after change"
    );
    let name = unsafe { CStr::from_ptr((*h.cast::<libc::hostent>()).h_name) };
    println!(
        "verify: OK (write_ipv4_text == to_string on 6 edge cases; gethostbyaddr -> {name:?})"
    );
}

fn paired<F, G, R1, R2>(samples: usize, mut a: F, mut b: G) -> (Vec<f64>, Vec<f64>)
where
    F: FnMut() -> R1,
    G: FnMut() -> R2,
{
    let mut xa = Vec::with_capacity(samples);
    let mut xb = Vec::with_capacity(samples);
    for i in 0..samples {
        let (ta, tb) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            (t1, t2)
        } else {
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            (t1, t2)
        };
        if i >= WARMUP {
            xa.push(ta.as_nanos() as f64);
            xb.push(tb.as_nanos() as f64);
        }
    }
    (xa, xb)
}

fn report(label: &str, per: f64, o: &[f64], c: &[f64], unit: &str) {
    let (om, cm) = (median(o), median(c));
    let paired_ratio: Vec<f64> = c.iter().zip(o.iter()).map(|(x, y)| x / y).collect();
    println!(
        "{label} n={} {unit}\n  orig median {:10.3}  cv={:5.2}%\n  cand median {:10.3}  cv={:5.2}%\n  PAIRED cand/orig median {:.4} ({:.2}x faster)  cv={:.2}%",
        o.len(),
        om / per,
        cv_pct(o),
        cm / per,
        cv_pct(c),
        median(&paired_ratio),
        1.0 / median(&paired_ratio),
        cv_pct(&paired_ratio)
    );
}

fn main() {
    verify();

    let (ko, kc) = paired(
        KERNEL_SAMPLES,
        || kernel_orig(LOOPBACK),
        || kernel_cand(LOOPBACK),
    );
    report(
        "KERNEL ip-text format",
        KERNEL_REPS as f64,
        &ko,
        &kc,
        "(ns/op)",
    );

    let (dpo, dpc) = paired(DEPLOYED_SAMPLES, deployed_orig, deployed_cand);
    report(
        "DEPLOYED gethostbyaddr",
        DEPLOYED_REPS as f64,
        &dpo,
        &dpc,
        "(ns/call)",
    );
}

// Silence the unused import warning when c_int is only used via libc aliases.
#[allow(dead_code)]
fn _unused(_: c_int) {}
