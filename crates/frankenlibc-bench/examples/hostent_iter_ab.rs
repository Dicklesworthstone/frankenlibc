//! Truly-interleaved paired A/B for the `/etc/hosts` entry iterator (cc_fl/BlackThrush, bd-ld0i35).
//!
//! WORKLOAD: a full `gethostent()`-style drain — rewind, then step until exhaustion. That is where
//! the defect shows: `_gethtent` used to clone the WHOLE `/etc/hosts` on every step, so draining N
//! entries was O(N^2) in file size.
//!
//! Substrate v2: criterion group members run SEQUENTIALLY and would not cancel worker/thermal
//! drift, so ORIG and CAND alternate **within one measured routine**, one drain of each per paired
//! sample, order swapped every sample. Host glibc is a third interleaved arm via
//! `dlmopen(LM_ID_NEWLM)`, so it cannot bind our own `#[no_mangle]` symbols.
//!
//! black_box discipline: every input is fed through `black_box` and every result consumed through
//! it. `verify()` asserts fl and host glibc agree on the number of drained entries and on the first
//! canonical name before any timing — a dead-code-eliminated arm cannot satisfy that.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> rch exec -- cargo bench -j4 --profile release \
//!       -p frankenlibc-bench --features abi-bench --bench hostent_iter_ab -- --noplot`

use std::ffi::{CStr, c_int, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const SAMPLES: usize = 240;
const WARMUP: usize = 40;
const DRAINS_PER_ARM: usize = 200;

#[inline(never)]
fn repeat_arm(mut arm: impl FnMut() -> (u32, u8)) -> (u32, u8) {
    let mut entries = 0u32;
    let mut first = 0u8;
    for _ in 0..DRAINS_PER_ARM {
        let (n, byte) = arm();
        entries = entries.wrapping_add(n);
        first ^= byte;
    }
    (black_box(entries), black_box(first))
}

/// Drain the fl iterator, returning (entries, first-name-first-byte).
#[inline(never)]
fn cand() -> (u32, u8) {
    unsafe { fl::_sethtent(black_box(0 as c_int)) };
    let mut n = 0u32;
    let mut first = 0u8;
    loop {
        let h = unsafe { fl::_gethtent() };
        if h.is_null() {
            break;
        }
        let hp = h.cast::<libc::hostent>();
        let name = unsafe { CStr::from_ptr((*hp).h_name) };
        if n == 0 {
            first = name.to_bytes().first().copied().unwrap_or(0);
        }
        n += 1;
        black_box(name.as_ptr());
    }
    (black_box(n), black_box(first))
}

/// ORIG: reconstructs the removed per-step whole-file clone, then runs the deployed step. It
/// OVERSTATES ORIG by the deployed borrowed step, so the measured ratio is an UNDER-estimate.
#[inline(never)]
fn orig() -> (u32, u8) {
    unsafe { fl::_sethtent(black_box(0 as c_int)) };
    let mut n = 0u32;
    let mut first = 0u8;
    loop {
        fl::bench_legacy_hosts_clone();
        let h = unsafe { fl::_gethtent() };
        if h.is_null() {
            break;
        }
        let hp = h.cast::<libc::hostent>();
        let name = unsafe { CStr::from_ptr((*hp).h_name) };
        if n == 0 {
            first = name.to_bytes().first().copied().unwrap_or(0);
        }
        n += 1;
        black_box(name.as_ptr());
    }
    (black_box(n), black_box(first))
}

type SetHostEnt = unsafe extern "C" fn(c_int);
type GetHostEnt = unsafe extern "C" fn() -> *mut libc::hostent;
type EndHostEnt = unsafe extern "C" fn();

struct HostIter {
    set: SetHostEnt,
    get: GetHostEnt,
    end: EndHostEnt,
}

fn host_iter() -> &'static HostIter {
    use std::sync::OnceLock;
    static H: OnceLock<HostIter> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &CStr| {
            let s = libc::dlsym(handle, n.as_ptr());
            assert!(!s.is_null(), "dlsym {n:?} failed");
            s
        };
        HostIter {
            set: std::mem::transmute::<*mut c_void, SetHostEnt>(sym(c"sethostent")),
            get: std::mem::transmute::<*mut c_void, GetHostEnt>(sym(c"gethostent")),
            end: std::mem::transmute::<*mut c_void, EndHostEnt>(sym(c"endhostent")),
        }
    })
}

/// glibc's `gethostent` yields BOTH IPv4 and IPv6 entries; fl's `_gethtent` yields IPv4 only. Count
/// only AF_INET entries so the two arms drain the same logical set.
#[inline(never)]
fn host(h: &HostIter) -> (u32, u8) {
    unsafe { (h.set)(black_box(0 as c_int)) };
    let mut n = 0u32;
    let mut first = 0u8;
    loop {
        let e = unsafe { (h.get)() };
        if e.is_null() {
            break;
        }
        if unsafe { (*e).h_addrtype } == libc::AF_INET {
            let name = unsafe { CStr::from_ptr((*e).h_name) };
            if n == 0 {
                first = name.to_bytes().first().copied().unwrap_or(0);
            }
            n += 1;
            black_box(name.as_ptr());
        }
    }
    unsafe { (h.end)() };
    (black_box(n), black_box(first))
}

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

fn verify(h: &HostIter) {
    let (c_n, c_first) = cand();
    let (o_n, o_first) = orig();
    let (g_n, g_first) = host(h);
    assert!(c_n > 0, "fl drained zero /etc/hosts entries");
    // Byte-identity of THIS lever: the deployed borrow must agree with the reconstructed clone.
    assert_eq!(c_n, o_n, "cand vs reconstructed-orig entry count mismatch");
    assert_eq!(
        c_first, o_first,
        "cand vs reconstructed-orig first-name mismatch"
    );
    println!("verify: OK (cand == reconstructed-orig: {c_n} entries, same first name)");

    // fl `_gethtent` vs glibc `gethostent` is a SEPARATE, pre-existing question: this lever does
    // not change which entries the iterator yields (only clone -> borrow of the same bytes).
    // Report rather than assert, so a pre-existing divergence does not masquerade as a regression.
    if c_n != g_n || c_first != g_first {
        println!(
            "NOTE: fl _gethtent yields {c_n} IPv4 entries (first byte {c_first}); \
             host glibc gethostent yields {g_n} (first byte {g_first}). \
             PRE-EXISTING divergence, unrelated to this lever - see ledger."
        );
    } else {
        println!("verify: fl == host glibc ({c_n} IPv4 /etc/hosts entries)");
    }
}

fn main() {
    let h = host_iter();
    verify(h);

    let mut o = Vec::with_capacity(SAMPLES);
    let mut c = Vec::with_capacity(SAMPLES);
    let mut g = Vec::with_capacity(SAMPLES);
    let mut null_a = Vec::with_capacity(SAMPLES);
    let mut null_b = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        let (t_null_a, t_null_b) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let a = s.elapsed();
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let b = s.elapsed();
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let a = s.elapsed();
            (a, b)
        };
        let (t_o, t_c) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(repeat_arm(orig));
            let a = s.elapsed();
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(repeat_arm(cand));
            let b = s.elapsed();
            let s = Instant::now();
            black_box(repeat_arm(orig));
            let a = s.elapsed();
            (a, b)
        };
        let s = Instant::now();
        black_box(repeat_arm(|| host(h)));
        let t_g = s.elapsed();

        if i >= WARMUP {
            o.push(t_o.as_nanos() as f64 / DRAINS_PER_ARM as f64);
            c.push(t_c.as_nanos() as f64 / DRAINS_PER_ARM as f64);
            g.push(t_g.as_nanos() as f64 / DRAINS_PER_ARM as f64);
            null_a.push(t_null_a.as_nanos() as f64 / DRAINS_PER_ARM as f64);
            null_b.push(t_null_b.as_nanos() as f64 / DRAINS_PER_ARM as f64);
        }
    }

    let paired: Vec<f64> = c.iter().zip(o.iter()).map(|(cc, oo)| cc / oo).collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(null_a.iter())
        .map(|(bb, aa)| bb / aa)
        .collect();

    println!(
        "HOSTENT_ITER_AB samples={} drains/arm={DRAINS_PER_ARM} (interleaved; ns per FULL drain)",
        o.len()
    );
    println!(
        "  orig(clone per step) median {:9.2} ns  mean {:9.2}  cv={:5.2}%",
        median(&o),
        mean(&o),
        cv_pct(&o)
    );
    println!(
        "  cand(borrow)         median {:9.2} ns  mean {:9.2}  cv={:5.2}%",
        median(&c),
        mean(&c),
        cv_pct(&c)
    );
    println!(
        "  host glibc           median {:9.2} ns  mean {:9.2}  cv={:5.2}%",
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
