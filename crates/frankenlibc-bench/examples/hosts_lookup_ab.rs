//! Truly-interleaved paired A/B for the `/etc/hosts` lookup path (cc_fl/BlackThrush, bd-0p00be).
//!
//! WHY NOT CRITERION. Registering ORIG and CAND as two members of one criterion group does NOT
//! cancel worker/thermal drift: criterion runs group members *sequentially*, so each arm sees a
//! different slice of machine time. This sampler alternates the two arms **within a single
//! measured routine** — one ORIG call and one CAND call per paired sample, order swapped every
//! sample — so drift lands on both arms equally and the per-sample ratio is drift-cancelled.
//! Host glibc is a third interleaved arm, resolved via `dlmopen` so it cannot bind our own
//! `#[no_mangle]` symbols.
//!
//! BLACK_BOX DISCIPLINE. Every input is fed through `black_box` and every result is consumed
//! through `black_box`, so no arm can be dead-code-eliminated. `verify()` additionally asserts
//! the arms agree before any timing runs — a DCE'd arm cannot satisfy that.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 RCH_WORKER=<worker> rch exec -- cargo bench -j4 --profile release \
//!       -p frankenlibc-bench --features abi-bench --bench hosts_lookup_ab -- --noplot`

use std::ffi::{CStr, c_char, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

/// Paired samples. Each sample times ORIG once and CAND once, alternating which goes first.
const SAMPLES: usize = 240;
/// Leading samples discarded (page-cache / branch warm-up).
const WARMUP: usize = 40;
/// Calls per arm per sample.
const REPS: usize = 500;

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

/// CAND: the deployed, allocation-free hosts walk (borrowed backend, `for_each_hosts_match`).
#[inline(never)]
fn cand(name: &[u8]) -> u32 {
    let mut acc = 0u32;
    for _ in 0..REPS {
        let h = unsafe { fl::gethostbyname(black_box(c"localhost").as_ptr()) };
        assert!(!h.is_null(), "fl gethostbyname(localhost) returned NULL");
        // Consume the resolved address so nothing can be elided.
        let hp = h.cast::<libc::hostent>();
        let addr = unsafe { *(*hp).h_addr_list.read().cast::<u32>() };
        acc = acc.wrapping_add(black_box(addr));
    }
    black_box(name);
    black_box(acc)
}

/// ORIG: reconstructs the removed per-call work in-process — a clone of the whole `/etc/hosts`
/// plus `lookup_hosts`, which `parse_hosts_line`-allocates every line — then runs the deployed
/// call. It therefore OVERSTATES ORIG by the deployed walk, making the measured ratio an
/// UNDER-estimate of the speedup.
#[inline(never)]
fn orig(name: &[u8]) -> u32 {
    let mut acc = 0u32;
    for _ in 0..REPS {
        fl::bench_legacy_hosts_scan(black_box(name));
        let h = unsafe { fl::gethostbyname(black_box(c"localhost").as_ptr()) };
        assert!(!h.is_null());
        let hp = h.cast::<libc::hostent>();
        let addr = unsafe { *(*hp).h_addr_list.read().cast::<u32>() };
        acc = acc.wrapping_add(black_box(addr));
    }
    black_box(acc)
}

type GetHostByName = unsafe extern "C" fn(*const c_char) -> *mut libc::hostent;

/// Host glibc in a private namespace, so `gethostbyname` cannot bind our exported symbol.
fn host_gethostbyname() -> GetHostByName {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let s = libc::dlsym(handle, c"gethostbyname".as_ptr());
        assert!(!s.is_null(), "dlsym gethostbyname failed");
        std::mem::transmute::<*mut c_void, GetHostByName>(s)
    }
}

#[inline(never)]
fn host(f: GetHostByName) -> u32 {
    let mut acc = 0u32;
    for _ in 0..REPS {
        let h = unsafe { f(black_box(c"localhost").as_ptr()) };
        assert!(!h.is_null(), "host gethostbyname(localhost) returned NULL");
        let addr = unsafe { *(*h).h_addr_list.read().cast::<u32>() };
        acc = acc.wrapping_add(black_box(addr));
    }
    black_box(acc)
}

/// Byte-identity: the deployed path, the reconstructed-ORIG path and host glibc must all resolve
/// `localhost` to the same address. Runs before timing, so a dead-code arm cannot pass.
fn verify(hf: GetHostByName) {
    let fl_h = unsafe { fl::gethostbyname(c"localhost".as_ptr()) };
    assert!(!fl_h.is_null());
    let fl_hp = fl_h.cast::<libc::hostent>();
    let fl_addr = unsafe { *(*fl_hp).h_addr_list.read().cast::<u32>() };
    let fl_name = unsafe { CStr::from_ptr((*fl_hp).h_name) };

    let h_h = unsafe { hf(c"localhost".as_ptr()) };
    assert!(!h_h.is_null());
    let h_addr = unsafe { *(*h_h).h_addr_list.read().cast::<u32>() };
    let h_name = unsafe { CStr::from_ptr((*h_h).h_name) };

    assert_eq!(fl_addr, h_addr, "fl vs host glibc address mismatch");
    assert_eq!(fl_name, h_name, "fl vs host glibc canonical name mismatch");
    println!("verify: OK (fl == host glibc for gethostbyname(localhost): {fl_name:?})");
}

fn main() {
    let hf = host_gethostbyname();
    verify(hf);

    let name: &[u8] = b"localhost";
    let mut o = Vec::with_capacity(SAMPLES);
    let mut c = Vec::with_capacity(SAMPLES);
    let mut g = Vec::with_capacity(SAMPLES);
    let mut null_a = Vec::with_capacity(SAMPLES);
    let mut null_b = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        // Per-function NULL CONTROL: time the deployed function against itself. Swap which
        // observation owns the first slot so drift cannot systematically favor one label.
        let (t_null_a, t_null_b) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(cand(name));
            let a = s.elapsed();
            let s = Instant::now();
            black_box(cand(name));
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(cand(name));
            let b = s.elapsed();
            let s = Instant::now();
            black_box(cand(name));
            let a = s.elapsed();
            (a, b)
        };
        // Alternate arm order every sample so neither arm systematically leads.
        let (t_o, t_c) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(orig(name));
            let a = s.elapsed();
            let s = Instant::now();
            black_box(cand(name));
            let b = s.elapsed();
            (a, b)
        } else {
            let s = Instant::now();
            black_box(cand(name));
            let b = s.elapsed();
            let s = Instant::now();
            black_box(orig(name));
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

    // Per-sample paired ratio: drift within a sample hits both arms, so the ratio cancels it.
    let paired: Vec<f64> = c.iter().zip(o.iter()).map(|(cc, oo)| cc / oo).collect();
    let null_paired: Vec<f64> = null_b
        .iter()
        .zip(null_a.iter())
        .map(|(bb, aa)| bb / aa)
        .collect();

    println!(
        "HOSTS_LOOKUP_AB samples={} reps/arm={REPS} (interleaved, order alternated)",
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
