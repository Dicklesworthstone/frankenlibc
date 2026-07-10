//! Truly-interleaved paired A/B for the `gethostbyname` needle allocation (cc_fl, bd-veb6ve).
//!
//! `resolve_gethostbyname_target` did `name_cstr.to_bytes().to_vec()` per call — one `Vec` heap
//! allocation through the interposed allocator — only so the bytes could be copied into the TLS
//! hostent a moment later. Now it borrows.
//!
//! TWO SCALES, deliberately. Last time I *estimated* a resolver micro-allocation at "3-5%, below my
//! sampler's resolution", declined to try it, and was wrong on both counts (it was 10.8%, resolved
//! at cv 3.75%). So: measure the primitive AND the deployed call, and report whatever comes out.
//!
//! Substrate v2: arms alternate WITHIN one measured routine, order swapped every sample. Every input
//! goes through `black_box` and every result is consumed through `black_box`. `verify()` asserts fl
//! agrees with host glibc (address + canonical name) before any timing, so a dead-code-eliminated
//! arm cannot pass.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example gethostbyname_needle_ab`

use std::ffi::{CStr, c_char, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const KERNEL_SAMPLES: usize = 400;
const KERNEL_REPS: usize = 20_000;
const DEPLOYED_SAMPLES: usize = 2000;
const DEPLOYED_REPS: usize = 20;
const WARMUP: usize = 50;

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

// --- kernel arms: the needle allocation itself -----------------------------------

#[inline(never)]
fn kernel_orig(name: *const c_char) -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        unsafe { fl::bench_legacy_gethostbyname_needle_alloc(black_box(name)) };
        acc = acc.wrapping_add(1);
    }
    black_box(acc)
}

/// CAND: what the deployed path now does instead — borrow the bytes, no allocation.
#[inline(never)]
fn kernel_cand(name: *const c_char) -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        let bytes = unsafe { CStr::from_ptr(black_box(name)) }.to_bytes();
        acc = acc.wrapping_add(black_box(bytes).len() as u64);
    }
    black_box(acc)
}

// --- deployed arms ---------------------------------------------------------------

#[inline(never)]
unsafe fn consume(h: *mut c_void) -> u32 {
    assert!(!h.is_null(), "gethostbyname returned NULL");
    let hp = h.cast::<libc::hostent>();
    let addr = unsafe { *(*hp).h_addr_list.read().cast::<u32>() };
    black_box(addr)
}

#[inline(never)]
fn deployed_cand(name: *const c_char) -> u32 {
    let mut acc = 0u32;
    for _ in 0..DEPLOYED_REPS {
        let h = unsafe { fl::gethostbyname(black_box(name)) };
        acc = acc.wrapping_add(unsafe { consume(h) });
    }
    black_box(acc)
}

#[inline(never)]
fn deployed_orig(name: *const c_char) -> u32 {
    let mut acc = 0u32;
    for _ in 0..DEPLOYED_REPS {
        // Reconstruct the removed per-call Vec, then run the deployed path.
        unsafe { fl::bench_legacy_gethostbyname_needle_alloc(black_box(name)) };
        let h = unsafe { fl::gethostbyname(black_box(name)) };
        acc = acc.wrapping_add(unsafe { consume(h) });
    }
    black_box(acc)
}

type GetHostByName = unsafe extern "C" fn(*const c_char) -> *mut libc::hostent;

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
fn host(f: GetHostByName, name: *const c_char) -> u32 {
    let mut acc = 0u32;
    for _ in 0..DEPLOYED_REPS {
        let h = unsafe { f(black_box(name)) };
        assert!(!h.is_null(), "host gethostbyname returned NULL");
        let addr = unsafe { *(*h).h_addr_list.read().cast::<u32>() };
        acc = acc.wrapping_add(black_box(addr));
    }
    black_box(acc)
}

fn verify(hf: GetHostByName, name: *const c_char) {
    let fl_h = unsafe { fl::gethostbyname(name) };
    assert!(!fl_h.is_null(), "fl gethostbyname NULL");
    let fl_hp = fl_h.cast::<libc::hostent>();
    let fl_addr = unsafe { *(*fl_hp).h_addr_list.read().cast::<u32>() };
    let fl_name = unsafe { CStr::from_ptr((*fl_hp).h_name) };

    let h_h = unsafe { hf(name) };
    assert!(!h_h.is_null(), "host gethostbyname NULL");
    let h_addr = unsafe { *(*h_h).h_addr_list.read().cast::<u32>() };
    let h_name = unsafe { CStr::from_ptr((*h_h).h_name) };

    assert_eq!(fl_addr, h_addr, "fl vs host glibc address mismatch");
    assert_eq!(fl_name, h_name, "fl vs host glibc canonical name mismatch");
    println!("verify: OK (fl == host glibc for gethostbyname: {fl_name:?})");
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

fn report(label: &str, per: f64, o: &[f64], c: &[f64], unit: &str) -> String {
    let ratio: Vec<f64> = c.iter().zip(o.iter()).map(|(x, y)| x / y).collect();
    println!(
        "{label} n={} {unit}\n  orig median {:10.3}  cv={:5.2}%\n  cand median {:10.3}  cv={:5.2}%\n  PAIRED cand/orig median {:.4} ({:.2}x faster)  cv={:.2}%",
        o.len(),
        median(o) / per,
        cv_pct(o),
        median(c) / per,
        cv_pct(c),
        median(&ratio),
        1.0 / median(&ratio),
        cv_pct(&ratio)
    );
    // Compact one-liner for the end-of-run SUMMARY block. rch only returns the TAIL of remote
    // stdout, so the mandatory null-control medians must be re-emitted together at the very end.
    format!(
        "{label}: paired median {:.4} ({:.2}x)  cv={:.2}%  [orig {:.3} / cand {:.3} {unit}]",
        median(&ratio),
        1.0 / median(&ratio),
        cv_pct(&ratio),
        median(o) / per,
        median(c) / per,
    )
}

fn main() {
    let name = c"localhost";
    let np = name.as_ptr();
    let hf = host_gethostbyname();
    verify(hf, np);

    // NULL CONTROL FIRST. Register the IDENTICAL arm twice in the same interleaved routine. Its
    // ratio is the harness's noise floor: any |1 - ratio| smaller than the null's deviation, or any
    // effect whose paired cv exceeds the null's, is indistinguishable from noise and must not be
    // claimed. Run before the real arms so it cannot be tuned to flatter them.
    let mut summary: Vec<String> = Vec::new();
    let (n1, n2) = paired(KERNEL_SAMPLES, || kernel_cand(np), || kernel_cand(np));
    summary.push(report(
        "NULL CONTROL kernel (cand vs cand)",
        KERNEL_REPS as f64,
        &n1,
        &n2,
        "(ns/op)",
    ));
    let (m1, m2) = paired(DEPLOYED_SAMPLES, || deployed_cand(np), || deployed_cand(np));
    summary.push(report(
        "NULL CONTROL deployed (cand vs cand)",
        DEPLOYED_REPS as f64,
        &m1,
        &m2,
        "(ns/call)",
    ));

    let (ko, kc) = paired(KERNEL_SAMPLES, || kernel_orig(np), || kernel_cand(np));
    summary.push(report(
        "KERNEL needle alloc",
        KERNEL_REPS as f64,
        &ko,
        &kc,
        "(ns/op)",
    ));

    let (dpo, dpc) = paired(
        DEPLOYED_SAMPLES,
        || deployed_orig(np),
        || deployed_cand(np),
    );
    summary.push(report(
        "DEPLOYED gethostbyname",
        DEPLOYED_REPS as f64,
        &dpo,
        &dpc,
        "(ns/call)",
    ));

    // Host glibc reference, same loop shape.
    let mut g = Vec::with_capacity(DEPLOYED_SAMPLES);
    for i in 0..DEPLOYED_SAMPLES {
        let s = Instant::now();
        black_box(host(hf, np));
        if i >= WARMUP {
            g.push(s.elapsed().as_nanos() as f64 / DEPLOYED_REPS as f64);
        }
    }
    summary.push(format!(
        "HOST glibc gethostbyname: median {:.3} ns/call  cv={:.2}%",
        median(&g),
        cv_pct(&g)
    ));

    // End-of-run SUMMARY: rch returns only the tail of remote stdout, so re-emit every arm's
    // paired median (incl. the two mandatory null controls) together here where the tail keeps them.
    println!("\n===== SUMMARY (bd-veb6ve gethostbyname needle) =====");
    for line in &summary {
        println!("  {line}");
    }
}
