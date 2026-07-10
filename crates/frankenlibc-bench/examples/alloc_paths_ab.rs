//! Profile-first: deployed fl allocator large-alloc + realloc paths vs host glibc (cc_fl, bd-2g7oyh).
//!
//! cod's segment magazines cover STRICT SMALL churn. This example measures the HOST-DELEGATED
//! large/realloc paths that still route through native_libc_* + the fallback hash table, to find
//! which allocator sub-path carries the biggest remaining gap to glibc. Pure measurement — no
//! malloc_abi.rs edit. fl and glibc arms interleave in ONE binary, order swapped every sample;
//! a paired(fl, fl) null control establishes the per-function floor first.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example alloc_paths_ab`

use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::malloc_abi as fl;

const SAMPLES: usize = 1500;
const REPS: usize = 400;
const WARMUP: usize = 100;
const LARGE: usize = 256 * 1024; // clearly above any segment size class -> host-delegated

type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;

struct Alloc {
    malloc: MallocFn,
    free: FreeFn,
    realloc: ReallocFn,
}

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

// --- workloads (per rep), each returns an accumulator so nothing is DCE'd --------

#[inline(never)]
fn large_cycle(a: &Alloc) -> u64 {
    let mut acc = 0u64;
    for _ in 0..REPS {
        let p = unsafe { (a.malloc)(black_box(LARGE)) };
        assert!(!p.is_null(), "malloc(LARGE) null");
        // touch first + last byte so the mapping is real
        unsafe {
            p.cast::<u8>().write_volatile(1);
            p.cast::<u8>().add(LARGE - 1).write_volatile(2);
            acc = acc.wrapping_add(p.cast::<u8>().read_volatile() as u64);
        }
        unsafe { (a.free)(black_box(p)) };
    }
    black_box(acc)
}

#[inline(never)]
fn realloc_cycle(a: &Alloc) -> u64 {
    let mut acc = 0u64;
    for _ in 0..REPS {
        let mut p = unsafe { (a.malloc)(black_box(2048)) };
        assert!(!p.is_null(), "malloc null");
        p = unsafe { (a.realloc)(black_box(p), black_box(16384)) }; // grow (likely moves)
        assert!(!p.is_null(), "realloc grow null");
        p = unsafe { (a.realloc)(black_box(p), black_box(512)) }; // shrink (likely in-place)
        assert!(!p.is_null(), "realloc shrink null");
        unsafe {
            p.cast::<u8>().write_volatile(3);
            acc = acc.wrapping_add(p.cast::<u8>().read_volatile() as u64);
        }
        unsafe { (a.free)(black_box(p)) };
    }
    black_box(acc)
}

fn host_alloc() -> Alloc {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &std::ffi::CStr| {
            let s = libc::dlsym(h, n.as_ptr());
            assert!(!s.is_null(), "dlsym {n:?} failed");
            s
        };
        Alloc {
            malloc: std::mem::transmute::<*mut c_void, MallocFn>(sym(c"malloc")),
            free: std::mem::transmute::<*mut c_void, FreeFn>(sym(c"free")),
            realloc: std::mem::transmute::<*mut c_void, ReallocFn>(sym(c"realloc")),
        }
    }
}

fn fl_alloc() -> Alloc {
    Alloc {
        malloc: fl::malloc,
        free: fl::free,
        realloc: fl::realloc,
    }
}

fn paired<F, G>(samples: usize, mut a: F, mut b: G) -> (Vec<f64>, Vec<f64>)
where
    F: FnMut() -> u64,
    G: FnMut() -> u64,
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
            xa.push(ta.as_nanos() as f64 / REPS as f64);
            xb.push(tb.as_nanos() as f64 / REPS as f64);
        }
    }
    (xa, xb)
}

fn report(label: &str, fl_ns: &[f64], glibc_ns: &[f64]) -> String {
    let ratio: Vec<f64> = fl_ns.iter().zip(glibc_ns.iter()).map(|(f, g)| f / g).collect();
    let (fm, gm) = (median(fl_ns), median(glibc_ns));
    let line = format!(
        "{label}: fl {:.1}ns  glibc {:.1}ns  paired fl/glibc median {:.3}x  cv={:.1}%  (fl cv {:.1}%, glibc cv {:.1}%)",
        fm,
        gm,
        median(&ratio),
        cv_pct(&ratio),
        cv_pct(fl_ns),
        cv_pct(glibc_ns),
    );
    println!("{line}");
    line
}

fn main() {
    let flo = fl_alloc();
    let host = host_alloc();
    // warm both allocators' lazy init
    black_box(large_cycle(&flo));
    black_box(large_cycle(&host));
    black_box(realloc_cycle(&flo));
    black_box(realloc_cycle(&host));

    let mut summary = Vec::new();

    // NULL CONTROL first: fl vs fl, per function.
    let (n1, n2) = paired(SAMPLES, || large_cycle(&flo), || large_cycle(&flo));
    summary.push(report("NULL large (fl vs fl)", &n1, &n2));
    let (r1, r2) = paired(SAMPLES, || realloc_cycle(&flo), || realloc_cycle(&flo));
    summary.push(report("NULL realloc (fl vs fl)", &r1, &r2));

    let (lf, lg) = paired(SAMPLES, || large_cycle(&flo), || large_cycle(&host));
    summary.push(report("LARGE malloc/free fl vs glibc", &lf, &lg));

    let (rf, rg) = paired(SAMPLES, || realloc_cycle(&flo), || realloc_cycle(&host));
    summary.push(report("REALLOC grow+shrink fl vs glibc", &rf, &rg));

    println!("\n===== SUMMARY (alloc_paths large + realloc, deployed fl vs glibc) =====");
    for l in &summary {
        println!("  {l}");
    }
}
