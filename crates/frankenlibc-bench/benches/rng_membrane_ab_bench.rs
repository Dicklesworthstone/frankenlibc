//! RNG membrane fast-path A/B: fl global-state RNG vs host glibc (cc/BlackThrush).
//!
//! random()/drand48()/lrand48()/mrand48() are ~5-10ns ops that previously paid the full
//! `decide()`+`observe()` Stdlib membrane tax per call (~8-12ns), so the tax dominated.
//! This bench checks the fast-path (stdlib_membrane_fastpath: skip the tax in non-test):
//! fl module fn (fast-path active in a bench bin) vs the host glibc symbol via
//! `dlmopen(LM_ID_NEWLM)` (fl's no_mangle symbols interpose the main namespace, so glibc
//! must be loaded into a fresh namespace).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench rng_membrane_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdlib_abi as fl;

type LongFn = unsafe extern "C" fn() -> std::ffi::c_long;
type DoubleFn = unsafe extern "C" fn() -> f64;

struct Host {
    random: LongFn,
    drand48: DoubleFn,
    lrand48: LongFn,
    mrand48: LongFn,
}

fn host() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        let g = |n: &[u8]| {
            let s = libc::dlsym(h, n.as_ptr().cast());
            assert!(!s.is_null());
            s
        };
        Host {
            random: std::mem::transmute::<*mut c_void, LongFn>(g(b"random\0")),
            drand48: std::mem::transmute::<*mut c_void, DoubleFn>(g(b"drand48\0")),
            lrand48: std::mem::transmute::<*mut c_void, LongFn>(g(b"lrand48\0")),
            mrand48: std::mem::transmute::<*mut c_void, LongFn>(g(b"mrand48\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

const M: usize = 1000;

fn measure(mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..50 {
        let mut acc = 0u64;
        for _ in 0..M {
            acc = acc.wrapping_add(f());
        }
        black_box(acc);
    }
    let mut samples = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let mut acc = 0u64;
        for _ in 0..M {
            acc = acc.wrapping_add(f());
        }
        black_box(acc);
        samples.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / M as f64);
    }
    p50(&mut samples)
}

fn bench(c: &mut Criterion) {
    let h = host();
    let report = |name: &str, flp: f64, gp: f64| {
        println!(
            "RNG_{} fl_p50_ns_per_call={flp:.4} glibc_p50_ns_per_call={gp:.4} ratio={:.3}",
            name.to_uppercase(),
            flp / gp
        );
    };
    report(
        "random",
        measure(|| unsafe { fl::random() } as u64),
        measure(|| unsafe { (h.random)() } as u64),
    );
    report(
        "drand48",
        measure(|| unsafe { fl::drand48() }.to_bits()),
        measure(|| unsafe { (h.drand48)() }.to_bits()),
    );
    report(
        "lrand48",
        measure(|| unsafe { fl::lrand48() } as u64),
        measure(|| unsafe { (h.lrand48)() } as u64),
    );
    report(
        "mrand48",
        measure(|| unsafe { fl::mrand48() } as u64),
        measure(|| unsafe { (h.mrand48)() } as u64),
    );

    let mut grp = c.benchmark_group("rng_membrane");
    grp.bench_function("random_fl", |b| b.iter(|| unsafe { fl::random() }));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
