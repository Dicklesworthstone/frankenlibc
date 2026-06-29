//! gmtime_r/timegm A/B: fl vs host glibc (cc/BlackThrush) — time<->broken-down conversion.
//!
//! Hot in logging/timestamps; pure date arithmetic (no printf pipeline). fl module fn vs
//! glibc via dlmopen(LM_ID_NEWLM). Varied epochs (recent, far past/future, leap days).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench gmtime_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::time_abi as fl;

type GmFn = unsafe extern "C" fn(*const i64, *mut libc::tm) -> *mut libc::tm;
type TgFn = unsafe extern "C" fn(*mut libc::tm) -> i64;

struct Host {
    gmtime_r: GmFn,
    timegm: TgFn,
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
            gmtime_r: std::mem::transmute::<*mut c_void, GmFn>(g(b"gmtime_r\0")),
            timegm: std::mem::transmute::<*mut c_void, TgFn>(g(b"timegm\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn epochs() -> Vec<i64> {
    vec![
        1_700_000_000,
        0,
        951_782_400,    // 2000-02-29 leap
        -2_208_988_800, // 1900
        4_102_444_800,  // 2100
        1_234_567_890,
        2_000_000_000,
        86_399,
    ]
}

fn measure(eps: &[i64], mut f: impl FnMut(i64) -> i32) -> f64 {
    for _ in 0..50 {
        let mut acc = 0i64;
        for &e in eps {
            acc += f(e) as i64;
        }
        black_box(acc);
    }
    let mut s = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let mut acc = 0i64;
        for _ in 0..50 {
            for &e in eps {
                acc += f(e) as i64;
            }
        }
        black_box(acc);
        s.push(
            t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / (50 * eps.len()) as f64,
        );
    }
    p50(&mut s)
}

fn bench(c: &mut Criterion) {
    let h = host();
    let eps = epochs();
    // gmtime_r
    let flp = measure(&eps, |e| {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { fl::gmtime_r(&e, &mut tm) };
        tm.tm_yday + tm.tm_hour
    });
    let gp = measure(&eps, |e| {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { (h.gmtime_r)(&e, &mut tm) };
        tm.tm_yday + tm.tm_hour
    });
    println!(
        "GMTIME_R fl_p50_ns_per_call={flp:.4} glibc_p50_ns_per_call={gp:.4} ratio={:.3}",
        flp / gp
    );

    // timegm (broken-down -> epoch)
    let mk = |e: i64, gm: &dyn Fn(i64, &mut libc::tm)| {
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        gm(e, &mut tm);
        tm
    };
    let flp = measure(&eps, |e| {
        let mut tm = mk(e, &|e, t| unsafe {
            fl::gmtime_r(&e, t);
        });
        unsafe { fl::timegm(&mut tm) as i32 }
    });
    let gp = measure(&eps, |e| {
        let mut tm = mk(e, &|e, t| unsafe {
            (h.gmtime_r)(&e, t);
        });
        unsafe { (h.timegm)(&mut tm) as i32 }
    });
    println!(
        "TIMEGM fl_p50_ns_per_call={flp:.4} glibc_p50_ns_per_call={gp:.4} ratio={:.3}",
        flp / gp
    );

    let mut grp = c.benchmark_group("gmtime");
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
