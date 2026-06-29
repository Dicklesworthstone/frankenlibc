//! Wide-ctype A/B: fl vs host glibc (cc/BlackThrush) — iswalpha/towlower/wcwidth.
//!
//! Per-char Unicode-table lookups, hot in wide text/terminal code. Checks fl's table
//! structure vs glibc's over a mixed codepoint stream (ASCII, Latin-1, CJK). fl module
//! fn vs glibc via dlmopen(LM_ID_NEWLM) with C.UTF-8 set on the loaded libc.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench wctype_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::wchar_abi as flw;

type I2I = unsafe extern "C" fn(u32) -> i32;

struct Host {
    iswalpha: I2I,
    towlower: I2I,
    wcwidth: I2I,
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
        let setloc = libc::dlsym(h, b"setlocale\0".as_ptr().cast());
        if !setloc.is_null() {
            let f = std::mem::transmute::<
                *mut c_void,
                unsafe extern "C" fn(i32, *const std::ffi::c_char) -> *mut std::ffi::c_char,
            >(setloc);
            f(libc::LC_ALL, b"C.UTF-8\0".as_ptr().cast());
        }
        let g = |n: &[u8]| {
            let s = libc::dlsym(h, n.as_ptr().cast());
            assert!(!s.is_null());
            s
        };
        Host {
            iswalpha: std::mem::transmute::<*mut c_void, I2I>(g(b"iswalpha\0")),
            towlower: std::mem::transmute::<*mut c_void, I2I>(g(b"towlower\0")),
            wcwidth: std::mem::transmute::<*mut c_void, I2I>(g(b"wcwidth\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn codepoints() -> Vec<u32> {
    // Mixed: ASCII, Latin-1, Greek/Cyrillic, CJK — realistic text distribution.
    let mut v = Vec::new();
    for c in 0x20u32..0x7f {
        v.push(c);
    }
    for c in [0xE9u32, 0xF1, 0x3B1, 0x416, 0x4E2D, 0x65E5, 0xAC00, 0x1F600] {
        v.push(c);
    }
    v
}

fn measure(cps: &[u32], mut f: impl FnMut(u32) -> i32) -> f64 {
    for _ in 0..50 {
        let mut acc = 0i64;
        for &c in cps {
            acc += f(c) as i64;
        }
        black_box(acc);
    }
    let mut samples = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        let mut acc = 0i64;
        for _ in 0..20 {
            for &c in cps {
                acc += f(c) as i64;
            }
        }
        black_box(acc);
        samples.push(
            t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / (20 * cps.len()) as f64,
        );
    }
    p50(&mut samples)
}

fn bench(c: &mut Criterion) {
    let h = host();
    let cps = codepoints();
    let report = |name: &str, flp: f64, gp: f64| {
        println!(
            "WCTYPE_{} fl_p50_ns_per_call={flp:.4} glibc_p50_ns_per_call={gp:.4} ratio={:.3}",
            name.to_uppercase(),
            flp / gp
        );
    };
    report(
        "iswalpha",
        measure(&cps, |c| unsafe { flw::iswalpha(c) }),
        measure(&cps, |c| unsafe { (h.iswalpha)(c) }),
    );
    report(
        "towlower",
        measure(&cps, |c| unsafe { flw::towlower(c) as i32 }),
        measure(&cps, |c| unsafe { (h.towlower)(c) }),
    );
    report(
        "wcwidth",
        measure(&cps, |c| unsafe { flw::wcwidth(c) }),
        measure(&cps, |c| unsafe { (h.wcwidth)(c) }),
    );

    let mut grp = c.benchmark_group("wctype");
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
