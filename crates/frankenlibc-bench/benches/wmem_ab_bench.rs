//! Wide-mem A/B: fl vs host glibc (cc/BlackThrush) — wmemset/wmemchr/wmemcmp/wmemcpy.
//!
//! 4-byte-element mem ops. Checks fl (std::simd / slice::fill) vs glibc's hand-SIMD over
//! a moderate buffer. fl module fn vs glibc via dlmopen(LM_ID_NEWLM).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench wmem_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::wchar_abi as fl;

type SetFn = unsafe extern "C" fn(*mut u32, u32, usize) -> *mut u32;
type ChrFn = unsafe extern "C" fn(*const u32, u32, usize) -> *mut u32;
type CmpFn = unsafe extern "C" fn(*const u32, *const u32, usize) -> i32;
type CpyFn = unsafe extern "C" fn(*mut u32, *const u32, usize) -> *mut u32;

struct Host {
    wmemset: SetFn,
    wmemchr: ChrFn,
    wmemcmp: CmpFn,
    wmemcpy: CpyFn,
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
            wmemset: std::mem::transmute::<*mut c_void, SetFn>(g(b"wmemset\0")),
            wmemchr: std::mem::transmute::<*mut c_void, ChrFn>(g(b"wmemchr\0")),
            wmemcmp: std::mem::transmute::<*mut c_void, CmpFn>(g(b"wmemcmp\0")),
            wmemcpy: std::mem::transmute::<*mut c_void, CpyFn>(g(b"wmemcpy\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn measure(n: usize, mut body: impl FnMut() -> u64) -> f64 {
    for _ in 0..50 {
        black_box(body());
    }
    let mut s = Vec::new();
    for _ in 0..400 {
        let t = Instant::now();
        for _ in 0..16 {
            black_box(body());
        }
        s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / (16 * n) as f64);
    }
    p50(&mut s)
}

fn bench(c: &mut Criterion) {
    let h = host();
    for &n in &[256usize, 4096] {
        let src: Vec<u32> = (0..n as u32).collect();
        let mut dst = vec![0u32; n];
        let report = |op: &str, flp: f64, gp: f64| {
            println!(
                "WMEM_{}_{} fl_p50_ns_per_elem={flp:.4} glibc_p50_ns_per_elem={gp:.4} ratio={:.3}",
                op,
                n,
                flp / gp
            );
        };
        report(
            "SET",
            measure(n, || unsafe { fl::wmemset(dst.as_mut_ptr(), 0x41, n) }
                as u64),
            measure(n, || unsafe { (h.wmemset)(dst.as_mut_ptr(), 0x41, n) }
                as u64),
        );
        report(
            "CPY",
            measure(
                n,
                || unsafe { fl::wmemcpy(dst.as_mut_ptr(), src.as_ptr(), n) } as u64,
            ),
            measure(
                n,
                || unsafe { (h.wmemcpy)(dst.as_mut_ptr(), src.as_ptr(), n) } as u64,
            ),
        );
        // wmemchr: needle absent (full scan)
        report(
            "CHR",
            measure(n, || unsafe { fl::wmemchr(src.as_ptr(), 0xFFFF_FFFF, n) }
                as u64),
            measure(n, || unsafe { (h.wmemchr)(src.as_ptr(), 0xFFFF_FFFF, n) }
                as u64),
        );
        // wmemcmp: equal buffers (full scan)
        let b2 = src.clone();
        report(
            "CMP",
            measure(
                n,
                || unsafe { fl::wmemcmp(src.as_ptr(), b2.as_ptr(), n) } as i64 as u64,
            ),
            measure(
                n,
                || unsafe { (h.wmemcmp)(src.as_ptr(), b2.as_ptr(), n) } as i64 as u64,
            ),
        );
    }
    let mut grp = c.benchmark_group("wmem");
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
