//! memset/memcpy mid-size A/B: fl vs host glibc (cc/BlackThrush).
//!
//! Settles whether fl's memset/memcpy match glibc across 256B..64KB (the wcsncpy-pad probe
//! suggested fl memset ~2.5x at 4-16KB; this measures it DIRECTLY, free of membrane/wcsncpy
//! overhead). fl module fn vs glibc via dlmopen(LM_ID_NEWLM).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench memset_midsize_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::string_abi as fl;

type SetFn = unsafe extern "C" fn(*mut c_void, i32, usize) -> *mut c_void;
type CpyFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;

struct Host {
    memset: SetFn,
    memcpy: CpyFn,
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
            memset: std::mem::transmute::<*mut c_void, SetFn>(g(b"memset\0")),
            memcpy: std::mem::transmute::<*mut c_void, CpyFn>(g(b"memcpy\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn measure(n: usize, mut body: impl FnMut() -> *mut c_void) -> f64 {
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
    // Correctness of the deployed strict fast-path: fl memset/memcpy must match expected.
    unsafe {
        let mut d = vec![0u8; 100];
        fl::memset(d.as_mut_ptr().cast(), 0x41, 100);
        assert!(
            d.iter().all(|&b| b == 0x41),
            "fl memset strict fast-path wrong"
        );
        let src: Vec<u8> = (0..100u8).collect();
        let mut d2 = vec![0u8; 100];
        fl::memcpy(d2.as_mut_ptr().cast(), src.as_ptr().cast(), 100);
        assert!(d2 == src, "fl memcpy strict fast-path wrong");
    }
    for &n in &[256usize, 1024, 4096, 16384, 65536] {
        let mut dst = vec![0u8; n];
        let src = vec![0x5au8; n];
        let flp = measure(n, || unsafe {
            fl::memset(dst.as_mut_ptr().cast(), 0x41, n)
        });
        let gp = measure(n, || unsafe {
            (h.memset)(dst.as_mut_ptr().cast(), 0x41, n)
        });
        println!(
            "MEMSET_{} fl_ns_per_byte={flp:.5} glibc_ns_per_byte={gp:.5} ratio={:.3}",
            n,
            flp / gp
        );
        let flp = measure(n, || unsafe {
            fl::memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n)
        });
        let gp = measure(n, || unsafe {
            (h.memcpy)(dst.as_mut_ptr().cast(), src.as_ptr().cast(), n)
        });
        println!(
            "MEMCPY_{} fl_ns_per_byte={flp:.5} glibc_ns_per_byte={gp:.5} ratio={:.3}",
            n,
            flp / gp
        );
    }
    let mut grp = c.benchmark_group("memset_mid");
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
