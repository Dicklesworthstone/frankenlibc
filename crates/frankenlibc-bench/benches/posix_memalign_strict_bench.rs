//! Head-to-head aligned-allocator benchmark: FrankenLibC strict host fast-path (CAND) vs the
//! pre-lever hardened membrane arena (ORIG) vs pristine host glibc.
//!
//! Lever: in strict mode, `posix_memalign`/`aligned_alloc`/`memalign` were the only hot alloc
//! entrypoints that still fell through to `pipeline.allocate_aligned` (SipHash fingerprint +
//! canary + generational arena) instead of the host fast path malloc/calloc use. This prices the
//! two mechanisms head-to-head IN ONE BINARY (worker-frequency-stable CAND/ORIG ratio):
//!   - `fl_arena`  : ORIG — `bench_aligned_arena_alloc` (full pre-lever hardened-arena path)
//!   - `fl_strict` : CAND — `bench_aligned_strict_host_alloc` (host aligned alloc + fallback table)
//!   - `glibc`     : pristine host `posix_memalign` via `dlmopen(LM_ID_NEWLM)`.
//!
//! Manual timing (`harness = false`, no criterion) — criterion's HTML report rendering aborts
//! under fl's `abi-bench` symbol interposition, and this bench only needs p50 medians.

use std::ffi::{c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type PosixMemalignFn = unsafe extern "C" fn(*mut *mut c_void, usize, usize) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);

struct HostAllocator {
    posix_memalign: PosixMemalignFn,
    free: FreeFn,
}

fn host_allocator() -> &'static HostAllocator {
    static HOST: OnceLock<HostAllocator> = OnceLock::new();
    HOST.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "failed to dlmopen host libc.so.6");
        let pm = libc::dlsym(handle, b"posix_memalign\0".as_ptr().cast());
        let free = libc::dlsym(handle, b"free\0".as_ptr().cast());
        assert!(
            !pm.is_null() && !free.is_null(),
            "failed to resolve host symbols"
        );
        HostAllocator {
            posix_memalign: std::mem::transmute::<*mut libc::c_void, PosixMemalignFn>(pm),
            free: std::mem::transmute::<*mut libc::c_void, FreeFn>(free),
        }
    })
}

fn p50(mut s: Vec<f64>) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s[s.len() / 2]
}

/// Time `op` (one alloc+free cycle) over `iters` per sample, `samples` samples; return p50 ns/op.
fn measure(samples: usize, iters: u64, mut op: impl FnMut()) -> f64 {
    // Warm up.
    for _ in 0..iters.min(50_000) {
        op();
    }
    let mut per = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iters {
            op();
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        per.push(dur.as_nanos() as f64 / iters as f64);
    }
    p50(per)
}

const ALIGN: usize = 64;
const SIZES: &[usize] = &[64, 256, 4096];
const SAMPLES: usize = 51;
const ITERS: u64 = 20_000;

fn main() {
    let host = host_allocator();
    for &size in SIZES {
        let arena = measure(SAMPLES, ITERS, || {
            let p = frankenlibc_abi::malloc_abi::bench_aligned_arena_alloc(ALIGN, size);
            black_box(p);
            // SAFETY: arena pointer is freeable through the exported free.
            unsafe { frankenlibc_abi::malloc_abi::free(p) };
        });
        let strict = measure(SAMPLES, ITERS, || {
            let p = frankenlibc_abi::malloc_abi::bench_aligned_strict_host_alloc(ALIGN, size);
            black_box(p);
            // SAFETY: host+fallback pointer is freeable through the exported free.
            unsafe { frankenlibc_abi::malloc_abi::free(p) };
        });
        let glibc = measure(SAMPLES, ITERS, || {
            let mut p: *mut c_void = std::ptr::null_mut();
            // SAFETY: host allocator paired with its own free; pointers never cross.
            unsafe {
                let rc = (host.posix_memalign)(&mut p, ALIGN, size);
                black_box(rc);
                black_box(p);
                (host.free)(p);
            }
        });
        let ratio_co = if strict > 0.0 { arena / strict } else { 0.0 };
        let ratio_cg = if glibc > 0.0 { strict / glibc } else { 0.0 };
        let ratio_og = if glibc > 0.0 { arena / glibc } else { 0.0 };
        println!(
            "ALIGNED_BENCH align={ALIGN} size={size} fl_arena_ns={arena:.3} fl_strict_ns={strict:.3} \
             glibc_ns={glibc:.3} arena_over_strict={ratio_co:.3} strict_over_glibc={ratio_cg:.3} \
             arena_over_glibc={ratio_og:.3}"
        );
    }
}
