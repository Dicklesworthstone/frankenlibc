//! Certified large-allocation malloc/free A/B (bd-mqgee7).
//!
//! fl arm: `frankenlibc_abi::malloc_abi::{malloc, free}` called directly (Rust).
//! glibc arm: dlmopen'd libc.so.6 (fresh namespace — cannot be interposed).
//! Per size: 31 interleaved samples (warm-order cancellation), median reported.
//! Lazy allocations — measures allocator cycle cost, not page-fault cost.
//! bd-mqgee7 probe receipts: 1.6-6.9x at 4KiB-1MiB vs live glibc 2.42.
//!
//! Run: RCH_CARGO_WRAPPER_BYPASS=1 env -u CARGO_TARGET_DIR cargo run \
//!        -p frankenlibc-bench --example malloc_large_ab --release

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

type MallocFn = unsafe extern "C" fn(usize) -> *mut libc::c_void;
type FreeFn = unsafe extern "C" fn(*mut libc::c_void);

fn glibc_syms() -> (MallocFn, FreeFn) {
    static SYMS: OnceLock<(usize, usize)> = OnceLock::new();
    let (m, f) = *SYMS.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let m = libc::dlsym(h, c"malloc".as_ptr().cast());
        let f = libc::dlsym(h, c"free".as_ptr().cast());
        assert!(!m.is_null() && !f.is_null(), "dlsym malloc/free failed");
        (m as usize, f as usize)
    });
    unsafe {
        (
            std::mem::transmute::<usize, MallocFn>(m),
            std::mem::transmute::<usize, FreeFn>(f),
        )
    }
}

fn cycle(m: MallocFn, f: FreeFn, size: usize, iters: usize) -> f64 {
    let t = Instant::now();
    for _ in 0..iters {
        let p = unsafe { black_box(m)(black_box(size)) };
        assert!(!p.is_null(), "malloc({size}) returned null");
        unsafe { black_box(f)(black_box(p)) };
    }
    t.elapsed().as_nanos() as f64 / iters as f64
}

fn main() {
    let fl_malloc: MallocFn = frankenlibc_abi::malloc_abi::malloc;
    let fl_free: FreeFn = frankenlibc_abi::malloc_abi::free;
    let (g_malloc, g_free) = glibc_syms();

    println!("malloc_large_ab (bd-mqgee7): fl vs dlmopen glibc, lazy alloc+free cycles");
    for size in [4096usize, 65_536, 262_144, 1_048_576] {
        let iters = (4_000_000 / size).clamp(64, 4_000);
        let mut fl_v = Vec::with_capacity(31);
        let mut g_v = Vec::with_capacity(31);
        // Warmup (3 unrecorded rounds per arm).
        for _ in 0..3 {
            black_box(cycle(fl_malloc, fl_free, size, 8));
            black_box(cycle(g_malloc, g_free, size, 8));
        }
        // 31 interleaved samples, alternating first-called arm.
        for i in 0..31 {
            let (fv, gv) = if i % 2 == 0 {
                (
                    cycle(fl_malloc, fl_free, size, iters),
                    cycle(g_malloc, g_free, size, iters),
                )
            } else {
                (
                    cycle(g_malloc, g_free, size, iters),
                    cycle(fl_malloc, fl_free, size, iters),
                )
            };
            fl_v.push(fv);
            g_v.push(gv);
        }
        fl_v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        g_v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let (fm, gm) = (fl_v[15], g_v[15]);
        println!(
            "size={:>7}: fl={:>8.1}ns glibc={:>8.1}ns ratio={:.3}",
            size, fm, gm, fm / gm
        );
    }
}
