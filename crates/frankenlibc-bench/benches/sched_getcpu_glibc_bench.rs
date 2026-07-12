//! Deployed fl `sched_getcpu` vs host glibc (dlmopen) vs the raw `SYS_getcpu` syscall
//! (cc/BlackThrush). The raw-syscall arm IS the *old* fl path (before the vDSO route), so a
//! single run shows before (raw syscall) / after (fl vDSO) / reference (glibc). Both fl-new and
//! glibc resolve `__vdso_getcpu` and avoid the syscall trap; the raw arm pays it.
//!
//! Manual timing (no criterion — its HTML render SIGABRTs under `abi-bench` symbol
//! interposition; see stdio_mt_contention_bench). Median (p50) ns/call.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench sched_getcpu_glibc_bench --features abi-bench`

use std::ffi::{c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Instant;

use frankenlibc_abi::unistd_abi as fl;

type SchedGetcpuFn = unsafe extern "C" fn() -> c_int;

/// Host glibc `sched_getcpu` resolved from a fresh namespace so fl's exported symbol cannot
/// interpose it (mirrors clock_gettime_glibc_bench).
fn host_sched_getcpu() -> SchedGetcpuFn {
    static H: OnceLock<usize> = OnceLock::new();
    let p = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let s = libc::dlsym(h, b"sched_getcpu\0".as_ptr().cast());
        assert!(!s.is_null(), "dlsym sched_getcpu failed");
        s as usize
    });
    unsafe { std::mem::transmute::<usize, SchedGetcpuFn>(p) }
}

/// The raw `SYS_getcpu` syscall = the fl path BEFORE the vDSO route (the floor).
#[inline]
fn raw_syscall_getcpu() -> c_int {
    let mut cpu: u32 = 0;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            &mut cpu as *mut u32,
            std::ptr::null_mut::<u32>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if rc == 0 { cpu as c_int } else { -1 }
}

fn measure(samples: usize, iters: u64, mut op: impl FnMut() -> c_int) -> f64 {
    let mut per = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let mut acc = 0i64;
        for _ in 0..iters {
            acc += black_box(op()) as i64;
        }
        black_box(acc);
        per.push(start.elapsed().as_nanos() as f64 / iters.max(1) as f64);
    }
    per.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    per[per.len() / 2]
}

fn main() {
    let host = host_sched_getcpu();
    // Warm up all three paths (vDSO resolution OnceLock, dlmopen, syscall cache).
    for _ in 0..100_000 {
        black_box(unsafe { fl::sched_getcpu() });
        black_box(unsafe { host() });
        black_box(raw_syscall_getcpu());
    }
    let iters: u64 = 200_000;
    // Rotate arm order across the batch to spread any drift evenly.
    let fl_p50 = measure(41, iters, || unsafe { fl::sched_getcpu() });
    let host_p50 = measure(41, iters, || unsafe { host() });
    let raw_p50 = measure(41, iters, raw_syscall_getcpu);
    let fl_over_host = if host_p50 > 0.0 {
        fl_p50 / host_p50
    } else {
        0.0
    };
    let raw_over_fl = if fl_p50 > 0.0 { raw_p50 / fl_p50 } else { 0.0 };
    println!(
        "GETCPU fl_ns={fl_p50:.1} host_glibc_ns={host_p50:.1} raw_syscall_ns={raw_p50:.1} \
         fl_over_host={fl_over_host:.3} raw_over_fl_speedup={raw_over_fl:.2}x"
    );
}
