//! Multi-threaded stdio contention benchmark: frankenlibc vs host glibc
//! (cc/BlackThrush, BOLD-VERIFY). The single-threaded benches cannot show the two
//! things this campaign's stdio work is really about:
//!   1. The bd-hqo6b6 gap: fl serializes ALL stdio on the GLOBAL `registry()` Mutex,
//!      so concurrent ops on DIFFERENT streams contend; glibc uses per-FILE locking
//!      and scales. This quantifies the architectural target.
//!   2. The MT value of the shipped lock-removal guards (is_cookie_stream,
//!      sync_memstream/sync_fmemopen, observe/decide membrane fast-paths): each
//!      removes a GLOBAL serialization point, so under contention fewer global-lock
//!      round-trips per op should help even where single-thread microbenches showed
//!      ~0-gain.
//!
//! Design: N threads, each opens its OWN `fmemopen` read stream IN-THREAD (no
//! cross-thread pointer passing → no Send/Sync gymnastics) and drains it with
//! `fgetc`. `thread::scope` joins all before the timed iteration returns. glibc is
//! resolved via `dlmopen(LM_ID_NEWLM)`; each thread uses glibc's own `fmemopen`.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench stdio_mt_contention_bench --features abi-bench`
//!
//! FIRST RUN (cc, 2026-06-27, rch remote ovh-a, sample-size 20 / measure 2s, on
//! current main = the LANDED parking_lot registry swap a564ca8ae): 8-thread
//! `stdio_mt_contention_8t` fl 56.7 ms vs host glibc 6.61 ms => 8.6x LOSS.
//! This quantifies the bd-hqo6b6 architectural target: even with the parking_lot
//! lock swap deployed, fl still serializes ALL stdio on the single global
//! `registry()` Mutex, so 8 threads draining 8 *independent* `fmemopen` streams
//! contend on one lock while glibc's per-FILE locking scales. The lock-IMPL swap
//! (std::sync::Mutex -> parking_lot) cannot close this gap because the
//! bottleneck is the single global serialization POINT, not per-acquire cost;
//! the real fix is per-FILE locking (Arc<Mutex<StdioStream>> resolved outside the
//! registry lock). Recorded so the contention gap is never re-measured blind.

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_abi::stdio_abi as fl;

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FgetcFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

struct HostStdio {
    fmemopen: FmemopenFn,
    fgetc: FgetcFn,
    fclose: FcloseFn,
}

// fn pointers are Send + Sync, so the resolved table is safe to share across threads.
fn host() -> &'static HostStdio {
    static H: OnceLock<HostStdio> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = |n: &[u8]| {
            let s = libc::dlsym(handle, n.as_ptr().cast());
            assert!(!s.is_null(), "dlsym failed");
            s
        };
        HostStdio {
            fmemopen: std::mem::transmute::<*mut c_void, FmemopenFn>(sym(b"fmemopen\0")),
            fgetc: std::mem::transmute::<*mut c_void, FgetcFn>(sym(b"fgetc\0")),
            fclose: std::mem::transmute::<*mut c_void, FcloseFn>(sym(b"fclose\0")),
        }
    })
}

const N: usize = 4096; // bytes drained per stream per thread

fn bench(c: &mut Criterion) {
    let nthreads: usize = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(4);

    let mut group = c.benchmark_group(format!("stdio_mt_contention_{nthreads}t"));

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                for _ in 0..nthreads {
                    s.spawn(|| {
                        // Each thread owns its buffer + stream (opened in-thread).
                        let data = vec![b'x'; N];
                        let fp = unsafe {
                            fl::fmemopen(data.as_ptr() as *mut c_void, N, c"r".as_ptr())
                        };
                        let mut sum = 0i64;
                        for _ in 0..N {
                            sum += unsafe { fl::fgetc(fp) } as i64;
                        }
                        unsafe { fl::fclose(fp) };
                        black_box(sum);
                        black_box(data.as_ptr());
                    });
                }
            });
        });
    });

    let h = host();
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                for _ in 0..nthreads {
                    s.spawn(|| {
                        let data = vec![b'x'; N];
                        let fp = unsafe {
                            (h.fmemopen)(data.as_ptr() as *mut c_void, N, c"r".as_ptr())
                        };
                        let mut sum = 0i64;
                        for _ in 0..N {
                            sum += unsafe { (h.fgetc)(fp) } as i64;
                        }
                        unsafe { (h.fclose)(fp) };
                        black_box(sum);
                        black_box(data.as_ptr());
                    });
                }
            });
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = bench
}
criterion_main!(benches);
