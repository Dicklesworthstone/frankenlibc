//! TLS errno accessor benchmarks (bd-hiogf).
//!
//! `__errno_location()` is the hottest accessor in the entire frankenlibc-abi
//! surface — every libc call that wants to set or read `errno` routes through
//! it. The function returns a pointer to the calling thread's errno slot,
//! preferring the Rust thread_local UnsafeCell fast path and falling back to
//! a hashmap-backed slot when TLS is unavailable (e.g. some bootstrap states).
//!
//! These cases collect strict/hardened-mode-agnostic baselines for:
//!   * `errno_location_fastpath` — the steady-state TLS hit on the calling
//!     thread (nearly all production reads).
//!   * `errno_set_then_read_roundtrip` — write-then-read round trip on the
//!     same thread.
//!   * `errno_location_per_thread` — accessor latency when called from a
//!     freshly spawned thread (cold TLS slot init).
//!
//! All three black_box their inputs and outputs; bench-time is wall-clock,
//! Criterion handles iteration count selection.

use std::ffi::c_int;
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;

use criterion::{Criterion, criterion_group, criterion_main};

use frankenlibc_abi::errno_abi;

fn bench_errno_location_fastpath(c: &mut Criterion) {
    // Warm the thread-local slot once so we're measuring the steady-state
    // fastpath, not the first-call init latency (covered separately below).
    let _ = unsafe { errno_abi::__errno_location() };
    c.bench_function("errno_location_fastpath", |b| {
        b.iter(|| {
            let p = unsafe { errno_abi::__errno_location() };
            black_box(p);
        });
    });
}

fn bench_errno_set_then_read_roundtrip(c: &mut Criterion) {
    let _ = unsafe { errno_abi::__errno_location() };
    c.bench_function("errno_set_then_read_roundtrip", |b| {
        b.iter(|| {
            let p = unsafe { errno_abi::__errno_location() };
            unsafe {
                *p = black_box(42 as c_int);
            }
            let v = unsafe { *p };
            black_box(v);
        });
    });
}

fn bench_errno_location_per_thread(c: &mut Criterion) {
    // Per-thread cold TLS slot init. Each iteration spawns a thread, syncs at
    // a barrier so the call latency dominates over thread startup, calls
    // __errno_location once, and joins.
    c.bench_function("errno_location_per_thread", |b| {
        b.iter(|| {
            let barrier = Arc::new(Barrier::new(2));
            let b2 = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                b2.wait();
                let p = unsafe { errno_abi::__errno_location() };
                black_box(p);
            });
            barrier.wait();
            handle.join().expect("errno bench thread panicked");
        });
    });
}

criterion_group!(
    benches,
    bench_errno_location_fastpath,
    bench_errno_set_then_read_roundtrip,
    bench_errno_location_per_thread
);
criterion_main!(benches);
