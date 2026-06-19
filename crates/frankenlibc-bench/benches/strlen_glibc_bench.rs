//! Head-to-head `strlen` benchmark: FrankenLibC vs host glibc (bd-4ibo52).
//!
//! `scan_c_str_len` had a 32-byte page-safe SIMD NUL scan; this measures the
//! length-escalated folded 4x32=128B tier added on top (the technique validated
//! for strchr, bd-4rxozm). glibc via `dlmopen(LM_ID_NEWLM)` to bypass fl's
//! `no_mangle` interposition.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

type StrlenFn = unsafe extern "C" fn(*const c_char) -> usize;

fn host_strlen() -> StrlenFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let p = libc::dlsym(handle, b"strlen\0".as_ptr().cast());
        assert!(!p.is_null(), "dlsym strlen failed");
        p as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, StrlenFn>(addr as *mut c_void) }
}

#[derive(Default)]
struct Stats {
    s: Vec<f64>,
    iters: u64,
    ns: u128,
}
impl Stats {
    fn record(&mut self, ops: u64, dur: Duration) {
        if ops == 0 {
            return;
        }
        self.iters += ops;
        self.ns += dur.as_nanos();
        self.s.push(dur.as_nanos() as f64 / ops as f64);
    }
    fn report(&self, label: &str, size: usize) {
        let mut s = self.s.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p = |q: f64| {
            let r = q * (s.len() - 1) as f64;
            let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
            if lo == hi {
                s[lo]
            } else {
                s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
            }
        };
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        println!(
            "STRLEN_BENCH impl={label} size={size} samples={} p50_ns_op={:.3} \
             p95_ns_op={:.3} mean_ns_op={mean:.3}",
            s.len(),
            p(0.50),
            p(0.95),
        );
    }
}

const SIZES: &[usize] = &[64, 1024, 16384, 65536, 262144];

fn bench(c: &mut Criterion) {
    let host = host_strlen();
    let mut group = c.benchmark_group("strlen");
    group.sample_size(40);

    for &size in SIZES {
        let mut buf = vec![b'a'; size];
        buf.push(0);
        let ptr = buf.as_ptr().cast::<c_char>();

        let fl_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("fl", size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let r = unsafe { frankenlibc_abi::string_abi::strlen(black_box(ptr)) };
                    black_box(r);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                fl_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        fl_stats.borrow().report("fl", size);

        let glibc_stats = std::cell::RefCell::new(Stats::default());
        group.bench_with_input(BenchmarkId::new("glibc", size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let r = unsafe { host(black_box(ptr)) };
                    black_box(r);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                glibc_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        glibc_stats.borrow().report("glibc", size);
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
