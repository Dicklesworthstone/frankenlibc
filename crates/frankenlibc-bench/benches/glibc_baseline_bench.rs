//! Host glibc baseline comparisons for top ported libc hot paths.

use std::cell::RefCell;
use std::ffi::c_void;
use std::hint::black_box;
use std::mem;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::malloc::MallocState;
use frankenlibc_core::string::{memcpy, memset, strcmp, strlen};

#[derive(Default)]
struct BenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, meta: BenchMeta) {
        let mut samples = self.samples_ns_per_op.clone();
        if samples.is_empty() {
            return;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile_sorted(&samples, 0.50);
        let p95 = percentile_sorted(&samples, 0.95);
        let p99 = percentile_sorted(&samples, 0.99);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let throughput_ops_s = if self.total_ns == 0 {
            0.0
        } else {
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };

        println!(
            "GLIBC_BASELINE_BENCH profile_id={} impl={} api_family={} symbol={} workload=\"{}\" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3} baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref={}",
            meta.profile_id,
            meta.impl_label,
            meta.api_family,
            meta.symbol,
            meta.workload,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s,
            meta.parity_proof_ref
        );
    }
}

#[derive(Clone, Copy)]
struct BenchMeta {
    profile_id: &'static str,
    impl_label: &'static str,
    api_family: &'static str,
    symbol: &'static str,
    workload: &'static str,
    parity_proof_ref: &'static str,
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn bench_op<F>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    meta: BenchMeta,
    mut op: F,
) where
    F: FnMut(),
{
    for _ in 0..1_000 {
        op();
    }

    let stats = RefCell::new(BenchStats::default());
    group.bench_function(BenchmarkId::new(meta.profile_id, meta.impl_label), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                op();
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    stats.borrow().report(meta);
}

fn bench_memcpy_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_memcpy_4096");
    group.throughput(Throughput::Bytes(4096));

    let src = vec![0xA5_u8; 4096];
    let mut fl_dst = vec![0_u8; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memcpy_4096",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "memcpy",
            workload: "4096 byte copy",
            parity_proof_ref: "tests/conformance/fixtures/string_memory_full",
        },
        || {
            black_box(memcpy(&mut fl_dst, &src, src.len()));
            black_box(fl_dst[0]);
        },
    );

    let mut host_dst = vec![0_u8; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memcpy_4096",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "memcpy",
            workload: "4096 byte copy",
            parity_proof_ref: "tests/conformance/fixtures/string_memory_full",
        },
        || {
            // SAFETY: source and destination are valid 4096-byte non-overlapping buffers.
            unsafe {
                libc::memcpy(
                    host_dst.as_mut_ptr().cast::<c_void>(),
                    src.as_ptr().cast::<c_void>(),
                    src.len(),
                );
            }
            black_box(host_dst[0]);
        },
    );

    group.finish();
}

fn bench_memset_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_memset_4096");
    group.throughput(Throughput::Bytes(4096));

    let mut fl_dst = vec![0_u8; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memset_4096",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "memset",
            workload: "4096 byte fill",
            parity_proof_ref: "tests/conformance/fixtures/string_memory_full",
        },
        || {
            black_box(memset(&mut fl_dst, 0x5A, 4096));
            black_box(fl_dst[4095]);
        },
    );

    let mut host_dst = vec![0_u8; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memset_4096",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "memset",
            workload: "4096 byte fill",
            parity_proof_ref: "tests/conformance/fixtures/string_memory_full",
        },
        || {
            // SAFETY: destination is a valid 4096-byte buffer.
            unsafe {
                libc::memset(host_dst.as_mut_ptr().cast::<c_void>(), 0x5A, 4096);
            }
            black_box(host_dst[4095]);
        },
    );

    group.finish();
}

fn bench_strlen_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strlen_4096");
    group.throughput(Throughput::Bytes(4096));

    let mut input = vec![b'A'; 4096];
    input.push(0);
    assert_eq!(strlen(&input), unsafe {
        // SAFETY: input is NUL-terminated.
        libc::strlen(input.as_ptr().cast())
    });

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strlen_4096",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strlen",
            workload: "4096 byte NUL scan",
            parity_proof_ref: "tests/conformance/fixtures/string_ops",
        },
        || {
            black_box(strlen(&input));
        },
    );

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strlen_4096",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strlen",
            workload: "4096 byte NUL scan",
            parity_proof_ref: "tests/conformance/fixtures/string_ops",
        },
        || {
            // SAFETY: input is NUL-terminated.
            unsafe {
                black_box(libc::strlen(input.as_ptr().cast()));
            }
        },
    );

    group.finish();
}

fn bench_strcmp_256_equal(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strcmp_256_equal");
    group.throughput(Throughput::Bytes(256));

    let mut left = vec![b'Q'; 256];
    let mut right = vec![b'Q'; 256];
    left.push(0);
    right.push(0);
    assert_eq!(strcmp(&left, &right).signum(), unsafe {
        // SAFETY: both inputs are NUL-terminated.
        libc::strcmp(left.as_ptr().cast(), right.as_ptr().cast()).signum()
    });

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcmp_256_equal",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strcmp",
            workload: "equal 256 byte strings",
            parity_proof_ref: "tests/conformance/fixtures/string_ops",
        },
        || {
            black_box(strcmp(&left, &right));
        },
    );

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcmp_256_equal",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strcmp",
            workload: "equal 256 byte strings",
            parity_proof_ref: "tests/conformance/fixtures/string_ops",
        },
        || {
            // SAFETY: both inputs are NUL-terminated.
            unsafe {
                black_box(libc::strcmp(left.as_ptr().cast(), right.as_ptr().cast()));
            }
        },
    );

    group.finish();
}

fn bench_malloc_free_64(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_malloc_free_64");

    let mut state = MallocState::new();
    let mut next_ptr = 0x1000_0000_usize;
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_free_64",
            impl_label: "frankenlibc_core_state",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "64 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            if let Some(ptr) = state.malloc(64, |size| {
                next_ptr = next_ptr.wrapping_add(size.max(1));
                Some(next_ptr)
            }) {
                state.free(ptr, 64, |_| {});
                if state.lifecycle_logs().len() > 2048 {
                    let _ = state.drain_lifecycle_logs();
                }
                black_box(ptr);
            }
        },
    );

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_free_64",
            impl_label: "host_glibc",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "64 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            // SAFETY: malloc/free are paired in the same iteration.
            unsafe {
                let ptr = libc::malloc(64);
                black_box(ptr);
                if !ptr.is_null() {
                    libc::free(ptr);
                }
            }
        },
    );

    group.finish();
}

fn bench_qsort_128_i32(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_qsort_128_i32");
    let template: Vec<i32> = (0..128).rev().map(|value| value * 17 % 97).collect();

    let mut parity_left = template.clone();
    let mut parity_right = template.clone();
    frankenlibc_core::stdlib::qsort(
        i32_slice_as_bytes_mut(&mut parity_left),
        mem::size_of::<i32>(),
        compare_i32_bytes,
    );
    // SAFETY: parity_right is a valid i32 array and comparator reads only one i32 per element.
    unsafe {
        libc::qsort(
            parity_right.as_mut_ptr().cast::<c_void>(),
            parity_right.len(),
            mem::size_of::<i32>(),
            Some(compare_i32_ptr),
        );
    }
    assert_eq!(parity_left, parity_right);

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "qsort_128_i32",
            impl_label: "frankenlibc_core",
            api_family: "stdlib",
            symbol: "qsort",
            workload: "128 i32 reverse-ish input",
            parity_proof_ref: "crates/frankenlibc-core/src/stdlib/sort.rs",
        },
        || {
            let mut values = template.clone();
            frankenlibc_core::stdlib::qsort(
                i32_slice_as_bytes_mut(&mut values),
                mem::size_of::<i32>(),
                compare_i32_bytes,
            );
            black_box(values[0]);
        },
    );

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "qsort_128_i32",
            impl_label: "host_glibc",
            api_family: "stdlib",
            symbol: "qsort",
            workload: "128 i32 reverse-ish input",
            parity_proof_ref: "crates/frankenlibc-core/src/stdlib/sort.rs",
        },
        || {
            let mut values = template.clone();
            // SAFETY: values is a valid i32 array and comparator reads only one i32 per element.
            unsafe {
                libc::qsort(
                    values.as_mut_ptr().cast::<c_void>(),
                    values.len(),
                    mem::size_of::<i32>(),
                    Some(compare_i32_ptr),
                );
            }
            black_box(values[0]);
        },
    );

    group.finish();
}

fn i32_slice_as_bytes_mut(values: &mut [i32]) -> &mut [u8] {
    // SAFETY: the byte slice covers exactly the initialized i32 slice storage.
    unsafe {
        std::slice::from_raw_parts_mut(
            values.as_mut_ptr().cast::<u8>(),
            std::mem::size_of_val(values),
        )
    }
}

fn compare_i32_bytes(left: &[u8], right: &[u8]) -> i32 {
    let Some(left) = left.get(..4) else {
        return 0;
    };
    let Some(right) = right.get(..4) else {
        return 0;
    };
    let lhs = i32::from_ne_bytes([left[0], left[1], left[2], left[3]]);
    let rhs = i32::from_ne_bytes([right[0], right[1], right[2], right[3]]);
    match lhs.cmp(&rhs) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

unsafe extern "C" fn compare_i32_ptr(left: *const c_void, right: *const c_void) -> libc::c_int {
    // SAFETY: qsort passes valid pointers to one i32 element per comparator argument.
    let lhs = unsafe { *(left.cast::<i32>()) };
    // SAFETY: qsort passes valid pointers to one i32 element per comparator argument.
    let rhs = unsafe { *(right.cast::<i32>()) };
    match lhs.cmp(&rhs) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(300));
    targets =
        bench_memcpy_4096,
        bench_memset_4096,
        bench_strlen_4096,
        bench_strcmp_256_equal,
        bench_malloc_free_64,
        bench_qsort_128_i32
}
criterion_main!(benches);
