//! Host glibc baseline comparisons for top ported libc hot paths.

use std::cell::RefCell;
use std::ffi::c_void;
use std::hint::black_box;
use std::mem;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::malloc::{MallocState, thread_cache::MAGAZINE_CAPACITY};
use frankenlibc_core::stdio::printf::{
    FormatSegment, FormatSpec, format_float, parse_format_string,
};
use frankenlibc_core::string::{
    memchr, memcmp, memcpy, memmem, memmove, memset, strchr, strcmp, strcpy, strlen, strncasecmp,
    strncmp, strpbrk, strrchr, strspn, strstr,
};

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

fn bench_getenv_miss(c: &mut Criterion) {
    let group = c.benchmark_group("glibc_baseline_getenv_miss");
    #[cfg(feature = "abi-bench")]
    let mut group = group;

    #[cfg(feature = "abi-bench")]
    {
        let name = b"FRANKENLIBC_BD_6J8KG9_GETENV_PROFILE_MISS\0";
        // SAFETY: name is NUL-terminated and does not outlive this call.
        unsafe { libc::unsetenv(name.as_ptr().cast()) };
        // SAFETY: name is NUL-terminated.
        assert!(unsafe { frankenlibc_abi::stdlib_abi::getenv(name.as_ptr().cast()) }.is_null());
        // SAFETY: name is NUL-terminated.
        assert!(unsafe { libc::getenv(name.as_ptr().cast()) }.is_null());

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getenv_miss",
                impl_label: "frankenlibc_abi",
                api_family: "stdlib",
                symbol: "getenv",
                workload: "missing environment variable scan",
                parity_proof_ref: "crates/frankenlibc-abi/tests/metamorphic_getenv.rs",
            },
            || {
                // SAFETY: name is NUL-terminated.
                let value = unsafe { frankenlibc_abi::stdlib_abi::getenv(name.as_ptr().cast()) };
                black_box(value);
            },
        );

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getenv_miss",
                impl_label: "host_glibc",
                api_family: "stdlib",
                symbol: "getenv",
                workload: "missing environment variable scan",
                parity_proof_ref: "crates/frankenlibc-abi/tests/metamorphic_getenv.rs",
            },
            || {
                // SAFETY: name is NUL-terminated.
                let value = unsafe { libc::getenv(name.as_ptr().cast()) };
                black_box(value);
            },
        );
    }

    group.finish();
}

fn bench_resolv_services_protocols_abi(c: &mut Criterion) {
    let group = c.benchmark_group("glibc_baseline_resolv_services_protocols");
    #[cfg(feature = "abi-bench")]
    let mut group = group;

    #[cfg(feature = "abi-bench")]
    {
        let service = c"http";
        let proto = c"tcp";

        let fl_service = unsafe {
            frankenlibc_abi::resolv_abi::getservbyname(service.as_ptr(), proto.as_ptr())
                as *mut libc::servent
        };
        let host_service = unsafe { libc::getservbyname(service.as_ptr(), proto.as_ptr()) };
        assert!(
            !fl_service.is_null(),
            "FrankenLibC getservbyname returned NULL"
        );
        assert!(
            !host_service.is_null(),
            "host glibc getservbyname returned NULL"
        );
        assert_eq!(
            unsafe { (*fl_service).s_port },
            unsafe { (*host_service).s_port },
            "getservbyname service port parity"
        );

        let fl_proto = unsafe {
            frankenlibc_abi::resolv_abi::getprotobyname(proto.as_ptr()) as *mut libc::protoent
        };
        let host_proto = unsafe { libc::getprotobyname(proto.as_ptr()) };
        assert!(
            !fl_proto.is_null(),
            "FrankenLibC getprotobyname returned NULL"
        );
        assert!(
            !host_proto.is_null(),
            "host glibc getprotobyname returned NULL"
        );
        assert_eq!(
            unsafe { (*fl_proto).p_proto },
            unsafe { (*host_proto).p_proto },
            "getprotobyname protocol number parity"
        );

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getservbyname_http_tcp",
                impl_label: "frankenlibc_abi",
                api_family: "resolver",
                symbol: "getservbyname",
                workload: "lookup http/tcp through /etc/services",
                parity_proof_ref: "tests/artifacts/perf/bd-9ran7n-byte-decimal-parser.md",
            },
            || {
                let entry = unsafe {
                    frankenlibc_abi::resolv_abi::getservbyname(service.as_ptr(), proto.as_ptr())
                        as *mut libc::servent
                };
                if !entry.is_null() {
                    black_box(unsafe { (*entry).s_port });
                }
                black_box(entry);
            },
        );

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getservbyname_http_tcp",
                impl_label: "host_glibc",
                api_family: "resolver",
                symbol: "getservbyname",
                workload: "lookup http/tcp through /etc/services",
                parity_proof_ref: "tests/artifacts/perf/bd-9ran7n-byte-decimal-parser.md",
            },
            || {
                let entry = unsafe { libc::getservbyname(service.as_ptr(), proto.as_ptr()) };
                if !entry.is_null() {
                    black_box(unsafe { (*entry).s_port });
                }
                black_box(entry);
            },
        );

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getprotobyname_tcp",
                impl_label: "frankenlibc_abi",
                api_family: "resolver",
                symbol: "getprotobyname",
                workload: "lookup tcp through /etc/protocols",
                parity_proof_ref: "tests/artifacts/perf/bd-9ran7n-byte-decimal-parser.md",
            },
            || {
                let entry = unsafe {
                    frankenlibc_abi::resolv_abi::getprotobyname(proto.as_ptr())
                        as *mut libc::protoent
                };
                if !entry.is_null() {
                    black_box(unsafe { (*entry).p_proto });
                }
                black_box(entry);
            },
        );

        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "getprotobyname_tcp",
                impl_label: "host_glibc",
                api_family: "resolver",
                symbol: "getprotobyname",
                workload: "lookup tcp through /etc/protocols",
                parity_proof_ref: "tests/artifacts/perf/bd-9ran7n-byte-decimal-parser.md",
            },
            || {
                let entry = unsafe { libc::getprotobyname(proto.as_ptr()) };
                if !entry.is_null() {
                    black_box(unsafe { (*entry).p_proto });
                }
                black_box(entry);
            },
        );
    }

    group.finish();
}

fn bench_scanf(c: &mut Criterion) {
    use frankenlibc_core::stdio::scanf::{parse_scanf_format, scan_input};
    let dirs = parse_scanf_format(b"%lld");
    let input = b"123456789012345678".to_vec();
    let mut group = c.benchmark_group("glibc_baseline_scanf_long");
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "scanf_long",
            impl_label: "frankenlibc_core",
            api_family: "stdio",
            symbol: "sscanf",
            workload: "%lld of an 18-digit decimal",
            parity_proof_ref: "crates/frankenlibc-core/src/stdio/scanf.rs",
        },
        || {
            black_box(scan_input(black_box(&input), &dirs));
        },
    );
    let cinput = b"123456789012345678\0".to_vec();
    let cfmt = b"%lld\0";
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "scanf_long",
            impl_label: "host_glibc",
            api_family: "stdio",
            symbol: "sscanf",
            workload: "%lld of an 18-digit decimal",
            parity_proof_ref: "crates/frankenlibc-core/src/stdio/scanf.rs",
        },
        || {
            let mut out: libc::c_longlong = 0;
            // SAFETY: NUL-terminated input/format, one %lld -> one long long out.
            unsafe {
                black_box(libc::sscanf(
                    black_box(cinput.as_ptr().cast()),
                    cfmt.as_ptr().cast(),
                    &mut out as *mut libc::c_longlong,
                ));
            }
            black_box(out);
        },
    );
    group.finish();
}

fn bench_strtol(c: &mut Criterion) {
    use frankenlibc_core::stdlib::conversion::strtol;
    for (label, s, base) in &[
        ("strtol_long", &b"123456789012345678\0"[..], 10i32),
        ("strtol_short", &b"42\0"[..], 10),
        ("strtol_hex_long", &b"1a2b3c4d5e6f7a8b\0"[..], 16),
    ] {
        let base = *base;
        let mut group = c.benchmark_group(format!("glibc_baseline_{label}"));
        let bytes = s.to_vec();
        // parity check
        let (fl_v, _) = strtol(&bytes, base);
        let glibc_v = unsafe { libc::strtol(bytes.as_ptr().cast(), std::ptr::null_mut(), base) };
        assert_eq!(fl_v, glibc_v as i64, "{label} parity");
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: label,
                impl_label: "frankenlibc_core",
                api_family: "stdlib",
                symbol: "strtol",
                workload: "base-10 decimal parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                black_box(strtol(black_box(&bytes), base));
            },
        );
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: label,
                impl_label: "host_glibc",
                api_family: "stdlib",
                symbol: "strtol",
                workload: "base-10 decimal parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                // SAFETY: NUL-terminated input, null endptr is allowed.
                unsafe {
                    black_box(libc::strtol(
                        black_box(bytes.as_ptr().cast()),
                        std::ptr::null_mut(),
                        base,
                    ));
                }
            },
        );
        group.finish();
    }

    // strtoul: same SWAR 8-digit base-10 fast path (bd-e4x0vi).
    {
        use frankenlibc_core::stdlib::conversion::strtoul;
        let bytes = b"123456789012345678\0".to_vec();
        let (fl_v, _) = strtoul(&bytes, 10);
        let glibc_v = unsafe { libc::strtoul(bytes.as_ptr().cast(), std::ptr::null_mut(), 10) };
        assert_eq!(fl_v, glibc_v as u64, "strtoul_long parity");
        let mut group = c.benchmark_group("glibc_baseline_strtoul_long");
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "strtoul_long",
                impl_label: "frankenlibc_core",
                api_family: "stdlib",
                symbol: "strtoul",
                workload: "base-10 decimal parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                black_box(strtoul(black_box(&bytes), 10));
            },
        );
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "strtoul_long",
                impl_label: "host_glibc",
                api_family: "stdlib",
                symbol: "strtoul",
                workload: "base-10 decimal parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                // SAFETY: NUL-terminated input, null endptr is allowed.
                unsafe {
                    black_box(libc::strtoul(
                        black_box(bytes.as_ptr().cast()),
                        std::ptr::null_mut(),
                        10,
                    ));
                }
            },
        );
        group.finish();
    }

    // strtoul base-16 (hex) SWAR fast path (bd-76y0j3 follow-up).
    {
        use frankenlibc_core::stdlib::conversion::strtoul;
        let bytes = b"1a2b3c4d5e6f7a8b\0".to_vec();
        let (fl_v, _) = strtoul(&bytes, 16);
        let glibc_v = unsafe { libc::strtoul(bytes.as_ptr().cast(), std::ptr::null_mut(), 16) };
        assert_eq!(fl_v, glibc_v as u64, "strtoul_hex_long parity");
        let mut group = c.benchmark_group("glibc_baseline_strtoul_hex_long");
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "strtoul_hex_long",
                impl_label: "frankenlibc_core",
                api_family: "stdlib",
                symbol: "strtoul",
                workload: "base-16 hex parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                black_box(strtoul(black_box(&bytes), 16));
            },
        );
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "strtoul_hex_long",
                impl_label: "host_glibc",
                api_family: "stdlib",
                symbol: "strtoul",
                workload: "base-16 hex parse",
                parity_proof_ref: "crates/frankenlibc-core/src/stdlib/conversion.rs",
            },
            || {
                // SAFETY: NUL-terminated input, null endptr is allowed.
                unsafe {
                    black_box(libc::strtoul(
                        black_box(bytes.as_ptr().cast()),
                        std::ptr::null_mut(),
                        16,
                    ));
                }
            },
        );
        group.finish();
    }
}

fn bench_memcmp(c: &mut Criterion) {
    for &n in &[16usize, 256, 4096] {
        let mut group = c.benchmark_group(format!("glibc_baseline_memcmp_{n}"));
        group.throughput(Throughput::Bytes(n as u64));
        let a = vec![b'Q'; n];
        let b = vec![b'Q'; n];
        assert_eq!(memcmp(&a, &b, n), core::cmp::Ordering::Equal);
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "memcmp",
                impl_label: "frankenlibc_core",
                api_family: "string",
                symbol: "memcmp",
                workload: "equal N-byte buffers",
                parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
            },
            || {
                black_box(memcmp(black_box(&a), black_box(&b), n));
            },
        );
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "memcmp",
                impl_label: "host_glibc",
                api_family: "string",
                symbol: "memcmp",
                workload: "equal N-byte buffers",
                parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
            },
            || {
                // SAFETY: both buffers are n bytes.
                unsafe {
                    black_box(libc::memcmp(
                        black_box(a.as_ptr().cast()),
                        black_box(b.as_ptr().cast()),
                        n,
                    ));
                }
            },
        );
        group.finish();
    }

    // scanf %llx: SWAR hex fast path in scan_int.
    {
        use frankenlibc_core::stdio::scanf::{parse_scanf_format, scan_input};
        let dirs = parse_scanf_format(b"%llx");
        let input = b"1a2b3c4d5e6f7a8b".to_vec();
        let mut group = c.benchmark_group("glibc_baseline_scanf_hex_long");
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "scanf_hex_long",
                impl_label: "frankenlibc_core",
                api_family: "stdio",
                symbol: "sscanf",
                workload: "%llx of a 16-hex-digit value",
                parity_proof_ref: "crates/frankenlibc-core/src/stdio/scanf.rs",
            },
            || {
                black_box(scan_input(black_box(&input), &dirs));
            },
        );
        let cinput = b"1a2b3c4d5e6f7a8b\0".to_vec();
        let cfmt = b"%llx\0";
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: "scanf_hex_long",
                impl_label: "host_glibc",
                api_family: "stdio",
                symbol: "sscanf",
                workload: "%llx of a 16-hex-digit value",
                parity_proof_ref: "crates/frankenlibc-core/src/stdio/scanf.rs",
            },
            || {
                let mut out: libc::c_ulonglong = 0;
                // SAFETY: NUL-terminated input/format, one %llx -> one ull out.
                unsafe {
                    black_box(libc::sscanf(
                        black_box(cinput.as_ptr().cast()),
                        cfmt.as_ptr().cast(),
                        &mut out as *mut libc::c_ulonglong,
                    ));
                }
                black_box(out);
            },
        );
        group.finish();
    }
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

// 256-byte cycle: unlike the 64-byte profile (which hits the certificate
// fast-path constant), a 256-byte request exercises the general size-class
// certificate path, so this profile reflects whether the diagnostic
// barrier/detail work runs on the hot path for arbitrary sizes.
fn bench_malloc_free_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_malloc_free_256");

    let mut state = MallocState::new();
    let mut next_ptr = 0x4000_0000_usize;
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_free_256",
            impl_label: "frankenlibc_core_state",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "256 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            if let Some(ptr) = state.malloc(256, |size| {
                next_ptr = next_ptr.wrapping_add(size.max(1));
                Some(next_ptr)
            }) {
                state.free(ptr, 256, |_| {});
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
            profile_id: "malloc_free_256",
            impl_label: "host_glibc",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "256 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            // SAFETY: malloc/free are paired in the same iteration.
            unsafe {
                let ptr = libc::malloc(256);
                black_box(ptr);
                if !ptr.is_null() {
                    libc::free(ptr);
                }
            }
        },
    );

    group.finish();
}

fn bench_malloc_cache_pressure_256(c: &mut Criterion) {
    const PRESSURE_OBJECTS: usize = MAGAZINE_CAPACITY + 1;

    let mut group = c.benchmark_group("glibc_baseline_malloc_cache_pressure_256");

    let mut state = MallocState::new();
    let mut next_ptr = 0x6000_0000_usize;
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_cache_pressure_256",
            impl_label: "frankenlibc_core_state",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "65 object 256 byte allocate-free-reallocate cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            let mut ptrs = [0_usize; PRESSURE_OBJECTS];
            for ptr in &mut ptrs {
                *ptr = state
                    .malloc(256, |size| {
                        next_ptr = next_ptr.wrapping_add(size.max(1));
                        Some(next_ptr)
                    })
                    .expect("benchmark allocation");
            }
            for &ptr in &ptrs {
                state.free(ptr, 256, |_| {});
            }

            let mut ptrs = [0_usize; PRESSURE_OBJECTS];
            for ptr in &mut ptrs {
                *ptr = state
                    .malloc(256, |size| {
                        next_ptr = next_ptr.wrapping_add(size.max(1));
                        Some(next_ptr)
                    })
                    .expect("benchmark reallocation");
            }
            for &ptr in &ptrs {
                state.free(ptr, 256, |_| {});
            }

            if state.lifecycle_logs().len() > 2048 {
                let _ = state.drain_lifecycle_logs();
            }
            black_box(ptrs[0]);
        },
    );

    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_cache_pressure_256",
            impl_label: "host_glibc",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "65 object 256 byte allocate-free-reallocate cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            let mut ptrs = [std::ptr::null_mut::<c_void>(); PRESSURE_OBJECTS];
            // SAFETY: every non-null allocation in this iteration is freed exactly once.
            unsafe {
                for ptr in &mut ptrs {
                    *ptr = libc::malloc(256);
                    black_box(*ptr);
                }
                for &ptr in &ptrs {
                    if !ptr.is_null() {
                        libc::free(ptr);
                    }
                }

                let mut ptrs = [std::ptr::null_mut::<c_void>(); PRESSURE_OBJECTS];
                for ptr in &mut ptrs {
                    *ptr = libc::malloc(256);
                    black_box(*ptr);
                }
                for &ptr in &ptrs {
                    if !ptr.is_null() {
                        libc::free(ptr);
                    }
                }
                black_box(ptrs[0]);
            }
        },
    );

    group.finish();
}

// 65536-byte cycle: above MAX_SMALL_SIZE, so it exercises the large-allocator
// path (which built a per-alloc `format!` detail string before this gate).
fn bench_malloc_free_large(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_malloc_free_large");

    let mut state = MallocState::new();
    let mut next_ptr = 0x5000_0000_usize;
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "malloc_free_large",
            impl_label: "frankenlibc_core_state",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "65536 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            if let Some(ptr) = state.malloc(65536, |size| {
                next_ptr = next_ptr.wrapping_add(size.max(1));
                Some(next_ptr)
            }) {
                state.free(ptr, 65536, |_| {});
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
            profile_id: "malloc_free_large",
            impl_label: "host_glibc",
            api_family: "malloc",
            symbol: "malloc/free",
            workload: "65536 byte allocate-free cycle",
            parity_proof_ref: "crates/frankenlibc-core/src/malloc",
        },
        || {
            // SAFETY: malloc/free are paired in the same iteration.
            unsafe {
                let ptr = libc::malloc(65536);
                black_box(ptr);
                if !ptr.is_null() {
                    libc::free(ptr);
                }
            }
        },
    );

    group.finish();
}

fn spec_of(fmt: &[u8]) -> FormatSpec {
    parse_format_string(fmt)
        .as_slice()
        .iter()
        .find_map(|s| match s {
            FormatSegment::Spec(spec) => Some(*spec),
            _ => None,
        })
        .expect("spec")
}

// printf float formatting (%.6f and %.6g) vs glibc snprintf. Sizes the gap on a
// hot path frankenlibc currently services via core::fmt + a per-call heap String.
fn bench_printf_float(c: &mut Criterion) {
    let f_spec = spec_of(b"%.6f");
    let g_spec = spec_of(b"%.6g");
    let value = 12345.678901_f64;

    let mut group = c.benchmark_group("glibc_baseline_printf_float");
    for (profile, spec, cfmt) in [
        ("printf_f_6", f_spec, c"%.6f"),
        ("printf_g_6", g_spec, c"%.6g"),
    ] {
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: profile,
                impl_label: "frankenlibc_core",
                api_family: "stdio",
                symbol: "printf/float",
                workload: "format f64 12345.678901",
                parity_proof_ref: "crates/frankenlibc-core/src/stdio/printf.rs",
            },
            || {
                let mut buf = Vec::with_capacity(32);
                format_float(black_box(value), &spec, &mut buf);
                black_box(&buf);
            },
        );
        bench_op(
            &mut group,
            BenchMeta {
                profile_id: profile,
                impl_label: "host_glibc",
                api_family: "stdio",
                symbol: "printf/float",
                workload: "format f64 12345.678901",
                parity_proof_ref: "crates/frankenlibc-core/src/stdio/printf.rs",
            },
            || {
                let mut buf = [0u8; 64];
                // SAFETY: buf is 64 bytes, format is a valid C string, one f64 arg.
                unsafe {
                    libc::snprintf(
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        cfmt.as_ptr(),
                        black_box(value),
                    );
                }
                black_box(&buf);
            },
        );
    }
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

fn bench_strchr_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strchr_absent");
    let mut s = vec![b'a'; 4096];
    s.push(0); // NUL terminator
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strchr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strchr",
            workload: "4096-byte scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strchr(black_box(&s), b'z'));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strchr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strchr",
            workload: "4096-byte scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: s is NUL-terminated.
            unsafe {
                black_box(libc::strchr(s.as_ptr().cast(), b'z' as i32));
            }
        },
    );
    group.finish();
}

fn bench_strncmp_256_equal(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strncmp_256_equal");
    let a = vec![b'Q'; 257];
    let b = vec![b'Q'; 257];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strncmp_256_equal",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strncmp",
            workload: "256-byte equal compare",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strncmp(black_box(&a), black_box(&b), 256));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strncmp_256_equal",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strncmp",
            workload: "256-byte equal compare",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both buffers are 257 bytes, n=256 stays in bounds.
            unsafe {
                black_box(libc::strncmp(a.as_ptr().cast(), b.as_ptr().cast(), 256));
            }
        },
    );
    group.finish();
}

fn bench_strncasecmp_256_equal(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strncasecmp_256_equal");
    let a = vec![b'q'; 257];
    let b = vec![b'Q'; 257]; // differ only in case
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strncasecmp_256_equal",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strncasecmp",
            workload: "256-byte case-insensitive equal compare",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strncasecmp(black_box(&a), black_box(&b), 256));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strncasecmp_256_equal",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strncasecmp",
            workload: "256-byte case-insensitive equal compare",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both buffers are 257 bytes, n=256 stays in bounds.
            unsafe {
                black_box(libc::strncasecmp(a.as_ptr().cast(), b.as_ptr().cast(), 256));
            }
        },
    );
    group.finish();
}

fn bench_memmove_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_memmove_4096");
    let src = vec![0xABu8; 4096];
    let mut dst = vec![0u8; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memmove_4096",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "memmove",
            workload: "4096-byte non-overlapping move",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            black_box(memmove(black_box(&mut dst), black_box(&src), 4096));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memmove_4096",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "memmove",
            workload: "4096-byte non-overlapping move",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            // SAFETY: dst and src are both 4096 bytes, non-overlapping.
            unsafe {
                black_box(libc::memmove(
                    dst.as_mut_ptr().cast(),
                    src.as_ptr().cast(),
                    4096,
                ));
            }
        },
    );
    group.finish();
}

fn bench_strrchr_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strrchr_absent");
    let mut s = vec![b'a'; 4096];
    s.push(0);
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strrchr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strrchr",
            workload: "4096-byte reverse scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strrchr(black_box(&s), b'z'));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strrchr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strrchr",
            workload: "4096-byte reverse scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: s is NUL-terminated.
            unsafe {
                black_box(libc::strrchr(s.as_ptr().cast(), b'z' as i32));
            }
        },
    );
    group.finish();
}

fn bench_strcpy_4096(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strcpy_4096");
    let mut src = vec![b'a'; 4096];
    src.push(0);
    let mut dst = vec![0u8; 4097];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcpy_4096",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strcpy",
            workload: "4096-byte string copy",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strcpy(black_box(&mut dst), black_box(&src)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcpy_4096",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strcpy",
            workload: "4096-byte string copy",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: src is NUL-terminated, dst has 4097 bytes (room for 4096 + NUL).
            unsafe {
                black_box(libc::strcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast()));
            }
        },
    );
    group.finish();
}

fn bench_memchr_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_memchr_absent");
    let s = vec![b'a'; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memchr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "memchr",
            workload: "4096-byte scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            black_box(memchr(black_box(&s), b'z', 4096));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memchr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "memchr",
            workload: "4096-byte scan for absent byte",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            // SAFETY: s is 4096 bytes, n=4096 stays in bounds.
            unsafe {
                black_box(libc::memchr(s.as_ptr().cast(), b'z' as i32, 4096));
            }
        },
    );
    group.finish();
}

fn bench_strspn_long(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strspn_long");
    // 4096 bytes all in the accept set; large (>4) accept set -> general table path.
    let s = {
        let mut v = vec![b'a'; 4096];
        v.push(0);
        v
    };
    let accept = {
        let mut v = b"abcdefgh".to_vec();
        v.push(0);
        v
    };
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strspn_long",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strspn",
            workload: "4096-byte span over 8-byte accept set",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strspn(black_box(&s), black_box(&accept)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strspn_long",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strspn",
            workload: "4096-byte span over 8-byte accept set",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both s and accept are NUL-terminated.
            unsafe {
                black_box(libc::strspn(s.as_ptr().cast(), accept.as_ptr().cast()));
            }
        },
    );
    group.finish();
}

fn bench_strpbrk_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strpbrk_absent");
    // 4096 bytes, none in the accept set -> full scan, returns None/NULL.
    let s = {
        let mut v = vec![b'a'; 4096];
        v.push(0);
        v
    };
    let accept = {
        let mut v = b"XYZ12345".to_vec();
        v.push(0);
        v
    };
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strpbrk_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strpbrk",
            workload: "4096-byte scan, 8-byte accept set absent",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strpbrk(black_box(&s), black_box(&accept)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strpbrk_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strpbrk",
            workload: "4096-byte scan, 8-byte accept set absent",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both s and accept are NUL-terminated.
            unsafe {
                black_box(libc::strpbrk(s.as_ptr().cast(), accept.as_ptr().cast()));
            }
        },
    );
    group.finish();
}

// Host glibc libm symbols (the `libc` crate does not bind the transcendentals);
// resolved at link time from the C runtime.
mod cmath {
    unsafe extern "C" {
        pub fn exp(x: f64) -> f64;
        pub fn exp2(x: f64) -> f64;
        pub fn sin(x: f64) -> f64;
        pub fn cos(x: f64) -> f64;
        pub fn log(x: f64) -> f64;
        pub fn log2(x: f64) -> f64;
        pub fn pow(x: f64, y: f64) -> f64;
        pub fn powf(x: f32, y: f32) -> f32;
        pub fn expf(x: f32) -> f32;
        pub fn sinh(x: f64) -> f64;
        pub fn cosh(x: f64) -> f64;
        pub fn tanh(x: f64) -> f64;
        pub fn log10(x: f64) -> f64;
        pub fn exp10(x: f64) -> f64;
        pub fn expm1(x: f64) -> f64;
        pub fn log1p(x: f64) -> f64;
        pub fn cbrt(x: f64) -> f64;
        pub fn tan(x: f64) -> f64;
        pub fn atan(x: f64) -> f64;
        pub fn asinh(x: f64) -> f64;
        #[allow(dead_code)]
        pub fn acosh(x: f64) -> f64;
        #[allow(dead_code)]
        pub fn atanh(x: f64) -> f64;
        pub fn erf(x: f64) -> f64;
        pub fn erfc(x: f64) -> f64;
        pub fn tgamma(x: f64) -> f64;
        pub fn lgamma(x: f64) -> f64;
        pub fn coshf(x: f32) -> f32;
        pub fn sinhf(x: f32) -> f32;
        pub fn tanhf(x: f32) -> f32;
        pub fn exp10f(x: f32) -> f32;
        pub fn log10f(x: f32) -> f32;
        pub fn expm1f(x: f32) -> f32;
        pub fn log2f(x: f32) -> f32;
    }
}

// Host glibc `strcasestr` (GNU extension) and `wcsstr`, not bound by `libc`.
mod chost {
    use std::ffi::{c_char, c_int};
    unsafe extern "C" {
        pub fn strcasestr(haystack: *const c_char, needle: *const c_char) -> *mut c_char;
        // wchar_t is c_int (i32) on Linux; bit-compatible with frankenlibc u32.
        pub fn wcsstr(haystack: *const c_int, needle: *const c_int) -> *mut c_int;
    }
}

fn bench_fnmatch_adversarial(c: &mut Criterion) {
    use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};
    let mut group = c.benchmark_group("glibc_baseline_fnmatch_adversarial");
    // Multi-star pattern that triggers exponential backtracking in a naive
    // recursive matcher: "*a*a*...*b" vs an all-'a' text with no 'b'.
    let pattern = b"*a*a*a*a*a*a*b"; // 6 stars
    let pattern_c = b"*a*a*a*a*a*a*b\0";
    let text = b"aaaaaaaaaaaaaaaaaa"; // 18 a, no b
    let text_c = b"aaaaaaaaaaaaaaaaaa\0";
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_adversarial",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star pattern vs 18-char no-match (exponential-backtrack stress)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            black_box(fnmatch_match(
                black_box(pattern),
                black_box(text),
                FnmatchFlags::NONE,
            ));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_adversarial",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star pattern vs 18-char no-match (exponential-backtrack stress)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            // SAFETY: both are NUL-terminated C strings; flags=0.
            unsafe {
                black_box(libc::fnmatch(
                    pattern_c.as_ptr().cast(),
                    text_c.as_ptr().cast(),
                    0,
                ));
            }
        },
    );
    group.finish();
}

fn bench_mbsrtowcs_ascii(c: &mut Criterion) {
    use frankenlibc_core::string::mbtowc;
    use frankenlibc_core::string::wchar::mbs_ascii_prefix;
    let mut group = c.benchmark_group("glibc_baseline_mbsrtowcs_ascii");
    // 4096-byte all-ASCII multibyte string — mbsrtowcs's common case. The new
    // SIMD ASCII prefix vs the previous per-char mbtowc loop.
    let src = vec![b'a'; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "mbsrtowcs_ascii",
            impl_label: "frankenlibc_core",
            api_family: "wchar",
            symbol: "mbsrtowcs",
            workload: "4096-byte ASCII -> wide (SIMD prefix)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wchar.rs",
        },
        || {
            let mut dest = [0u32; 4096];
            black_box(mbs_ascii_prefix(black_box(&mut dest), black_box(&src)));
            black_box(dest[0]);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "mbsrtowcs_ascii",
            impl_label: "frankenlibc_old_perchar",
            api_family: "wchar",
            symbol: "mbsrtowcs",
            workload: "4096-byte ASCII -> wide (old per-char mbtowc loop)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wchar.rs",
        },
        || {
            let mut dest = [0u32; 4096];
            let mut i = 0usize;
            let mut w = 0usize;
            while i < src.len() {
                match mbtowc(black_box(&src[i..])) {
                    Some((wc, used)) => {
                        dest[w] = wc;
                        w += 1;
                        i += used;
                    }
                    None => break,
                }
            }
            black_box(dest[0]);
        },
    );
    group.finish();
}

fn bench_wcsrtombs_ascii(c: &mut Criterion) {
    use frankenlibc_core::string::wchar::wcs_ascii_prefix;
    use frankenlibc_core::string::wctomb;
    let mut group = c.benchmark_group("glibc_baseline_wcsrtombs_ascii");
    // 4096 wide ASCII codepoints — wcsrtombs's common case. The new SIMD ASCII
    // narrow vs the previous per-char wctomb loop.
    let src: Vec<u32> = vec![b'a' as u32; 4096];
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "wcsrtombs_ascii",
            impl_label: "frankenlibc_core",
            api_family: "wchar",
            symbol: "wcsrtombs",
            workload: "4096 wide ASCII -> bytes (SIMD prefix)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wchar.rs",
        },
        || {
            let mut dest = [0u8; 4096];
            black_box(wcs_ascii_prefix(black_box(&mut dest), black_box(&src)));
            black_box(dest[0]);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "wcsrtombs_ascii",
            impl_label: "frankenlibc_old_perchar",
            api_family: "wchar",
            symbol: "wcsrtombs",
            workload: "4096 wide ASCII -> bytes (old per-char wctomb loop)",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wchar.rs",
        },
        || {
            let mut dest = [0u8; 4096];
            let mut w = 0usize;
            for &wc in &src {
                let mut tmp = [0u8; 6];
                match wctomb(black_box(wc), &mut tmp) {
                    Some(n) => {
                        dest[w..w + n].copy_from_slice(&tmp[..n]);
                        w += n;
                    }
                    None => break,
                }
            }
            black_box(dest[0]);
        },
    );
    group.finish();
}

fn bench_fnmatch_bracket(c: &mut Criterion) {
    use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};
    let mut group = c.benchmark_group("glibc_baseline_fnmatch_bracket");
    // Multi-star pattern with bracket classes that backtracks on a no-match:
    // "*[ab]*[ab]*...*c" vs an all-'a'/'b' text with no 'c'.
    let pattern = b"*[ab]*[ab]*[ab]*[ab]*[ab]*c"; // 6 stars + 5 brackets
    let pattern_c = b"*[ab]*[ab]*[ab]*[ab]*[ab]*c\0";
    let text = b"ababababababababab"; // 18 chars, no 'c'
    let text_c = b"ababababababababab\0";
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_bracket",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star+bracket pattern vs 18-char no-match",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            black_box(fnmatch_match(
                black_box(pattern),
                black_box(text),
                FnmatchFlags::NONE,
            ));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_bracket",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star+bracket pattern vs 18-char no-match",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            // SAFETY: both are NUL-terminated C strings; flags=0.
            unsafe {
                black_box(libc::fnmatch(
                    pattern_c.as_ptr().cast(),
                    text_c.as_ptr().cast(),
                    0,
                ));
            }
        },
    );
    group.finish();
}

fn bench_fnmatch_pathname(c: &mut Criterion) {
    use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};
    let mut group = c.benchmark_group("glibc_baseline_fnmatch_pathname");
    // Multi-star pattern under FNM_PATHNAME (the path-matching flag) — exercises
    // the flag-aware iterative matcher vs the old recursive path. No '/' in the
    // text so the '*' backtracks freely within the component.
    let pattern = b"*a*a*a*a*a*a*b"; // 6 stars
    let pattern_c = b"*a*a*a*a*a*a*b\0";
    let text = b"aaaaaaaaaaaaaaaaaa"; // 18 a, no b
    let text_c = b"aaaaaaaaaaaaaaaaaa\0";
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_pathname",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star PATHNAME pattern vs 18-char no-match",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            black_box(fnmatch_match(
                black_box(pattern),
                black_box(text),
                FnmatchFlags::PATHNAME,
            ));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "fnmatch_pathname",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "fnmatch",
            workload: "6-star PATHNAME pattern vs 18-char no-match",
            parity_proof_ref: "crates/frankenlibc-core/src/string/fnmatch.rs",
        },
        || {
            // SAFETY: both are NUL-terminated C strings; FNM_PATHNAME flag.
            unsafe {
                black_box(libc::fnmatch(
                    pattern_c.as_ptr().cast(),
                    text_c.as_ptr().cast(),
                    libc::FNM_PATHNAME,
                ));
            }
        },
    );
    group.finish();
}

fn bench_wcsstr_absent(c: &mut Criterion) {
    use frankenlibc_core::string::wcsstr;
    let mut group = c.benchmark_group("glibc_baseline_wcsstr_absent");
    // 4096 wide 'a' chars; 32-wide common-first-char absent needle — the
    // O(n*m)-vs-O(n) wide Two-Way stress case.
    let mut haystack: Vec<u32> = vec![b'a' as u32; 4096];
    haystack.push(0);
    let mut needle: Vec<u32> = vec![b'a' as u32; 31];
    needle.push(b'b' as u32);
    needle.push(0);
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "wcsstr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "wcsstr",
            workload: "4096-wide 'a' haystack, 32-wide common-first-char absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wide.rs",
        },
        || {
            black_box(wcsstr(black_box(&haystack), black_box(&needle)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "wcsstr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "wcsstr",
            workload: "4096-wide 'a' haystack, 32-wide common-first-char absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/wide.rs",
        },
        || {
            // SAFETY: both buffers are wchar_t (i32) and NUL-terminated.
            unsafe {
                black_box(chost::wcsstr(
                    haystack.as_ptr().cast(),
                    needle.as_ptr().cast(),
                ));
            }
        },
    );
    group.finish();
}

fn bench_strcasestr_absent(c: &mut Criterion) {
    use frankenlibc_core::string::strcasestr;
    let mut group = c.benchmark_group("glibc_baseline_strcasestr_absent");
    // Mixed-case 'a'/'A' run; 32B common-first-byte absent needle — every
    // position is a folded candidate, the O(n*m)-vs-O(n) icase Two-Way stress.
    let mut haystack: Vec<u8> = (0..4096)
        .map(|k| if k % 2 == 0 { b'a' } else { b'A' })
        .collect();
    haystack.push(0);
    let needle = b"aAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaB\0"; // 31 mixed 'a' + 'B', absent
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcasestr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strcasestr",
            workload: "4096B mixed-case haystack, 32B common-first-byte absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strcasestr(black_box(&haystack), black_box(needle)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strcasestr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strcasestr",
            workload: "4096B mixed-case haystack, 32B common-first-byte absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both haystack and needle are NUL-terminated.
            unsafe {
                black_box(chost::strcasestr(
                    haystack.as_ptr().cast(),
                    needle.as_ptr().cast(),
                ));
            }
        },
    );
    group.finish();
}

fn bench_memmem_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_memmem_absent");
    // Common-first-byte absent needle: every position matches the 'a' run then
    // fails at the trailing 'b' — the O(n*m)-vs-O(n) Two-Way stress case.
    let haystack = vec![b'a'; 4096];
    let needle = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"; // 31 a + b, common-first-byte absent
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memmem_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "memmem",
            workload: "4096B all-'a' haystack, common-first-byte 8B absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            black_box(memmem(
                black_box(&haystack),
                4096,
                black_box(needle),
                needle.len(),
            ));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "memmem_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "memmem",
            workload: "4096B all-'a' haystack, common-first-byte 8B absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/mem.rs",
        },
        || {
            // SAFETY: haystack is 4096 bytes, needle is 8 bytes, lengths exact.
            unsafe {
                black_box(libc::memmem(
                    haystack.as_ptr().cast(),
                    4096,
                    needle.as_ptr().cast(),
                    needle.len(),
                ));
            }
        },
    );
    group.finish();
}

fn bench_strstr_absent(c: &mut Criterion) {
    let mut group = c.benchmark_group("glibc_baseline_strstr_absent");
    let mut haystack = vec![b'a'; 4096];
    haystack.push(0);
    let needle = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab\0"; // 31 a + b, absent
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strstr_absent",
            impl_label: "frankenlibc_core",
            api_family: "string",
            symbol: "strstr",
            workload: "4096B all-'a' haystack, common-first-byte 8B absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            black_box(strstr(black_box(&haystack), black_box(needle)));
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "strstr_absent",
            impl_label: "host_glibc",
            api_family: "string",
            symbol: "strstr",
            workload: "4096B all-'a' haystack, common-first-byte 8B absent needle",
            parity_proof_ref: "crates/frankenlibc-core/src/string/str.rs",
        },
        || {
            // SAFETY: both haystack and needle are NUL-terminated.
            unsafe {
                black_box(libc::strstr(
                    haystack.as_ptr().cast(),
                    needle.as_ptr().cast(),
                ));
            }
        },
    );
    group.finish();
}

fn bench_math(c: &mut Criterion) {
    use frankenlibc_core::math;
    let mut group = c.benchmark_group("glibc_baseline_math");

    // Vary the input every call (loop over a table) so the inlinable Rust libm
    // is NOT hoisted out of the timing loop — a constant input made sin/cos look
    // artificially ~4x faster than glibc's opaque extern. Each op sums over all
    // inputs; the franken/glibc ratio is per-batch and hoist-free.
    let inputs: Vec<f64> = (0..64).map(|k| 0.5 + (k as f64) * 0.031_25).collect();

    macro_rules! pair {
        ($id:expr, $sym:expr, $work:expr, $franken:expr, $glibc:expr) => {{
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "frankenlibc_core",
                    api_family: "math",
                    symbol: $sym,
                    workload: $work,
                    parity_proof_ref: "crates/frankenlibc-core/src/math/",
                },
                || {
                    let mut acc = 0.0_f64;
                    for &x in &inputs {
                        let f: fn(f64) -> f64 = $franken;
                        acc += f(black_box(x));
                    }
                    black_box(acc);
                },
            );
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "host_glibc",
                    api_family: "math",
                    symbol: $sym,
                    workload: $work,
                    parity_proof_ref: "crates/frankenlibc-core/src/math/",
                },
                || {
                    let mut acc = 0.0_f64;
                    for &x in &inputs {
                        let g: unsafe extern "C" fn(f64) -> f64 = $glibc;
                        // SAFETY: plain libm call on a finite f64 input.
                        acc += unsafe { g(black_box(x)) };
                    }
                    black_box(acc);
                },
            );
        }};
    }

    pair!("exp", "exp", "exp(x) x in [0.5,2.5)", math::exp, cmath::exp);
    pair!("sin", "sin", "sin(x) x in [0.5,2.5)", math::sin, cmath::sin);
    pair!("cos", "cos", "cos(x) x in [0.5,2.5)", math::cos, cmath::cos);
    pair!("log", "log", "log(x) x in [0.5,2.5)", math::log, cmath::log);
    // log2/exp2 components of the pow fast path: profiling (bd-2g7oyh.116)
    // showed pow's gap lives in log2 (~12.9ns) — 2.3x the cost of exp2 (~5.7ns)
    // — so these standalone head-to-heads track the real pow bottleneck.
    pair!(
        "log2",
        "log2",
        "log2(x) x in [0.5,2.5)",
        math::log2,
        cmath::log2
    );
    pair!(
        "exp2",
        "exp2",
        "exp2(x) x in [0.5,2.5)",
        math::exp2,
        cmath::exp2
    );
    pair!(
        "sinh",
        "sinh",
        "sinh(x) x in [0.5,2.5)",
        math::sinh,
        cmath::sinh
    );
    pair!(
        "cosh",
        "cosh",
        "cosh(x) x in [0.5,2.5)",
        math::cosh,
        cmath::cosh
    );
    pair!(
        "tanh",
        "tanh",
        "tanh(x) x in [0.5,2.5)",
        math::tanh,
        cmath::tanh
    );
    pair!(
        "log10",
        "log10",
        "log10(x) x in [0.5,2.5)",
        math::log10,
        cmath::log10
    );
    pair!(
        "exp10",
        "exp10",
        "exp10(x) x in [0.5,2.5)",
        math::exp10,
        cmath::exp10
    );
    pair!(
        "expm1",
        "expm1",
        "expm1(x) x in [0.5,2.5)",
        math::expm1,
        cmath::expm1
    );
    pair!(
        "log1p",
        "log1p",
        "log1p(x) x in [0.5,2.5)",
        math::log1p,
        cmath::log1p
    );
    pair!(
        "cbrt",
        "cbrt",
        "cbrt(x) x in [0.5,2.5)",
        math::cbrt,
        cmath::cbrt
    );
    pair!("tan", "tan", "tan(x) x in [0.5,2.5)", math::tan, cmath::tan);
    pair!(
        "atan",
        "atan",
        "atan(x) x in [0.5,2.5)",
        math::atan,
        cmath::atan
    );
    pair!(
        "asinh",
        "asinh",
        "asinh(x) x in [0.5,2.5)",
        math::asinh,
        cmath::asinh
    );
    pair!("erf", "erf", "erf(x) x in [0.5,2.5)", math::erf, cmath::erf);
    pair!(
        "erfc",
        "erfc",
        "erfc(x) x in [0.5,2.5)",
        math::erfc,
        cmath::erfc
    );
    pair!(
        "tgamma",
        "tgamma",
        "tgamma(x) x in [0.5,2.5)",
        math::tgamma,
        cmath::tgamma
    );
    pair!(
        "lgamma",
        "lgamma",
        "lgamma(x) x in [0.5,2.5)",
        math::lgamma,
        cmath::lgamma
    );

    // pow is binary — bench it explicitly (exponent 2.5, varying base).
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow",
            impl_label: "frankenlibc_core",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,3) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                acc += math::pow(black_box(x), black_box(3.0));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow",
            impl_label: "host_glibc",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,3) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                // SAFETY: plain libm call on finite f64 inputs.
                acc += unsafe { cmath::pow(black_box(x), black_box(3.0)) };
            }
            black_box(acc);
        },
    );

    // Half-integer exponent (fast path x^2 * sqrt(x)).
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow_half",
            impl_label: "frankenlibc_core",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,2.5) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                acc += math::pow(black_box(x), black_box(2.5));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow_half",
            impl_label: "host_glibc",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,2.5) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                // SAFETY: plain libm call on finite f64 inputs.
                acc += unsafe { cmath::pow(black_box(x), black_box(2.5)) };
            }
            black_box(acc);
        },
    );

    // Irrational exponent: exercises the general pow path rather than the
    // integer or half-integer fast paths.
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow_irrational",
            impl_label: "frankenlibc_core",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,1.337) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                acc += math::pow(black_box(x), black_box(1.337));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "pow_irrational",
            impl_label: "host_glibc",
            api_family: "math",
            symbol: "pow",
            workload: "pow(x,1.337) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs {
                // SAFETY: plain libm call on finite f64 inputs.
                acc += unsafe { cmath::pow(black_box(x), black_box(1.337)) };
            }
            black_box(acc);
        },
    );

    // powf (f32): the fast paths added in float32.rs mirror the f64 `pow` ones.
    // Integer exponent (x^3) exercises the exp-by-squaring fast path; the
    // irrational exponent exercises the medium exp2f/log2f fast path.
    let inputs_f32: Vec<f32> = (0..64).map(|k| 0.5 + (k as f32) * 0.031_25).collect();
    macro_rules! powf_pair {
        ($id:expr, $work:expr, $y:expr) => {{
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "frankenlibc_core",
                    api_family: "math",
                    symbol: "powf",
                    workload: $work,
                    parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
                },
                || {
                    let mut acc = 0.0_f32;
                    for &x in &inputs_f32 {
                        acc += math::powf(black_box(x), black_box($y));
                    }
                    black_box(acc);
                },
            );
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "frankenlibc_old_libm",
                    api_family: "math",
                    symbol: "powf",
                    workload: $work,
                    parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
                },
                || {
                    let mut acc = 0.0_f32;
                    for &x in &inputs_f32 {
                        acc += libm::powf(black_box(x), black_box($y));
                    }
                    black_box(acc);
                },
            );
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "host_glibc",
                    api_family: "math",
                    symbol: "powf",
                    workload: $work,
                    parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
                },
                || {
                    let mut acc = 0.0_f32;
                    for &x in &inputs_f32 {
                        // SAFETY: plain libm call on finite f32 inputs.
                        acc += unsafe { cmath::powf(black_box(x), black_box($y)) };
                    }
                    black_box(acc);
                },
            );
        }};
    }
    powf_pair!("powf_int", "powf(x,3) x in [0.5,2.5)", 3.0f32);
    powf_pair!("powf_irrational", "powf(x,1.337) x in [0.5,2.5)", 1.337f32);

    macro_rules! f32_pair {
        ($id:expr, $sym:expr, $franken:expr, $glibc:expr) => {{
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "frankenlibc_core",
                    api_family: "math",
                    symbol: $sym,
                    workload: concat!($sym, "(x) x in [0.5,2.5)"),
                    parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
                },
                || {
                    let mut acc = 0.0_f32;
                    for &x in &inputs_f32 {
                        let f: fn(f32) -> f32 = $franken;
                        acc += f(black_box(x));
                    }
                    black_box(acc);
                },
            );
            bench_op(
                &mut group,
                BenchMeta {
                    profile_id: $id,
                    impl_label: "host_glibc",
                    api_family: "math",
                    symbol: $sym,
                    workload: concat!($sym, "(x) x in [0.5,2.5)"),
                    parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
                },
                || {
                    let mut acc = 0.0_f32;
                    for &x in &inputs_f32 {
                        let g: unsafe extern "C" fn(f32) -> f32 = $glibc;
                        // SAFETY: plain libm call on a finite f32 input.
                        acc += unsafe { g(black_box(x)) };
                    }
                    black_box(acc);
                },
            );
        }};
    }
    f32_pair!("coshf", "coshf", math::coshf, cmath::coshf);
    f32_pair!("sinhf", "sinhf", math::sinhf, cmath::sinhf);
    f32_pair!("tanhf", "tanhf", math::tanhf, cmath::tanhf);
    f32_pair!("exp10f", "exp10f", math::exp10f, cmath::exp10f);
    f32_pair!("log10f", "log10f", math::log10f, cmath::log10f);
    f32_pair!("expm1f", "expm1f", math::expm1f, cmath::expm1f);
    f32_pair!("log2f", "log2f", math::log2f, cmath::log2f);

    // expf medium fast path (exp2f-based) vs old libm::expf vs glibc.
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "expf_medium",
            impl_label: "frankenlibc_core",
            api_family: "math",
            symbol: "expf",
            workload: "expf(x) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
        },
        || {
            let mut acc = 0.0_f32;
            for &x in &inputs_f32 {
                acc += math::expf(black_box(x));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "expf_medium",
            impl_label: "frankenlibc_old_libm",
            api_family: "math",
            symbol: "expf",
            workload: "expf(x) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
        },
        || {
            let mut acc = 0.0_f32;
            for &x in &inputs_f32 {
                acc += libm::expf(black_box(x));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "expf_medium",
            impl_label: "host_glibc",
            api_family: "math",
            symbol: "expf",
            workload: "expf(x) x in [0.5,2.5)",
            parity_proof_ref: "crates/frankenlibc-core/src/math/float32.rs",
        },
        || {
            let mut acc = 0.0_f32;
            for &x in &inputs_f32 {
                // SAFETY: plain libm call on finite f32 inputs.
                acc += unsafe { cmath::expf(black_box(x)) };
            }
            black_box(acc);
        },
    );

    // exp(f64) over [-4,4]: this range is mostly OUTSIDE the old [0.5,2.5) gate,
    // so the old fast path covered almost none of it (fell to slow libm::exp).
    // The widened [-5,5] gate now fast-paths it all.
    let inputs_wide: Vec<f64> = (0..64).map(|k| -4.0 + (k as f64) * 0.125).collect();
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "exp_wide",
            impl_label: "frankenlibc_core",
            api_family: "math",
            symbol: "exp",
            workload: "exp(x) x in [-4,4]",
            parity_proof_ref: "crates/frankenlibc-core/src/math/exp.rs",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs_wide {
                acc += math::exp(black_box(x));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "exp_wide",
            impl_label: "frankenlibc_old_libm",
            api_family: "math",
            symbol: "exp",
            workload: "exp(x) x in [-4,4]",
            parity_proof_ref: "crates/frankenlibc-core/src/math/exp.rs",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs_wide {
                acc += libm::exp(black_box(x));
            }
            black_box(acc);
        },
    );
    bench_op(
        &mut group,
        BenchMeta {
            profile_id: "exp_wide",
            impl_label: "host_glibc",
            api_family: "math",
            symbol: "exp",
            workload: "exp(x) x in [-4,4]",
            parity_proof_ref: "crates/frankenlibc-core/src/math/exp.rs",
        },
        || {
            let mut acc = 0.0_f64;
            for &x in &inputs_wide {
                // SAFETY: plain libm call on finite f64 inputs.
                acc += unsafe { cmath::exp(black_box(x)) };
            }
            black_box(acc);
        },
    );

    group.finish();
}

// Deployed-ABI math head-to-head: unlike bench_math (pure `frankenlibc_core`
// kernels), this benches the real `frankenlibc_abi` entry points, which route
// through `unary_entry` (runtime_policy decide/observe membrane) per call. It
// isolates the deployed per-call membrane overhead vs the core wins — answering
// whether deployed fl math still beats glibc.
fn bench_math_abi(c: &mut Criterion) {
    #[allow(unused_mut)]
    let mut group = c.benchmark_group("glibc_baseline_math_abi");
    #[cfg(feature = "abi-bench")]
    {
        use frankenlibc_abi::math_abi;
        use frankenlibc_core::math as core_math;
        let inputs: Vec<f64> = (0..64).map(|k| 0.5 + (k as f64) * 0.031_25).collect();
        // SAME-RUN core + abi + glibc, so the core-vs-abi membrane delta is
        // measured on ONE worker (no cross-run/worker-variance confounding).
        macro_rules! pair_abi {
            ($id:expr, $sym:expr, $core:expr, $fl:expr, $glibc:expr) => {{
                bench_op(
                    &mut group,
                    BenchMeta {
                        profile_id: $id,
                        impl_label: "frankenlibc_core",
                        api_family: "math",
                        symbol: $sym,
                        workload: "core kernel (no membrane), x in [0.5,2.5)",
                        parity_proof_ref: "crates/frankenlibc-core/src/math/",
                    },
                    || {
                        let mut acc = 0.0_f64;
                        for &x in &inputs {
                            let f: fn(f64) -> f64 = $core;
                            acc += f(black_box(x));
                        }
                        black_box(acc);
                    },
                );
                bench_op(
                    &mut group,
                    BenchMeta {
                        profile_id: $id,
                        impl_label: "frankenlibc_abi",
                        api_family: "math",
                        symbol: $sym,
                        workload: "deployed abi (membrane), x in [0.5,2.5)",
                        parity_proof_ref: "crates/frankenlibc-abi/src/math_abi.rs",
                    },
                    || {
                        let mut acc = 0.0_f64;
                        for &x in &inputs {
                            let f: unsafe extern "C" fn(f64) -> f64 = $fl;
                            // SAFETY: finite f64 input to a deployed math abi entry.
                            acc += unsafe { f(black_box(x)) };
                        }
                        black_box(acc);
                    },
                );
                bench_op(
                    &mut group,
                    BenchMeta {
                        profile_id: $id,
                        impl_label: "host_glibc",
                        api_family: "math",
                        symbol: $sym,
                        workload: "deployed abi (membrane), x in [0.5,2.5)",
                        parity_proof_ref: "crates/frankenlibc-abi/src/math_abi.rs",
                    },
                    || {
                        let mut acc = 0.0_f64;
                        for &x in &inputs {
                            let g: unsafe extern "C" fn(f64) -> f64 = $glibc;
                            // SAFETY: plain libm call on a finite f64 input.
                            acc += unsafe { g(black_box(x)) };
                        }
                        black_box(acc);
                    },
                );
            }};
        }
        pair_abi!("exp_abi", "exp", core_math::exp, math_abi::exp, cmath::exp);
        pair_abi!("sin_abi", "sin", core_math::sin, math_abi::sin, cmath::sin);
        pair_abi!("cos_abi", "cos", core_math::cos, math_abi::cos, cmath::cos);
        pair_abi!("log_abi", "log", core_math::log, math_abi::log, cmath::log);
        pair_abi!("exp2_abi", "exp2", core_math::exp2, math_abi::exp2, cmath::exp2);
        pair_abi!("log2_abi", "log2", core_math::log2, math_abi::log2, cmath::log2);
    }
    group.finish();
}

// Deployed-ABI mem/string head-to-head: benches the real PUBLIC `frankenlibc_abi`
// entry points (string_abi::memset/strcmp/strlen) which carry the membrane
// (stage_context + runtime_policy::decide), vs glibc. Resolves whether the
// membrane erodes the small-op wins (as it does for math) on the deployed path.
fn bench_memstring_abi(c: &mut Criterion) {
    #[allow(unused_mut)]
    let mut group = c.benchmark_group("glibc_baseline_memstring_abi");
    #[cfg(feature = "abi-bench")]
    {
        use frankenlibc_abi::string_abi;
        use std::os::raw::{c_char, c_void};

        let mut s = vec![0x41u8; 4097];
        s[4096] = 0;
        let sp = s.as_ptr() as *const c_char;
        let mut a = vec![0x42u8; 257];
        a[256] = 0;
        let b = a.clone();
        let ap = a.as_ptr() as *const c_char;
        let bp = b.as_ptr() as *const c_char;
        let mut m = vec![0u8; 4096];
        let mp = m.as_mut_ptr() as *mut c_void;
        // Short, early-mismatch strcmp: glibc returns at byte 2 (~3 ns); the
        // deployed fl path pays its fixed ~82 ns membrane regardless -> predicts
        // a clear deployed LOSS (tests the membrane-on-cheap-op caveat).
        let sa = b"ab\0\0\0\0\0\0".to_vec();
        let sb = b"ac\0\0\0\0\0\0".to_vec();
        let sap = sa.as_ptr() as *const c_char;
        let sbp = sb.as_ptr() as *const c_char;

        macro_rules! pair_ms {
            ($id:expr, $sym:expr, $fl:expr, $gl:expr) => {{
                bench_op(&mut group, BenchMeta { profile_id: $id, impl_label: "frankenlibc_abi",
                    api_family: "string", symbol: $sym, workload: "deployed public abi (membrane)",
                    parity_proof_ref: "crates/frankenlibc-abi/src/string_abi.rs" }, $fl);
                bench_op(&mut group, BenchMeta { profile_id: $id, impl_label: "host_glibc",
                    api_family: "string", symbol: $sym, workload: "deployed public abi (membrane)",
                    parity_proof_ref: "crates/frankenlibc-abi/src/string_abi.rs" }, $gl);
            }};
        }
        pair_ms!("strlen_4096_abi", "strlen",
            || { black_box(unsafe { string_abi::strlen(black_box(sp)) }); },
            || { black_box(unsafe { libc::strlen(black_box(sp)) }); });
        pair_ms!("strcmp_256_equal_abi", "strcmp",
            || { black_box(unsafe { string_abi::strcmp(black_box(ap), black_box(bp)) }); },
            || { black_box(unsafe { libc::strcmp(black_box(ap), black_box(bp)) }); });
        pair_ms!("strcmp_short_mismatch_abi", "strcmp",
            || { black_box(unsafe { string_abi::strcmp(black_box(sap), black_box(sbp)) }); },
            || { black_box(unsafe { libc::strcmp(black_box(sap), black_box(sbp)) }); });
        pair_ms!("memset_64_abi", "memset",
            || { black_box(unsafe { string_abi::memset(black_box(mp), 0x5A, 64) }); },
            || { black_box(unsafe { libc::memset(black_box(mp), 0x5A, 64) }); });
        pair_ms!("memset_4096_abi", "memset",
            || { black_box(unsafe { string_abi::memset(black_box(mp), 0x5A, 4096) }); },
            || { black_box(unsafe { libc::memset(black_box(mp), 0x5A, 4096) }); });
    }
    group.finish();
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
        bench_getenv_miss,
        bench_resolv_services_protocols_abi,
        bench_memcmp,
        bench_strtol,
        bench_scanf,
        bench_malloc_free_64,
        bench_malloc_free_256,
        bench_malloc_cache_pressure_256,
        bench_malloc_free_large,
        bench_printf_float,
        bench_qsort_128_i32,
        bench_strchr_absent,
        bench_strrchr_absent,
        bench_strncmp_256_equal,
        bench_strncasecmp_256_equal,
        bench_memmove_4096,
        bench_strcpy_4096,
        bench_memchr_absent,
        bench_strspn_long,
        bench_strpbrk_absent,
        bench_math,
        bench_math_abi,
        bench_memstring_abi,
        bench_memmem_absent,
        bench_strstr_absent,
        bench_strcasestr_absent,
        bench_wcsstr_absent,
        bench_fnmatch_adversarial,
        bench_fnmatch_bracket,
        bench_fnmatch_pathname,
        bench_mbsrtowcs_ascii,
        bench_wcsrtombs_ascii
}
criterion_main!(benches);
