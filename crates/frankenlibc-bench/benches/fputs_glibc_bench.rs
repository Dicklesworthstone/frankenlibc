//! Head-to-head end-to-end `fputs` benchmark: frankenlibc vs host glibc
//! (cc/BlackThrush, BOLD-VERIFY). Validates the deployed `fputs` strlen lever
//! (scan_c_str_len -> scan_c_string, commit 66867910e) at the WHOLE-call level —
//! not just the strlen kernel — so the negative-evidence ledger gets a real
//! fl/glibc ratio instead of a kernel-only inference.
//!
//! Both arms write the SAME C string K times into an `fmemopen`-backed write
//! stream, then `rewind` ONCE per K — so the per-call seek cost is amortized
//! 1/K and the measured delta is dominated by `fputs` itself (strlen + buffered
//! copy). glibc is resolved through `dlmopen(LM_ID_NEWLM)` so frankenlibc's
//! exported `fmemopen`/`fputs`/`rewind` symbols cannot shadow the baseline, and
//! glibc's `FILE*` comes from glibc's own `fmemopen` (no cross-libc FILE* mix).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench fputs_glibc_bench --features abi-bench`

use std::ffi::{CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

type FmemopenFn = unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void;
type FputsFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
type RewindFn = unsafe extern "C" fn(*mut c_void);

struct HostStdio {
    fmemopen: FmemopenFn,
    fputs: FputsFn,
    rewind: RewindFn,
}

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
            fputs: std::mem::transmute::<*mut c_void, FputsFn>(sym(b"fputs\0")),
            rewind: std::mem::transmute::<*mut c_void, RewindFn>(sym(b"rewind\0")),
        }
    })
}

const K: usize = 64; // fputs calls per rewind (amortizes seek cost 1/K)

fn bench(c: &mut Criterion) {
    let payloads: &[(&str, usize)] = &[("8B", 8), ("38B", 38), ("200B", 200)];
    let mode = CString::new("w").expect("mode");

    for &(name, n) in payloads {
        let s: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
        let cstr = CString::new(s).expect("payload");
        let arg = cstr.as_ptr();
        let cap = n * K + 16;

        let mut group = c.benchmark_group(format!("fputs_{name}"));
        group.throughput(Throughput::Bytes((n * K) as u64));

        // frankenlibc
        let mut fl_buf = vec![0u8; cap];
        let fl_fp = unsafe { fl::fmemopen(fl_buf.as_mut_ptr() as *mut c_void, cap, mode.as_ptr()) };
        assert!(!fl_fp.is_null(), "fl::fmemopen NULL");
        group.bench_with_input(
            BenchmarkId::new("frankenlibc_abi", name),
            &arg,
            |b, &arg| {
                b.iter(|| {
                    unsafe { fl::rewind(fl_fp) };
                    for _ in 0..K {
                        black_box(unsafe { fl::fputs(black_box(arg), fl_fp) });
                    }
                });
            },
        );
        unsafe { fl::fclose(fl_fp) };

        // host glibc (own fmemopen FILE*)
        let h = host();
        let mut gl_buf = vec![0u8; cap];
        let gl_fp = unsafe { (h.fmemopen)(gl_buf.as_mut_ptr() as *mut c_void, cap, mode.as_ptr()) };
        assert!(!gl_fp.is_null(), "host fmemopen NULL");
        group.bench_with_input(BenchmarkId::new("host_glibc", name), &arg, |b, &arg| {
            b.iter(|| {
                unsafe { (h.rewind)(gl_fp) };
                for _ in 0..K {
                    black_box(unsafe { (h.fputs)(black_box(arg), gl_fp) });
                }
            });
        });

        group.finish();
        drop(fl_buf);
        drop(gl_buf);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench
}
criterion_main!(benches);
