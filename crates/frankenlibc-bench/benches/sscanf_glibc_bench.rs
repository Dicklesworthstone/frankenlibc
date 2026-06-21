//! Head-to-head `sscanf` benchmark: frankenlibc vs host glibc (cc/BlackThrush,
//! BOLD-VERIFY). Establishes the baseline for the DOCUMENTED-PENDING sscanf
//! known_remaining-lock lever (the strict-gated `scan_c_str_len`→`scan_c_string`
//! swap at the sscanf input scan + the shared `c_str_bytes`/scanf_core format scan).
//! sscanf parses a CALLER STRING (no stream/registry lock), so it is strlen+parse-
//! dominated — a real measurable surface, snprintf("%s")-class.
//!
//! glibc resolved via `dlmopen(LM_ID_NEWLM)`. sscanf is VARIADIC: the host fn type
//! MUST be declared `...` or the AL (SSE vararg count) register is left unset =
//! intermittent crashes (lesson from the sprintf bench).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench sscanf_glibc_bench --features abi-bench`
//! (PENDING: authored during the disk-low window; to be RUN when disk recovers.)

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_abi::stdio_abi as fl;

type SscanfFn = unsafe extern "C" fn(*const c_char, *const c_char, ...) -> c_int;

/// Host glibc `sscanf` via dlmopen. VARIADIC type (see module docs).
fn host_sscanf() -> SscanfFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"sscanf\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym sscanf failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, SscanfFn>(addr as *mut c_void) }
}

fn bench(c: &mut Criterion) {
    let input = c"10 20 30";
    let fmt = c"%d %d %d";
    let host = host_sscanf();

    // Sanity: fl and glibc parse identically (rc=3, same three ints).
    {
        let (mut a, mut b, mut d) = (0i32, 0i32, 0i32);
        let rc = unsafe { fl::sscanf(input.as_ptr(), fmt.as_ptr(), &mut a, &mut b, &mut d) };
        let (mut ga, mut gb, mut gd) = (0i32, 0i32, 0i32);
        let grc = unsafe { host(input.as_ptr(), fmt.as_ptr(), &mut ga, &mut gb, &mut gd) };
        assert_eq!(rc, 3, "fl::sscanf should assign 3 fields");
        assert_eq!(grc, 3, "glibc sscanf should assign 3 fields");
        assert_eq!((a, b, d), (10, 20, 30), "fl::sscanf parsed wrong values");
        assert_eq!((ga, gb, gd), (10, 20, 30), "glibc sscanf parsed wrong values");
    }

    let mut group = c.benchmark_group("sscanf_three_ints");
    group.bench_function("frankenlibc_abi", |bencher| {
        bencher.iter(|| {
            let (mut a, mut b, mut d) = (0i32, 0i32, 0i32);
            let rc = unsafe {
                fl::sscanf(black_box(input.as_ptr()), fmt.as_ptr(), &mut a, &mut b, &mut d)
            };
            black_box((rc, a, b, d));
        });
    });
    group.bench_function("host_glibc", |bencher| {
        bencher.iter(|| {
            let (mut a, mut b, mut d) = (0i32, 0i32, 0i32);
            let rc = unsafe {
                host(black_box(input.as_ptr()), fmt.as_ptr(), &mut a, &mut b, &mut d)
            };
            black_box((rc, a, b, d));
        });
    });
    group.finish();
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
