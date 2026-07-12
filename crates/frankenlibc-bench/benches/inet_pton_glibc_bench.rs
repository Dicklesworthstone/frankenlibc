//! Head-to-head `inet_pton` benchmark: frankenlibc vs host glibc (cc/BlackThrush,
//! BOLD-VERIFY). Validates the `ApiFamily::Inet` membrane fast-path additions
//! (observe() + STRICT decide(), commit d3fb26c0d): `inet_pton` is a pure
//! string->address conversion (no syscall), looped when parsing IP lists / ACLs /
//! configs, so the per-call membrane overhead it previously paid was a meaningful
//! fraction.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench inet_pton_glibc_bench --features abi-bench`
//! (PENDING: authored during the disk-low window; to be RUN when disk recovers.)

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::inet_abi as fl;

type InetPtonFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> c_int;

/// Host glibc `inet_pton` via dlmopen so frankenlibc's exported `inet_pton` cannot
/// shadow the baseline.
fn host_inet_pton() -> InetPtonFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"inet_pton\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym inet_pton failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, InetPtonFn>(addr as *mut c_void) }
}

fn bench(c: &mut Criterion) {
    let src = c"192.168.1.100";
    let af = libc::AF_INET;
    let host = host_inet_pton();

    // Sanity: both parse to the same 4-byte network-order address and return 1.
    {
        let mut a = [0u8; 4];
        let mut b = [0u8; 4];
        let ra = unsafe { fl::inet_pton(af, src.as_ptr(), a.as_mut_ptr().cast()) };
        let rb = unsafe { host(af, src.as_ptr(), b.as_mut_ptr().cast()) };
        assert_eq!(ra, 1, "fl::inet_pton should accept a valid IPv4");
        assert_eq!(rb, 1, "glibc inet_pton should accept a valid IPv4");
        assert_eq!(a, b, "inet_pton result mismatch fl vs glibc");
    }

    let mut group = c.benchmark_group("inet_pton_ipv4");
    group.bench_function("frankenlibc_abi", |bencher| {
        bencher.iter(|| {
            let mut out = [0u8; 4];
            let rc = unsafe { fl::inet_pton(af, black_box(src.as_ptr()), out.as_mut_ptr().cast()) };
            black_box((rc, out));
        });
    });
    group.bench_function("host_glibc", |bencher| {
        bencher.iter(|| {
            let mut out = [0u8; 4];
            let rc = unsafe { host(af, black_box(src.as_ptr()), out.as_mut_ptr().cast()) };
            black_box((rc, out));
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
