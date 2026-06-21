//! Head-to-head `inet_addr` benchmark: frankenlibc vs host glibc (cc/BlackThrush,
//! BOLD-VERIFY). `inet_addr` parses the BSD numbers-and-dots grammar via
//! `parse_ipv4_bsd`/`parse_bsd_part`, which (like the strict inet_pton parser did)
//! used `core::str::from_utf8` + `from_str_radix`/`str::parse`. This measures the
//! byte-walk rewrite of that path (sibling of the inet_pton 4.4x win).
//!
//! glibc resolved via `dlmopen(LM_ID_NEWLM)` so fl's exported symbols can't shadow
//! it. A byte-identity sanity assert (fl == glibc, same in_addr_t) runs before timing.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench inet_addr_glibc_bench --features abi-bench`

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};

type InetAddrFn = unsafe extern "C" fn(*const c_char) -> u32;

fn host_inet_addr() -> InetAddrFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"inet_addr\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym inet_addr failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, InetAddrFn>(addr as *mut c_void) }
}

fn bench(c: &mut Criterion) {
    let src = c"192.168.1.100";
    let host = host_inet_addr();

    // Sanity: fl and glibc produce the same in_addr_t.
    let fl_val = unsafe { frankenlibc_abi::inet_abi::inet_addr(src.as_ptr()) };
    let gl_val = unsafe { host(src.as_ptr()) };
    assert_eq!(fl_val, gl_val, "fl::inet_addr != glibc inet_addr");

    let mut group = c.benchmark_group("inet_addr_ipv4");
    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            black_box(unsafe { frankenlibc_abi::inet_abi::inet_addr(black_box(src.as_ptr())) });
        });
    });
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            black_box(unsafe { host(black_box(src.as_ptr())) });
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
