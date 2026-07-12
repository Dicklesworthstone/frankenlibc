//! Head-to-head `inet_ntop` benchmark: frankenlibc vs host glibc (cc/BlackThrush,
//! BOLD-VERIFY). `inet_ntop(AF_INET)` formats 4 bytes to dotted-decimal via
//! `format_ipv4`, which used `format!("{}.{}.{}.{}")` (a per-call String alloc +
//! generic Display machinery) AND `format_ipv4_len` allocated a second String just
//! to measure length. Measures the byte-level rewrite.
//!
//! glibc resolved via `dlmopen(LM_ID_NEWLM)`. A byte-identity sanity assert (fl ==
//! glibc output string) runs before timing.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench inet_ntop_glibc_bench --features abi-bench`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::inet_abi as fl;

const AF_INET: c_int = 2;

type InetNtopFn = unsafe extern "C" fn(c_int, *const c_void, *mut c_char, u32) -> *const c_char;

fn host_inet_ntop() -> InetNtopFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"inet_ntop\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym inet_ntop failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, InetNtopFn>(addr as *mut c_void) }
}

fn bench(c: &mut Criterion) {
    let src: [u8; 4] = [192, 168, 1, 100]; // network-order address bytes
    let host = host_inet_ntop();

    // Sanity: fl and glibc produce the same text.
    let mut fl_buf = [0i8; 16];
    let mut gl_buf = [0i8; 16];
    let fr = unsafe {
        fl::inet_ntop(
            AF_INET,
            src.as_ptr() as *const c_void,
            fl_buf.as_mut_ptr(),
            16,
        )
    };
    let gr = unsafe {
        host(
            AF_INET,
            src.as_ptr() as *const c_void,
            gl_buf.as_mut_ptr(),
            16,
        )
    };
    assert!(!fr.is_null() && !gr.is_null(), "inet_ntop returned NULL");
    assert_eq!(fl_buf, gl_buf, "fl::inet_ntop != glibc inet_ntop");

    let mut group = c.benchmark_group("inet_ntop_ipv4");
    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0i8; 16];
            let r = unsafe {
                fl::inet_ntop(
                    AF_INET,
                    black_box(src.as_ptr()) as *const c_void,
                    buf.as_mut_ptr(),
                    16,
                )
            };
            black_box((r, buf));
        });
    });
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 16];
            let r = unsafe {
                host(
                    AF_INET,
                    black_box(src.as_ptr()) as *const c_void,
                    buf.as_mut_ptr(),
                    16,
                )
            };
            black_box((r, buf));
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
