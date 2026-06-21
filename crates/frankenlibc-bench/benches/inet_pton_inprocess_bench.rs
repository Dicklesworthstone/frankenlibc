//! RELIABLE in-process inet_pton benchmark: frankenlibc CORE vs REAL in-process
//! glibc (cc/BlackThrush, BOLD-VERIFY).
//!
//! WHY THIS EXISTS (methodology): the `*_glibc_bench` family resolves glibc via
//! `dlmopen(LM_ID_NEWLM)`, which gives an UNRELIABLE baseline for ifunc / locale /
//! namespace-state-sensitive functions (measured glibc `wcsrtombs` at 1.19 ms and
//! `memset` 4 KB at 633 ns — both impossible for real glibc; see NEGATIVE_EVIDENCE.md).
//! This bench links NO frankenlibc ABI symbols (no `abi-bench` feature), so
//! `inet_pton` resolves to the REAL, ifunc-resolved, in-process glibc, while
//! `frankenlibc_core::inet::inet_pton` is callable directly — a trustworthy A/B.
//!
//! inet_pton is pure ASCII / non-ifunc / non-locale, so its dlmopen baseline WAS
//! believable; this confirms the parse_ipv4 byte-walk win on a rock-solid baseline.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench inet_pton_inprocess_bench`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_core::inet as core_inet;

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

// Declared directly (the `libc` crate doesn't re-export inet_pton). With NO
// `abi-bench` feature, no frankenlibc no_mangle symbol exists, so this links to the
// REAL, ifunc-resolved, in-process glibc inet_pton.
unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}

fn bench(c: &mut Criterion) {
    let src_bytes = b"192.168.1.100"; // no NUL: core parser takes a byte slice
    let src_cstr = c"192.168.1.100"; // NUL-terminated for libc

    // Sanity: core and real glibc produce the same 4 network-order bytes.
    let mut core_out = [0u8; 4];
    let rc_core = core_inet::inet_pton(AF_INET, src_bytes, &mut core_out);
    let mut gl_out = [0u8; 4];
    let rc_gl = unsafe { inet_pton(AF_INET, src_cstr.as_ptr(), gl_out.as_mut_ptr().cast::<c_void>()) };
    assert_eq!(rc_core, 1, "core inet_pton should succeed");
    assert_eq!(rc_gl, 1, "glibc inet_pton should succeed");
    assert_eq!(core_out, gl_out, "core vs real-glibc inet_pton byte mismatch");

    let mut group = c.benchmark_group("inet_pton_inprocess_ipv4");
    group.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut out = [0u8; 4];
            let rc = core_inet::inet_pton(AF_INET, black_box(&src_bytes[..]), &mut out);
            black_box((rc, out));
        });
    });
    group.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut out = [0u8; 4];
            let rc = unsafe {
                inet_pton(AF_INET, black_box(src_cstr.as_ptr()), out.as_mut_ptr().cast::<c_void>())
            };
            black_box((rc, out));
        });
    });
    group.finish();

    // IPv6: parse_ipv6 is alloc-heavy (from_utf8 + 2x Vec::collect + 2 group Vecs);
    // measure it against real glibc to decide if the Vec-elimination is warranted.
    let v6_bytes = b"2001:db8:85a3::8a2e:370:7334";
    let v6_cstr = c"2001:db8:85a3::8a2e:370:7334";
    let mut c6 = [0u8; 16];
    let rc_c6 = core_inet::inet_pton(AF_INET6, v6_bytes, &mut c6);
    let mut g6 = [0u8; 16];
    let rc_g6 = unsafe { inet_pton(AF_INET6, v6_cstr.as_ptr(), g6.as_mut_ptr().cast::<c_void>()) };
    assert_eq!(rc_c6, 1, "core inet_pton v6 should succeed");
    assert_eq!(rc_g6, 1, "glibc inet_pton v6 should succeed");
    assert_eq!(c6, g6, "core vs real-glibc inet_pton v6 byte mismatch");

    // Strengthened differential gate: diverse IPv6 forms (::, leading/trailing ::,
    // embedded IPv4, full, loopback, all-zeros) must byte-match real glibc, and
    // invalid forms must both reject. Covers the parse_ipv6 alloc-elimination.
    for (txt, expect_ok) in [
        ("::1", true),
        ("::", true),
        ("2001:db8::", true),
        ("::ffff:192.168.1.1", true),
        ("2001:0db8:0000:0000:0000:ff00:0042:8329", true),
        ("fe80::1ff:fe23:4567:890a", true),
        ("0:0:0:0:0:0:0:1", true),
        ("1:2:3:4:5:6:7:8", true),
        ("a:b:c:d:e:f:1.2.3.4", true),
        ("1:2:3:4:5:6:7:8:9", false),
        ("1::2::3", false),
        ("::g", false),
        ("12345::", false),
        (":1:2:3:4:5:6:7", false),
    ] {
        let cs = std::ffi::CString::new(txt).unwrap();
        let mut cc = [0u8; 16];
        let rcc = core_inet::inet_pton(AF_INET6, txt.as_bytes(), &mut cc);
        let mut gg = [0u8; 16];
        let rcg = unsafe { inet_pton(AF_INET6, cs.as_ptr(), gg.as_mut_ptr().cast::<c_void>()) };
        assert_eq!(rcc == 1, expect_ok, "core inet_pton6 accept/reject wrong for {txt:?}");
        assert_eq!(rcc, rcg, "core vs glibc rc mismatch for {txt:?} (core={rcc}, glibc={rcg})");
        if rcc == 1 {
            assert_eq!(cc, gg, "core vs glibc bytes mismatch for {txt:?}");
        }
    }

    let mut g6group = c.benchmark_group("inet_pton_inprocess_ipv6");
    g6group.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut out = [0u8; 16];
            let rc = core_inet::inet_pton(AF_INET6, black_box(&v6_bytes[..]), &mut out);
            black_box((rc, out));
        });
    });
    g6group.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut out = [0u8; 16];
            let rc = unsafe {
                inet_pton(AF_INET6, black_box(v6_cstr.as_ptr()), out.as_mut_ptr().cast::<c_void>())
            };
            black_box((rc, out));
        });
    });
    g6group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench
}
criterion_main!(benches);
