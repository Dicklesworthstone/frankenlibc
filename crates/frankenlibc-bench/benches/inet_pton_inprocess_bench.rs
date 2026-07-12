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

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::inet as core_inet;

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

// Declared directly (the `libc` crate doesn't re-export inet_pton). With NO
// `abi-bench` feature, no frankenlibc no_mangle symbol exists, so this links to the
// REAL, ifunc-resolved, in-process glibc inet_pton.
unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
}

// inet_net_pton lives in libresolv, not libc.
#[link(name = "resolv")]
unsafe extern "C" {
    fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int;
}

fn bench(c: &mut Criterion) {
    let src_bytes = b"192.168.1.100"; // no NUL: core parser takes a byte slice
    let src_cstr = c"192.168.1.100"; // NUL-terminated for libc

    // Sanity: core and real glibc produce the same 4 network-order bytes.
    let mut core_out = [0u8; 4];
    let rc_core = core_inet::inet_pton(AF_INET, src_bytes, &mut core_out);
    let mut gl_out = [0u8; 4];
    let rc_gl = unsafe {
        inet_pton(
            AF_INET,
            src_cstr.as_ptr(),
            gl_out.as_mut_ptr().cast::<c_void>(),
        )
    };
    assert_eq!(rc_core, 1, "core inet_pton should succeed");
    assert_eq!(rc_gl, 1, "glibc inet_pton should succeed");
    assert_eq!(
        core_out, gl_out,
        "core vs real-glibc inet_pton byte mismatch"
    );

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
                inet_pton(
                    AF_INET,
                    black_box(src_cstr.as_ptr()),
                    out.as_mut_ptr().cast::<c_void>(),
                )
            };
            black_box((rc, out));
        });
    });
    group.finish();

    // inet_net_pton (libresolv CIDR network parse). fl core net_pton::parse used a
    // per-call Vec heap alloc for the octets (decimal) / nibbles+octets (hex) that
    // glibc avoids — measure the stack-array rewrite vs real glibc.
    let net_bytes = b"192.168.0.0/24";
    let net_cstr = c"192.168.0.0/24";
    let mut net_core = [0u8; 4];
    let net_core_rc = core_inet::net_pton::parse(net_bytes, &mut net_core);
    let mut net_gl = [0u8; 4];
    let net_gl_rc = unsafe {
        inet_net_pton(
            AF_INET,
            net_cstr.as_ptr(),
            net_gl.as_mut_ptr().cast::<c_void>(),
            4,
        )
    };
    assert_eq!(net_core_rc, Ok(24), "core net_pton should yield /24");
    assert_eq!(net_gl_rc, 24, "glibc inet_net_pton should yield /24");
    assert_eq!(
        net_core, net_gl,
        "core vs real-glibc inet_net_pton byte mismatch"
    );
    let mut netg = c.benchmark_group("inet_net_pton_inprocess_ipv4");
    netg.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut out = [0u8; 4];
            let rc = core_inet::net_pton::parse(black_box(&net_bytes[..]), &mut out);
            black_box((rc, out));
        });
    });
    netg.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut out = [0u8; 4];
            let rc = unsafe {
                inet_net_pton(
                    AF_INET,
                    black_box(net_cstr.as_ptr()),
                    out.as_mut_ptr().cast::<c_void>(),
                    4,
                )
            };
            black_box((rc, out));
        });
    });
    netg.finish();

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
        assert_eq!(
            rcc == 1,
            expect_ok,
            "core inet_pton6 accept/reject wrong for {txt:?}"
        );
        assert_eq!(
            rcc, rcg,
            "core vs glibc rc mismatch for {txt:?} (core={rcc}, glibc={rcg})"
        );
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
                inet_pton(
                    AF_INET6,
                    black_box(v6_cstr.as_ptr()),
                    out.as_mut_ptr().cast::<c_void>(),
                )
            };
            black_box((rc, out));
        });
    });
    g6group.finish();

    // inet_ntop IPv6: format_ipv6_canonical still returns a heap String -> likely a
    // loss vs real glibc. Measure reliably (core inet_ntop_into vs real glibc inet_ntop).
    let addr6: [u8; 16] = c6; // the 16 bytes parsed above
    let mut nt_core = [0u8; 46];
    let n_core = core_inet::inet_ntop_into(AF_INET6, &addr6, &mut nt_core).expect("core ntop6");
    let mut nt_gl = [0i8; 46];
    let p_gl = unsafe {
        inet_ntop(
            AF_INET6,
            addr6.as_ptr().cast::<c_void>(),
            nt_gl.as_mut_ptr(),
            46,
        )
    };
    assert!(!p_gl.is_null(), "glibc inet_ntop6 returned NULL");
    let gl_bytes: &[u8] = unsafe {
        let cs = std::ffi::CStr::from_ptr(nt_gl.as_ptr());
        cs.to_bytes()
    };
    assert_eq!(
        &nt_core[..n_core],
        gl_bytes,
        "core vs glibc inet_ntop6 text mismatch"
    );

    let mut n6group = c.benchmark_group("inet_ntop_inprocess_ipv6");
    n6group.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut out = [0u8; 46];
            let n = core_inet::inet_ntop_into(AF_INET6, black_box(&addr6), &mut out);
            black_box((n, out));
        });
    });
    n6group.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut out = [0i8; 46];
            let p = unsafe {
                inet_ntop(
                    AF_INET6,
                    black_box(addr6.as_ptr()).cast::<c_void>(),
                    out.as_mut_ptr(),
                    46,
                )
            };
            black_box((p, out));
        });
    });
    n6group.finish();
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
