//! Head-to-head span-family benchmark: deployed FrankenLibC vs host glibc for
//! `strcspn`/`strpbrk`/`strspn` with SMALL (2..=4-byte) sets — the hot delimiter
//! case (e.g. `strcspn(s, "\r\n ")` when tokenizing).
//!
//! Lever (NEGATIVE_EVIDENCE follow-up): the deployed strict path used to PRE-SCAN
//! the whole `s` to bound the slice, THEN run a second membership pass — two
//! passes; glibc fuses into one early-stopping pass. The new `scan_c_string_for_set4`
//! makes ONE page-safe early-stopping pass straight from the raw pointer.
//!
//! Two regimes per size: EARLY (a set member sits ~1/8 in, the common short-token
//! case — early stop skips the rest) and ABSENT (no member; full scan to NUL — the
//! pre-scan elimination still removes one whole pass).
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` symbols don't
//! interpose the host's. Run with `FRANKENLIBC_MODE` unset (default strict) so the
//! deployed fast path is active.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};

type SpnFn = unsafe extern "C" fn(*const c_char, *const c_char) -> usize;
type PbrkFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

fn host(sym: &[u8]) -> *mut c_void {
    static H: OnceLock<usize> = OnceLock::new();
    let handle = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        h as usize
    });
    let p = unsafe { libc::dlsym(handle as *mut c_void, sym.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym failed");
    p
}

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let r = q * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi {
        s[lo]
    } else {
        s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
    }
}

const SIZES: &[usize] = &[64, 256, 4096];

fn build(size: usize, early: bool) -> Vec<u8> {
    // Body of 'a' (never in the set), a terminating NUL. Set = b"|;," (3 chars).
    let mut buf = vec![b'a'; size];
    if early {
        let pos = (size / 8).max(1);
        buf[pos] = b';'; // a set member ~1/8 in
    }
    buf.push(0);
    buf
}

fn bench(c: &mut Criterion) {
    let g_spn: SpnFn = unsafe { std::mem::transmute(host(b"strcspn\0")) };
    let g_pbrk: PbrkFn = unsafe { std::mem::transmute(host(b"strpbrk\0")) };
    let g_strspn: SpnFn = unsafe { std::mem::transmute(host(b"strspn\0")) };
    let set = b"|;,\0".as_ptr().cast::<c_char>();
    let accept = b"a\0".as_ptr().cast::<c_char>(); // strspn: leading run of 'a'

    let mut group = c.benchmark_group("fused_span");
    group.sample_size(50);

    for &size in SIZES {
        for &early in &[true, false] {
            let regime = if early { "early" } else { "absent" };
            let buf = build(size, early);
            let p = buf.as_ptr().cast::<c_char>();
            // strspn buffer: all 'a' until either the early ';' or NUL.
            let sp_buf = build(size, early);
            let sp = sp_buf.as_ptr().cast::<c_char>();

            // Verify byte-identity of the deployed path vs glibc before timing.
            unsafe {
                assert_eq!(
                    frankenlibc_abi::string_abi::strcspn(p, set),
                    g_spn(p, set),
                    "strcspn fl!=glibc size={size} {regime}"
                );
                let fp = frankenlibc_abi::string_abi::strpbrk(p, set);
                let gp = g_pbrk(p, set);
                assert_eq!(fp.is_null(), gp.is_null(), "strpbrk null disagree");
                if !fp.is_null() {
                    assert_eq!(fp as usize - p as usize, gp as usize - p as usize);
                }
                assert_eq!(
                    frankenlibc_abi::string_abi::strspn(sp, accept),
                    g_strspn(sp, accept),
                    "strspn fl!=glibc size={size} {regime}"
                );
            }

            let runs = 2000u64;
            // Time a deployed-fl fn vs its glibc twin, same-process interleaved.
            let mut timeit = |name: &str, fl_fn: &dyn Fn() -> usize, g_fn: &dyn Fn() -> usize| {
                let mut fl_s = Vec::new();
                let mut g_s = Vec::new();
                for _ in 0..120 {
                    let t = Instant::now();
                    for _ in 0..runs {
                        black_box(fl_fn());
                    }
                    fl_s.push(t.elapsed().as_nanos() as f64 / runs as f64);
                    let t = Instant::now();
                    for _ in 0..runs {
                        black_box(g_fn());
                    }
                    g_s.push(t.elapsed().as_nanos() as f64 / runs as f64);
                }
                let (flp, gp) = (pctl(&fl_s, 0.50), pctl(&g_s, 0.50));
                println!(
                    "FUSED_SPAN fn={name} size={size} regime={regime} \
                     fl_p50={flp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}",
                    flp / gp
                );
            };

            timeit(
                "strcspn",
                &|| unsafe { frankenlibc_abi::string_abi::strcspn(black_box(p), black_box(set)) },
                &|| unsafe { g_spn(black_box(p), black_box(set)) },
            );
            timeit(
                "strpbrk",
                &|| unsafe {
                    frankenlibc_abi::string_abi::strpbrk(black_box(p), black_box(set)) as usize
                },
                &|| unsafe { g_pbrk(black_box(p), black_box(set)) as usize },
            );
            timeit(
                "strspn",
                &|| unsafe {
                    frankenlibc_abi::string_abi::strspn(black_box(sp), black_box(accept))
                },
                &|| unsafe { g_strspn(black_box(sp), black_box(accept)) },
            );
            let _ = Duration::from_secs(0);
        }
    }
    // Keep criterion happy with one nominal measured target.
    group.bench_function("noop", |b| b.iter(|| black_box(1u64)));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
