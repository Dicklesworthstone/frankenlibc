//! Hot string-family small-size A/B: fl vs host glibc (cc/BlackThrush).
//!
//! At small sizes the per-call StringMemory membrane tax dominates; this finds which fns
//! still pay it (memset was fixed via the strict-skip). fl module fn vs glibc via dlmopen.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench string_family_small_ab_bench`

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::string_abi as fl;

type LenFn = unsafe extern "C" fn(*const c_char) -> usize;
type CmpFn = unsafe extern "C" fn(*const c_char, *const c_char) -> i32;
type ChrFn = unsafe extern "C" fn(*const c_char, i32) -> *mut c_char;
type MchrFn = unsafe extern "C" fn(*const c_void, i32, usize) -> *mut c_void;
type McmpFn = unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32;
type MmvFn = unsafe extern "C" fn(*mut c_void, *const c_void, usize) -> *mut c_void;

struct Host {
    strlen: LenFn,
    strcmp: CmpFn,
    strchr: ChrFn,
    memchr: MchrFn,
    memcmp: McmpFn,
    memmove: MmvFn,
}

fn host() -> &'static Host {
    static H: OnceLock<Host> = OnceLock::new();
    H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        let g = |n: &[u8]| {
            let s = libc::dlsym(h, n.as_ptr().cast());
            assert!(!s.is_null());
            s
        };
        Host {
            strlen: std::mem::transmute::<*mut c_void, LenFn>(g(b"strlen\0")),
            strcmp: std::mem::transmute::<*mut c_void, CmpFn>(g(b"strcmp\0")),
            strchr: std::mem::transmute::<*mut c_void, ChrFn>(g(b"strchr\0")),
            memchr: std::mem::transmute::<*mut c_void, MchrFn>(g(b"memchr\0")),
            memcmp: std::mem::transmute::<*mut c_void, McmpFn>(g(b"memcmp\0")),
            memmove: std::mem::transmute::<*mut c_void, MmvFn>(g(b"memmove\0")),
        }
    })
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn measure(mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..100 {
        black_box(f());
    }
    let mut s = Vec::new();
    for _ in 0..400 {
        let t = Instant::now();
        let mut acc = 0u64;
        for _ in 0..64 {
            acc = acc.wrapping_add(f());
        }
        black_box(acc);
        s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / 64.0);
    }
    p50(&mut s)
}

fn bench(c: &mut Criterion) {
    let h = host();
    // 32-byte NUL-terminated buffers (small — membrane-tax-dominated regime).
    let a: Vec<c_char> = b"the quick brown fox jumps abcde\0"
        .iter()
        .map(|&b| b as c_char)
        .collect();
    let b: Vec<c_char> = b"the quick brown fox jumps abcde\0"
        .iter()
        .map(|&b| b as c_char)
        .collect();
    let n = 31usize;
    let mut dst = vec![0u8; 64];
    let rep = |name: &str, flp: f64, gp: f64| {
        println!(
            "STRFAM_{} fl_p50_ns={flp:.4} glibc_p50_ns={gp:.4} ratio={:.3}",
            name,
            flp / gp
        );
    };
    rep(
        "strlen",
        measure(|| unsafe { fl::strlen(black_box(a.as_ptr())) } as u64),
        measure(|| unsafe { (h.strlen)(black_box(a.as_ptr())) } as u64),
    );
    rep(
        "strcmp",
        measure(
            || unsafe { fl::strcmp(black_box(a.as_ptr()), black_box(b.as_ptr())) } as i64 as u64,
        ),
        measure(
            || unsafe { (h.strcmp)(black_box(a.as_ptr()), black_box(b.as_ptr())) } as i64 as u64,
        ),
    );
    rep(
        "strchr",
        measure(|| unsafe { fl::strchr(black_box(a.as_ptr()), b'z' as i32) } as usize as u64),
        measure(|| unsafe { (h.strchr)(black_box(a.as_ptr()), b'z' as i32) } as usize as u64),
    );
    rep(
        "memchr",
        measure(
            || unsafe { fl::memchr(black_box(a.as_ptr().cast()), b'z' as i32, n) } as usize as u64,
        ),
        measure(
            || unsafe { (h.memchr)(black_box(a.as_ptr().cast()), b'z' as i32, n) } as usize as u64,
        ),
    );
    rep(
        "memcmp",
        measure(|| unsafe {
            fl::memcmp(
                black_box(a.as_ptr().cast()),
                black_box(b.as_ptr().cast()),
                n,
            )
        } as i64 as u64),
        measure(|| unsafe {
            (h.memcmp)(
                black_box(a.as_ptr().cast()),
                black_box(b.as_ptr().cast()),
                n,
            )
        } as i64 as u64),
    );
    rep(
        "memmove",
        measure(|| unsafe {
            fl::memmove(
                black_box(dst.as_mut_ptr().cast()),
                black_box(a.as_ptr().cast()),
                n,
            )
        } as usize as u64),
        measure(|| unsafe {
            (h.memmove)(
                black_box(dst.as_mut_ptr().cast()),
                black_box(a.as_ptr().cast()),
                n,
            )
        } as usize as u64),
    );

    let mut grp = c.benchmark_group("strfam");
    grp.bench_function("noop", |bb| bb.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
