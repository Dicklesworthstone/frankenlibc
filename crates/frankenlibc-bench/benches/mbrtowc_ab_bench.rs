//! mbrtowc A/B: fl vs host glibc (cc/BlackThrush) — UTF-8 decode (hot text primitive).
//!
//! Checks whether fl's mbrtowc (ASCII fast path + multibyte decoder) is at parity with
//! glibc's C.UTF-8 decoder, or whether the multibyte path is a lever. fl module fn vs glibc
//! via dlmopen(LM_ID_NEWLM). Separate ASCII and multibyte (2/3-byte) streams.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench mbrtowc_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::wchar_abi as fl;

type MbrtowcFn =
    unsafe extern "C" fn(*mut u32, *const std::ffi::c_char, usize, *mut c_void) -> usize;

fn host_mbrtowc() -> MbrtowcFn {
    static H: OnceLock<usize> = OnceLock::new();
    let p = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        // Match fl's effective C.UTF-8: set the dlmopen'd libc's locale to C.UTF-8.
        let setloc = libc::dlsym(h, b"setlocale\0".as_ptr().cast());
        if !setloc.is_null() {
            let f = std::mem::transmute::<
                *mut c_void,
                unsafe extern "C" fn(i32, *const std::ffi::c_char) -> *mut std::ffi::c_char,
            >(setloc);
            f(libc::LC_ALL, b"C.UTF-8\0".as_ptr().cast());
        }
        libc::dlsym(h, b"mbrtowc\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, MbrtowcFn>(p) }
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn measure(
    buf: &[u8],
    mut f: impl FnMut(*const std::ffi::c_char, usize, *mut c_void) -> usize,
) -> f64 {
    let mut st = [0u8; 16];
    let run = |f: &mut dyn FnMut(*const std::ffi::c_char, usize, *mut c_void) -> usize,
               st: &mut [u8; 16]|
     -> u64 {
        let mut i = 0usize;
        let mut acc = 0u64;
        while i < buf.len() {
            let r = f(
                buf[i..].as_ptr().cast(),
                buf.len() - i,
                st.as_mut_ptr().cast(),
            );
            let step = if (r as isize) <= 0 { 1 } else { r };
            acc = acc.wrapping_add(r as u64);
            i += step;
        }
        acc
    };
    for _ in 0..50 {
        black_box(run(&mut f, &mut st));
    }
    let mut samples = Vec::new();
    for _ in 0..300 {
        let t = Instant::now();
        for _ in 0..20 {
            black_box(run(&mut f, &mut st));
        }
        samples.push(
            t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / (20 * buf.len()) as f64,
        );
    }
    p50(&mut samples)
}

fn bench(c: &mut Criterion) {
    let hf = host_mbrtowc();
    let ascii = "the quick brown fox jumps over the lazy dog 0123456789".repeat(4);
    let multi = "café résumé naïve Москва 日本語 한국어 ".repeat(8);
    for (name, s) in [("ascii", ascii.as_bytes()), ("multibyte", multi.as_bytes())] {
        let flp = measure(s, |p, n, st| unsafe {
            fl::mbrtowc(std::ptr::null_mut(), p, n, st)
        });
        let gp = measure(s, |p, n, st| unsafe { hf(std::ptr::null_mut(), p, n, st) });
        println!(
            "MBRTOWC_{} fl_p50_ns_per_byte={flp:.4} glibc_p50_ns_per_byte={gp:.4} ratio={:.3}",
            name.to_uppercase(),
            flp / gp
        );
    }
    let mut grp = c.benchmark_group("mbrtowc");
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
