//! strtok_r with a LARGE (>4-byte) delimiter set — deployed FrankenLibC vs glibc.
//!
//! Covers the fused bitmap tokenizer path (delim_len > 4, e.g. the 6-char
//! whitespace set " \t\n\r\x0c\x0b"). Two shapes:
//!   - COMMON: many short tokens (what tokenizers actually do) — ORIG was O(n²).
//!   - ADVERSARIAL: few LONG tokens — stresses the scalar bitmap body scan against
//!     the OLD path's PSHUFB body scan (checks for a regression there).
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)`. Default strict mode.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

type TokFn = unsafe extern "C" fn(*mut c_char, *const c_char, *mut *mut c_char) -> *mut c_char;

fn host_strtok_r() -> TokFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let p = libc::dlsym(h, b"strtok_r\0".as_ptr().cast());
        assert!(!p.is_null(), "dlsym strtok_r failed");
        p as usize
    });
    unsafe { std::mem::transmute::<usize, TokFn>(addr) }
}

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let r = q * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi { s[lo] } else { s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64) }
}

/// `k` tokens each `tok_len` bytes, separated by a single space (a delim member).
fn make_buf(k: usize, tok_len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..k {
        if i > 0 {
            v.push(b' ');
        }
        for j in 0..tok_len {
            v.push(b'A' + ((i + j) % 26) as u8);
        }
    }
    v.push(0);
    v
}

unsafe fn run_host(f: TokFn, template: &[u8], delim: *const c_char) -> usize {
    let mut buf = template.to_vec();
    let mut save: *mut c_char = std::ptr::null_mut();
    let mut cur: *mut c_char = buf.as_mut_ptr().cast();
    let mut n = 0usize;
    loop {
        let tok = unsafe { f(cur, delim, &mut save) };
        if tok.is_null() { break; }
        cur = std::ptr::null_mut();
        n += 1;
    }
    black_box(buf.as_ptr());
    n
}

unsafe fn run_fl(template: &[u8], delim: *const c_char) -> usize {
    let mut buf = template.to_vec();
    let mut save: *mut c_char = std::ptr::null_mut();
    let mut cur: *mut c_char = buf.as_mut_ptr().cast();
    let mut n = 0usize;
    loop {
        let tok = unsafe { frankenlibc_abi::string_abi::strtok_r(cur, delim, &mut save) };
        if tok.is_null() { break; }
        cur = std::ptr::null_mut();
        n += 1;
    }
    black_box(buf.as_ptr());
    n
}

fn bench(c: &mut Criterion) {
    let g = host_strtok_r();
    // 6-char whitespace delimiter set (>4 → fused bitmap path).
    let delim = b" \t\n\r\x0c\x0b\0".as_ptr().cast::<c_char>();

    let mut group = c.benchmark_group("strtok_bigdelim");
    group.sample_size(30);

    // (label, k tokens, tok_len) — common = many short; adversarial = few long.
    let cases: &[(&str, usize, usize)] =
        &[("common_k512x7", 512, 7), ("common_k2048x7", 2048, 7), ("adversarial_k4x4000", 4, 4000)];

    for &(label, k, tl) in cases {
        let template = make_buf(k, tl);
        let fl_n = unsafe { run_fl(&template, delim) };
        let g_n = unsafe { run_host(g, &template, delim) };
        assert_eq!(fl_n, g_n, "token count fl!=glibc {label}");
        assert_eq!(fl_n, k, "expected {k} tokens {label}");

        let iters = 100u64;
        let mut fl_s = Vec::new();
        let mut g_s = Vec::new();
        for _ in 0..80 {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_fl(&template, black_box(delim)) });
            }
            fl_s.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_host(g, &template, black_box(delim)) });
            }
            g_s.push(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        let (flp, gp) = (pctl(&fl_s, 0.50), pctl(&g_s, 0.50));
        println!(
            "STRTOK_BIGDELIM case={label} fl_p50={flp:.1}ns glibc_p50={gp:.1}ns \
             ns_per_token_fl={:.2} ratio_fl_over_glibc={:.2}",
            flp / k as f64,
            flp / gp
        );
    }
    group.bench_function("noop", |b| b.iter(|| black_box(1u64)));
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
