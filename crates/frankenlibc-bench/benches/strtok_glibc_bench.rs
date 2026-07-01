//! Full-tokenization `strtok_r` benchmark: deployed FrankenLibC vs host glibc.
//!
//! Lever (sibling of the strsep O(n²)→O(n) fix): the deployed strict strtok_r ran
//! `scan_c_string(current, None)` — a full strlen of the REMAINING string — on
//! EVERY call, so a complete tokenization loop over K tokens was O(n²). The fused
//! early-stop (small delim sets: skip leading delims via strspn, find token end via
//! strcspn, both `scan_c_string_for_set4`) makes each call O(token) → O(n) total.
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` strtok_r doesn't
//! interpose the host symbol. Default strict mode → deployed fast path active.

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
    if lo == hi {
        s[lo]
    } else {
        s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
    }
}

/// Buffer of `k` 7-char tokens separated by ';' + trailing NUL.
fn make_buf(k: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..k {
        if i > 0 {
            v.push(b';');
        }
        v.extend_from_slice(b"tok");
        v.extend_from_slice(format!("{:04}", i % 10000).as_bytes());
    }
    v.push(0);
    v
}

/// Tokenize a FRESH copy of `template` with host strtok_r, counting tokens.
unsafe fn run_host(f: TokFn, template: &[u8], delim: *const c_char) -> usize {
    let mut buf = template.to_vec();
    let mut save: *mut c_char = std::ptr::null_mut();
    let mut cur: *mut c_char = buf.as_mut_ptr().cast();
    let mut n = 0usize;
    loop {
        let tok = unsafe { f(cur, delim, &mut save) };
        if tok.is_null() {
            break;
        }
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
        if tok.is_null() {
            break;
        }
        cur = std::ptr::null_mut();
        n += 1;
    }
    black_box(buf.as_ptr());
    n
}

const KS: &[usize] = &[8, 64, 512, 2048];

fn bench(c: &mut Criterion) {
    let g = host_strtok_r();
    let delim = b";\0".as_ptr().cast::<c_char>();

    let mut group = c.benchmark_group("strtok_loop");
    group.sample_size(30);

    for &k in KS {
        let template = make_buf(k);
        let fl_n = unsafe { run_fl(&template, delim) };
        let g_n = unsafe { run_host(g, &template, delim) };
        assert_eq!(fl_n, g_n, "token count fl!=glibc k={k}");
        assert_eq!(fl_n, k, "expected {k} tokens");

        let iters = 200u64;
        let mut fl_s = Vec::new();
        let mut g_s = Vec::new();
        for _ in 0..100 {
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
            "STRTOK_LOOP tokens={k} fl_p50={flp:.1}ns glibc_p50={gp:.1}ns \
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
