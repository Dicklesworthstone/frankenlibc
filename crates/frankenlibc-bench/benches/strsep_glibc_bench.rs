//! Full-tokenization `strsep` benchmark: deployed FrankenLibC vs host glibc.
//!
//! Lever: the deployed strict strsep used to `scan_c_string(s, None)` (a full
//! strlen of the REMAINING string) on EVERY call just to bound the slice, then a
//! second membership pass — so a complete tokenization loop over K tokens was
//! O(n²). The fused early-stop (small delim sets, `scan_c_string_for_set4`) makes
//! each call O(token-length) → O(n) total. This bench tokenizes a buffer of K
//! short tokens separated by ';' and times the WHOLE loop, fl vs glibc.
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` strsep doesn't
//! interpose the host symbol. Default strict mode → deployed fast path active.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

type SepFn = unsafe extern "C" fn(*mut *mut c_char, *const c_char) -> *mut c_char;

fn host_strsep() -> SepFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc.so.6 failed");
        let p = libc::dlsym(h, b"strsep\0".as_ptr().cast());
        assert!(!p.is_null(), "dlsym strsep failed");
        p as usize
    });
    unsafe { std::mem::transmute::<usize, SepFn>(addr) }
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

/// Tokenize a FRESH copy of `template` with `sep`, counting tokens (keeps the
/// loop honest — strsep mutates the buffer, so each run needs a fresh copy).
unsafe fn run_loop(sep: SepFn, template: &[u8], delim: *const c_char) -> usize {
    let mut buf = template.to_vec();
    let mut cur: *mut c_char = buf.as_mut_ptr().cast();
    let sp: *mut *mut c_char = &mut cur;
    let mut n = 0usize;
    loop {
        let tok = unsafe { sep(sp, delim) };
        if tok.is_null() {
            break;
        }
        n += 1;
    }
    black_box(buf.as_ptr());
    n
}

const KS: &[usize] = &[8, 64, 512, 2048];

fn bench(c: &mut Criterion) {
    let g = host_strsep();
    let delim = b";\0".as_ptr().cast::<c_char>();

    let mut group = c.benchmark_group("strsep_loop");
    group.sample_size(30);

    for &k in KS {
        let template = make_buf(k);

        // Byte-identity: token count must match glibc.
        let fl_n = unsafe {
            let mut buf = template.clone();
            let mut cur: *mut c_char = buf.as_mut_ptr().cast();
            let sp: *mut *mut c_char = &mut cur;
            let mut n = 0;
            loop {
                let t = frankenlibc_abi::string_abi::strsep(sp, delim);
                if t.is_null() {
                    break;
                }
                n += 1;
            }
            n
        };
        let g_n = unsafe { run_loop(g, &template, delim) };
        assert_eq!(fl_n, g_n, "token count fl!=glibc k={k}");
        assert_eq!(fl_n, k, "expected {k} tokens");

        let iters = 200u64;
        let mut fl_s = Vec::new();
        let mut g_s = Vec::new();
        for _ in 0..100 {
            let t = Instant::now();
            for _ in 0..iters {
                let mut buf = template.clone();
                let mut cur: *mut c_char = buf.as_mut_ptr().cast();
                let sp: *mut *mut c_char = &mut cur;
                loop {
                    let tok = unsafe { frankenlibc_abi::string_abi::strsep(sp, black_box(delim)) };
                    if tok.is_null() {
                        break;
                    }
                }
                black_box(buf.as_ptr());
            }
            fl_s.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(unsafe { run_loop(g, &template, black_box(delim)) });
            }
            g_s.push(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        let (flp, gp) = (pctl(&fl_s, 0.50), pctl(&g_s, 0.50));
        println!(
            "STRSEP_LOOP tokens={k} fl_p50={flp:.1}ns glibc_p50={gp:.1}ns \
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
