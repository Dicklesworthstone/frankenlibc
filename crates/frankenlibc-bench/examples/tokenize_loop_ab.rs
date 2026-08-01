//! Deployed-FrankenLibC vs LIVE glibc for the TOKENIZATION LOOP: `strtok`,
//! `strtok_r` and `strsep` driven to exhaustion over one line, which is how these
//! functions are actually used.
//!
//! WHY WHOLE-LOOP: per-call setup is multiplied by the token count here. Each
//! `strtok` call re-derives its delimiter set from scratch — a `strlen`, an ASCII
//! check, and a PSHUFB LUT build — before scanning, so an N-token line pays that
//! fixed cost N times. glibc's per-token setup is a single 16-byte `pcmpistri`
//! needle load. Measuring one call hides this; measuring the loop is the job.
//!
//! Tokens are short (5-12 bytes), which is both the realistic case and the regime
//! where the fixed setup dominates the scan.
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` symbols cannot
//! interpose the host's. Run with `FRANKENLIBC_MODE` unset (default strict).

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;

type TokFn = unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char;
type TokRFn = unsafe extern "C" fn(*mut c_char, *const c_char, *mut *mut c_char) -> *mut c_char;
type SepFn = unsafe extern "C" fn(*mut *mut c_char, *const c_char) -> *mut c_char;

fn host(sym: &[u8]) -> *mut c_void {
    static H: OnceLock<usize> = OnceLock::new();
    let handle = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr().cast(),
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

/// A line of `tokens` short fields separated by single delimiters drawn from `set`.
fn line(set: &[u8], tokens: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..tokens {
        if i > 0 {
            v.push(set[i % set.len()]);
        }
        let len = 5 + (i % 8);
        v.extend(std::iter::repeat_n(b'a' + (i % 26) as u8, len));
    }
    v.push(0);
    v
}

fn main() {
    let g_tok: TokFn = unsafe { std::mem::transmute(host(b"strtok\0")) };
    let g_tok_r: TokRFn = unsafe { std::mem::transmute(host(b"strtok_r\0")) };
    let g_sep: SepFn = unsafe { std::mem::transmute(host(b"strsep\0")) };

    // Delimiter sets straddling the 16-byte `pcmpistri` needle width. `ws6` and
    // `punct16` take the probe; `mixed22` is the control that must stay neutral.
    let sets: &[(&str, &[u8])] = &[
        ("ws6", b" \t\n\r;,"),
        ("punct16", b" \t;,:|/\\=&%$#@!"),
        ("mixed22", b" \t;,:|/\\=&%$#@!^~`+*<>?"),
    ];

    for &(sname, set) in sets {
        let mut setz = set.to_vec();
        setz.push(0);
        let dp = setz.as_ptr().cast::<c_char>();

        for &tokens in &[2usize, 8, 32, 128] {
            let src = line(set, tokens);

            // Byte-identity of the whole token sequence vs live glibc, before timing.
            let fl_toks = {
                let mut buf = src.clone();
                let mut out = Vec::new();
                let mut save: *mut c_char = std::ptr::null_mut();
                unsafe {
                    let mut t = frankenlibc_abi::string_abi::strtok_r(
                        buf.as_mut_ptr().cast(),
                        dp,
                        &mut save,
                    );
                    while !t.is_null() {
                        out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                        t = frankenlibc_abi::string_abi::strtok_r(
                            std::ptr::null_mut(),
                            dp,
                            &mut save,
                        );
                    }
                }
                out
            };
            let g_toks = {
                let mut buf = src.clone();
                let mut out = Vec::new();
                let mut save: *mut c_char = std::ptr::null_mut();
                unsafe {
                    let mut t = g_tok_r(buf.as_mut_ptr().cast(), dp, &mut save);
                    while !t.is_null() {
                        out.push(std::ffi::CStr::from_ptr(t).to_bytes().to_vec());
                        t = g_tok_r(std::ptr::null_mut(), dp, &mut save);
                    }
                }
                out
            };
            assert_eq!(
                fl_toks, g_toks,
                "strtok_r token stream set={sname} n={tokens}"
            );
            assert_eq!(fl_toks.len(), tokens, "expected {tokens} tokens");

            let runs = 200u64;
            let mut timeit = |name: &str, fl_fn: &dyn Fn() -> usize, g_fn: &dyn Fn() -> usize| {
                for _ in 0..200 {
                    std::hint::black_box(fl_fn());
                    std::hint::black_box(g_fn());
                }
                let mut fl_s = Vec::new();
                let mut g_s = Vec::new();
                for _ in 0..80 {
                    let t = Instant::now();
                    for _ in 0..runs {
                        std::hint::black_box(fl_fn());
                    }
                    fl_s.push(t.elapsed().as_nanos() as f64 / runs as f64);
                    let t = Instant::now();
                    for _ in 0..runs {
                        std::hint::black_box(g_fn());
                    }
                    g_s.push(t.elapsed().as_nanos() as f64 / runs as f64);
                }
                let (flp, gp) = (pctl(&fl_s, 0.50), pctl(&g_s, 0.50));
                println!(
                    "TOKLOOP fn={name} set={sname} setlen={} tokens={tokens} \
                     fl_p50={flp:.1}ns glibc_p50={gp:.1}ns ratio_fl_over_glibc={:.2}",
                    set.len(),
                    flp / gp
                );
            };

            // Each arm re-copies the line (strtok writes NULs into it) and drives the
            // loop to exhaustion — whole-job, not one call.
            timeit(
                "strtok_r",
                &|| {
                    let mut buf = src.clone();
                    let mut save: *mut c_char = std::ptr::null_mut();
                    let mut n = 0;
                    unsafe {
                        let mut t = frankenlibc_abi::string_abi::strtok_r(
                            buf.as_mut_ptr().cast(),
                            dp,
                            &mut save,
                        );
                        while !t.is_null() {
                            n += 1;
                            t = frankenlibc_abi::string_abi::strtok_r(
                                std::ptr::null_mut(),
                                dp,
                                &mut save,
                            );
                        }
                    }
                    n
                },
                &|| {
                    let mut buf = src.clone();
                    let mut save: *mut c_char = std::ptr::null_mut();
                    let mut n = 0;
                    unsafe {
                        let mut t = g_tok_r(buf.as_mut_ptr().cast(), dp, &mut save);
                        while !t.is_null() {
                            n += 1;
                            t = g_tok_r(std::ptr::null_mut(), dp, &mut save);
                        }
                    }
                    n
                },
            );

            timeit(
                "strsep",
                &|| {
                    let mut buf = src.clone();
                    let mut cur = buf.as_mut_ptr().cast::<c_char>();
                    let mut n = 0;
                    unsafe {
                        while !frankenlibc_abi::string_abi::strsep(&mut cur, dp).is_null() {
                            n += 1;
                        }
                    }
                    n
                },
                &|| {
                    let mut buf = src.clone();
                    let mut cur = buf.as_mut_ptr().cast::<c_char>();
                    let mut n = 0;
                    unsafe {
                        while !g_sep(&mut cur, dp).is_null() {
                            n += 1;
                        }
                    }
                    n
                },
            );

            timeit(
                "strtok",
                &|| {
                    let mut buf = src.clone();
                    let mut n = 0;
                    unsafe {
                        let mut t =
                            frankenlibc_abi::string_abi::strtok(buf.as_mut_ptr().cast(), dp);
                        while !t.is_null() {
                            n += 1;
                            t = frankenlibc_abi::string_abi::strtok(std::ptr::null_mut(), dp);
                        }
                    }
                    n
                },
                &|| {
                    let mut buf = src.clone();
                    let mut n = 0;
                    unsafe {
                        let mut t = g_tok(buf.as_mut_ptr().cast(), dp);
                        while !t.is_null() {
                            n += 1;
                            t = g_tok(std::ptr::null_mut(), dp);
                        }
                    }
                    n
                },
            );
        }
    }
}
