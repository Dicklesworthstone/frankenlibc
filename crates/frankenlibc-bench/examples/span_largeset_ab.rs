//! Deployed-FrankenLibC vs LIVE glibc for the LARGE-set (>4-byte) span family:
//! `strspn` / `strcspn` / `strpbrk`.
//!
//! WHY THIS SHAPE: glibc's `__strspn_sse42` / `__strcspn_sse42` / `__strpbrk_sse42`
//! handle a set of up to 16 bytes with ONE unaligned 16-byte load of the set plus a
//! `pcmpistri` per 16 input bytes — the per-call setup is O(1). FrankenLibC's
//! deployed strict path instead pays THREE passes over the set (a SIMD `strlen`, an
//! `all_bytes_ascii` scalar loop, and the `build_pshufb_lut` scalar loop) before it
//! touches the haystack. That fixed setup is invisible on long spans and dominant on
//! short ones, so we sweep the span length and read the ratio's shape, not one point.
//!
//! Sets are chosen around glibc's 16-byte `pcmpistri` boundary: at 17+ bytes glibc
//! falls back to its own 256-byte table build, so those arms are the control — if the
//! gap is a setup gap it must SHRINK there.
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM)` so fl's `no_mangle` symbols cannot
//! interpose the host's. Run with `FRANKENLIBC_MODE` unset (default strict) so the
//! deployed fast path is the one measured.

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;
use std::time::Instant;

type SpnFn = unsafe extern "C" fn(*const c_char, *const c_char) -> usize;
type PbrkFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

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

/// A set byte and a non-set byte, for building the two haystack shapes.
fn filler_and_stopper(set: &[u8]) -> (u8, u8) {
    let mut member = [false; 256];
    for &b in set {
        member[b as usize] = true;
    }
    let filler = set[set.len() / 2];
    let stopper = (1u8..=127)
        .find(|&b| !member[b as usize])
        .expect("dense set");
    (filler, stopper)
}

/// `strspn` haystack: `span` set members, then a run of non-members, then NUL.
/// The trailing run is real string past the stop, so any full-haystack pre-scan is
/// charged for it.
fn spn_buf(set: &[u8], span: usize) -> Vec<u8> {
    let (filler, stopper) = filler_and_stopper(set);
    let mut v = vec![filler; span];
    v.extend(std::iter::repeat_n(stopper, 64));
    v.push(0);
    v
}

/// `strcspn`/`strpbrk` haystack: `span` non-members, then a run of members, then NUL.
fn cspn_buf(set: &[u8], span: usize) -> Vec<u8> {
    let (filler, stopper) = filler_and_stopper(set);
    let mut v = vec![stopper; span];
    v.extend(std::iter::repeat_n(filler, 64));
    v.push(0);
    v
}

/// Deliberately OFF any power-of-two probe budget: a sweep whose points coincide
/// with the budget only ever samples the worst case (a span that just outruns the
/// probe pays for both the probe and the LUT setup) and hides the curve either side
/// of it.
const SPANS: &[usize] = &[4, 20, 44, 100, 180, 300, 1000, 4096];

fn main() {
    let g_spn: SpnFn = unsafe { std::mem::transmute(host(b"strspn\0")) };
    let g_cspn: SpnFn = unsafe { std::mem::transmute(host(b"strcspn\0")) };
    let g_pbrk: PbrkFn = unsafe { std::mem::transmute(host(b"strpbrk\0")) };

    // name, set. Sets straddle glibc's 16-byte pcmpistri boundary on purpose.
    let sets: &[(&str, &[u8])] = &[
        ("ws6", b" \t\n\r\x0b\x0c"),
        ("digits10", b"0123456789"),
        ("punct16", b"!\"#$%&'()*+,-./:"),
        ("hex22", b"0123456789abcdefABCDEF"),
        (
            "ident63",
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
        ),
    ];

    for &(sname, set) in sets {
        let mut setz = set.to_vec();
        setz.push(0);
        let sp = setz.as_ptr().cast::<c_char>();

        for &span in SPANS {
            let sb = spn_buf(set, span);
            let cb = cspn_buf(set, span);
            let sptr = sb.as_ptr().cast::<c_char>();
            let cptr = cb.as_ptr().cast::<c_char>();

            // Byte-identity vs live glibc BEFORE timing — a fast wrong answer is not a win.
            unsafe {
                assert_eq!(
                    frankenlibc_abi::string_abi::strspn(sptr, sp),
                    g_spn(sptr, sp),
                    "strspn fl!=glibc set={sname} span={span}"
                );
                assert_eq!(
                    frankenlibc_abi::string_abi::strcspn(cptr, sp),
                    g_cspn(cptr, sp),
                    "strcspn fl!=glibc set={sname} span={span}"
                );
                let fp = frankenlibc_abi::string_abi::strpbrk(cptr, sp);
                let gp = g_pbrk(cptr, sp);
                assert_eq!(fp.is_null(), gp.is_null(), "strpbrk null disagree");
                if !fp.is_null() {
                    assert_eq!(
                        fp as usize - cptr as usize,
                        gp as usize - cptr as usize,
                        "strpbrk offset disagree set={sname} span={span}"
                    );
                }
            }

            let runs = 2000u64;
            let mut timeit = |name: &str, fl_fn: &dyn Fn() -> usize, g_fn: &dyn Fn() -> usize| {
                // Warm both arms so neither pays first-touch/branch-predictor cost.
                for _ in 0..2000 {
                    std::hint::black_box(fl_fn());
                    std::hint::black_box(g_fn());
                }
                let mut fl_s = Vec::new();
                let mut g_s = Vec::new();
                for _ in 0..120 {
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
                    "SPANSET fn={name} set={sname} setlen={} span={span} \
                     fl_p50={flp:.2}ns glibc_p50={gp:.2}ns ratio_fl_over_glibc={:.2}",
                    set.len(),
                    flp / gp
                );
            };

            timeit(
                "strspn",
                &|| unsafe {
                    frankenlibc_abi::string_abi::strspn(
                        std::hint::black_box(sptr),
                        std::hint::black_box(sp),
                    )
                },
                &|| unsafe { g_spn(std::hint::black_box(sptr), std::hint::black_box(sp)) },
            );
            timeit(
                "strcspn",
                &|| unsafe {
                    frankenlibc_abi::string_abi::strcspn(
                        std::hint::black_box(cptr),
                        std::hint::black_box(sp),
                    )
                },
                &|| unsafe { g_cspn(std::hint::black_box(cptr), std::hint::black_box(sp)) },
            );
            timeit(
                "strpbrk",
                &|| unsafe {
                    frankenlibc_abi::string_abi::strpbrk(
                        std::hint::black_box(cptr),
                        std::hint::black_box(sp),
                    ) as usize
                },
                &|| unsafe {
                    g_pbrk(std::hint::black_box(cptr), std::hint::black_box(sp)) as usize
                },
            );
        }
    }
}
