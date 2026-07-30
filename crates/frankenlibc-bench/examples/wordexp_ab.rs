//! `wordexp` vs host glibc — an UNMINED surface with zero prior perf coverage in this repo.
//!
//! WHY THIS TARGET, under the mechanism as CORRECTED by the strfmon refutation. A
//! specialization beats glibc only where the incumbent's per-call interpretation is
//! (a) present AND (b) not already hoisted. `strfmon` failed (b): its monetary locale
//! lookup is cached, proven by `%^n` (grouping off) costing glibc the same as `%n`.
//! `wordexp` cannot fail (b) even in principle: the WORD is a different string on every
//! call, so tilde expansion, parameter expansion, field splitting and quote removal must
//! all be re-derived per call. There is no state to hoist. That makes it the cleanest
//! remaining test of the corrected mechanism, and it is outside the time/locale family
//! where our four wins came from.
//!
//! SCOPE, deliberately narrow so the measurement means something:
//!   * `WRDE_NOCMD` on every case — glibc's `wordexp` forks `/bin/sh` for command
//!     substitution, and a fork is process-spawn noise, not per-call interpretation.
//!   * words chosen to avoid glob metacharacters, so pathname expansion does not turn
//!     this into a filesystem benchmark. Both arms still run identical words on the same
//!     filesystem in the same invocation, so any residual FS cost is matched.
//!
//! Contract, same shape as the harnesses that produced the banked wins:
//!   1. line 1 is the SHA-256 of this binary, hashed by the binary itself.
//!   2. incumbent held via `dlmopen(LM_ID_NEWLM)`, proven with `dladdr` in both
//!      directions so an fl-vs-fl or glibc-vs-glibc run aborts instead of reporting.
//!   3. TWO nulls per case — FL/FL and glibc/glibc — and a ratio is decisive only when
//!      BOTH straddle 1.0.
//!   4. bootstrap median CIs decide; effect must clear 2x the LARGER null half-width and
//!      exclude 1.0. CV is telemetry and never gates.
//!   5. conformance BEFORE timing: identical return code, identical `we_wordc`, and every
//!      `we_wordv[i]` byte-identical. A mismatch aborts.
//!
//! Each arm frees with ITS OWN `wordfree`: the words were allocated by that
//! implementation's allocator, so crossing them would be a cross-allocator free.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use sha2::{Digest, Sha256};

const SAMPLES: usize = 37;
const WARMUP: usize = 4;
const REPS: usize = 20_000;
const BOOTSTRAP_RESAMPLES: usize = 4096;

/// POSIX `WRDE_NOCMD`: fail rather than run command substitution.
const WRDE_NOCMD: c_int = 1 << 2;

#[repr(C)]
struct WordExp {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

impl WordExp {
    fn zeroed() -> Self {
        Self {
            we_wordc: 0,
            we_wordv: std::ptr::null_mut(),
            we_offs: 0,
        }
    }
}

type WordexpFn = unsafe extern "C" fn(*const c_char, *mut c_void, c_int) -> c_int;
type WordfreeFn = unsafe extern "C" fn(*mut c_void);

struct Case {
    label: &'static str,
    /// NUL-terminated word to expand.
    words: &'static [u8],
    /// What a user would recognise this as.
    note: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "plain_split",
        words: b"alpha beta gamma delta\0",
        note: "field splitting only — the floor case for per-call parsing",
    },
    Case {
        label: "quoted_mix",
        words: b"'single quoted' \"double quoted\" bare\0",
        note: "quote removal across both quote styles",
    },
    Case {
        label: "param_simple",
        words: b"$WORDEXP_AB_VAR tail\0",
        note: "parameter expansion, the most common non-glob expansion",
    },
    Case {
        label: "param_braced",
        words: b"${WORDEXP_AB_VAR}/suffix\0",
        note: "braced parameter expansion concatenated with a literal",
    },
    Case {
        label: "param_default",
        words: b"${WORDEXP_AB_UNSET:-fallbackvalue}\0",
        note: "${VAR:-default} — the operator config parsers rely on",
    },
    Case {
        label: "escapes",
        words: b"a\\ b c\\ d literal\0",
        note: "backslash escapes producing embedded spaces",
    },
    Case {
        label: "many_fields",
        words: b"f1 f2 f3 f4 f5 f6 f7 f8 f9 f10 f11 f12 f13 f14 f15 f16\0",
        note: "16 fields — scales the word-vector growth path",
    },
];

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".into();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".into();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut digest_hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest_hex, "{byte:02x}").expect("write SHA-256 hex");
    }
    format!("{} ({} bytes) {}", digest_hex, bytes.len(), path.display())
}

fn median(xs: &[f64]) -> f64 {
    let mut values = xs.to_vec();
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let avg = mean(xs);
    let variance = xs.iter().map(|v| (v - avg) * (v - avg)).sum::<f64>() / xs.len() as f64;
    100.0 * variance.sqrt() / avg
}

fn median_absolute_deviation(xs: &[f64], center: f64) -> f64 {
    median(&xs.iter().map(|v| (v - center).abs()).collect::<Vec<_>>())
}

fn bootstrap_median_ci95(xs: &[f64]) -> (f64, f64) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ xs.len() as u64;
    let mut medians = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let mut resample = vec![0.0; xs.len()];
    for _ in 0..BOOTSTRAP_RESAMPLES {
        for value in &mut resample {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = xs[(state as usize) % xs.len()];
        }
        medians.push(median(&resample));
    }
    medians.sort_by(f64::total_cmp);
    let low = (BOOTSTRAP_RESAMPLES * 25) / 1000;
    let high = ((BOOTSTRAP_RESAMPLES * 975) / 1000).min(BOOTSTRAP_RESAMPLES - 1);
    (medians[low], medians[high])
}

/// One expand + free pair. The free is part of the job a user pays for, and pairing it
/// here also keeps memory flat across REPS iterations.
#[inline(never)]
fn run_fl(words: *const c_char) -> usize {
    let mut acc = 0usize;
    for _ in 0..REPS {
        let mut we = WordExp::zeroed();
        let rc = unsafe {
            frankenlibc_abi::unistd_abi::wordexp(
                black_box(words),
                (&raw mut we).cast::<c_void>(),
                WRDE_NOCMD,
            )
        };
        acc = acc.wrapping_add(rc as usize).wrapping_add(we.we_wordc);
        unsafe { frankenlibc_abi::unistd_abi::wordfree((&raw mut we).cast::<c_void>()) };
    }
    black_box(acc)
}

#[inline(never)]
fn run_host(host: WordexpFn, host_free: WordfreeFn, words: *const c_char) -> usize {
    let mut acc = 0usize;
    for _ in 0..REPS {
        let mut we = WordExp::zeroed();
        let rc = unsafe { host(black_box(words), (&raw mut we).cast::<c_void>(), WRDE_NOCMD) };
        acc = acc.wrapping_add(rc as usize).wrapping_add(we.we_wordc);
        unsafe { host_free((&raw mut we).cast::<c_void>()) };
    }
    black_box(acc)
}

/// Conformance before timing: same return code, same word count, same bytes per word.
/// A faster expander that splits fields differently or drops a quote is a bug, not a win.
fn verify(host: WordexpFn, host_free: WordfreeFn, case: &Case) {
    let words = case.words.as_ptr().cast::<c_char>();

    let mut fl_we = WordExp::zeroed();
    let mut gl_we = WordExp::zeroed();
    let fl_rc = unsafe {
        frankenlibc_abi::unistd_abi::wordexp(words, (&raw mut fl_we).cast::<c_void>(), WRDE_NOCMD)
    };
    let gl_rc = unsafe { host(words, (&raw mut gl_we).cast::<c_void>(), WRDE_NOCMD) };

    assert_eq!(
        fl_rc, gl_rc,
        "{}: return code differs (fl {fl_rc} vs glibc {gl_rc})",
        case.label
    );
    if fl_rc == 0 {
        assert_eq!(
            fl_we.we_wordc, gl_we.we_wordc,
            "{}: we_wordc differs (fl {} vs glibc {})",
            case.label, fl_we.we_wordc, gl_we.we_wordc
        );
        for i in 0..fl_we.we_wordc {
            let a = unsafe { CStr::from_ptr(*fl_we.we_wordv.add(i)) };
            let b = unsafe { CStr::from_ptr(*gl_we.we_wordv.add(i)) };
            assert_eq!(
                a.to_bytes(),
                b.to_bytes(),
                "{}: word[{i}] differs (fl {:?} vs glibc {:?})",
                case.label,
                a.to_string_lossy(),
                b.to_string_lossy(),
            );
        }
    }
    // Each side frees what it allocated.
    unsafe { frankenlibc_abi::unistd_abi::wordfree((&raw mut fl_we).cast::<c_void>()) };
    unsafe { host_free((&raw mut gl_we).cast::<c_void>()) };
}

fn measure_case(host: WordexpFn, host_free: WordfreeFn, case: &Case, host_label: &str) {
    let words = case.words.as_ptr().cast::<c_char>();

    let mut fl = Vec::with_capacity(SAMPLES - WARMUP);
    let mut glibc = Vec::with_capacity(SAMPLES - WARMUP);
    let mut fl_na = Vec::with_capacity(SAMPLES - WARMUP);
    let mut fl_nb = Vec::with_capacity(SAMPLES - WARMUP);
    let mut gl_na = Vec::with_capacity(SAMPLES - WARMUP);
    let mut gl_nb = Vec::with_capacity(SAMPLES - WARMUP);

    for sample in 0..SAMPLES {
        let start = Instant::now();
        black_box(run_fl(words));
        let fa = start.elapsed();
        let start = Instant::now();
        black_box(run_fl(words));
        let fb = start.elapsed();

        let start = Instant::now();
        black_box(run_host(host, host_free, words));
        let ga = start.elapsed();
        let start = Instant::now();
        black_box(run_host(host, host_free, words));
        let gb = start.elapsed();

        let (fl_elapsed, gl_elapsed) = if sample % 2 == 0 {
            let start = Instant::now();
            black_box(run_fl(words));
            let a = start.elapsed();
            let start = Instant::now();
            black_box(run_host(host, host_free, words));
            (a, start.elapsed())
        } else {
            let start = Instant::now();
            black_box(run_host(host, host_free, words));
            let b = start.elapsed();
            let start = Instant::now();
            black_box(run_fl(words));
            (start.elapsed(), b)
        };

        if sample >= WARMUP {
            let scale = REPS as f64;
            fl.push(fl_elapsed.as_nanos() as f64 / scale);
            glibc.push(gl_elapsed.as_nanos() as f64 / scale);
            fl_na.push(fa.as_nanos() as f64 / scale);
            fl_nb.push(fb.as_nanos() as f64 / scale);
            gl_na.push(ga.as_nanos() as f64 / scale);
            gl_nb.push(gb.as_nanos() as f64 / scale);
        }
    }

    let effect: Vec<f64> = fl.iter().zip(&glibc).map(|(f, h)| f / h).collect();
    let fl_null: Vec<f64> = fl_nb.iter().zip(&fl_na).map(|(b, a)| b / a).collect();
    let gl_null: Vec<f64> = gl_nb.iter().zip(&gl_na).map(|(b, a)| b / a).collect();

    let effect_median = median(&effect);
    let (elo, ehi) = bootstrap_median_ci95(&effect);
    let fl_nm = median(&fl_null);
    let (flo, fhi) = bootstrap_median_ci95(&fl_null);
    let gl_nm = median(&gl_null);
    let (glo, ghi) = bootstrap_median_ci95(&gl_null);

    let fl_hw = (1.0 - flo).abs().max((fhi - 1.0).abs());
    let gl_hw = (1.0 - glo).abs().max((ghi - 1.0).abs());
    let null_half_width = fl_hw.max(gl_hw);
    let fl_holds = flo <= 1.0 && fhi >= 1.0;
    let gl_holds = glo <= 1.0 && ghi >= 1.0;
    let nulls_hold = fl_holds && gl_holds;
    let clears = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let excludes_one = ehi < 1.0 || elo > 1.0;
    let comparison = if !nulls_hold {
        "NULL_VIOLATED"
    } else if clears && excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears && excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "WORDEXP case={} host={host_label} threads=1 samples={} reps/arm={REPS} \
         fl_median_ns={:.3} glibc_median_ns={:.3} note={}",
        case.label,
        fl.len(),
        median(&fl),
        median(&glibc),
        case.note,
    );
    println!(
        "WORDEXP_CONTRACT case={} host={host_label} threads=1 kind=null_fl_fl \
         ratio_median={fl_nm:.6} ratio_ci95=[{flo:.6},{fhi:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6} null_holds={fl_holds}",
        case.label,
        cv_pct(&fl_null),
        median_absolute_deviation(&fl_null, fl_nm),
    );
    println!(
        "WORDEXP_CONTRACT case={} host={host_label} threads=1 kind=null_glibc_glibc \
         ratio_median={gl_nm:.6} ratio_ci95=[{glo:.6},{ghi:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6} null_holds={gl_holds}",
        case.label,
        cv_pct(&gl_null),
        median_absolute_deviation(&gl_null, gl_nm),
    );
    println!(
        "WORDEXP_CONTRACT case={} host={host_label} threads=1 kind=fl_glibc \
         ratio_median={effect_median:.6} ratio_ci95=[{elo:.6},{ehi:.6}] ratio_cv_pct={:.3} \
         ratio_mad={:.6} null_half_width={null_half_width:.6} clears_2x_null={clears} \
         nulls_hold={nulls_hold} comparison={comparison}",
        case.label,
        cv_pct(&effect),
        median_absolute_deviation(&effect, effect_median),
    );
}

fn main() {
    println!("BENCH_ELF_SHA256 {}", self_identity());
    println!(
        "ISA_PROVENANCE built_avx2={} built_fma={} built_sse42={} cpu_avx2={} cpu_sse42={}",
        cfg!(target_feature = "avx2"),
        cfg!(target_feature = "fma"),
        cfg!(target_feature = "sse4.2"),
        std::arch::is_x86_feature_detected!("avx2"),
        std::arch::is_x86_feature_detected!("sse4.2"),
    );
    println!(
        "HOST_IDENTITY {} cpus={} loadavg={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        std::fs::read_to_string("/proc/loadavg")
            .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(","))
            .unwrap_or_else(|_| "unknown".into()),
    );

    // Parameter expansion needs a value both arms can see. Set it before the incumbent
    // namespace is loaded so its environ is identical to ours.
    // SAFETY: single-threaded, before any thread is spawned.
    unsafe { std::env::set_var("WORDEXP_AB_VAR", "expanded_value") };
    unsafe { std::env::remove_var("WORDEXP_AB_UNSET") };

    let handle = unsafe {
        libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        )
    };
    assert!(!handle.is_null(), "dlmopen(libc.so.6) failed");
    let sym = unsafe { libc::dlsym(handle, c"wordexp".as_ptr()) };
    let free_sym = unsafe { libc::dlsym(handle, c"wordfree".as_ptr()) };
    assert!(!sym.is_null(), "dlsym(wordexp) failed");
    assert!(!free_sym.is_null(), "dlsym(wordfree) failed");
    let host: WordexpFn = unsafe { std::mem::transmute(sym) };
    let host_free: WordfreeFn = unsafe { std::mem::transmute(free_sym) };

    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let host_label = if unsafe { libc::dladdr(sym as *const c_void, &mut info) } != 0
        && !info.dli_fname.is_null()
    {
        unsafe { CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned()
    } else {
        "unresolved".into()
    };
    println!("INCUMBENT_OBJECT {host_label}");
    assert!(
        host_label.contains("libc.so"),
        "incumbent resolved to {host_label}, not a host libc: this would measure fl vs fl"
    );

    let fl_fn: WordexpFn = frankenlibc_abi::unistd_abi::wordexp;
    let mut fl_info: libc::Dl_info = unsafe { std::mem::zeroed() };
    let fl_label = if unsafe { libc::dladdr(fl_fn as *const c_void, &mut fl_info) } != 0
        && !fl_info.dli_fname.is_null()
    {
        unsafe { CStr::from_ptr(fl_info.dli_fname) }
            .to_string_lossy()
            .into_owned()
    } else {
        "unresolved".into()
    };
    println!("FL_OBJECT {fl_label}");
    assert!(
        !fl_label.contains("libc.so"),
        "FL arm resolved into {fl_label}: this would measure glibc vs glibc"
    );

    for case in CASES {
        verify(host, host_free, case);
    }
    println!(
        "verify: OK ({} cases — return code, we_wordc, and every word byte-identical)",
        CASES.len()
    );

    for case in CASES {
        measure_case(host, host_free, case, &host_label);
    }
}
