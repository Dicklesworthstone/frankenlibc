//! Truly-interleaved paired A/A + A/B for the `getnameinfo` numeric-path
//! `String` allocations (cc_fl).
//!
//! The AF_INET numeric path did `ip.to_string()` + `port.to_string()` per call — two `String` heap
//! allocations through the interposed allocator — purely to copy the bytes into the caller's C
//! buffer and drop them. `getnameinfo` in NI_NUMERIC* mode does NO file I/O, so unlike the
//! resolution-dominated `gethostbyname` needle, those allocations are a LARGE fraction of the total
//! call cost. Now the path formats into two stack buffers (`write_ipv4_text` + `write_u16_dec`).
//!
//! The former version used a fresh `dlmopen` namespace for glibc and only timed
//! it separately. That is not a campaign incumbent comparison: namespace-local
//! state can distort a stateful libc API, and a separate timing cannot detect
//! arm-order drift. The deployed comparison below resolves the already-live
//! process libc with `dlopen`/`dlsym`, proves its object with `dladdr`, and
//! interleaves host/Franken calls alongside both A/A controls.
//!
//! NULL CONTROL first: paired(cand, cand). Gate the deployed effect on the MEDIAN against that
//! per-function floor — a paired median inside the null's spread is noise and must not be claimed.
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example getnameinfo_ab`

use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::hint::black_box;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;
use sha2::{Digest, Sha256};

const KERNEL_SAMPLES: usize = 400;
const KERNEL_REPS: usize = 20_000;
// DEPLOYED_REPS raised 20 -> 400 so each paired sample times ~560us of work instead of ~30us: the
// null-control cv on the first run was 77% (an A/A arm beat itself by 16%), which is Instant::now()
// jitter on too-short samples, not a real effect. Longer samples crush that relative jitter.
const DEPLOYED_SAMPLES: usize = 1200;
const DEPLOYED_REPS: usize = 400;
const WARMUP: usize = 80;
const BOOTSTRAP_RESAMPLES: usize = 4096;
const NULL_BIAS_TOLERANCE: f64 = 0.02;

const NI_NUMERICHOST: c_int = 1;
const NI_NUMERICSERV: c_int = 2;
const OCTETS: [u8; 4] = [127, 0, 0, 1];
const PORT: u16 = 80;

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn cv_pct(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    100.0 * var.sqrt() / m
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

#[derive(Debug)]
struct ObjectIdentity {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

fn sha256_file(path: &Path) -> ObjectIdentity {
    let path = std::fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("canonicalize {}: {error}", path.display()));
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let mut sha256 = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut sha256, "{byte:02x}").expect("format SHA-256");
    }
    ObjectIdentity {
        path,
        bytes: bytes.len() as u64,
        sha256,
    }
}

fn symbol_object(symbol: *const c_void) -> ObjectIdentity {
    // SAFETY: `symbol` is a non-null dynamic symbol address returned by dlsym.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    assert!(
        unsafe { libc::dladdr(symbol, &mut info) } != 0 && !info.dli_fname.is_null(),
        "dladdr could not identify serving object"
    );
    // SAFETY: dladdr returned a non-null, NUL-terminated pathname.
    let path = unsafe { CStr::from_ptr(info.dli_fname) };
    sha256_file(Path::new(OsStr::from_bytes(path.to_bytes())))
}

fn print_identity(role: &str, identity: &ObjectIdentity) {
    println!(
        "{role}_ELF path={} bytes={} sha256={}",
        identity.path.display(),
        identity.bytes,
        identity.sha256
    );
}

/// Build a `sockaddr_in` for OCTETS:PORT (network byte order in memory).
fn make_sockaddr() -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain-old-data; zeroed is a valid starting state.
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_port = PORT.to_be();
    sin.sin_addr.s_addr = u32::from_ne_bytes(OCTETS);
    sin
}

// --- kernel arms: the two String allocations themselves ---------------------------

#[inline(never)]
fn kernel_orig() -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        fl::bench_legacy_getnameinfo_numeric_alloc(black_box(OCTETS), black_box(PORT));
        acc = acc.wrapping_add(1);
    }
    black_box(acc)
}

/// CAND kernel: what the deployed path now does — format into stack buffers, no allocation.
#[inline(never)]
fn kernel_cand() -> u64 {
    let mut acc = 0u64;
    for _ in 0..KERNEL_REPS {
        acc = acc.wrapping_add(black_box(fl::bench_getnameinfo_numeric_stack(
            black_box(OCTETS),
            black_box(PORT),
        )) as u64);
    }
    black_box(acc)
}

// --- deployed arms ----------------------------------------------------------------

type GetNameInfo = unsafe extern "C" fn(
    *const libc::sockaddr,
    libc::socklen_t,
    *mut c_char,
    libc::socklen_t,
    *mut c_char,
    libc::socklen_t,
    c_int,
) -> c_int;

#[inline(never)]
fn deployed_cand(sin: &libc::sockaddr_in) -> u8 {
    let mut acc = 0u8;
    let mut host = [0 as c_char; 64];
    let mut serv = [0 as c_char; 32];
    for _ in 0..DEPLOYED_REPS {
        let rc = unsafe {
            fl::getnameinfo(
                black_box(sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                black_box(size_of::<libc::sockaddr_in>() as libc::socklen_t),
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                serv.as_mut_ptr(),
                serv.len() as libc::socklen_t,
                black_box(NI_NUMERICHOST | NI_NUMERICSERV),
            )
        };
        assert_eq!(rc, 0, "fl getnameinfo failed");
        acc = acc.wrapping_add(host[0] as u8).wrapping_add(serv[0] as u8);
    }
    black_box(acc)
}

#[inline(never)]
fn deployed_orig(sin: &libc::sockaddr_in) -> u8 {
    let mut acc = 0u8;
    let mut host = [0 as c_char; 64];
    let mut serv = [0 as c_char; 32];
    for _ in 0..DEPLOYED_REPS {
        // ORIG = the full membrane path (adaptive check-ordering bookkeeping) the deployed strict
        // fast path now skips. CAND (deployed_cand) is `fl::getnameinfo`, which takes the strict
        // fast path in this non-test binary (MODE_UNRESOLVED => strict_passthrough_active()).
        let rc = unsafe {
            fl::bench_getnameinfo_full(
                black_box(sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                black_box(size_of::<libc::sockaddr_in>() as libc::socklen_t),
                host.as_mut_ptr(),
                host.len() as libc::socklen_t,
                serv.as_mut_ptr(),
                serv.len() as libc::socklen_t,
                black_box(NI_NUMERICHOST | NI_NUMERICSERV),
            )
        };
        assert_eq!(rc, 0, "fl getnameinfo_full failed");
        acc = acc.wrapping_add(host[0] as u8).wrapping_add(serv[0] as u8);
    }
    black_box(acc)
}

fn host_getnameinfo() -> (GetNameInfo, ObjectIdentity) {
    // `dlopen` joins the process's live namespace; unlike a fresh `dlmopen`
    // namespace it shares the incumbent's initialized libc state. dlsym scoped
    // to this handle returns libc's definition rather than this benchmark's FL
    // export, and `symbol_object` below proves the serving ELF.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "dlopen libc.so.6 failed");
        let s = libc::dlsym(handle, c"getnameinfo".as_ptr());
        assert!(!s.is_null(), "dlsym getnameinfo failed");
        (
            std::mem::transmute::<*mut c_void, GetNameInfo>(s),
            symbol_object(s.cast_const()),
        )
    }
}

#[inline(never)]
fn host(f: GetNameInfo, sin: &libc::sockaddr_in) -> u8 {
    let mut acc = 0u8;
    let mut hbuf = [0 as c_char; 64];
    let mut sbuf = [0 as c_char; 32];
    for _ in 0..DEPLOYED_REPS {
        let rc = unsafe {
            f(
                black_box(sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                black_box(size_of::<libc::sockaddr_in>() as libc::socklen_t),
                hbuf.as_mut_ptr(),
                hbuf.len() as libc::socklen_t,
                sbuf.as_mut_ptr(),
                sbuf.len() as libc::socklen_t,
                black_box(NI_NUMERICHOST | NI_NUMERICSERV),
            )
        };
        assert_eq!(rc, 0, "host getnameinfo failed");
        acc = acc.wrapping_add(hbuf[0] as u8).wrapping_add(sbuf[0] as u8);
    }
    black_box(acc)
}

fn verify(hf: GetNameInfo, sin: &libc::sockaddr_in) {
    let sa = (sin as *const libc::sockaddr_in).cast::<libc::sockaddr>();
    let salen = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let flags = NI_NUMERICHOST | NI_NUMERICSERV;

    let mut fh = [0 as c_char; 64];
    let mut fs = [0 as c_char; 32];
    let frc = unsafe {
        fl::getnameinfo(
            sa,
            salen,
            fh.as_mut_ptr(),
            fh.len() as libc::socklen_t,
            fs.as_mut_ptr(),
            fs.len() as libc::socklen_t,
            flags,
        )
    };
    assert_eq!(frc, 0, "fl getnameinfo NULL/err");

    let mut gh = [0 as c_char; 64];
    let mut gs = [0 as c_char; 32];
    let grc = unsafe {
        hf(
            sa,
            salen,
            gh.as_mut_ptr(),
            gh.len() as libc::socklen_t,
            gs.as_mut_ptr(),
            gs.len() as libc::socklen_t,
            flags,
        )
    };
    assert_eq!(grc, 0, "host getnameinfo err");

    let fhb = unsafe { CStr::from_ptr(fh.as_ptr()) };
    let ghb = unsafe { CStr::from_ptr(gh.as_ptr()) };
    let fsb = unsafe { CStr::from_ptr(fs.as_ptr()) };
    let gsb = unsafe { CStr::from_ptr(gs.as_ptr()) };
    assert_eq!(fhb, ghb, "fl vs host host-string mismatch");
    assert_eq!(fsb, gsb, "fl vs host serv-string mismatch");
    println!("verify: OK (fl == host glibc getnameinfo: host={fhb:?} serv={fsb:?})");
}

fn paired<F, G, R1, R2>(samples: usize, mut a: F, mut b: G) -> (Vec<f64>, Vec<f64>)
where
    F: FnMut() -> R1,
    G: FnMut() -> R2,
{
    let mut xa = Vec::with_capacity(samples);
    let mut xb = Vec::with_capacity(samples);
    for i in 0..samples {
        let (ta, tb) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            (t1, t2)
        } else {
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            (t1, t2)
        };
        if i >= WARMUP {
            xa.push(ta.as_nanos() as f64);
            xb.push(tb.as_nanos() as f64);
        }
    }
    (xa, xb)
}

fn report(label: &str, per: f64, o: &[f64], c: &[f64], unit: &str) -> String {
    let ratio: Vec<f64> = c.iter().zip(o.iter()).map(|(x, y)| x / y).collect();
    println!(
        "{label} n={} {unit}\n  orig median {:10.3}  cv={:5.2}%\n  cand median {:10.3}  cv={:5.2}%\n  PAIRED cand/orig median {:.4} ({:.2}x faster)  cv={:.2}%",
        o.len(),
        median(o) / per,
        cv_pct(o),
        median(c) / per,
        cv_pct(c),
        median(&ratio),
        1.0 / median(&ratio),
        cv_pct(&ratio)
    );
    format!(
        "{label}: paired median {:.4} ({:.2}x)  cv={:.2}%  [orig {:.3} / cand {:.3} {unit}]",
        median(&ratio),
        1.0 / median(&ratio),
        cv_pct(&ratio),
        median(o) / per,
        median(c) / per,
    )
}

fn report_live_incumbent(
    fl: &[f64],
    host: &[f64],
    fl_null_a: &[f64],
    fl_null_b: &[f64],
    host_null_a: &[f64],
    host_null_b: &[f64],
) {
    let effect = fl
        .iter()
        .zip(host)
        .map(|(fl_ns, host_ns)| fl_ns / host_ns)
        .collect::<Vec<_>>();
    let fl_null = fl_null_b
        .iter()
        .zip(fl_null_a)
        .map(|(second, first)| second / first)
        .collect::<Vec<_>>();
    let host_null = host_null_b
        .iter()
        .zip(host_null_a)
        .map(|(second, first)| second / first)
        .collect::<Vec<_>>();

    let effect_median = median(&effect);
    let (effect_low, effect_high) = bootstrap_median_ci95(&effect);
    let fl_null_median = median(&fl_null);
    let (fl_null_low, fl_null_high) = bootstrap_median_ci95(&fl_null);
    let host_null_median = median(&host_null);
    let (host_null_low, host_null_high) = bootstrap_median_ci95(&host_null);
    let fl_null_holds = (fl_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let host_null_holds = (host_null_median - 1.0).abs() <= NULL_BIAS_TOLERANCE;
    let null_half_width = (fl_null_low - 1.0)
        .abs()
        .max((fl_null_high - 1.0).abs())
        .max((host_null_low - 1.0).abs())
        .max((host_null_high - 1.0).abs());
    let clears_2x_null = (effect_median - 1.0).abs() > 2.0 * null_half_width;
    let effect_excludes_one = effect_high < 1.0 || effect_low > 1.0;
    let verdict = if !(fl_null_holds && host_null_holds) {
        "NULL_VIOLATED"
    } else if clears_2x_null && effect_excludes_one && effect_median < 1.0 {
        "FL_FASTER"
    } else if clears_2x_null && effect_excludes_one {
        "FL_SLOWER"
    } else {
        "UNDECIDABLE"
    };

    println!(
        "LIVE_INCUMBENT_CONTRACT symbol=getnameinfo kind=null_fl_fl \
         ratio_median={fl_null_median:.6} ratio_ci95=[{fl_null_low:.6},{fl_null_high:.6}] \
         bias_tolerance={NULL_BIAS_TOLERANCE:.3} pass={fl_null_holds}"
    );
    println!(
        "LIVE_INCUMBENT_CONTRACT symbol=getnameinfo kind=null_glibc_glibc \
         ratio_median={host_null_median:.6} ratio_ci95=[{host_null_low:.6},{host_null_high:.6}] \
         bias_tolerance={NULL_BIAS_TOLERANCE:.3} pass={host_null_holds}"
    );
    println!(
        "LIVE_INCUMBENT_RESULT symbol=getnameinfo samples={} reps_per_arm={DEPLOYED_REPS} \
         fl_median_ns={:.3} glibc_median_ns={:.3} ratio_fl_over_glibc={effect_median:.6} \
         ratio_ci95=[{effect_low:.6},{effect_high:.6}] null_half_width={null_half_width:.6} \
         clears_2x_null={clears_2x_null} verdict={verdict}",
        fl.len(),
        median(fl),
        median(host),
    );
}

fn main() {
    let sin = make_sockaddr();
    let bench_identity =
        sha256_file(&std::env::current_exe().expect("resolve benchmark executable"));
    print_identity("BENCH", &bench_identity);
    let (hf, incumbent_identity) = host_getnameinfo();
    print_identity("INCUMBENT", &incumbent_identity);
    println!("INCUMBENT_LINKAGE live_process_dlopen symbol=getnameinfo");
    verify(hf, &sin);

    let mut summary: Vec<String> = Vec::new();

    // NULL CONTROL FIRST — identical arm twice, per function.
    let (n1, n2) = paired(KERNEL_SAMPLES, kernel_cand, kernel_cand);
    summary.push(report(
        "NULL CONTROL kernel (cand vs cand)",
        KERNEL_REPS as f64,
        &n1,
        &n2,
        "(ns/op)",
    ));
    let (m1, m2) = paired(
        DEPLOYED_SAMPLES,
        || deployed_cand(&sin),
        || deployed_cand(&sin),
    );
    summary.push(report(
        "NULL CONTROL deployed (cand vs cand)",
        DEPLOYED_REPS as f64,
        &m1,
        &m2,
        "(ns/call)",
    ));

    let (ko, kc) = paired(KERNEL_SAMPLES, kernel_orig, kernel_cand);
    summary.push(report(
        "KERNEL numeric alloc",
        KERNEL_REPS as f64,
        &ko,
        &kc,
        "(ns/op)",
    ));

    let (dpo, dpc) = paired(
        DEPLOYED_SAMPLES,
        || deployed_orig(&sin),
        || deployed_cand(&sin),
    );
    summary.push(report(
        "DEPLOYED getnameinfo",
        DEPLOYED_REPS as f64,
        &dpo,
        &dpc,
        "(ns/call)",
    ));

    // The campaign row: both A/A controls and the live host/FL comparison are
    // interleaved in this one invocation. `host_getnameinfo` is a handle-scoped
    // lookup in the already-live process libc, not the benchmark's FL export.
    let (host_null_a, host_null_b) = paired(DEPLOYED_SAMPLES, || host(hf, &sin), || host(hf, &sin));
    let (host_times, fl_times) =
        paired(DEPLOYED_SAMPLES, || host(hf, &sin), || deployed_cand(&sin));
    report_live_incumbent(&fl_times, &host_times, &m1, &m2, &host_null_a, &host_null_b);

    println!("\n===== SUMMARY (getnameinfo numeric String elision) =====");
    for line in &summary {
        println!("  {line}");
    }
}
