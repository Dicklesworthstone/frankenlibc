//! Head-to-head numeric-parse benchmark: FrankenLibC vs host glibc.
//!
//! Measures the DEPLOYED ABI strtol/strtoul/strtod/strtof path (`frankenlibc_abi::
//! stdlib_abi::*`) — this is a criterion bench, so the lib is built WITHOUT
//! `cfg(test)`, i.e. the membrane fast-paths are live and `known_remaining`
//! routes through the cheap deployed bookkeeping (unlike a `--test` integration
//! bench, which compiles the lib with `cfg(test)=true` and measures the slow
//! validate_ptr path — see NEGATIVE_EVIDENCE 2026-06-20 strtol artifact).
//!
//! glibc baseline via `dlmopen(LM_ID_NEWLM, "libc.so.6")` so fl's `no_mangle`
//! symbols do not interpose the host.

use std::ffi::{c_char, c_int};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

unsafe extern "C" {
    /// The process environment table (the one fl::getenv walks).
    static environ: *mut *mut c_char;
}

type StrtolFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char, c_int) -> i64;
type StrtodFn = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> f64;
type AtoiFn = unsafe extern "C" fn(*const c_char) -> c_int;
type AtolFn = unsafe extern "C" fn(*const c_char) -> i64;

fn host(name: &[u8]) -> usize {
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
    let p = unsafe { libc::dlsym(handle as *mut _, name.as_ptr().cast()) };
    assert!(!p.is_null(), "dlsym failed");
    p as usize
}

fn report(label: &str, samples: &mut [f64]) {
    if samples.is_empty() {
        return;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p50 = samples[samples.len() / 2];
    println!("STRTOL_BENCH impl={label} p50_ns_op={p50:.2}");
}

fn time_it<F: FnMut() -> i64>(mut f: F) -> f64 {
    let mut s: Vec<f64> = Vec::new();
    for _ in 0..200 {
        let iters = 2000u64;
        let start = Instant::now();
        for _ in 0..iters {
            black_box(f());
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        s.push(dur.as_nanos() as f64 / iters as f64);
    }
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    s[s.len() / 2]
}

fn bench(c: &mut Criterion) {
    let gstrtol: StrtolFn = unsafe { std::mem::transmute(host(b"strtol\0")) };
    let gstrtod: StrtodFn = unsafe { std::mem::transmute(host(b"strtod\0")) };
    let gatoi: AtoiFn = unsafe { std::mem::transmute(host(b"atoi\0")) };
    let gatol: AtolFn = unsafe { std::mem::transmute(host(b"atol\0")) };
    let gatoll: AtolFn = unsafe { std::mem::transmute(host(b"atoll\0")) };
    let mut group = c.benchmark_group("numeric_parse");
    group.sample_size(10);

    // strtol cases
    for (name, s, base) in [
        ("strtol_dec_short", b"42\0".as_slice(), 10i32),
        ("strtol_dec_long", b"1234567890\0", 10),
        ("strtol_hex", b"0xdeadbeef\0", 16),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { frankenlibc_abi::stdlib_abi::strtol(black_box(p), &mut e, base) }
        });
        let gl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { gstrtol(black_box(p), &mut e, base) }
        });
        println!(
            "{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}",
            fl / gl
        );
    }

    // ato* cases: no endptr write, base 10 only, but still ubiquitous in C
    // parser/config code. This catches deployed ABI overhead distinct from
    // strtol's endptr validation path.
    for (name, s) in [
        ("atoi_short", b"42\0".as_slice()),
        ("atoi_long", b"1234567890\0"),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| unsafe { frankenlibc_abi::stdlib_abi::atoi(black_box(p)) as i64 });
        let gl = time_it(|| unsafe { gatoi(black_box(p)) as i64 });
        println!(
            "{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}",
            fl / gl
        );
    }

    for (name, s) in [
        ("atol_short", b"42\0".as_slice()),
        ("atol_long", b"1234567890\0"),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| unsafe { frankenlibc_abi::stdlib_abi::atol(black_box(p)) as i64 });
        let gl = time_it(|| unsafe { gatol(black_box(p)) });
        println!(
            "{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}",
            fl / gl
        );
    }

    for (name, s) in [
        ("atoll_short", b"42\0".as_slice()),
        ("atoll_long", b"1234567890\0"),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| unsafe { frankenlibc_abi::stdlib_abi::atoll(black_box(p)) as i64 });
        let gl = time_it(|| unsafe { gatoll(black_box(p)) });
        println!(
            "{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}",
            fl / gl
        );
    }

    // strtod cases
    for (name, s) in [
        ("strtod_int", b"12345\0".as_slice()),
        ("strtod_simple", b"3.14159\0"),
        ("strtod_sci", b"1.234567e10\0"),
    ] {
        let p = s.as_ptr() as *const c_char;
        let fl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { frankenlibc_abi::stdlib_abi::strtod(black_box(p), &mut e) as i64 }
        });
        let gl = time_it(|| {
            let mut e: *mut c_char = std::ptr::null_mut();
            unsafe { gstrtod(black_box(p), &mut e) as i64 }
        });
        println!(
            "{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}",
            fl / gl
        );
    }

    // rand() — no args; glibc skips its lock when single-threaded, fl always
    // takes a std::sync::Mutex.
    type RandFn = unsafe extern "C" fn() -> c_int;
    let grand: RandFn = unsafe { std::mem::transmute(host(b"rand\0")) };
    let fl = time_it(|| unsafe { frankenlibc_abi::stdlib_abi::rand() as i64 });
    let gl = time_it(|| unsafe { grand() as i64 });
    println!("rand: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}", fl / gl);

    // getenv: point the dlmopen glibc's private `environ` at the process table so
    // both walk the same env; fl exports no_mangle getenv so dlmopen avoids it.
    type GetenvFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        let g_env = libc::dlsym(h as *mut _, b"environ\0".as_ptr().cast()) as *mut *mut *mut c_char;
        if !g_env.is_null() {
            *g_env = environ;
        }
        let ggetenv: GetenvFn = std::mem::transmute(libc::dlsym(h as *mut _, b"getenv\0".as_ptr().cast()));
        for (name, key) in [("getenv_hit", b"PATH\0".as_slice()), ("getenv_miss", b"NOPE_XYZZY_123\0")] {
            let p = key.as_ptr() as *const c_char;
            let fl = time_it(|| frankenlibc_abi::stdlib_abi::getenv(black_box(p)) as i64);
            let gl = time_it(|| ggetenv(black_box(p)) as i64);
            println!("{name}: fl={fl:.2}ns glibc={gl:.2}ns fl/glibc={:.2}", fl / gl);
        }
    }

    // clock_gettime/time use the vDSO once runtime-ready (gates resolution).
    frankenlibc_abi::string_abi::signal_runtime_ready_for_tests();
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        type CgFn = unsafe extern "C" fn(c_int, *mut libc::timespec) -> c_int;
        type TimeFn = unsafe extern "C" fn(*mut libc::time_t) -> libc::time_t;
        let gcg: CgFn = std::mem::transmute(libc::dlsym(h as *mut _, b"clock_gettime\0".as_ptr().cast()));
        let gtime: TimeFn = std::mem::transmute(libc::dlsym(h as *mut _, b"time\0".as_ptr().cast()));
        let mut ts = std::mem::zeroed::<libc::timespec>();
        let tsp = &mut ts as *mut libc::timespec;
        let flc = time_it(|| frankenlibc_abi::time_abi::clock_gettime(black_box(1), tsp) as i64);
        let glc = time_it(|| gcg(black_box(1), tsp) as i64);
        println!("clock_gettime: fl={flc:.2}ns glibc={glc:.2}ns fl/glibc={:.2}", flc / glc);
        let flt = time_it(|| frankenlibc_abi::time_abi::time(std::ptr::null_mut()) as i64);
        let glt = time_it(|| gtime(std::ptr::null_mut()) as i64);
        println!("time: fl={flt:.2}ns glibc={glt:.2}ns fl/glibc={:.2}", flt / glt);
    }

    // pthread_self — extremely hot (every mutex op); must not syscall. The bench
    // main thread is kernel-created like a deployed process's main thread.
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        type PtSelfFn = unsafe extern "C" fn() -> libc::pthread_t;
        let gpts: PtSelfFn =
            std::mem::transmute(libc::dlsym(h as *mut _, b"pthread_self\0".as_ptr().cast()));
        let flp = time_it(|| frankenlibc_abi::pthread_abi::pthread_self() as i64);
        let glp = time_it(|| gpts() as i64);
        println!("pthread_self: fl={flp:.2}ns glibc={glp:.2}ns fl/glibc={:.2}", flp / glp);
    }

    let _ = report;
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
