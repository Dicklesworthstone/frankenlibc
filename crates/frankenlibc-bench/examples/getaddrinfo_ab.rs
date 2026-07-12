//! Profile-first: deployed fl `getaddrinfo` (numeric query) vs host glibc, post resolver-bookkeeping
//! fix (cc_fl). Shows what dominates getaddrinfo now that the ~1.2us membrane tax is ~9ns — is the
//! resolver vein done (parity) or is there residual (addrinfo alloc / resolution) to attack?
//! Interleaved paired in ONE binary, order swapped every sample; fl-vs-fl null control first. Each
//! arm allocates + frees its own addrinfo list (fl via fl malloc/free, glibc via its own).
//!
//! Run: `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo run --release \
//!       -p frankenlibc-bench --features abi-bench --example getaddrinfo_ab`

use std::ffi::{CStr, c_char, c_int, c_void};
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::resolv_abi as fl;

const SAMPLES: usize = 2000;
const REPS: usize = 200;
const WARMUP: usize = 80;

const NODE: &CStr = c"127.0.0.1";
const SERVICE: &CStr = c"80";

fn median(xs: &[f64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
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
fn cv(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    100.0 * (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64).sqrt() / m
}

fn hints() -> libc::addrinfo {
    // SAFETY: addrinfo is POD; zeroed is a valid base.
    let mut h: libc::addrinfo = unsafe { std::mem::zeroed() };
    h.ai_family = libc::AF_INET;
    h.ai_socktype = libc::SOCK_STREAM;
    h.ai_flags = libc::AI_NUMERICHOST | libc::AI_NUMERICSERV;
    h
}

type GaiFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;
type FreeaiFn = unsafe extern "C" fn(*mut libc::addrinfo);

#[inline(never)]
fn fl_cycle(h: &libc::addrinfo) -> u32 {
    let mut acc = 0u32;
    for _ in 0..REPS {
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let rc = unsafe {
            fl::getaddrinfo(
                black_box(NODE.as_ptr()),
                black_box(SERVICE.as_ptr()),
                black_box(h as *const libc::addrinfo),
                &mut res,
            )
        };
        assert_eq!(rc, 0, "fl getaddrinfo failed");
        assert!(!res.is_null());
        acc = acc.wrapping_add(unsafe { (*res).ai_addrlen });
        unsafe { fl::freeaddrinfo(res) };
    }
    black_box(acc)
}

#[inline(never)]
fn host_cycle(gai: GaiFn, freeai: FreeaiFn, h: &libc::addrinfo) -> u32 {
    let mut acc = 0u32;
    for _ in 0..REPS {
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let rc = unsafe {
            gai(
                black_box(NODE.as_ptr()),
                black_box(SERVICE.as_ptr()),
                black_box(h as *const libc::addrinfo),
                &mut res,
            )
        };
        assert_eq!(rc, 0, "host getaddrinfo failed");
        assert!(!res.is_null());
        acc = acc.wrapping_add(unsafe { (*res).ai_addrlen });
        unsafe { freeai(res) };
    }
    black_box(acc)
}

fn host_syms() -> (GaiFn, FreeaiFn) {
    unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            c"libc.so.6".as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let gai = libc::dlsym(handle, c"getaddrinfo".as_ptr());
        let freeai = libc::dlsym(handle, c"freeaddrinfo".as_ptr());
        assert!(!gai.is_null() && !freeai.is_null());
        (
            std::mem::transmute::<*mut c_void, GaiFn>(gai),
            std::mem::transmute::<*mut c_void, FreeaiFn>(freeai),
        )
    }
}

fn verify(gai: GaiFn, h: &libc::addrinfo) {
    let mut fres: *mut libc::addrinfo = std::ptr::null_mut();
    let frc = unsafe { fl::getaddrinfo(NODE.as_ptr(), SERVICE.as_ptr(), h, &mut fres) };
    assert_eq!(frc, 0, "fl getaddrinfo verify");
    let mut gres: *mut libc::addrinfo = std::ptr::null_mut();
    let grc = unsafe { gai(NODE.as_ptr(), SERVICE.as_ptr(), h, &mut gres) };
    assert_eq!(grc, 0, "host getaddrinfo verify");
    let fsin = unsafe { &*(*fres).ai_addr.cast::<libc::sockaddr_in>() };
    let gsin = unsafe { &*(*gres).ai_addr.cast::<libc::sockaddr_in>() };
    assert_eq!(
        fsin.sin_addr.s_addr, gsin.sin_addr.s_addr,
        "fl vs glibc addr mismatch"
    );
    assert_eq!(fsin.sin_port, gsin.sin_port, "fl vs glibc port mismatch");
    println!(
        "verify: OK (fl == glibc getaddrinfo {NODE:?}:{SERVICE:?} -> addr {:08x} port {})",
        u32::from_be(fsin.sin_addr.s_addr),
        u16::from_be(fsin.sin_port)
    );
    unsafe { fl::freeaddrinfo(fres) };
}

fn paired<F: FnMut() -> u32, G: FnMut() -> u32>(mut a: F, mut b: G) -> (Vec<f64>, Vec<f64>) {
    let (mut xa, mut xb) = (Vec::new(), Vec::new());
    for i in 0..SAMPLES {
        let (ta, tb) = if i % 2 == 0 {
            let s = Instant::now();
            black_box(a());
            let t1 = s.elapsed();
            let s = Instant::now();
            black_box(b());
            (t1, s.elapsed())
        } else {
            let s = Instant::now();
            black_box(b());
            let t2 = s.elapsed();
            let s = Instant::now();
            black_box(a());
            (s.elapsed(), t2)
        };
        if i >= WARMUP {
            xa.push(ta.as_nanos() as f64 / REPS as f64);
            xb.push(tb.as_nanos() as f64 / REPS as f64);
        }
    }
    (xa, xb)
}

fn report(label: &str, fl_ns: &[f64], other: &[f64]) {
    let ratio: Vec<f64> = fl_ns.iter().zip(other.iter()).map(|(f, g)| f / g).collect();
    println!(
        "{label}: fl {:.1}ns  other {:.1}ns  paired fl/other median {:.4} ({:.2}x)  cv={:.1}%",
        median(fl_ns),
        median(other),
        median(&ratio),
        if median(&ratio) > 0.0 {
            1.0 / median(&ratio)
        } else {
            0.0
        },
        cv(&ratio),
    );
}

fn main() {
    let h = hints();
    let (gai, freeai) = host_syms();
    verify(gai, &h);

    black_box(fl_cycle(&h));
    black_box(host_cycle(gai, freeai, &h));

    let (n1, n2) = paired(|| fl_cycle(&h), || fl_cycle(&h));
    report("NULL CONTROL (fl vs fl)", &n1, &n2);
    let (f, g) = paired(|| fl_cycle(&h), || host_cycle(gai, freeai, &h));
    report("getaddrinfo fl vs glibc", &f, &g);
}
