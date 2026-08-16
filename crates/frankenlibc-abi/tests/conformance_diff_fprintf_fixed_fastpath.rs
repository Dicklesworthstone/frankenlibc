#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fprintf oracle resolved by dlsym

//! Differential gate for `fprintf`'s `%f` / `%.Nf` output (bd-5pfs0p).
//!
//! LANDED BEFORE THE FAST PATH IT WILL GATE, deliberately. `fprintf` still takes
//! the general path for floats today, so this records the BASELINE the
//! optimisation must preserve. When the probe is added, this becomes the gate
//! that holds it. A gate written after the change can only confirm the change
//! agrees with itself, which is the failure this suite has already been bitten
//! by twice (see bd-v0388t).
//!
//! WHY `fprintf` NEEDS ITS OWN GATE RATHER THAN A ROW IN THE SNPRINTF ONE. The
//! four buffer entry points (`snprintf`, `sprintf`, `vsnprintf`, `vsprintf`) all
//! write into a caller array, so the destination bytes are the observable and a
//! single helper covers them. `fprintf` writes into a `FILE*`, which means the
//! rendered bytes have to come back through the stream layer -- buffering,
//! flushing and the file position all sit between the formatter and anything
//! observable. Those are exactly the parts a fast path can get wrong while the
//! digits are perfect: a probe that returns the right count but bypasses the
//! stream's buffer accounting produces correct-looking output and a corrupted
//! FILE. So this gate compares the FILE CONTENTS after flush, not just the
//! return value.
//!
//! Each implementation writes through its OWN stdio to its OWN temp file, which
//! is required rather than tidy: an fl-opened `FILE*` handed to glibc's
//! `fprintf` is a different struct layout, so cross-passing would be undefined
//! behaviour rather than a comparison.
//!
//! THE ORACLE IS RESOLVED WITH `dlsym`, NOT DECLARED AT LINK TIME. A link-time
//! `extern "C" { fn fprintf(..) }` in an abi test binary is not reliably glibc:
//! `catopen` and `fma` are both confirmed cases where such a reference bound
//! locally in a plain `cargo test`, and `catopen`'s hid a live errno divergence
//! for months.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::Read as _;
use std::sync::atomic::{AtomicU64, Ordering};

type Fprintf = unsafe extern "C" fn(*mut c_void, *const c_char, ...) -> c_int;
type Fopen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Fclose = unsafe extern "C" fn(*mut c_void) -> c_int;

union SymF {
    raw: *mut c_void,
    function: Fprintf,
}
union SymO {
    raw: *mut c_void,
    function: Fopen,
}
union SymC {
    raw: *mut c_void,
    function: Fclose,
}

fn libc_handle() -> *mut c_void {
    // SAFETY: the name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
    // out of the global namespace.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6 — the oracle is unavailable");
    h
}

fn host_fprintf() -> (Fprintf, Fopen, Fclose) {
    let h = libc_handle();
    // SAFETY: handle came from dlopen; names are NUL-terminated constants.
    let (p, o, c) = unsafe {
        (
            libc::dlsym(h, c"fprintf".as_ptr()),
            libc::dlsym(h, c"fopen".as_ptr()),
            libc::dlsym(h, c"fclose".as_ptr()),
        )
    };
    assert!(!p.is_null() && !o.is_null() && !c.is_null(), "dlsym stdio trio");
    assert_ne!(
        p as usize,
        frankenlibc_abi::stdio_abi::fprintf as *const () as usize,
        "the resolved oracle IS fl's fprintf — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbols have C's documented signatures.
    unsafe {
        (
            SymF { raw: p }.function,
            SymO { raw: o }.function,
            SymC { raw: c }.function,
        )
    }
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> CString {
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let p = format!(
        "/tmp/fl-fprintf-{}-{}-{}",
        std::process::id(),
        tag,
        n
    );
    CString::new(p).unwrap()
}

fn read_back(path: &CStr) -> Vec<u8> {
    let s = path.to_str().expect("ascii path");
    let mut buf = Vec::new();
    std::fs::File::open(s)
        .expect("temp file should exist")
        .read_to_end(&mut buf)
        .expect("read temp file");
    let _ = std::fs::remove_file(s);
    buf
}

/// Render one value through fl's fprintf into a fresh temp file, returning the
/// return value and the FILE CONTENTS after close.
fn render_fl(fmt: &CStr, value: f64) -> (c_int, Vec<u8>) {
    let path = temp_path("fl");
    // SAFETY: path and mode are NUL-terminated; the stream is closed below.
    let f = unsafe { frankenlibc_abi::stdio_abi::fopen(path.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null(), "fl fopen failed");
    // SAFETY: `f` is an open fl stream and `fmt` names exactly one double.
    let rc = unsafe { frankenlibc_abi::stdio_abi::fprintf(f, fmt.as_ptr(), value) };
    // SAFETY: closing flushes, which is what makes the bytes observable.
    assert_eq!(unsafe { frankenlibc_abi::stdio_abi::fclose(f) }, 0, "fl fclose");
    (rc, read_back(&path))
}

fn render_host(t: (Fprintf, Fopen, Fclose), fmt: &CStr, value: f64) -> (c_int, Vec<u8>) {
    let (fprintf, fopen, fclose) = t;
    let path = temp_path("glibc");
    // SAFETY: as above, through the dlsym'd host trio.
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null(), "glibc fopen failed");
    // SAFETY: `f` is an open glibc stream and `fmt` names exactly one double.
    let rc = unsafe { fprintf(f, fmt.as_ptr(), value) };
    // SAFETY: closing flushes.
    assert_eq!(unsafe { fclose(f) }, 0, "glibc fclose");
    (rc, read_back(&path))
}

fn formats() -> Vec<(CString, String)> {
    let mut v = vec![(CString::new("%f").unwrap(), "%f".to_string())];
    for p in 0..=12 {
        // 0 and >9 sit outside the fast path the probe will add and must still
        // agree — a probe that accepted them would be a silent divergence
        // rather than a missed optimisation.
        let s = format!("%.{p}f");
        v.push((CString::new(s.clone()).unwrap(), s));
    }
    v
}

fn values() -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.5,
        0.125,
        // The money case a fixed-precision fast path exists for: neither
        // integral nor dyadic.
        1234.56,
        -1234.56,
        0.1,
        // Round-half-to-even traps: the exact binary value sits just below the
        // decimal tie, so a naive round-half-up prints the wrong last digit.
        2.675,
        1.005,
        8.835,
        99.995,
        1e15,
        1e19,
        1e300,
        f64::MAX,
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -f64::NAN,
    ];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..40 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        v.push(((state >> 11) as f64) / 4096.0);
    }
    v
}

#[test]
fn fprintf_fixed_matches_glibc_stream_bytes() {
    let host = host_fprintf();
    let mut compared = 0usize;
    for (fmt, label) in formats() {
        for &value in &values() {
            let (frc, fbytes) = render_fl(&fmt, value);
            let (grc, gbytes) = render_host(host, &fmt, value);
            assert_eq!(
                frc, grc,
                "{label} of {value:?} [{:#018x}]: return fl={frc} glibc={grc}",
                value.to_bits()
            );
            assert_eq!(
                fbytes,
                gbytes,
                "{label} of {value:?} [{:#018x}]: FILE contents differ after flush\n \
                 fl   ={:?}\n glibc={:?}",
                value.to_bits(),
                String::from_utf8_lossy(&fbytes),
                String::from_utf8_lossy(&gbytes)
            );
            // The return value must equal the bytes actually delivered to the
            // stream. This is the invariant a stream fast path breaks when it
            // renders correctly but bypasses the buffer accounting.
            assert_eq!(
                frc as usize,
                fbytes.len(),
                "{label} of {value:?}: fl returned {frc} but wrote {} bytes",
                fbytes.len()
            );
            compared += 1;
        }
    }
    // A zero only counts if the runner did work: assert the positive fact.
    assert!(
        compared > 800,
        "only {compared} comparisons ran — the grid collapsed"
    );
    println!("fprintf: compared {compared} (format, value) pairs against host glibc");
}

/// Formats the future probe must DECLINE. They carry a width, a flag, a
/// different conversion or a precision outside 1..=9, so they have to keep
/// taking the general path — and still match glibc byte-for-byte.
#[test]
fn adjacent_fprintf_float_formats_still_match_glibc() {
    let host = host_fprintf();
    let specs = [
        "%10.2f", "%-10.2f", "%+.2f", "% .2f", "%010.2f", "%#.2f", "%.0f", "%.10f", "%.15f",
        "%e", "%.2e", "%g", "%.2g", "%a", "%.2a", "%E", "%G",
    ];
    for spec in specs {
        let fmt = CString::new(spec).unwrap();
        for &value in &[0.0f64, -0.0, 1234.56, -1234.56, 0.1, 1e19, f64::INFINITY, f64::NAN] {
            let (frc, fbytes) = render_fl(&fmt, value);
            let (grc, gbytes) = render_host(host, &fmt, value);
            assert_eq!(frc, grc, "{spec} of {value:?}: return value");
            assert_eq!(
                fbytes,
                gbytes,
                "{spec} of {value:?}: FILE contents differ\n fl   ={:?}\n glibc={:?}",
                String::from_utf8_lossy(&fbytes),
                String::from_utf8_lossy(&gbytes)
            );
        }
    }
}
