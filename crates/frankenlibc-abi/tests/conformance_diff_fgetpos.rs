#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // real FILE* streams over a temp file; live host-glibc oracle

//! fgetpos/fsetpos gate (bd-678e8f) — roundtrip arms PLUS a host-glibc
//! differential over the same observable script.
//!
//! WHY THE HOST ARM EXISTS. bd-c4z8fx recorded this gate as unaudited for a
//! single reason: it had no glibc arm to audit. It drove fl's own streams and
//! checked them against fl's own reported offsets, so the claim in the header
//! above — "matches host glibc's observable behaviour" — was an intent rather
//! than a measurement; the file never called glibc. That is the
//! golden-values-wearing-a-differential-name class that
//! `scripts/audit_oracle_arms.py --no-host-arm` reports, and the coverage it
//! appears to contribute is not coverage (bd-reality-202609-lx578q.7).
//!
//! `fgetpos`, `fsetpos`, `ftell`, `ftello64`, `fgetpos64` and `fsetpos64` all
//! exist in host libc, so a real oracle is available. Resolution goes through
//! `common/dlsym_oracle`, which asserts the resolved address is NOT fl's own
//! export: fl exports every one of these symbols into this same test binary, so
//! a link-time declaration is only an oracle as long as the linker happens to
//! choose libc.so.6 instead. In a release-profile run it never does.
//!
//! WHAT IS COMPARED, AND WHY NOT THE BYTES OF `fpos_t`. `fpos_t` is opaque and
//! its layout is implementation-defined; POSIX only requires that a value
//! written by `fgetpos` and handed back to `fsetpos` on the same stream restore
//! the position. Comparing the struct would be asserting a layout, so the script
//! compares what a caller observes: return codes, the offsets `ftell`/`ftello64`
//! report, and the bytes a re-read returns. The `*64` scratch buffer is zeroed
//! and never inspected for the same reason.
//!
//! NULL-POINTER ARMS ARE NOT DIFFERENTIAL, DELIBERATELY. glibc dereferences a
//! null stream; fl returns -1/EINVAL. That divergence is FrankenLibC's specified
//! contract, so it is asserted against fl's documented behaviour rather than
//! compared against a call glibc does not survive.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp_with(content: &[u8]) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetpos-{}-{}", std::process::id(), n));
    std::fs::write(&p, content).unwrap();
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

// ---------------------------------------------------------------------------
// The differential script: one sequence of observable calls, run against fl and
// against host glibc, compared line for line.
// ---------------------------------------------------------------------------

type Fopen = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type Fclose = unsafe extern "C" fn(*mut c_void) -> c_int;
type Fread = unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize;
type Ftell = unsafe extern "C" fn(*mut c_void) -> c_long;
type Fgetpos = unsafe extern "C" fn(*mut c_void, *mut libc::fpos_t) -> c_int;
type Fsetpos = unsafe extern "C" fn(*mut c_void, *const libc::fpos_t) -> c_int;
type Fgetpos64 = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type Fsetpos64 = unsafe extern "C" fn(*mut c_void, *const c_void) -> c_int;
type Ftello64 = unsafe extern "C" fn(*mut c_void) -> i64;

/// One implementation's entry points, all resolved to the same provider.
struct Streams {
    fopen: Fopen,
    fclose: Fclose,
    fread: Fread,
    ftell: Ftell,
    fgetpos: Fgetpos,
    fsetpos: Fsetpos,
    fgetpos64: Fgetpos64,
    fsetpos64: Fsetpos64,
    ftello64: Ftello64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run the full script and return every observable result, in order.
///
/// The two arms must produce IDENTICAL vectors: any difference is a real
/// divergence in position reporting or in the bytes a restore re-reads.
unsafe fn run_script(s: &Streams, path: &CStr) -> Vec<String> {
    let mut t: Vec<String> = Vec::new();
    // SAFETY: every pointer passed here is either freshly created by this
    // function (the stream), a stack buffer of the stated length, or the
    // caller-owned path. Signature types are declared above and match the C
    // prototypes of the resolved symbols.
    unsafe {
        let f = (s.fopen)(path.as_ptr(), c"r".as_ptr());
        t.push(format!("fopen_is_null={}", f.is_null()));
        if f.is_null() {
            return t;
        }

        let mut buf = [0u8; 3];
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("read3={n}:{}", hex(&buf[..n.min(3)])));
        t.push(format!("ftell_at_3={}", (s.ftell)(f)));

        // Save position 3, read past it, restore, and re-read.
        let mut pos: libc::fpos_t = std::mem::zeroed();
        t.push(format!("fgetpos={}", (s.fgetpos)(f, &mut pos)));
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("read3b={n}:{}", hex(&buf[..n.min(3)])));
        t.push(format!("ftell_at_6={}", (s.ftell)(f)));

        t.push(format!("fsetpos={}", (s.fsetpos)(f, &pos)));
        t.push(format!("ftell_restored={}", (s.ftell)(f)));
        let n = (s.fread)(buf.as_mut_ptr().cast(), 1, 3, f);
        t.push(format!("reread3={n}:{}", hex(&buf[..n.min(3)])));

        // The 64-bit pair at offset 6, through a zeroed 16-byte opaque slot.
        let mut pos64 = [0u8; 16];
        t.push(format!(
            "fgetpos64={}",
            (s.fgetpos64)(f, pos64.as_mut_ptr().cast())
        ));
        t.push(format!("ftello64_at_6={}", (s.ftello64)(f)));
        let mut rest = [0u8; 4];
        let n = (s.fread)(rest.as_mut_ptr().cast(), 1, 4, f);
        t.push(format!("read4={n}:{}", hex(&rest[..n.min(4)])));
        t.push(format!(
            "fsetpos64={}",
            (s.fsetpos64)(f, pos64.as_ptr().cast())
        ));
        t.push(format!("ftello64_restored={}", (s.ftello64)(f)));
        let n = (s.fread)(rest.as_mut_ptr().cast(), 1, 4, f);
        t.push(format!("reread4={n}:{}", hex(&rest[..n.min(4)])));

        // Read the remainder to EOF: the offset at EOF must agree too.
        let mut tail = [0u8; 32];
        let n = (s.fread)(tail.as_mut_ptr().cast(), 1, 32, f);
        t.push(format!("read_tail={n}:{}", hex(&tail[..n.min(32)])));
        t.push(format!("ftell_at_eof={}", (s.ftell)(f)));

        t.push(format!("fclose={}", (s.fclose)(f)));
    }
    t
}

fn fl_streams() -> Streams {
    Streams {
        fopen: fl::fopen,
        fclose: fl::fclose,
        fread: fl::fread,
        ftell: fl::ftell,
        fgetpos: fl::fgetpos,
        fsetpos: fl::fsetpos,
        fgetpos64: fl::fgetpos64,
        fsetpos64: fl::fsetpos64,
        ftello64: fl::ftello64,
    }
}

/// Host glibc, resolved explicitly and rejected if it aliases fl's own export.
///
/// # Safety
///
/// The `F` type parameters must match each symbol's C prototype; the declared
/// type aliases above do.
fn host_streams() -> Streams {
    // SAFETY: each resolved address is given the declared type of the C
    // prototype and is checked against fl's own definition inside `host_fn`,
    // which panics rather than handing back an arm that IS fl.
    unsafe {
        Streams {
            fopen: host_fn(c"fopen", fl::fopen as *const ()),
            fclose: host_fn(c"fclose", fl::fclose as *const ()),
            fread: host_fn(c"fread", fl::fread as *const ()),
            ftell: host_fn(c"ftell", fl::ftell as *const ()),
            fgetpos: host_fn(c"fgetpos", fl::fgetpos as *const ()),
            fsetpos: host_fn(c"fsetpos", fl::fsetpos as *const ()),
            fgetpos64: host_fn(c"fgetpos64", fl::fgetpos64 as *const ()),
            fsetpos64: host_fn(c"fsetpos64", fl::fsetpos64 as *const ()),
            ftello64: host_fn(c"ftello64", fl::ftello64 as *const ()),
        }
    }
}

#[test]
fn fgetpos_fsetpos_match_host_glibc_trace() {
    let (path, c) = tmp_with(b"ABCDEFGHIJ");
    let fl_trace = unsafe { run_script(&fl_streams(), &c) };
    let host_trace = unsafe { run_script(&host_streams(), &c) };
    let _ = std::fs::remove_file(&path);

    // Pinned glibc reference values, so a host glibc change is visible rather
    // than silently absorbed into a passing comparison. This also makes the
    // comparison non-vacuous: a script that bailed out at the first call (for
    // example `fopen_is_null=true`, or an arm that returned early) would
    // otherwise compare equal to a similarly truncated run.
    let expected = vec![
        "fopen_is_null=false",
        "read3=3:414243",
        "ftell_at_3=3",
        "fgetpos=0",
        "read3b=3:444546",
        "ftell_at_6=6",
        "fsetpos=0",
        "ftell_restored=3",
        "reread3=3:444546",
        "fgetpos64=0",
        "ftello64_at_6=6",
        "read4=4:4748494a",
        "fsetpos64=0",
        "ftello64_restored=6",
        "reread4=4:4748494a",
        "read_tail=0:",
        "ftell_at_eof=10",
        "fclose=0",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    assert_eq!(
        host_trace, expected,
        "host glibc reference trace changed; re-derive the pinned values"
    );
    assert_eq!(
        fl_trace, host_trace,
        "fgetpos/fsetpos observable trace diverged from host glibc"
    );
}

/// The provider-identity control. A gate whose "glibc" arm resolves to fl's own
/// export would compare fl against itself and pass unconditionally; this asserts
/// that the resolver refuses that case rather than returning it.
#[test]
fn fgetpos_oracle_rejects_identical_candidate_provider() {
    // SAFETY: only resolves and compares code addresses; no mismatched call.
    let host = unsafe { host_addr(c"fgetpos", fl::fgetpos as *const ()) };
    let rejected = std::panic::catch_unwind(|| unsafe {
        host_addr(c"fgetpos", host.cast());
    });
    let error = rejected.expect_err("an identical candidate/oracle provider must be rejected");
    let message = error
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| error.downcast_ref::<&str>().copied())
        .expect("provider rejection must report a diagnostic");
    assert!(
        message.contains("IS fl's own definition"),
        "expected the provider-identity rejection, got: {message}"
    );
}

/// FrankenLibC's specified null-argument contract, which glibc does not share
/// (it dereferences) and which therefore cannot be a differential arm.
#[test]
fn fgetpos_null_arguments_follow_the_specified_fl_contract() {
    // SAFETY: the whole point is that these calls do not touch the pointers.
    unsafe {
        let errno_loc = frankenlibc_abi::errno_abi::__errno_location;
        assert_eq!(fl::fgetpos(std::ptr::null_mut(), std::ptr::null_mut()), -1);
        assert_eq!(*errno_loc(), libc::EINVAL);

        let (path, c) = tmp_with(b"xy");
        let f = fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>());
        assert!(!f.is_null());
        assert_eq!(fl::fgetpos(f, std::ptr::null_mut()), -1);
        assert_eq!(fl::fsetpos(f, std::ptr::null()), -1);
        assert_eq!(fl::fclose(f), 0);
        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// Roundtrip arms, unchanged from bd-678e8f: these pin fl's own stream
// behaviour independently of the oracle above (a divergence in BOTH arms
// would cancel out of the comparison but must not pass here).
// ---------------------------------------------------------------------------

#[test]
fn fgetpos_fsetpos_roundtrip() {
    let (path, c) = tmp_with(b"ABCDEFGHIJ");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    let mut buf = [0u8; 3];
    // Read "ABC".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"ABC");

    // Save position (offset 3).
    let mut pos: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { fl::fgetpos(f, &mut pos) },
        0,
        "fgetpos should succeed"
    );
    assert_eq!(
        unsafe { fl::ftell(f) },
        3,
        "position should be 3 after reading ABC"
    );

    // Read "DEF".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF");

    // Restore to offset 3, re-read -> "DEF" again.
    assert_eq!(unsafe { fl::fsetpos(f, &pos) }, 0, "fsetpos should succeed");
    assert_eq!(unsafe { fl::ftell(f) }, 3, "fsetpos must restore offset 3");
    buf = [0u8; 3];
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF", "re-read after fsetpos must match");

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fsetpos_to_start_rereads_whole_file() {
    let (path, c) = tmp_with(b"hello world");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    // Save start, read everything, restore start, read first 5.
    let mut start: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { fl::fgetpos(f, &mut start) }, 0);
    let mut all = [0u8; 11];
    assert_eq!(unsafe { fl::fread(all.as_mut_ptr().cast(), 1, 11, f) }, 11);
    assert_eq!(&all, b"hello world");

    assert_eq!(unsafe { fl::fsetpos(f, &start) }, 0);
    let mut five = [0u8; 5];
    assert_eq!(unsafe { fl::fread(five.as_mut_ptr().cast(), 1, 5, f) }, 5);
    assert_eq!(
        &five, b"hello",
        "fsetpos to start must re-read from the beginning"
    );

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}
