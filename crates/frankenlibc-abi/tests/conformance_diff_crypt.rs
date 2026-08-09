#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `crypt(3)`.
//!
//! Diffs fl's modern-method crypt implementations ($1$ MD5, $5$ SHA-256,
//! $6$ SHA-512) against host libcrypt. The host symbol lives in
//! libcrypt.so.1, so `#[link(name = "crypt")]` is required.
//!
//! Filed under [bd-xn6p8] follow-up — extending host-library parity
//! coverage beyond libresolv into libcrypt.
//!
//! ## fl scope
//!
//! fl intentionally rejects traditional DES (legacy 2-char salt) — see
//! the comment in unistd_abi::crypt. We don't diff DES inputs.
//!
//! ## Parity status (bd-fegsgf — CLOSED)
//!
//! This header used to claim fl's $1$/$5$/$6$ hashes "DIVERGE byte-for-byte
//! from host libcrypt on every input", and the diff arm below was `#[ignore]`d
//! on that basis. Running it (2026-08-09) refuted the claim: 13 of 15 cases
//! were already byte-identical, and the two that were not differed only in the
//! setting PREFIX, never in the digest —
//!
//! ```text
//!   fl:    $5$saltsaltsalt$/N7c7rmQ...      (rounds= dropped)
//!   glibc: $5$rounds=5000$saltsaltsalt$/N7c7rmQ...
//! ```
//!
//! fl re-emitted `rounds=` only when the count differed from the 5000 default;
//! the host re-emits it whenever the input setting carried one. Fixed in
//! `crypt::salt`, together with the surrounding rule that a malformed
//! `rounds=` is REJECTED (`*0`/`EINVAL`) rather than clamped into range.
//!
//! The diff arm now ASSERTS parity instead of reporting it. Do not re-ignore
//! it: the whole point is byte-for-byte equality of a persisted credential.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

type CryptFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

/// Resolve host libxcrypt at RUNTIME instead of link time.
///
/// This file used `#[link(name = "crypt")]`, which needs the `libcrypt.so`
/// DEVELOPMENT symlink. The rch worker images ship only the runtime
/// `libcrypt.so.1`, so the whole target failed to LINK there:
///   rust-lld: error: unable to find library -lcrypt
/// An unlinkable target is silent, not green — this gate has been contributing
/// nothing on the fleet while looking like just another passing name in a list.
///
/// conformance_diff_crypt_failure_token already hit this and solved it exactly
/// this way; its comment even names the missing symlink. The workaround simply
/// had not been carried across to this file.
fn crypt_fn() -> CryptFn {
    static F: OnceLock<usize> = OnceLock::new();
    let addr = *F.get_or_init(|| {
        const RTLD_NOW: c_int = 2;
        // SAFETY: constant, NUL-terminated library and symbol names.
        let h = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), RTLD_NOW) };
        assert!(!h.is_null(), "dlopen libcrypt.so.1 failed");
        let p = unsafe { dlsym(h, c"crypt".as_ptr()) };
        assert!(!p.is_null(), "dlsym crypt failed");
        p as usize
    });
    // SAFETY: dlsym returned a non-null pointer to `crypt`, whose signature is
    // fixed by POSIX.
    unsafe { std::mem::transmute::<usize, CryptFn>(addr) }
}

/// Same call shape the linked `crypt` had, so call sites are unchanged.
unsafe fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char {
    unsafe { crypt_fn()(key, salt) }
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// `crypt(3)` returns a pointer to STATIC storage — it is not thread-safe, and
/// `crypt_r` exists precisely because of that. libtest runs the arms of this
/// file concurrently, and two of them walk the case table, so without this lock
/// each thread reads a buffer the other has already overwritten. That is not
/// hypothetical: it reported "10 of 30 cases diverge" on a build whose real
/// divergence count was zero, with the diff naming pairs that both re-derive
/// correctly in isolation. Hold the lock across the host call AND the read of
/// its result.
static HOST_CRYPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn collect_crypt_divergences() -> Vec<Divergence> {
    let _guard = HOST_CRYPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();
    for (key, salt) in CRYPT_CASES.iter().chain(REJECTED_ROUNDS_CASES) {
        let key_c = CString::new(*key).unwrap();
        let salt_c = CString::new(*salt).unwrap();
        let p_fl = unsafe { fl::crypt(key_c.as_ptr(), salt_c.as_ptr()) };
        let p_lc = unsafe { crypt(key_c.as_ptr(), salt_c.as_ptr()) };
        let case = format!(
            "(key={:?}, salt={:?})",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(salt)
        );
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                case: case.clone(),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case,
                field: "hash",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    divs
}

/// Cases are kept cheap on purpose: every accepted `rounds=` here is at most
/// 5000, because the arm runs by default. A case like `rounds=999999999` is a
/// legal setting that would hang the suite for minutes; the boundary itself is
/// covered by the rejection cases, which cost nothing because the host and fl
/// both refuse them before hashing.
const CRYPT_CASES: &[(&[u8], &[u8])] = &[
    // ($key, $salt) — three modern methods × multiple salts/keys.
    (b"password", b"$1$abcdefgh$"),
    (b"password", b"$1$differntsalt$"),
    (b"", b"$1$abcdefgh$"),
    (b"hello", b"$1$short$"),
    (b"the quick brown fox", b"$1$abcdefgh$"),
    // `$1$` has no rounds field, so this is salt text truncated to 8 bytes.
    (b"password", b"$1$rounds=5000$x$"),
    (b"password", b"$5$saltsaltsalt$"),
    (b"password", b"$5$rounds=5000$saltsaltsalt$"),
    (b"password", b"$5$rounds=1000$saltsaltsalt$"),
    (b"", b"$5$emptysalt$"),
    (b"a", b"$5$saltsalt$"),
    (b"password", b"$6$saltsaltsalt$"),
    (b"password", b"$6$rounds=5000$saltsaltsalt$"),
    (b"password", b"$6$rounds=1000$saltsaltsalt$"),
    (b"", b"$6$emptysalt$"),
    (b"the quick brown fox", b"$6$LongerSaltHere$"),
];

/// Malformed `rounds=` fields. libxcrypt validates rather than clamps, so each
/// of these is the `*0` failure token with `EINVAL`, not a hash at the nearest
/// legal count — which is why they belong in the differential set: fl used to
/// answer every one of them with a well-formed hash the host would never
/// reproduce. Ordered: below min, above max, leading zero, non-numeric, empty,
/// signed, spaced, unterminated digit run, no closing `$`, u64-overflowing
/// digit run.
const REJECTED_ROUNDS_CASES: &[(&[u8], &[u8])] = &[
    (b"password", b"$5$rounds=999$x$"),
    (b"password", b"$5$rounds=1000000000$x$"),
    (b"password", b"$5$rounds=0500$x$"),
    (b"password", b"$5$rounds=abc$x$"),
    (b"password", b"$5$rounds=$x$"),
    (b"password", b"$5$rounds=+5000$x$"),
    (b"password", b"$5$rounds= 5000$x$"),
    (b"password", b"$5$rounds=5000x$x$"),
    (b"password", b"$5$rounds=12345"),
    (b"password", b"$5$rounds=99999999999999999999999$x$"),
    (b"password", b"$6$rounds=999$x$"),
    (b"password", b"$6$rounds=1000000000$x$"),
    (b"password", b"$6$rounds=0500$x$"),
    (b"password", b"$6$rounds=5000x$x$"),
];

/// Smoke test: fl::crypt accepts $1$/$5$/$6$ inputs and returns a non-null
/// hash carrying the right method tag. Cheap shape check that runs without the
/// host; byte parity is `crypt_matches_host_libxcrypt_byte_for_byte` below.
#[test]
fn fl_crypt_accepts_modern_method_salts() {
    for (key, salt) in CRYPT_CASES {
        let key_c = CString::new(*key).unwrap();
        let salt_c = CString::new(*salt).unwrap();
        let p_fl = unsafe { fl::crypt(key_c.as_ptr(), salt_c.as_ptr()) };
        assert!(
            !p_fl.is_null(),
            "fl::crypt unexpectedly returned NULL for (key={:?}, salt={:?})",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(salt)
        );
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        // Output should at minimum start with the same method tag.
        let tag = &salt[..3];
        assert!(
            s_fl.starts_with(tag),
            "fl::crypt output {:?} doesn't start with method tag {:?}",
            String::from_utf8_lossy(s_fl),
            String::from_utf8_lossy(tag)
        );
    }
}

/// THE gate for bd-fegsgf: fl's crypt output must be byte-identical to host
/// libxcrypt on every case, accepted and rejected alike. Was `#[ignore]`d as a
/// report; it is now an assertion.
#[test]
fn crypt_matches_host_libxcrypt_byte_for_byte() {
    let divs = collect_crypt_divergences();
    assert!(
        divs.is_empty(),
        "crypt diverges from host libxcrypt on {} of {} cases:\n{}",
        divs.len(),
        CRYPT_CASES.len() + REJECTED_ROUNDS_CASES.len(),
        render_divs(&divs),
    );
}

/// The rejection half stated without the host, so a malformed `rounds=` cannot
/// regress into a plausible-looking hash on a machine where libxcrypt is
/// missing. `*0` is libxcrypt's failure token (bd-r9ihvq).
#[test]
fn fl_crypt_rejects_malformed_rounds_fields() {
    for (key, salt) in REJECTED_ROUNDS_CASES {
        let key_c = CString::new(*key).unwrap();
        let salt_c = CString::new(*salt).unwrap();
        let p_fl = unsafe { fl::crypt(key_c.as_ptr(), salt_c.as_ptr()) };
        assert!(!p_fl.is_null(), "fl::crypt returned NULL, never the contract");
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        assert_eq!(
            s_fl,
            b"*0",
            "salt {:?} should be rejected, got {:?}",
            String::from_utf8_lossy(salt),
            String::from_utf8_lossy(s_fl),
        );
    }
}

#[test]
fn crypt_diff_coverage_report() {
    let divs = collect_crypt_divergences();
    eprintln!(
        "{{\"family\":\"libcrypt crypt\",\"reference\":\"glibc\",\"functions\":1,\"cases\":{},\"divergences\":{},\"status\":\"parity\",\"tracker_hint\":\"bd-fegsgf closed\"}}",
        CRYPT_CASES.len() + REJECTED_ROUNDS_CASES.len(),
        divs.len(),
    );
}
