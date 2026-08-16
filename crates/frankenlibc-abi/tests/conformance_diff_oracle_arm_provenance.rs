#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // dladdr provenance probe over live oracle arms
//! Meta-gate: prove the `extern "C"` oracle arms in the differential suite
//! actually reach host glibc.
//!
//! Most `conformance_diff_*` gates compare fl against glibc by calling fl
//! through an unambiguous Rust path (`frankenlibc_abi::string_abi::memccpy`)
//! and glibc through a link-time declaration:
//!
//! ```ignore
//! unsafe extern "C" { fn memccpy(dst: *mut c_void, ...) -> *mut c_void; }
//! ```
//!
//! That second arm is only an oracle if the reference binds to `libc.so.6`.
//! fl exports its own `#[no_mangle] memccpy` into the very same test binary, so
//! if the linker were to satisfy the declaration locally, BOTH arms would be fl
//! and every one of those gates would be comparing fl against itself — passing
//! unconditionally while proving nothing. That failure mode is invisible from
//! the outside: the suite stays green precisely because it has stopped testing
//! anything (this repo already carries two of these, bd-86hcwh's dark test
//! targets and the dlsym-vs-dlvsym compat-symbol trap).
//!
//! `dladdr` settles it by reporting which object a code address actually lives
//! in, which is PLT-safe in a way that comparing raw addresses is not: a
//! locally-bound symbol reports the test binary, a properly imported one
//! reports libc.
//!
//! This gate asserts the provenance rather than the behaviour, so it stays
//! valid as fl's implementations change.
//!
//! It is a CURATED list, not a sweep — nothing at runtime can enumerate which
//! other test binaries declare which symbols. When a new differential gate
//! reaches for glibc through a link-time declaration, add its symbol here.
//!
//! Whether a reference binds locally or to libc is per-symbol and NOT
//! predictable by inspection, which is the whole reason this probe exists:
//! `fma` collapsed onto fl while `memccpy`, `mempcpy`, `rawmemchr`, `strlcpy`
//! and `wcsnlen` did not, in the same binary, under the same toolchain. That
//! made `conformance_diff_fma` — 40,000+ random triples plus engineered
//! double-rounding cases — compare fl against fl and pass unconditionally. It
//! now resolves its oracle with `dlsym` and so is deliberately absent below.

use std::ffi::{CStr, c_char, c_int, c_void};

unsafe extern "C" {
    fn memccpy(dst: *mut c_void, src: *const c_void, c: c_int, n: usize) -> *mut c_void;
    fn mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void;
    fn strlcpy(dst: *mut c_char, src: *const c_char, n: usize) -> usize;
    fn wcsnlen(s: *const libc::wchar_t, n: usize) -> usize;
    fn strlcat(dst: *mut c_char, src: *const c_char, n: usize) -> usize;
    fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *mut c_void;
    fn strcasestr(h: *const c_char, n: *const c_char) -> *mut c_char;
    fn remquo(x: f64, y: f64, q: *mut c_int) -> f64;
    fn remquof(x: f32, y: f32, q: *mut c_int) -> f32;
    fn getw(stream: *mut libc::FILE) -> c_int;
    fn putw(w: c_int, stream: *mut libc::FILE) -> c_int;
    fn wmempcpy(dst: *mut libc::wchar_t, src: *const libc::wchar_t, n: usize)
    -> *mut libc::wchar_t;
}

/// Which shared object does this code address live in?
///
/// Returns the `dli_fname` dladdr reports. Panicking rather than returning an
/// Option keeps a failed lookup from reading as "not glibc" — an unresolvable
/// address is a broken probe, not evidence about the arm.
fn owning_object(addr: *const c_void, what: &str) -> String {
    let mut info = std::mem::MaybeUninit::<libc::Dl_info>::uninit();
    // SAFETY: addr is a live code address and info is writable.
    let rc = unsafe { libc::dladdr(addr, info.as_mut_ptr()) };
    assert!(rc != 0, "dladdr found no object for {what}");
    // SAFETY: dladdr returned non-zero, so it initialised the struct.
    let info = unsafe { info.assume_init() };
    assert!(
        !info.dli_fname.is_null(),
        "dladdr gave no object name for {what}"
    );
    // SAFETY: dli_fname is a NUL-terminated string owned by the loader.
    unsafe { CStr::from_ptr(info.dli_fname) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn extern_c_oracle_arms_resolve_to_host_glibc_not_to_fl() {
    // (link-time arm, fl's own definition, name). The fl column is what the
    // link-time arm would collapse onto if the linker satisfied it locally.
    let probes: [(*const c_void, *const c_void, &str); 13] = [
        (
            strlcat as *const c_void,
            frankenlibc_abi::string_abi::strlcat as *const c_void,
            "strlcat",
        ),
        (
            memmem as *const c_void,
            frankenlibc_abi::string_abi::memmem as *const c_void,
            "memmem",
        ),
        (
            strcasestr as *const c_void,
            frankenlibc_abi::string_abi::strcasestr as *const c_void,
            "strcasestr",
        ),
        (
            remquo as *const c_void,
            frankenlibc_abi::math_abi::remquo as *const c_void,
            "remquo",
        ),
        (
            remquof as *const c_void,
            frankenlibc_abi::math_abi::remquof as *const c_void,
            "remquof",
        ),
        (
            getw as *const c_void,
            frankenlibc_abi::stdio_abi::getw as *const c_void,
            "getw",
        ),
        (
            putw as *const c_void,
            frankenlibc_abi::stdio_abi::putw as *const c_void,
            "putw",
        ),
        (
            wmempcpy as *const c_void,
            frankenlibc_abi::glibc_internal_abi::wmempcpy as *const c_void,
            "wmempcpy",
        ),
        (
            memccpy as *const c_void,
            frankenlibc_abi::string_abi::memccpy as *const c_void,
            "memccpy",
        ),
        (
            mempcpy as *const c_void,
            frankenlibc_abi::string_abi::mempcpy as *const c_void,
            "mempcpy",
        ),
        (
            rawmemchr as *const c_void,
            frankenlibc_abi::string_abi::rawmemchr as *const c_void,
            "rawmemchr",
        ),
        (
            strlcpy as *const c_void,
            frankenlibc_abi::string_abi::strlcpy as *const c_void,
            "strlcpy",
        ),
        (
            wcsnlen as *const c_void,
            frankenlibc_abi::wchar_abi::wcsnlen as *const c_void,
            "wcsnlen",
        ),
    ];

    let mut vacuous = Vec::new();
    let mut reached_libc = 0usize;
    for (linked, fl, name) in probes {
        let linked_obj = owning_object(linked, &format!("link-time {name}"));
        let fl_obj = owning_object(fl, &format!("fl {name}"));

        // Probe validity: fl's own definition must live in this test binary, not
        // in libc. If dladdr reported fl inside libc.so the comparison below
        // would be meaningless, and the gate would pass for the wrong reason.
        assert!(
            !fl_obj.contains("libc.so") && !fl_obj.contains("libm.so"),
            "probe is broken: dladdr places fl's own {name} in {fl_obj}"
        );
        // libm.so.6 counts: glibc still ships a separate math object on some
        // layouts, and remquo/remquof legitimately resolve there.
        let reaches_host = linked_obj.contains("libc.so") || linked_obj.contains("libm.so");
        if reaches_host {
            reached_libc += 1;
        }

        // The decisive check. If the link-time arm lives in the same object as
        // fl's own definition, the "glibc" arm IS fl and the gate that relies
        // on it compares fl against itself.
        if linked_obj == fl_obj || !reaches_host {
            vacuous.push(format!(
                "  {name}: link-time arm resolves into {linked_obj}, fl lives in {fl_obj}"
            ));
        }
    }

    // A zero only counts if the probe did work: assert the positive fact that
    // every arm was actually located in libc, not merely that none was flagged.
    assert_eq!(
        reached_libc,
        probes.len(),
        "only {reached_libc} of {} arms were located in libc",
        probes.len()
    );
    assert!(
        vacuous.is_empty(),
        "{} of 13 extern-\"C\" oracle arms do NOT reach host glibc, so every \
         differential gate built on them is comparing fl against fl and passing \
         vacuously:\n{}",
        vacuous.len(),
        vacuous.join("\n")
    );
}
