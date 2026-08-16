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
//! ## Two separate things, and only one of them is real
//!
//! An earlier version of this file claimed the binding was per-symbol and
//! unpredictable — that `fma` collapsed onto fl while `memccpy` and friends did
//! not, in the same binary. Two independent findings killed that reading.
//!
//! **(1) The `fma` observation was a probe artifact, not a collapse.** The old
//! predicate compared `dli_fname` and flagged any arm sharing an object with fl.
//! But taking the address of an imported function can yield a PLT stub, which
//! lives in the executable — the same object as fl — while calls through it
//! still land in glibc. A standalone binary with **no frankenlibc in it at all**,
//! running this same probe, reports `fma` and `fmaf` inside the executable with
//! `dli_sname` NULL and `remquo`, `sinhf`, `memccpy`, `mempcpy`, `strlcpy`
//! inside libc/libm — the exact asymmetry that was read as per-symbol collapse —
//! and `fma(1,2,3)` still returns 5. So `conformance_diff_fma` was never
//! comparing fl against fl. The predicate below now compares ADDRESSES, which is
//! the only thing that answers the question.
//!
//! **(2) There IS a real collapse, and the build profile is what triggers it.**
//! Every one of fl's exports is gated by the SAME attribute:
//!
//! ```ignore
//! #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
//! pub unsafe extern "C" fn fma(..) -> f64
//! ```
//!
//! so they cannot disagree with each other. What they disagree with is the
//! profile, and the split is total:
//!
//! - **`debug_assertions` ON** (plain `cargo test`, this suite's normal mode):
//!   `no_mangle` is OFF, fl exports no C symbols into the test binary, and every
//!   link-time reference resolves through the PLT to `libc.so.6`. The oracle
//!   arms are real.
//! - **`debug_assertions` OFF** (`cargo test --release`, `--profile bench`,
//!   `release-perf`): `no_mangle` is ON, fl's definitions land in the rlib as
//!   strong globals, and ELF resolves the reference from the archive BEFORE the
//!   shared library. **Every** link-time oracle arm becomes fl. Not one symbol —
//!   all 1184 of them, across all 539 gates that use this pattern.
//!
//! Reproduced directly: a two-crate probe mirroring the attribute above, with
//! the rlib's `fma` returning a sentinel, prints `oracle_arm=5` under
//! `-Cdebug-assertions=on` and `oracle_arm=<sentinel>` under
//! `-Cdebug-assertions=off`.
//!
//! The practical rule this gate enforces: **a green `conformance_diff_*` run is
//! only evidence if it was built with `debug_assertions` on.** A release-profile
//! run of the differential suite proves nothing at all, and looks identical to a
//! passing one from the outside. `conformance_diff_fma` sidesteps the question
//! entirely by resolving its oracle with `dlsym`, which is correct in either
//! profile, and so is deliberately absent from the list below.

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
    // The six gates bd-c4z8fx listed as unaudited. conformance_diff_fgetpos is
    // absent because it has no glibc arm to audit at all — see that bead's note.
    fn lsearch(
        key: *const c_void,
        base: *mut c_void,
        nelp: *mut usize,
        width: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn lfind(
        key: *const c_void,
        base: *const c_void,
        nelp: *mut usize,
        width: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn qsort_r(
        base: *mut c_void,
        nmemb: usize,
        size: usize,
        compar: unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int,
        arg: *mut c_void,
    );
    fn catopen(name: *const c_char, oflag: c_int) -> *mut c_void;
    fn catclose(catd: *mut c_void) -> c_int;
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
}

/// What dladdr reports for a code address: the owning object and the symbol it
/// attributes the address to (`dli_sname` is NULL for a PLT stub).
///
/// Panicking rather than returning an Option keeps a failed lookup from reading
/// as "not glibc" — an unresolvable address is a broken probe, not evidence
/// about the arm.
fn describe(addr: *const c_void, what: &str) -> (String, Option<String>) {
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
    let object = unsafe { CStr::from_ptr(info.dli_fname) }
        .to_string_lossy()
        .into_owned();
    let symbol = if info.dli_sname.is_null() {
        None
    } else {
        // SAFETY: dli_sname is a NUL-terminated string owned by the loader.
        Some(
            unsafe { CStr::from_ptr(info.dli_sname) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    (object, symbol)
}

fn in_host_object(object: &str) -> bool {
    // libm.so.6 counts: glibc still ships a separate math object on some
    // layouts, and remquo/remquof legitimately resolve there.
    object.contains("libc.so") || object.contains("libm.so")
}

#[test]
fn extern_c_oracle_arms_resolve_to_host_glibc_not_to_fl() {
    // (link-time arm, fl's own definition, name). The fl column is what the
    // link-time arm would collapse onto if the linker satisfied it locally.
    let probes: [(*const c_void, *const c_void, &str); 21] = [
        (
            lsearch as *const c_void,
            frankenlibc_abi::search_abi::lsearch as *const c_void,
            "lsearch",
        ),
        (
            lfind as *const c_void,
            frankenlibc_abi::search_abi::lfind as *const c_void,
            "lfind",
        ),
        (
            qsort_r as *const c_void,
            frankenlibc_abi::stdlib_abi::qsort_r as *const c_void,
            "qsort_r",
        ),
        (
            catopen as *const c_void,
            frankenlibc_abi::locale_abi::catopen as *const c_void,
            "catopen",
        ),
        (
            catclose as *const c_void,
            frankenlibc_abi::locale_abi::catclose as *const c_void,
            "catclose",
        ),
        (
            setlocale as *const c_void,
            frankenlibc_abi::locale_abi::setlocale as *const c_void,
            "setlocale",
        ),
        (
            newlocale as *const c_void,
            frankenlibc_abi::locale_abi::newlocale as *const c_void,
            "newlocale",
        ),
        (
            freelocale as *const c_void,
            frankenlibc_abi::locale_abi::freelocale as *const c_void,
            "freelocale",
        ),
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
    let mut classified = 0usize;
    let mut via_plt_stub = Vec::new();
    for (linked, fl, name) in probes {
        let (linked_obj, linked_sym) = describe(linked, &format!("link-time {name}"));
        let (fl_obj, _) = describe(fl, &format!("fl {name}"));

        // Probe validity: fl's own definition must live in this test binary, not
        // in libc. If dladdr reported fl inside libc.so the comparison below
        // would be meaningless, and the gate would pass for the wrong reason.
        assert!(
            !in_host_object(&fl_obj),
            "probe is broken: dladdr places fl's own {name} in {fl_obj}"
        );

        // THE DECISIVE CHECK IS THE ADDRESS, NOT THE OBJECT NAME.
        //
        // An earlier version compared `dli_fname` and flagged any arm sharing an
        // object with fl. That is wrong, and it produced a false positive that
        // cost a day: taking the address of an imported function does not
        // necessarily yield the implementation's address. For some symbols the
        // linker hands back a PLT stub, which lives in the EXECUTABLE — the same
        // object as fl — while calls through it still land in glibc.
        //
        // Reproduced with fl absent entirely: a standalone binary declaring
        // fma/fmaf/remquo/sinhf/memccpy/mempcpy/strlcpy and running this same
        // dladdr probe reports fma and fmaf inside the executable with
        // dli_sname NULL, and the other five inside libc/libm — and `fma(1,2,3)`
        // still returns 5, the correct glibc result. "Same object as fl" is
        // therefore not evidence of anything. "Same ADDRESS as fl" is.
        if std::ptr::eq(linked, fl) {
            vacuous.push(format!(
                "  {name}: link-time arm IS fl's own definition at {linked:p} (object {linked_obj})"
            ));
            continue;
        }

        if in_host_object(&linked_obj) {
            classified += 1;
        } else {
            // Exe-resident but NOT fl's address. That is a PLT stub: the call
            // goes through the GOT to glibc. Recorded rather than ignored,
            // because it is the shape that was previously misread as a collapse.
            classified += 1;
            via_plt_stub.push(format!(
                "  {name}: PLT stub at {linked:p} in {linked_obj} (dli_sname {:?}); \
                 fl's own {name} is at {fl:p} — different address, so the call \
                 cannot be reaching fl",
                linked_sym
            ));
        }
    }

    // A zero only counts if the probe did work: assert the positive fact that
    // every arm was reached and classified, not merely that none was flagged.
    assert_eq!(
        classified,
        probes.len(),
        "only {classified} of {} arms were classified",
        probes.len()
    );
    assert!(
        vacuous.is_empty(),
        "{} of {} extern-\"C\" oracle arms ARE fl's own definition, so every \
         differential gate built on them is comparing fl against fl and passing \
         vacuously:\n{}\n\nIf ALL of them are flagged, the cause is the build \
         profile, not anything per-symbol — see \
         `differential_suite_is_only_evidence_with_debug_assertions_on` below.",
        vacuous.len(),
        probes.len(),
        vacuous.join("\n")
    );
    if !via_plt_stub.is_empty() {
        // Not a failure. Printed so the next person who runs this sees the shape
        // that was once misdiagnosed as a collapse, with the address evidence
        // that rules it out, instead of rediscovering it as a red.
        println!(
            "{} of {} arms are imported through a PLT stub (benign — the call \
             still reaches glibc):\n{}",
            via_plt_stub.len(),
            probes.len(),
            via_plt_stub.join("\n")
        );
    }
}

/// The precondition the whole `conformance_diff_*` suite rests on.
///
/// fl's C exports are gated `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`.
/// With `debug_assertions` off they become strong globals in the rlib, ELF
/// resolves every link-time `extern "C"` oracle arm from the archive instead of
/// `libc.so.6`, and all 539 gates that use that pattern start comparing fl
/// against fl — passing unconditionally while proving nothing.
///
/// The dladdr probe above would also catch that, but only for its 13 curated
/// symbols and only with a message about provenance. This states the cause
/// directly, so a release-profile run of the differential suite fails with the
/// reason rather than a puzzle.
///
/// This is deliberately NOT `#[cfg(debug_assertions)]`-skipped: a gate that
/// disappears in the exact configuration it exists to catch is no gate at all.
#[test]
fn differential_suite_is_only_evidence_with_debug_assertions_on() {
    assert!(
        cfg!(debug_assertions),
        "this test binary was built with debug_assertions OFF (--release, \
         --profile bench, or release-perf). In that configuration fl's \
         #[cfg_attr(not(debug_assertions), unsafe(no_mangle))] exports are LIVE, \
         so every link-time `extern \"C\"` oracle arm in the conformance_diff \
         suite binds to fl's own definition rather than to libc.so.6, and those \
         gates compare fl against itself. A green run in this profile is not \
         evidence of anything. Run the differential suite with the default dev \
         profile, or resolve the oracle with dlsym as conformance_diff_fma does."
    );
}
