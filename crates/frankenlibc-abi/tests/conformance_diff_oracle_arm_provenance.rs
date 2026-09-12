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
//! ## A fourth disguise: the host arm that is never declared at all
//!
//! The three disguises `scripts/audit_oracle_arms.py` was built for are all
//! spellings of an in-file `unsafe extern "C" { .. }` block. There is a fourth
//! that block-scanning cannot see, because the declaration is not in the gate:
//!
//! ```ignore
//! assert_eq!(fl_result, unsafe { libc::memcpy(dst, src, n) });
//! ```
//!
//! `libc::memcpy` is an `extern "C"` declaration too — it just lives in the
//! `libc` crate. The linker treats it identically to one written in the test
//! file, so it carries exactly the same hazard, while a scan keyed on in-file
//! extern blocks reports the gate as having no host arm at all. Measured on
//! 2026-08-16 over the 624 `conformance_diff_*` gates: **146 call `libc::<sym>`
//! on a symbol fl also exports, 129 of them with no `dlsym` anywhere in the
//! file** — a class disjoint from the 386 the script reports, and containing
//! the whole string/mem family (`conformance_diff_memcpy`, `_memset`, `_strlen`,
//! `_strcmp`, `_strchr`, `_string`, `_string_mut`, the four `_qsort_*`), which is
//! the most heavily hand-optimised code in the repo and therefore where a hollow
//! arm would hide the most.
//!
//! Those symbols also carry a second-order risk the declared ones do not: the
//! mem/str family is exactly what a Rust binary may get from a LOCAL provider
//! other than fl — `compiler_builtins` supplies `memcpy`/`memmove`/`memset`/
//! `memcmp`/`bcmp`/`strlen` — so "fl exports nothing in this profile" is not by
//! itself enough to conclude the arm reaches glibc. The probe below settles
//! that by address, the same way the declared one does, and prints the object
//! and `dli_sname` for each arm so the run banks which object answered rather
//! than only that nothing was flagged.
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
    // bd-v6t3e6 (conformance_diff_exceptflag) and bd-ij9mvq
    // (conformance_diff_reallocarray). The allocator pair matters most of any
    // arm here: that gate frees each impl's blocks with that impl's own free,
    // so if `malloc` and `free` did not both reach the same allocator it would
    // be mixing allocators, not just measuring nothing.
    fn fegetexceptflag(flagp: *mut u16, excepts: c_int) -> c_int;
    fn fesetexceptflag(flagp: *const u16, excepts: c_int) -> c_int;
    fn reallocarray(p: *mut c_void, nmemb: usize, size: usize) -> *mut c_void;
    fn malloc_usable_size(p: *mut c_void) -> usize;
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn catopen(name: *const c_char, oflag: c_int) -> *mut c_void;
    fn catclose(catd: *mut c_void) -> c_int;
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);

    // PROBE SUBJECTS, not oracles (bd-reality-202609-lx578q.7).
    //
    // The census below asks what the LINKER binds a link-time arm to, and the
    // `libc` crate does not expose these eleven names, so they are declared here
    // to be measured. They are never called — only their addresses are taken and
    // handed to `dladdr` — so the prototypes do not have to be exact, and a
    // capture reported against one of them is the finding, not a defect in this
    // file. Gates that reach these names by hand-declaring them are exactly the
    // population this measures.
    // `rawmemchr` is already declared above; it is the same kind of subject.
    fn strsep(stringp: *mut *mut c_char, delim: *const c_char) -> *mut c_char;
    fn index(s: *const c_char, c: c_int) -> *mut c_char;
    fn rindex(s: *const c_char, c: c_int) -> *mut c_char;
    fn bzero(s: *mut c_void, n: usize);
    fn bcopy(src: *const c_void, dst: *mut c_void, n: usize);
    fn bcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
    fn wcsstr(haystack: *const libc::wchar_t, needle: *const libc::wchar_t) -> *mut libc::wchar_t;
    fn wmemcpy(dst: *mut libc::wchar_t, src: *const libc::wchar_t, n: usize) -> *mut libc::wchar_t;
    fn wmemset(dst: *mut libc::wchar_t, c: libc::wchar_t, n: usize) -> *mut libc::wchar_t;
    fn wmemcmp(a: *const libc::wchar_t, b: *const libc::wchar_t, n: usize) -> c_int;
}

/// Where this thread is running right now: logical CPU, the physical core it
/// belongs to, its SMT siblings, and the core's current clock.
///
/// ## Why a provenance gate records core identity
///
/// Not for timing — nothing here is timed. For IFUNC selection. glibc resolves
/// `memcpy` and friends by running a resolver that reads CPUID, and the
/// implementation it picks is a property of the CORE THAT RAN THE RESOLVER. This
/// gate banks statements like "the arm resolved into libc.so.6 at an address
/// whose `dli_sname` is NULL, which is the ifunc shape". On a fleet whose cores
/// differ — different sockets, an asymmetric or partially-offlined machine, a
/// cpuset that spans microarchitectures — that statement is only as portable as
/// the core it was measured on, and a reader deserves to know which one that
/// was rather than to assume homogeneity.
///
/// The clock is recorded for the same reason a hostname is: it costs one file
/// read and it is the fastest way to notice that a run landed somewhere
/// unexpected (a throttled core, a shared SMT sibling under load).
/// The SLOT: which logical CPU, which physical core, which SMT siblings.
/// Reported separately from the clock because they change for different reasons
/// and only one of them can invalidate a result — see [`audit_arms`].
fn cpu_slot() -> String {
    // SAFETY: sched_getcpu takes no arguments and only reads scheduler state.
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        return "cpu=? (sched_getcpu failed)".to_string();
    }
    let read = |p: String| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    let base = format!("/sys/devices/system/cpu/cpu{cpu}");
    let core = read(format!("{base}/topology/core_id")).unwrap_or_else(|| "?".into());
    let siblings =
        read(format!("{base}/topology/thread_siblings_list")).unwrap_or_else(|| "?".into());
    format!("cpu={cpu} core={core} smt_siblings=[{siblings}]")
}

/// The current clock of the CPU this thread is on, in MHz.
fn cpu_mhz() -> String {
    // SAFETY: as in `cpu_slot`.
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        return "MHz unavailable".into();
    }
    std::fs::read_to_string(format!(
        "/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"
    ))
    .ok()
    .and_then(|khz| khz.trim().parse::<u64>().ok())
    .map(|khz| format!("{} MHz", khz / 1000))
    .unwrap_or_else(|| "MHz unavailable".into())
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
    let probes: [(*const c_void, *const c_void, &str); 27] = [
        (
            fegetexceptflag as *const c_void,
            frankenlibc_abi::fenv_abi::fegetexceptflag as *const c_void,
            "fegetexceptflag",
        ),
        (
            fesetexceptflag as *const c_void,
            frankenlibc_abi::fenv_abi::fesetexceptflag as *const c_void,
            "fesetexceptflag",
        ),
        (
            reallocarray as *const c_void,
            frankenlibc_abi::stdlib_abi::reallocarray as *const c_void,
            "reallocarray",
        ),
        (
            malloc_usable_size as *const c_void,
            frankenlibc_abi::malloc_abi::malloc_usable_size as *const c_void,
            "malloc_usable_size",
        ),
        (
            malloc as *const c_void,
            frankenlibc_abi::malloc_abi::malloc as *const c_void,
            "malloc",
        ),
        (
            free as *const c_void,
            frankenlibc_abi::malloc_abi::free as *const c_void,
            "free",
        ),
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

    audit_arms(&probes, "extern-\"C\"");
}

/// Classify each `(host arm, fl's own definition, name)` triple by ADDRESS and
/// fail if any arm turns out to be fl itself.
///
/// Shared by both probes because the question is identical whether the host arm
/// was declared in the gate or reached through the `libc` crate — only the way
/// the declaration is spelled differs, and the linker does not care which.
fn audit_arms(probes: &[(*const c_void, *const c_void, &str)], class: &str) {
    let (slot_at_start, mhz_at_start) = (cpu_slot(), cpu_mhz());
    let mut vacuous = Vec::new();
    let mut classified = 0usize;
    let mut via_plt_stub = Vec::new();
    let mut provenance = Vec::new();
    for &(linked, fl, name) in probes {
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

        provenance.push(format!(
            "  {name}: arm at {linked:p} in {linked_obj} (dli_sname {linked_sym:?})"
        ));

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
    // Print the object that answered for every arm, passing or not. A green run
    // of this gate is otherwise indistinguishable from one where the probe list
    // was empty, and "which object answered" is the fact the whole differential
    // suite rests on.
    // Placement is read at BOTH ends, not once. A single reading cannot
    // distinguish "this whole probe ran on core 17" from "it started on core 17
    // and the scheduler moved it", and for ifunc-resolved arms the core that ran
    // the resolver is the one that chose the implementation.
    //
    // SLOT and CLOCK are reported apart because only one of them can invalidate
    // anything here. A MIGRATION means a later arm may have been resolved on a
    // different core than an earlier one — that is the fact worth flagging. A
    // RECLOCK is normal boost behaviour on an idle-ish box and means nothing for
    // a value comparison; it is printed only so a row carries the frequency it
    // ran at. Conflating the two makes every run on a boosting CPU look
    // suspicious, which is how a real migration gets ignored.
    let (slot_at_end, mhz_at_end) = (cpu_slot(), cpu_mhz());
    let slot_note = if slot_at_start == slot_at_end {
        String::new()
    } else {
        format!("   <-- MIGRATED: {slot_at_start} -> {slot_at_end}")
    };
    println!(
        "{} {class} arms, provenance as reported by dladdr\n  placement: {} @ {} -> {} \
         (start -> end){}\n{}",
        probes.len(),
        slot_at_start,
        mhz_at_start,
        mhz_at_end,
        slot_note,
        provenance.join("\n")
    );
    assert!(
        vacuous.is_empty(),
        "{} of {} {class} oracle arms ARE fl's own definition, so every \
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

/// The same question for host arms reached through the `libc` crate rather than
/// through a declaration written in the gate.
///
/// 129 gates take their oracle this way with no `dlsym` anywhere in the file,
/// and `scripts/audit_oracle_arms.py` cannot see any of them: it scans for
/// in-file `extern "C"` blocks and these gates declare nothing. The symbols
/// below are the ones that carry weight — the mem/str family that
/// `conformance_diff_memcpy`, `_memset`, `_strlen`, `_strcmp`, `_strchr`,
/// `_string` and `_string_mut` compare against, the sort/search pair the four
/// `_qsort_*` gates use, and the calendar and numeric-parse arms.
///
/// The mem/str entries answer a question the declared-arm probe does not: fl is
/// not the only local provider of those symbols in a Rust binary, since
/// `compiler_builtins` carries `memcpy`/`memmove`/`memset`/`memcmp`/`strlen`.
/// Whatever answers, the address decides — and the printed `dli_sname` names it.
///
/// MEASURED 2026-08-16, dev profile, worker vmi1153651: all 20 arms land in
/// `/lib/x86_64-linux-gnu/libc.so.6`. No local provider captures any of them, so
/// the string/mem gates that take their oracle this way are real. Two shapes in
/// that output are worth recognising before they are misread:
///
/// - **`dli_sname` NULL inside libc.so** is the IFUNC shape, and is NOT the
///   PLT-stub shape documented above (which is NULL inside the EXECUTABLE). The
///   mem/str entries resolve to the implementation glibc's ifunc selected —
///   `__memcpy_avx_unaligned_erms` and friends — which are local symbols, so
///   dladdr has an object but no name for them. Object plus address still
///   answer the only question being asked.
/// - **`memcpy` and `memmove` report the same address**, because that ERMS
///   implementation serves both. Worth knowing when reading
///   `conformance_diff_memcpy`: its oracle is the overlap-safe routine.
/// - **`strtod` reports `strtof64`**, glibc's alias for it, the same way `free`
///   reports `__libc_free` in the declared-arm probe.
#[test]
fn libc_crate_oracle_arms_resolve_to_host_glibc_not_to_fl() {
    let probes: [(*const c_void, *const c_void, &str); 51] = [
        (
            libc::memcpy as *const c_void,
            frankenlibc_abi::string_abi::memcpy as *const c_void,
            "memcpy",
        ),
        (
            libc::memmove as *const c_void,
            frankenlibc_abi::string_abi::memmove as *const c_void,
            "memmove",
        ),
        (
            libc::memset as *const c_void,
            frankenlibc_abi::string_abi::memset as *const c_void,
            "memset",
        ),
        (
            libc::memcmp as *const c_void,
            frankenlibc_abi::string_abi::memcmp as *const c_void,
            "memcmp",
        ),
        (
            libc::strlen as *const c_void,
            frankenlibc_abi::string_abi::strlen as *const c_void,
            "strlen",
        ),
        (
            libc::strnlen as *const c_void,
            frankenlibc_abi::string_abi::strnlen as *const c_void,
            "strnlen",
        ),
        (
            libc::strchr as *const c_void,
            frankenlibc_abi::string_abi::strchr as *const c_void,
            "strchr",
        ),
        (
            libc::strrchr as *const c_void,
            frankenlibc_abi::string_abi::strrchr as *const c_void,
            "strrchr",
        ),
        (
            libc::strcmp as *const c_void,
            frankenlibc_abi::string_abi::strcmp as *const c_void,
            "strcmp",
        ),
        (
            libc::strncmp as *const c_void,
            frankenlibc_abi::string_abi::strncmp as *const c_void,
            "strncmp",
        ),
        (
            libc::strcasecmp as *const c_void,
            frankenlibc_abi::string_abi::strcasecmp as *const c_void,
            "strcasecmp",
        ),
        (
            libc::strstr as *const c_void,
            frankenlibc_abi::string_abi::strstr as *const c_void,
            "strstr",
        ),
        (
            libc::strspn as *const c_void,
            frankenlibc_abi::string_abi::strspn as *const c_void,
            "strspn",
        ),
        (
            libc::qsort as *const c_void,
            frankenlibc_abi::stdlib_abi::qsort as *const c_void,
            "qsort",
        ),
        (
            libc::bsearch as *const c_void,
            frankenlibc_abi::stdlib_abi::bsearch as *const c_void,
            "bsearch",
        ),
        (
            libc::mktime as *const c_void,
            frankenlibc_abi::time_abi::mktime as *const c_void,
            "mktime",
        ),
        (
            libc::timegm as *const c_void,
            frankenlibc_abi::time_abi::timegm as *const c_void,
            "timegm",
        ),
        (
            libc::strftime as *const c_void,
            frankenlibc_abi::time_abi::strftime as *const c_void,
            "strftime",
        ),
        (
            libc::strtod as *const c_void,
            frankenlibc_abi::stdlib_abi::strtod as *const c_void,
            "strtod",
        ),
        (
            libc::atoi as *const c_void,
            frankenlibc_abi::stdlib_abi::atoi as *const c_void,
            "atoi",
        ),
        // THE REST OF THE MEM/STR/WIDE SURFACE (bd-reality-202609-lx578q.7).
        //
        // The 20 symbols above were a sample. The rest of this family is the
        // part of the suite where a hollow arm would hide the most — it is the
        // most heavily hand-optimised code in the repo, and it is also exactly
        // what a LOCAL provider other than fl supplies: `compiler_builtins`
        // defines memcpy/memmove/memset/memcmp/bcmp/strlen, so "fl exports
        // nothing in this profile" was never sufficient to conclude the arm
        // reaches glibc. Censusing the family settles it by address.
        //
        // The first group goes through the `libc` crate, which is how the gates
        // themselves reach these symbols. The second group is reached through the
        // PROBE declarations in the extern block at the top of this file, because
        // the crate does not expose those names — those declarations are the
        // probe's SUBJECT, not an oracle this file relies on: the question the
        // measurement answers is precisely what the linker binds them to.
        (
            libc::memchr as *const c_void,
            frankenlibc_abi::string_abi::memchr as *const c_void,
            "memchr",
        ),
        (
            libc::memrchr as *const c_void,
            frankenlibc_abi::string_abi::memrchr as *const c_void,
            "memrchr",
        ),
        (
            rawmemchr as *const c_void,
            frankenlibc_abi::string_abi::rawmemchr as *const c_void,
            "rawmemchr",
        ),
        (
            libc::mempcpy as *const c_void,
            frankenlibc_abi::string_abi::mempcpy as *const c_void,
            "mempcpy",
        ),
        (
            libc::memmem as *const c_void,
            frankenlibc_abi::string_abi::memmem as *const c_void,
            "memmem",
        ),
        (
            libc::strcpy as *const c_void,
            frankenlibc_abi::string_abi::strcpy as *const c_void,
            "strcpy",
        ),
        (
            libc::stpcpy as *const c_void,
            frankenlibc_abi::string_abi::stpcpy as *const c_void,
            "stpcpy",
        ),
        (
            libc::strncpy as *const c_void,
            frankenlibc_abi::string_abi::strncpy as *const c_void,
            "strncpy",
        ),
        (
            libc::stpncpy as *const c_void,
            frankenlibc_abi::string_abi::stpncpy as *const c_void,
            "stpncpy",
        ),
        (
            libc::strcat as *const c_void,
            frankenlibc_abi::string_abi::strcat as *const c_void,
            "strcat",
        ),
        (
            libc::strncat as *const c_void,
            frankenlibc_abi::string_abi::strncat as *const c_void,
            "strncat",
        ),
        (
            libc::strtok as *const c_void,
            frankenlibc_abi::string_abi::strtok as *const c_void,
            "strtok",
        ),
        (
            strsep as *const c_void,
            frankenlibc_abi::string_abi::strsep as *const c_void,
            "strsep",
        ),
        (
            libc::strdup as *const c_void,
            frankenlibc_abi::string_abi::strdup as *const c_void,
            "strdup",
        ),
        (
            libc::strndup as *const c_void,
            frankenlibc_abi::string_abi::strndup as *const c_void,
            "strndup",
        ),
        (
            libc::strcspn as *const c_void,
            frankenlibc_abi::string_abi::strcspn as *const c_void,
            "strcspn",
        ),
        (
            libc::strpbrk as *const c_void,
            frankenlibc_abi::string_abi::strpbrk as *const c_void,
            "strpbrk",
        ),
        (
            libc::strcasestr as *const c_void,
            frankenlibc_abi::string_abi::strcasestr as *const c_void,
            "strcasestr",
        ),
        (
            libc::strcoll as *const c_void,
            frankenlibc_abi::string_abi::strcoll as *const c_void,
            "strcoll",
        ),
        (
            libc::strxfrm as *const c_void,
            frankenlibc_abi::string_abi::strxfrm as *const c_void,
            "strxfrm",
        ),
        // The BSD compat aliases and the legacy byte routines. These are the
        // symbols a link-time gate is most likely to declare by hand (the crate
        // does not offer them), which makes them the ones worth probing.
        (
            index as *const c_void,
            frankenlibc_abi::string_abi::index as *const c_void,
            "index",
        ),
        (
            rindex as *const c_void,
            frankenlibc_abi::string_abi::rindex as *const c_void,
            "rindex",
        ),
        (
            bzero as *const c_void,
            frankenlibc_abi::string_abi::bzero as *const c_void,
            "bzero",
        ),
        (
            bcopy as *const c_void,
            frankenlibc_abi::string_abi::bcopy as *const c_void,
            "bcopy",
        ),
        (
            bcmp as *const c_void,
            frankenlibc_abi::string_abi::bcmp as *const c_void,
            "bcmp",
        ),
        // The wide family, same hazard: `wmemcpy`/`wmemset`/`wmemcmp`/`wmemchr`
        // are the wide spellings of the compiler_builtins-supplied set.
        (
            libc::wcslen as *const c_void,
            frankenlibc_abi::wchar_abi::wcslen as *const c_void,
            "wcslen",
        ),
        (
            wcsstr as *const c_void,
            frankenlibc_abi::wchar_abi::wcsstr as *const c_void,
            "wcsstr",
        ),
        (
            wmemcpy as *const c_void,
            frankenlibc_abi::wchar_abi::wmemcpy as *const c_void,
            "wmemcpy",
        ),
        (
            wmemset as *const c_void,
            frankenlibc_abi::wchar_abi::wmemset as *const c_void,
            "wmemset",
        ),
        (
            wmemcmp as *const c_void,
            frankenlibc_abi::wchar_abi::wmemcmp as *const c_void,
            "wmemcmp",
        ),
        (
            libc::wmemchr as *const c_void,
            frankenlibc_abi::wchar_abi::wmemchr as *const c_void,
            "wmemchr",
        ),
    ];

    audit_arms(&probes, "libc-crate");
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

// ---------------------------------------------------------------------------
// The NONE class, and why it has to be named rather than counted
// (bd-reality-202609-lx578q.7)
// ---------------------------------------------------------------------------

/// Differential gates that legitimately never reach the host, with the reason
/// each one cannot.
///
/// `scripts/audit_oracle_arms.py --no-host-arm` reports this class, and it is
/// the one class the script cannot distinguish from a defect: a file named
/// `conformance_diff_*` that never calls glibc may be a golden-values test
/// wearing a differential name (a defect, because a coverage audit counts it as
/// a live comparison) or it may be an INTERNAL invariant that has no host
/// counterpart at all (legitimate, but not conformance evidence either).
///
/// Only the second kind belongs here, and only with a reason. Three gates were
/// removed from this list by giving them the host arm they were missing —
/// `conformance_diff_fgetpos`, `conformance_diff_sigmask` and
/// `conformance_diff_floatn_aliases` (the last only for its bit-defined subset;
/// the rest of that surface has no bit-exact oracle and stays aliased to its own
/// base).
///
/// Removing an entry is the point of the list; adding one asserts that no host
/// arm exists AND that the file does not claim conformance it cannot deliver.
const INTERNAL_INVARIANT_GATES: &[(&str, &str)] = &[
    (
        "conformance_diff_known_remaining_stack.rs",
        "internal membrane property: whether a stack address reports a remaining \
         length. There is no C function to call; the question is about fl's own \
         arena lookup, and the host has no equivalent to compare against.",
    ),
    (
        "conformance_diff_malloc_stats_binning.rs",
        "internal allocator histogram invariant across size-class boundaries. \
         glibc has no observable equivalent of fl's per-class accumulator.",
    ),
    (
        "conformance_diff_mergesort.rs",
        "glibc does not export `mergesort` at all (it is a BSD/musl entry point), \
         so there is no host arm to have. The file compares fl's in-place index \
         sort against a reference stable sort — a metamorphic invariant, not \
         conformance.",
    ),
    (
        "conformance_diff_scan_c_string.rs",
        "internal SWAR scanner behind strcpy/stpcpy/strncat, checked against a \
         byte-at-a-time reference. `bench_scan_c_string` is not a libc function.",
    ),
    (
        "conformance_diff_segment_free_st_elision.rs",
        "internal allocator property: every live allocation has a distinct \
         address across free-and-reuse cycles. Asserting it against glibc would \
         be asserting glibc's allocator, not fl's.",
    ),
];

/// Linker/loader plumbing that is present in almost every gate without making
/// it a differential: capturing test output, driving subprocesses, or reading
/// errno. Deliberately the same list the Python audit uses, so the two cannot
/// disagree about what counts.
const INFRASTRUCTURE_SYMBOLS: &[&str] = &[
    "dlopen",
    "dlsym",
    "dlvsym",
    "dlclose",
    "dladdr",
    "dlerror",
    "fork",
    "waitpid",
    "_exit",
    "raise",
    "abort",
    "kill",
    "__errno_location",
    "pipe",
    "close",
    "read",
    "write",
    "unlink",
    "mkstemp",
    "signal",
    "sigaction",
    "sigprocmask",
    "sigemptyset",
    "sigaddset",
    "sigismember",
    "feclearexcept",
    "fetestexcept",
];

/// Remove Rust comments so prose cannot be mistaken for a declaration.
///
/// The Python audit learned this the hard way: a gate that correctly documents
/// the `unsafe extern "C"` block it replaced matches a naive scan of that block,
/// so the better a gate is annotated the more certainly it is reported as
/// unfixed. Comments are stripped before classification for the same reason.
fn strip_rust_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b = src.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        match b[i] {
            b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            // A `//` inside a string literal is not a comment; skipping strings
            // keeps a URL or a format string from truncating the file.
            b'"' => {
                out.push('"');
                i += 1;
                while i < b.len() {
                    let c = b[i];
                    out.push(c as char);
                    i += 1;
                    if c == b'\\' {
                        if i < b.len() {
                            out.push(b[i] as char);
                            i += 1;
                        }
                    } else if c == b'"' {
                        break;
                    }
                }
            }
            c => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    out
}

/// Does this gate reach the host at all, by any of the mechanisms the suite
/// actually uses?
///
/// Deliberately BROADER than the Python audit's classification: an in-file
/// `unsafe extern "C"` declaration counts when its symbol is not infrastructure
/// plumbing, and so does `libc::<name>(..)`, because both are `extern "C"`
/// imports the linker resolves the same way. What this function decides is only
/// whether the file reaches a host arm of SOME kind; whether that arm can be
/// captured by a local provider is the audit's question, tracked separately by
/// the curated probes above.
fn gate_reaches_a_host_arm(src: &str) -> bool {
    if src.contains("dlsym") || src.contains("dlvsym") || src.contains("host_addr") {
        return true;
    }
    if src.contains("Command::new") {
        return true;
    }
    for block in src.split("extern \"C\" {").skip(1) {
        let Some(end) = block.find("\n}") else {
            continue;
        };
        for line in block[..end].lines() {
            let t = line.trim();
            let Some(rest) = t.strip_prefix("fn ").or_else(|| t.strip_prefix("pub fn ")) else {
                continue;
            };
            let Some(symbol) = rest.split(['(', '<', ' ']).next() else {
                continue;
            };
            if !symbol.is_empty() && !INFRASTRUCTURE_SYMBOLS.contains(&symbol) {
                return true;
            }
        }
    }
    for (idx, _) in src.match_indices("libc::") {
        let rest = &src[idx + "libc::".len()..];
        let symbol: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !symbol.is_empty() && !INFRASTRUCTURE_SYMBOLS.contains(&symbol.as_str()) {
            return true;
        }
    }
    false
}

/// Every `conformance_diff_*` gate reaches the host, or is named here as an
/// internal invariant with a reason.
///
/// This is the half of the oracle-arm audit that can be enforced WITHOUT running
/// the gates. The provenance probes above ask "does this arm reach glibc?" for a
/// curated list of symbols; this asks the strictly weaker question "does this
/// file reach the host at all?" for every gate, and fails when the answer is no
/// and nobody has said why. Without it, a new `conformance_diff_*` file that
/// compares fl against frozen literals is counted as differential coverage by
/// every audit downstream, which is precisely the promotion .7 forbids.
#[test]
fn every_differential_gate_reaches_a_host_arm_or_is_a_declared_invariant() {
    let dir = std::path::Path::new("tests");
    let mut scanned = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    let mut allowlisted: Vec<String> = Vec::new();

    for entry in std::fs::read_dir(dir).expect("read tests/ -- test CWD is the package root") {
        let path = entry.expect("readable dir entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.starts_with("conformance_diff_") || !name.ends_with(".rs") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        scanned += 1;
        if gate_reaches_a_host_arm(&strip_rust_comments(&text)) {
            continue;
        }
        if let Some((_, reason)) = INTERNAL_INVARIANT_GATES
            .iter()
            .find(|(file, _)| *file == name)
        {
            assert!(
                reason.len() > 40,
                "the reason for {name} must actually explain why no host arm exists"
            );
            allowlisted.push(name);
            continue;
        }
        offenders.push(name);
    }

    assert!(
        scanned > 500,
        "only {scanned} differentials scanned; the glob is wrong"
    );
    assert!(
        offenders.is_empty(),
        "these gates are named conformance_diff_* but never reach host glibc, \
         so nothing in them is a comparison against the reference. Give the file \
         a real oracle (see common/dlsym_oracle.rs) or add it to \
         INTERNAL_INVARIANT_GATES with the reason it cannot have one:\n{}",
        offenders.join("\n")
    );
    // A stale allowlist entry is not a defect in the gate, but it is exactly the
    // silent drift this file keeps warning about, so it is checked too.
    for (file, _) in INTERNAL_INVARIANT_GATES {
        assert!(
            allowlisted.contains(&file.to_string()),
            "{file} is allowlisted as an internal invariant but now reaches a \
             host arm; remove it from INTERNAL_INVARIANT_GATES"
        );
    }
}

/// Negative control for the classifier the gate above rests on.
///
/// The gate is only worth its runtime if `gate_reaches_a_host_arm` answers
/// FALSE for the shape it exists to catch and TRUE for the shapes it must not
/// report. That discrimination is asserted here on synthetic sources, so a
/// classifier that degenerated to "everything reaches the host" (which would
/// make the gate silently vacuous) fails loudly instead.
#[test]
fn host_arm_classifier_discriminates_the_golden_values_shape() {
    // Frozen literals only: no host arm, and this is the class that must be
    // reported rather than counted as differential coverage.
    assert!(!gate_reaches_a_host_arm(
        "let got = frankenlibc_abi::string_abi::strlen(p);\nassert_eq!(got, 3);\n"
    ));
    // An `unsafe extern "C"` declaration of a real libc entry point is a host
    // arm (whether it can be CAPTURED is the audit's separate question).
    assert!(gate_reaches_a_host_arm(
        "unsafe extern \"C\" {\n    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;\n}\n"
    ));
    // A `libc::foo(..)` call is the same kind of import.
    assert!(gate_reaches_a_host_arm(
        "let a = unsafe { libc::strcmp(x, y) };\n"
    ));
    // Loader plumbing is not a differential. `free` is deliberately NOT in this
    // list — the allocator gates compare it as a real oracle — so the plumbing
    // here is the process/errno plumbing the suite uses to capture output.
    assert!(!gate_reaches_a_host_arm(
        "unsafe extern \"C\" {\n    fn close(fd: c_int) -> c_int;\n    fn read(fd: c_int, b: *mut c_void, n: usize) -> isize;\n}\n"
    ));
    // ... while an allocator entry point IS a host arm, which is the same
    // distinction `scripts/audit_oracle_arms.py` draws with the same list.
    assert!(gate_reaches_a_host_arm(
        "unsafe extern \"C\" {\n    fn malloc(n: usize) -> *mut c_void;\n}\n"
    ));
    // Runtime resolution is a host arm by definition.
    assert!(gate_reaches_a_host_arm(
        "let f = unsafe { dlsym_oracle::host_fn(c\"strchr\", fl::strchr as *const ()) };\n"
    ));
    // A subprocess oracle is still an oracle.
    assert!(gate_reaches_a_host_arm(
        "let out = std::process::Command::new(\"hostprobe\").output().unwrap();\n"
    ));
    // Prose is not code: documenting the declaration a gate replaced must not
    // make the gate look like it still has one. This is the failure mode the
    // Python audit hit, and it punished the best-documented conversions.
    assert!(!gate_reaches_a_host_arm(&strip_rust_comments(
        "// A link-time `unsafe extern \"C\" { fn strchr(..) }` is not reliably\n\
         // glibc in an abi test binary.\n"
    )));
    // A `//` inside a string literal is not a comment, and a URL must not
    // truncate the rest of the file.
    assert!(gate_reaches_a_host_arm(&strip_rust_comments(
        "let u = \"http://example.invalid\";\nunsafe extern \"C\" {\n    fn strchr(s: *const c_char, c: c_int) -> *mut c_char;\n}\n"
    )));
}
