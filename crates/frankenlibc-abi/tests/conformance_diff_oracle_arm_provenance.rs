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
    let read = |p: String| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string());
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
    let probes: [(*const c_void, *const c_void, &str); 20] = [
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
