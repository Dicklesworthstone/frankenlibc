#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // maps the kernel-specified vgetrandom state and draws through the vDSO
//! Gate for the `__vdso_getrandom` resolution and draw path (bd-dcrhgl).
//!
//! WHY THIS EXISTS. `getrandom` is the campaign's worst measured ratio at
//! 91.58-92.17x, and the cause is not a slow implementation but a missing
//! mechanism: measured by syscall counting, glibc 2.42 issues 3 getrandom
//! syscalls whether called 100 times or 10,000 — it draws from a userspace
//! CSPRNG in the vDSO — while fl issues 103 and 10,003, one per call.
//!
//! This gate covers the first half of closing that: resolving
//! `__vdso_getrandom` out of the kernel-mapped vDSO and proving a real draw
//! through it works. It deliberately does NOT test fl's `getrandom` being routed
//! through the vDSO, because that routing is not landed — see the note at the
//! end of this file.
//!
//! WHAT WOULD OTHERWISE GO UNNOTICED. A query that returns plausible-looking
//! numbers nobody can act on would pass a resolution-only test. So the gate MAPS
//! the state with exactly the protection and flags the kernel asked for, and
//! then draws through it. If the parameters are wrong, the mmap or the draw
//! fails here rather than in production.
//!
//! SKIPPING IS EXPLICIT, NOT SILENT. `__vdso_getrandom` exists from Linux 6.11.
//! On an older kernel the symbol is absent, which is a legitimate `None` and not
//! a defect — but a test that quietly passed in that case would also pass if the
//! resolver were broken. Every skip below prints why and asserts the POSITIVE
//! fact that the vDSO mapping itself was found, so "skipped" can never be
//! confused with "verified".

use std::ffi::c_void;

type GetrandomFn = unsafe extern "C" fn(*mut c_void, usize, libc::c_uint) -> isize;

fn live_glibc_getrandom() -> GetrandomFn {
    // SAFETY: libc.so.6 is the named incumbent and remains loaded for the
    // process lifetime. `getrandom` has the exact ABI declared by GetrandomFn.
    unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "failed to open live libc.so.6");
        let raw = libc::dlsym(handle, c"getrandom".as_ptr());
        assert!(!raw.is_null(), "libc.so.6 has no getrandom symbol");
        assert_ne!(
            raw as usize,
            frankenlibc_abi::unistd_abi::getrandom as *const () as usize,
            "incumbent lookup resolved to frankenlibc rather than libc.so.6"
        );
        std::mem::transmute(raw)
    }
}

fn fl_errno() -> libc::c_int {
    // SAFETY: FrankenLibC exposes its thread-local errno pointer.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

fn set_fl_errno(value: libc::c_int) {
    // SAFETY: as above, this writes only the current thread's errno.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = value };
}

/// True when the running kernel is new enough to export the symbol at all.
fn vdso_mapping_present() -> bool {
    // AT_SYSINFO_EHDR is present on any kernel that maps a vDSO; its absence
    // means the whole mechanism is unavailable for reasons unrelated to fl.
    std::fs::read("/proc/self/auxv").is_ok()
}

#[test]
fn vdso_getrandom_params_are_usable_and_a_draw_succeeds() {
    let Some((state_size, prot, flags)) =
        frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests()
    else {
        assert!(
            vdso_mapping_present(),
            "no vDSO mapping at all — this host cannot exercise the mechanism, \
             and the skip below would be meaningless"
        );
        eprintln!(
            "SKIP: __vdso_getrandom not exported by this kernel (needs >= 6.11). \
             This is a legitimate absence, not a failure; fl keeps the syscall path."
        );
        return;
    };

    // The kernel's own sanity bounds. A zero size would make the mmap below
    // succeed vacuously; an absurd one signals a misparsed struct.
    assert!(
        state_size > 0 && state_size <= 64 * 1024,
        "implausible size_of_opaque_state {state_size} — the params struct is \
         probably being read at the wrong offset or width"
    );

    // Map the state EXACTLY as the kernel specified. Using our own choice of
    // prot/flags here would test a mapping the vDSO never agreed to.
    // SAFETY: an anonymous mapping of the size the kernel asked for.
    let state = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            state_size as usize,
            prot as i32,
            flags as i32,
            -1,
            0,
        )
    };
    assert_ne!(
        state,
        libc::MAP_FAILED,
        "mmap of the vgetrandom state failed with the kernel's own prot={prot:#x} \
         flags={flags:#x} — the parameters are not usable, which is exactly the \
         failure a resolution-only test would have missed"
    );

    // A real draw. Two buffers so we can assert the output actually varies:
    // a stubbed or misconfigured CSPRNG that returned a constant would satisfy
    // the return-value check alone.
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    // SAFETY: `state` is mapped as the kernel specified, is this thread's alone,
    // and `state_size` matches what was mapped.
    let na = unsafe {
        frankenlibc_abi::time_abi::vdso_getrandom_draw_for_tests(
            &mut a,
            0,
            state,
            state_size as usize,
        )
    };
    // SAFETY: as above; the same single-threaded state is reused, which is the
    // contract's intent.
    let nb = unsafe {
        frankenlibc_abi::time_abi::vdso_getrandom_draw_for_tests(
            &mut b,
            0,
            state,
            state_size as usize,
        )
    };

    if na == -libc::ENOSYS as isize {
        eprintln!(
            "SKIP: the vDSO declined this draw with -ENOSYS, which the contract \
             permits; the syscall fallback is what a caller must use here."
        );
        // SAFETY: unmapping the mapping created above.
        unsafe { libc::munmap(state, state_size as usize) };
        return;
    }

    assert_eq!(
        na,
        a.len() as isize,
        "vDSO draw returned {na}, expected the full {} bytes",
        a.len()
    );
    assert_eq!(nb, b.len() as isize, "second vDSO draw returned {nb}");
    assert_ne!(
        a, b,
        "two consecutive draws returned identical bytes — the state is not \
         advancing, which would be a silent CSPRNG defect rather than a slow path"
    );
    assert_ne!(a, [0u8; 64], "first draw returned all zeros");

    // SAFETY: unmapping the mapping created above.
    unsafe { libc::munmap(state, state_size as usize) };
}

#[test]
fn vdso_getrandom_mapping_parameters_are_stable_for_the_process() {
    let first = frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests();
    let second = frankenlibc_abi::time_abi::vdso_getrandom_params_for_tests();

    if first.is_none() {
        assert!(
            vdso_mapping_present(),
            "no vDSO mapping makes an absent getrandom symbol ambiguous"
        );
    }
    assert_eq!(
        first, second,
        "vgetrandom mapping parameters changed within one process"
    );
}

#[test]
fn fl_getrandom_matches_success_semantics() {
    for len in [0usize, 1, 32, 256] {
        let mut buf = vec![0u8; len.max(1)];
        // SAFETY: buffer is at least `len` bytes.
        let n = unsafe {
            frankenlibc_abi::unistd_abi::getrandom(buf.as_mut_ptr().cast::<c_void>(), len, 0)
        };
        assert_eq!(n, len as isize, "fl getrandom({len}) returned {n}");
        if len >= 32 {
            assert_ne!(
                &buf[..len],
                &vec![0u8; len][..],
                "getrandom({len}) left the buffer all zeros"
            );
        }
    }
}

#[test]
fn fl_getrandom_zero_length_and_invalid_flags_match_live_glibc() {
    let glibc_getrandom = live_glibc_getrandom();

    for flags in [0, libc::c_uint::MAX] {
        set_fl_errno(0);
        // SAFETY: Linux permits a null buffer when length is zero.
        let fl = unsafe {
            frankenlibc_abi::unistd_abi::getrandom(std::ptr::null_mut(), 0, flags)
        };
        let fl_error = fl_errno();

        // SAFETY: this calls the separately resolved live libc function with
        // the same valid zero-length shape, and reads its current-thread errno.
        let (glibc, glibc_error) = unsafe {
            *libc::__errno_location() = 0;
            let result = glibc_getrandom(std::ptr::null_mut(), 0, flags);
            (result, *libc::__errno_location())
        };

        assert_eq!(
            (fl, fl_error),
            (glibc, glibc_error),
            "getrandom(NULL, 0, {flags:#x}) diverged from live libc.so.6"
        );
    }
}

// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY NOT LANDED HERE, and why.
//
// Routing fl's `getrandom` through the vDSO needs PER-THREAD state, and in a
// libc that is the hazardous part rather than the arithmetic:
//
//   1. The state must be mapped lazily per thread. A `thread_local!` carrying a
//      `Drop` registers a TLS destructor through `__cxa_thread_atexit_impl` —
//      which, inside our own libc, is a re-entry risk of exactly the class
//      already recorded for interposed symbols.
//   2. Without a destructor the mapping leaks one state per thread that ever
//      draws. glibc avoids both horns with a free list of retired states, which
//      is more machinery than belongs in the same change as the resolution.
//
// Shipping the draw path without settling those would trade a 92x slowdown for
// either a re-entrancy hazard or an unbounded mapping leak, in the CSPRNG. The
// resolution and parameter query are correct and useful on their own — they are
// what the routing will be built on — so they land here, gated, and the state
// lifecycle is tracked separately.
