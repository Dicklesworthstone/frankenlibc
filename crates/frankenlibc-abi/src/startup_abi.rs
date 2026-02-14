//! Phase-0 CRT bootstrap ABI plumbing.
//!
//! This module exposes a constrained startup path for controlled fixtures.
//! `__libc_start_main` delegates to host libc by default to avoid hijacking
//! normal process bootstrap in LD_PRELOAD mode.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;
use crate::startup_helpers::{
    AT_NULL, MAX_STARTUP_SCAN, StartupInvariants, build_invariants, normalize_argc, scan_auxv_pairs,
};

type MainFn = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;
type HookFn = unsafe extern "C" fn();
type HostStartMainFn = unsafe extern "C" fn(
    Option<MainFn>,
    c_int,
    *mut *mut c_char,
    Option<HookFn>,
    Option<HookFn>,
    Option<HookFn>,
    *mut c_void,
) -> c_int;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

static LAST_ARGC: AtomicUsize = AtomicUsize::new(0);
static LAST_ARGV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_ENV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_AUXV_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_SECURE_MODE: AtomicU8 = AtomicU8::new(0);

#[repr(C)]
pub struct StartupInvariantSnapshot {
    pub argc: usize,
    pub argv_count: usize,
    pub env_count: usize,
    pub auxv_count: usize,
    pub secure_mode: c_int,
}

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    // SAFETY: `__errno_location` returns a valid TLS errno pointer.
    let p = unsafe { super::errno_abi::__errno_location() };
    // SAFETY: errno pointer is valid for writes on this thread.
    unsafe { *p = val };
}

fn store_invariants(inv: StartupInvariants) {
    LAST_ARGC.store(inv.argc, Ordering::Relaxed);
    LAST_ARGV_COUNT.store(inv.argv_count, Ordering::Relaxed);
    LAST_ENV_COUNT.store(inv.env_count, Ordering::Relaxed);
    LAST_AUXV_COUNT.store(inv.auxv_count, Ordering::Relaxed);
    LAST_SECURE_MODE.store(u8::from(inv.secure_mode), Ordering::Relaxed);
}

fn startup_phase0_env_enabled() -> bool {
    const KEY_EQ: &[u8] = b"FRANKENLIBC_STARTUP_PHASE0=";
    const MAX_SCAN: usize = 4096;

    // Read process environment directly from `environ` to avoid calling any
    // interposed ABI symbol (notably getenv/strlen/memcpy) during startup.
    let mut envp = unsafe { environ };
    if envp.is_null() {
        return false;
    }

    for _ in 0..MAX_SCAN {
        // SAFETY: `envp` is a null-terminated vector of C string pointers.
        let entry = unsafe { *envp };
        if entry.is_null() {
            return false;
        }

        let mut matched = true;
        for (idx, want) in KEY_EQ.iter().enumerate() {
            // SAFETY: `entry` points to a NUL-terminated string; reading prefix
            // bytes is valid until mismatch or NUL.
            let got = unsafe { *entry.add(idx) as u8 };
            if got != *want {
                matched = false;
                break;
            }
        }

        if matched {
            // Accept only exact value `1`.
            // SAFETY: KEY_EQ matched exactly; value bytes are in-bounds.
            let value = unsafe { *entry.add(KEY_EQ.len()) as u8 };
            // SAFETY: same as above.
            let terminator = unsafe { *entry.add(KEY_EQ.len() + 1) as u8 };
            return value == b'1' && terminator == 0;
        }

        // SAFETY: advance to next env pointer slot.
        envp = unsafe { envp.add(1) };
    }

    false
}

unsafe fn delegate_to_host_libc_start_main(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> Option<c_int> {
    let symbol = b"__libc_start_main\0";
    let glibc_v34 = b"GLIBC_2.34\0";
    let glibc_v225 = b"GLIBC_2.2.5\0";
    // SAFETY: versioned lookup via host dynamic loader, bypassing our interposed
    // dlsym symbol to avoid recursive startup-resolution loops.
    let mut ptr = unsafe {
        libc::dlvsym(
            libc::RTLD_NEXT,
            symbol.as_ptr().cast::<c_char>(),
            glibc_v34.as_ptr().cast::<c_char>(),
        )
    };
    if ptr.is_null() {
        // SAFETY: fallback to older glibc symbol version when 2.34 alias is absent.
        ptr = unsafe {
            libc::dlvsym(
                libc::RTLD_NEXT,
                symbol.as_ptr().cast::<c_char>(),
                glibc_v225.as_ptr().cast::<c_char>(),
            )
        };
    }
    if ptr.is_null() {
        return None;
    }

    // SAFETY: symbol is expected to match HostStartMainFn ABI and signature.
    let host_fn: HostStartMainFn = unsafe { std::mem::transmute(ptr) };
    // SAFETY: forwards original startup ABI arguments to host libc.
    Some(unsafe { host_fn(main, argc, ubp_av, init, fini, rtld_fini, stack_end) })
}

unsafe fn count_c_string_vector(base: *mut *mut c_char, max_entries: usize) -> Option<usize> {
    if base.is_null() {
        return None;
    }

    for idx in 0..max_entries {
        // SAFETY: caller guarantees `base` points to readable pointer slots.
        let p = unsafe { *base.add(idx) };
        if p.is_null() {
            return Some(idx);
        }
    }

    None
}

unsafe fn read_auxv_pairs(stack_end: *mut c_void, max_pairs: usize) -> Vec<(usize, usize)> {
    if stack_end.is_null() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let auxv_ptr = stack_end.cast::<usize>();

    for idx in 0..max_pairs {
        let off = idx.saturating_mul(2);
        // SAFETY: caller provides a readable auxv-like key/value array in phase-0 fixtures.
        let key = unsafe { *auxv_ptr.add(off) };
        // SAFETY: same as above; key/value pairs are adjacent entries.
        let value = unsafe { *auxv_ptr.add(off + 1) };
        out.push((key, value));
        if key == AT_NULL {
            break;
        }
    }

    out
}

unsafe fn startup_phase0_impl(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    let normalized_argc = normalize_argc(argc);
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Process,
        ubp_av as usize,
        normalized_argc,
        true,
        ubp_av.is_null() || main.is_none(),
        0,
    );

    if matches!(decision.action, MembraneAction::Deny) {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EPERM) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        return -1;
    }

    let Some(main_fn) = main else {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        return -1;
    };

    if ubp_av.is_null() {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        return -1;
    }

    // SAFETY: `ubp_av` is validated non-null above.
    let argv_count = match unsafe { count_c_string_vector(ubp_av, MAX_STARTUP_SCAN) } {
        Some(v) => v,
        None => {
            // SAFETY: writes TLS errno.
            unsafe { set_abi_errno(libc::E2BIG) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
            return -1;
        }
    };

    if argv_count < normalized_argc {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EINVAL) };
        runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
        return -1;
    }

    // SAFETY: argv_count >= normalized_argc and argv vector has a terminating null.
    let envp = unsafe { ubp_av.add(normalized_argc.saturating_add(1)) };
    // SAFETY: `envp` points at the null-terminated env vector in phase-0 fixtures.
    let env_count = match unsafe { count_c_string_vector(envp, MAX_STARTUP_SCAN) } {
        Some(v) => v,
        None => {
            // SAFETY: writes TLS errno.
            unsafe { set_abi_errno(libc::E2BIG) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 20, true);
            return -1;
        }
    };

    // SAFETY: `stack_end` is treated as an auxv key/value array in controlled fixtures.
    let auxv_pairs = unsafe { read_auxv_pairs(stack_end, MAX_STARTUP_SCAN) };
    let (auxv_count, secure_mode) = scan_auxv_pairs(&auxv_pairs, MAX_STARTUP_SCAN);

    let inv = build_invariants(argc, argv_count, env_count, auxv_count, secure_mode);
    store_invariants(inv);

    if let Some(init_fn) = init {
        // SAFETY: callback pointer provided by caller.
        unsafe { init_fn() };
    }

    // SAFETY: callback pointer + argv/envp pointers are validated for phase-0 fixture usage.
    let rc = unsafe { main_fn(normalized_argc as c_int, ubp_av, envp) };

    if let Some(fini_fn) = fini {
        // SAFETY: callback pointer provided by caller.
        unsafe { fini_fn() };
    }
    if let Some(rtld_fini_fn) = rtld_fini {
        // SAFETY: callback pointer provided by caller.
        unsafe { rtld_fini_fn() };
    }

    runtime_policy::observe(ApiFamily::Process, decision.profile, 20, false);
    rc
}

/// libc-compatible startup symbol. Delegates to host libc unless phase-0 mode is explicitly enabled.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __libc_start_main(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    if startup_phase0_env_enabled() {
        // SAFETY: explicit phase-0 opt-in path.
        return unsafe {
            startup_phase0_impl(main, argc, ubp_av, init, fini, rtld_fini, stack_end)
        };
    }

    // SAFETY: forwards to host libc startup for normal LD_PRELOAD operation.
    if let Some(rc) = unsafe {
        delegate_to_host_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end)
    } {
        return rc;
    }

    // SAFETY: writes TLS errno.
    unsafe { set_abi_errno(libc::ENOSYS) };
    -1
}

/// Test-hook alias that always executes the phase-0 startup path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __frankenlibc_startup_phase0(
    main: Option<MainFn>,
    argc: c_int,
    ubp_av: *mut *mut c_char,
    init: Option<HookFn>,
    fini: Option<HookFn>,
    rtld_fini: Option<HookFn>,
    stack_end: *mut c_void,
) -> c_int {
    // SAFETY: dedicated fixture path invokes the same validated implementation.
    unsafe { startup_phase0_impl(main, argc, ubp_av, init, fini, rtld_fini, stack_end) }
}

/// Returns the last captured startup invariants from `startup_phase0_impl`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __frankenlibc_startup_snapshot(
    out: *mut StartupInvariantSnapshot,
) -> c_int {
    if out.is_null() {
        // SAFETY: writes TLS errno.
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let snapshot = StartupInvariantSnapshot {
        argc: LAST_ARGC.load(Ordering::Relaxed),
        argv_count: LAST_ARGV_COUNT.load(Ordering::Relaxed),
        env_count: LAST_ENV_COUNT.load(Ordering::Relaxed),
        auxv_count: LAST_AUXV_COUNT.load(Ordering::Relaxed),
        secure_mode: i32::from(LAST_SECURE_MODE.load(Ordering::Relaxed) != 0),
    };

    // SAFETY: `out` is validated non-null above.
    unsafe { *out = snapshot };
    0
}
