//! ABI layer for `<fenv.h>` functions.
//!
//! Native x86_64 floating-point environment control using inline assembly.
//! Directly manipulates x87 FPU control/status words and SSE MXCSR register
//! — no glibc delegation required.

use std::ffi::{c_int, c_void};

use crate::malloc_abi::known_remaining;

// ---------------------------------------------------------------------------
// x86_64 FPU constants
// ---------------------------------------------------------------------------

/// x87 control word rounding-mode mask (bits 10–11).
const X87_ROUND_MASK: u16 = 0x0C00;

/// MXCSR rounding-mode mask (bits 13–14).
const MXCSR_ROUND_MASK: u32 = 0x6000;

/// Default x87 control word: all exceptions masked, round-to-nearest, extended precision.
const X87_DEFAULT_CW: u16 = 0x037F;

/// Default MXCSR: all exceptions masked, round-to-nearest, no flags.
const MXCSR_DEFAULT: u32 = 0x1F80;

/// All hardware exception flag bits (bits 0–5), including denormal.
const HW_ALL_EXCEPT: u32 = 0x3F;

/// MXCSR exception mask bits (bits 7–12).
const MXCSR_ALL_MASKS: u32 = 0x1F80;

/// Sentinel value for `FE_DFL_ENV` = `(const fenv_t *) -1`.
const FE_DFL_ENV_SENTINEL: usize = usize::MAX;

// ---------------------------------------------------------------------------
// fenv_t layout for glibc x86_64 (32 bytes)
// ---------------------------------------------------------------------------

/// Internal representation of `fenv_t` matching glibc x86_64 layout.
/// `fnstenv`/`fldenv` operate on the first 28 bytes; MXCSR is stored separately.
#[repr(C)]
struct FenvT {
    cw: u16,        // 0: x87 control word
    _pad1: u16,     // 2
    sw: u16,        // 4: x87 status word
    _pad2: u16,     // 6
    tags: u16,      // 8: x87 tag word
    _pad3: u16,     // 10
    eip: u32,       // 12: instruction pointer
    cs_opcode: u32, // 16: code segment + opcode
    data_off: u32,  // 20: data offset
    ds_pad: u32,    // 24: data segment + padding
    mxcsr: u32,     // 28: SSE control/status register
}

#[inline]
fn tracked_object_fits<T>(ptr: *const T) -> bool {
    !ptr.is_null()
        && known_remaining(ptr as usize)
            .is_none_or(|remaining| core::mem::size_of::<T>() <= remaining)
}

#[inline]
fn tracked_fenv_fits(ptr: *const c_void) -> bool {
    !ptr.is_null()
        && known_remaining(ptr as usize)
            .is_none_or(|remaining| core::mem::size_of::<FenvT>() <= remaining)
}

fn zeroed_fenv() -> FenvT {
    let env = core::mem::MaybeUninit::<FenvT>::zeroed();
    // SAFETY: FenvT is a repr(C), integer-only mirror of glibc x86_64 fenv_t.
    // Every bit pattern is valid for its fields, and callers use this as a
    // scratch record before overwriting the hardware-owned environment slots.
    unsafe { env.assume_init() }
}

// ---------------------------------------------------------------------------
// Inline asm helpers
// ---------------------------------------------------------------------------

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn read_x87_cw() -> u16 {
    let mut cw: u16 = 0;
    unsafe {
        core::arch::asm!(
            "fnstcw [{}]",
            in(reg) &mut cw,
            options(nostack, preserves_flags),
        );
    }
    cw
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_x87_cw() -> u16 {
    X87_DEFAULT_CW
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn write_x87_cw(cw: u16) {
    unsafe {
        core::arch::asm!(
            "fldcw [{}]",
            in(reg) &cw,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_x87_cw(_cw: u16) {}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn read_x87_sw() -> u16 {
    let mut sw: u16 = 0;
    unsafe {
        core::arch::asm!(
            "fnstsw [{}]",
            in(reg) &mut sw,
            options(nostack, preserves_flags),
        );
    }
    sw
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_x87_sw() -> u16 {
    0
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn read_mxcsr() -> u32 {
    let mut mxcsr: u32 = 0;
    unsafe {
        core::arch::asm!(
            "stmxcsr [{}]",
            in(reg) &mut mxcsr,
            options(nostack, preserves_flags),
        );
    }
    mxcsr
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn read_mxcsr() -> u32 {
    MXCSR_DEFAULT
}

#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn write_mxcsr(mxcsr: u32) {
    unsafe {
        core::arch::asm!(
            "ldmxcsr [{}]",
            in(reg) &mxcsr,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn write_mxcsr(_mxcsr: u32) {}

/// `fnstenv` stores the full x87 environment (28 bytes) and masks all exceptions.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn store_x87_env(env: *mut FenvT) {
    unsafe {
        core::arch::asm!(
            "fnstenv [{}]",
            in(reg) env,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn store_x87_env(env: *mut FenvT) {
    if !env.is_null() {
        unsafe { *env = zeroed_fenv() };
    }
}

/// `fldenv` loads the full x87 environment (28 bytes).
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn load_x87_env(env: *const FenvT) {
    unsafe {
        core::arch::asm!(
            "fldenv [{}]",
            in(reg) env,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn load_x87_env(_env: *const FenvT) {}

// ---------------------------------------------------------------------------
// Rounding mode control
// ---------------------------------------------------------------------------

/// Get the current rounding direction mode.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetround() -> c_int {
    let cw = unsafe { read_x87_cw() };
    (cw & X87_ROUND_MASK) as c_int
}

/// Set the rounding direction mode. Returns 0 on success, nonzero on failure.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetround(rnd: c_int) -> c_int {
    let rnd_u = rnd as u32;
    // Validate: only bits 10-11 may be set
    if rnd_u & !(X87_ROUND_MASK as u32) != 0 {
        return -1;
    }
    unsafe {
        // Update x87 control word bits 10-11
        let mut cw = read_x87_cw();
        cw = (cw & !X87_ROUND_MASK) | (rnd as u16 & X87_ROUND_MASK);
        write_x87_cw(cw);

        // Update MXCSR bits 13-14 (x87 rounding shifted left by 3)
        let mut mxcsr = read_mxcsr();
        mxcsr = (mxcsr & !MXCSR_ROUND_MASK) | ((rnd_u & X87_ROUND_MASK as u32) << 3);
        write_mxcsr(mxcsr);
    }
    0
}

// ---------------------------------------------------------------------------
// Exception flag manipulation
// ---------------------------------------------------------------------------

/// Clear the specified floating-point exception flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feclearexcept(excepts: c_int) -> c_int {
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    if mask == 0 {
        return 0;
    }
    unsafe {
        // Clear x87 status word bits via fnstenv/modify/fldenv
        let mut env = zeroed_fenv();
        store_x87_env(&mut env);
        env.sw &= !(mask as u16);
        load_x87_env(&env);

        // Clear MXCSR exception flag bits
        let mut mxcsr = read_mxcsr();
        mxcsr &= !mask;
        write_mxcsr(mxcsr);
    }
    0
}

/// Test the specified floating-point exception flags.
/// Returns the bitwise OR of currently set flags masked by `excepts`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexcept(excepts: c_int) -> c_int {
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    unsafe {
        let sw = read_x87_sw() as u32;
        let mxcsr = read_mxcsr();
        ((sw | mxcsr) & mask) as c_int
    }
}

/// Raise the specified floating-point exceptions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feraiseexcept(excepts: c_int) -> c_int {
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    if mask == 0 {
        return 0;
    }
    unsafe {
        // Set exception flags in MXCSR (SSE exceptions are non-trapping by default)
        let mut mxcsr = read_mxcsr();
        mxcsr |= mask;
        write_mxcsr(mxcsr);
    }
    0
}

/// Get the floating-point exception flags into `*flagp` (fexcept_t = u16).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexceptflag(flagp: *mut u16, excepts: c_int) -> c_int {
    if flagp.is_null() {
        return -1;
    }
    if !tracked_object_fits(flagp.cast_const()) {
        return -1;
    }
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    unsafe {
        let sw = read_x87_sw() as u32;
        let mxcsr = read_mxcsr();
        *flagp = ((sw | mxcsr) & mask) as u16;
    }
    0
}

/// Set the floating-point exception flags from `*flagp` without raising them.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexceptflag(flagp: *const u16, excepts: c_int) -> c_int {
    if flagp.is_null() {
        return -1;
    }
    if !tracked_object_fits(flagp) {
        return -1;
    }
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    let flags = unsafe { *flagp } as u32 & mask;
    unsafe {
        // Update x87 status via fnstenv/modify/fldenv
        let mut env = zeroed_fenv();
        store_x87_env(&mut env);
        env.sw = (env.sw & !(mask as u16)) | (flags as u16);
        load_x87_env(&env);

        // Update MXCSR exception flags
        let mut mxcsr = read_mxcsr();
        mxcsr = (mxcsr & !mask) | flags;
        write_mxcsr(mxcsr);
    }
    0
}

// ---------------------------------------------------------------------------
// GNU/C23 exception-flag and trap-mask extensions
//
// The FE_* exception constants map directly onto x87 control/status bits 0-5
// (a SET control-word bit MASKS the exception) and onto MXCSR flag bits 0-5 /
// mask bits 7-12. feenableexcept/fedisableexcept return the PREVIOUSLY enabled
// (unmasked) set; fegetexcept returns the current enabled set.
// ---------------------------------------------------------------------------

/// Set the given exception flags without raising a trap. Returns 0.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetexcept(excepts: c_int) -> c_int {
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    unsafe {
        let mut mxcsr = read_mxcsr();
        mxcsr |= mask;
        write_mxcsr(mxcsr);
    }
    0
}

/// Test which of `excepts` are set in the saved `*flagp` (fexcept_t = u16).
/// Returns the subset (the FE_* bits), 0 if none or flagp is null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fetestexceptflag(flagp: *const u16, excepts: c_int) -> c_int {
    if flagp.is_null() || !tracked_object_fits(flagp) {
        return 0;
    }
    let saved = unsafe { *flagp } as u32;
    (saved & (excepts as u32) & HW_ALL_EXCEPT) as c_int
}

/// Return the set of exceptions currently enabled (unmasked) for trapping.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetexcept() -> c_int {
    let cw = unsafe { read_x87_cw() } as u32;
    (((!cw) & HW_ALL_EXCEPT)) as c_int
}

/// Enable trapping for `excepts` (clear their mask bits in the x87 CW and
/// MXCSR). Returns the previously enabled set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feenableexcept(excepts: c_int) -> c_int {
    let old = unsafe { fegetexcept() };
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    unsafe {
        let cw = read_x87_cw();
        write_x87_cw(cw & !(mask as u16));
        let mxcsr = read_mxcsr();
        write_mxcsr(mxcsr & !(mask << 7));
    }
    old
}

/// Disable trapping for `excepts` (set their mask bits). Returns the previously
/// enabled set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fedisableexcept(excepts: c_int) -> c_int {
    let old = unsafe { fegetexcept() };
    let mask = (excepts as u32) & HW_ALL_EXCEPT;
    unsafe {
        let cw = read_x87_cw();
        write_x87_cw(cw | (mask as u16));
        let mxcsr = read_mxcsr();
        write_mxcsr(mxcsr | (mask << 7));
    }
    old
}

// ---------------------------------------------------------------------------
// Dynamic FP mode (rounding + trap enables, NOT the status flags): fegetmode /
// fesetmode (C23). femode_t holds the x87 control word and the MXCSR control
// bits; fesetmode preserves the current exception STATUS flags.
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct FeMode {
    x87_cw: u16,
    _pad: u16,
    mxcsr: u32,
}

/// MXCSR status flag bits (0-5); everything else in MXCSR is "mode".
const MXCSR_STATUS: u32 = 0x3F;
/// FE_DFL_MODE is `(const femode_t *) -1`.
fn is_dfl_mode(modep: *const FeMode) -> bool {
    modep as usize == usize::MAX
}

/// Save the current dynamic FP mode to `*modep`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetmode(modep: *mut FeMode) -> c_int {
    if modep.is_null() || !tracked_object_fits(modep.cast_const()) {
        return -1;
    }
    unsafe {
        (*modep).x87_cw = read_x87_cw();
        (*modep)._pad = 0;
        (*modep).mxcsr = read_mxcsr();
    }
    0
}

/// Restore the dynamic FP mode from `*modep` (or reset to default when modep is
/// FE_DFL_MODE). The exception status flags are left untouched.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetmode(modep: *const FeMode) -> c_int {
    let (cw, ctrl) = if is_dfl_mode(modep) {
        (X87_DEFAULT_CW, MXCSR_DEFAULT)
    } else if modep.is_null() || !tracked_object_fits(modep) {
        return -1;
    } else {
        let m = unsafe { &*modep };
        (m.x87_cw, m.mxcsr)
    };
    unsafe {
        write_x87_cw(cw);
        // Keep the current status flags (bits 0-5); take the mode bits from ctrl.
        let cur = read_mxcsr();
        write_mxcsr((cur & MXCSR_STATUS) | (ctrl & !MXCSR_STATUS));
    }
    0
}

// ---------------------------------------------------------------------------
// Environment save/restore
// ---------------------------------------------------------------------------

/// Save the current floating-point environment to `*envp`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fegetenv(envp: *mut c_void) -> c_int {
    if envp.is_null() {
        return -1;
    }
    if !tracked_fenv_fits(envp.cast_const()) {
        return -1;
    }
    let envp = envp.cast::<FenvT>();
    unsafe {
        // fnstenv saves 28 bytes and masks all x87 exceptions as a side effect
        store_x87_env(envp);
        // Store MXCSR at offset 28
        (*envp).mxcsr = read_mxcsr();
        // Restore x87 control word (fnstenv masked exceptions)
        write_x87_cw((*envp).cw);
    }
    0
}

/// Set the floating-point environment from `*envp`.
/// Pass `FE_DFL_ENV` (pointer value -1) to reset to default environment.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fesetenv(envp: *const c_void) -> c_int {
    if envp as usize == FE_DFL_ENV_SENTINEL {
        // Reset to default: fninit resets x87, then set default MXCSR
        unsafe {
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("fninit", options(nostack));
            write_x87_cw(X87_DEFAULT_CW);
            write_mxcsr(MXCSR_DEFAULT);
        }
        return 0;
    }
    if envp.is_null() {
        return -1;
    }
    if !tracked_fenv_fits(envp) {
        return -1;
    }
    let envp = envp.cast::<FenvT>();
    unsafe {
        load_x87_env(envp);
        write_mxcsr((*envp).mxcsr);
    }
    0
}

/// Save the current floating-point environment and enable non-stop mode
/// (clear all exceptions, mask all exception traps).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feholdexcept(envp: *mut c_void) -> c_int {
    if envp.is_null() {
        return -1;
    }
    if !tracked_fenv_fits(envp.cast_const()) {
        return -1;
    }
    let envp = envp.cast::<FenvT>();
    unsafe {
        // Save current environment (fnstenv masks x87 exceptions automatically)
        store_x87_env(envp);
        (*envp).mxcsr = read_mxcsr();

        // Clear pending x87 exceptions
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("fnclex", options(nostack, preserves_flags));

        // Clear MXCSR exception flags, set all exception masks
        let mut mxcsr = read_mxcsr();
        mxcsr = (mxcsr & !HW_ALL_EXCEPT) | MXCSR_ALL_MASKS;
        write_mxcsr(mxcsr);
    }
    0
}

/// Install the floating-point environment from `*envp` and re-raise
/// any currently pending exceptions.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn feupdateenv(envp: *const c_void) -> c_int {
    unsafe {
        // Capture currently pending exceptions before restoring environment
        let pending = fetestexcept(HW_ALL_EXCEPT as c_int);
        let rc = fesetenv(envp);
        if rc != 0 {
            return rc;
        }
        feraiseexcept(pending);
    }
    0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fegetround_returns_valid_mode() {
        let mode = unsafe { fegetround() };
        // Must be one of: 0x000, 0x400, 0x800, 0xC00
        assert!(
            mode == 0x000 || mode == 0x400 || mode == 0x800 || mode == 0xC00,
            "unexpected rounding mode: {:#x}",
            mode
        );
    }

    #[test]
    fn fesetround_roundtrip() {
        let original = unsafe { fegetround() };

        // Set to round-toward-zero (0xC00)
        assert_eq!(unsafe { fesetround(0xC00) }, 0);
        assert_eq!(unsafe { fegetround() }, 0xC00);

        // Set to round-down (0x400)
        assert_eq!(unsafe { fesetround(0x400) }, 0);
        assert_eq!(unsafe { fegetround() }, 0x400);

        // Restore original
        assert_eq!(unsafe { fesetround(original) }, 0);
        assert_eq!(unsafe { fegetround() }, original);
    }

    #[test]
    fn fesetround_rejects_invalid() {
        assert_eq!(unsafe { fesetround(0x1234) }, -1);
        assert_eq!(unsafe { fesetround(0x01) }, -1);
    }

    #[test]
    fn feclearexcept_and_fetestexcept() {
        // Clear all, then test — should be zero
        unsafe { feclearexcept(0x3F) };
        let flags = unsafe { fetestexcept(0x3F) };
        assert_eq!(flags, 0, "flags after clear: {:#x}", flags);
    }

    #[test]
    fn feraiseexcept_and_fetestexcept() {
        unsafe { feclearexcept(0x3F) };

        // Raise inexact (0x20)
        assert_eq!(unsafe { feraiseexcept(0x20) }, 0);
        let flags = unsafe { fetestexcept(0x20) };
        assert_ne!(flags & 0x20, 0, "inexact not raised");

        // Clean up
        unsafe { feclearexcept(0x3F) };
    }

    #[test]
    fn fegetexceptflag_and_fesetexceptflag() {
        unsafe { feclearexcept(0x3F) };
        unsafe { feraiseexcept(0x20) }; // raise inexact

        let mut saved: u16 = 0;
        assert_eq!(unsafe { fegetexceptflag(&mut saved, 0x3F) }, 0);
        assert_ne!(saved & 0x20, 0);

        // Clear, then restore flags without raising
        unsafe { feclearexcept(0x3F) };
        assert_eq!(unsafe { fesetexceptflag(&saved, 0x3F) }, 0);
        assert_ne!(unsafe { fetestexcept(0x20) } & 0x20, 0);

        unsafe { feclearexcept(0x3F) };
    }

    // Helper to get a properly-sized buffer for fenv_t (32 bytes)
    fn fenv_buf() -> [u8; 32] {
        [0u8; 32]
    }

    #[test]
    fn fegetenv_fesetenv_roundtrip() {
        let mut buf = fenv_buf();
        let envp = buf.as_mut_ptr().cast::<c_void>();
        assert_eq!(unsafe { fegetenv(envp) }, 0);

        // Change rounding mode
        let original_round = unsafe { fegetround() };
        let new_round = if original_round == 0xC00 {
            0x400
        } else {
            0xC00
        };
        unsafe { fesetround(new_round) };
        assert_eq!(unsafe { fegetround() }, new_round);

        // Restore environment
        assert_eq!(unsafe { fesetenv(envp.cast_const()) }, 0);
        assert_eq!(unsafe { fegetround() }, original_round);
    }

    #[test]
    fn fesetenv_default_resets() {
        // Change rounding mode
        let original = unsafe { fegetround() };
        unsafe { fesetround(0xC00) };

        // Reset to default via FE_DFL_ENV sentinel
        assert_eq!(unsafe { fesetenv(FE_DFL_ENV_SENTINEL as *const c_void) }, 0);
        // Default is FE_TONEAREST = 0x000
        assert_eq!(unsafe { fegetround() }, 0x000);

        // Restore
        unsafe { fesetround(original) };
    }

    #[test]
    fn feholdexcept_saves_and_clears() {
        // Raise an exception first
        unsafe { feraiseexcept(0x20) };
        assert_ne!(unsafe { fetestexcept(0x20) }, 0);

        let mut buf = fenv_buf();
        let envp = buf.as_mut_ptr().cast::<c_void>();
        assert_eq!(unsafe { feholdexcept(envp) }, 0);

        // After feholdexcept, exceptions should be cleared
        assert_eq!(unsafe { fetestexcept(0x3F) }, 0);

        // Restore
        unsafe { fesetenv(envp.cast_const()) };
    }

    #[test]
    fn feupdateenv_reraises_pending() {
        unsafe { feclearexcept(0x3F) };

        let mut buf = fenv_buf();
        let envp = buf.as_mut_ptr().cast::<c_void>();
        unsafe { fegetenv(envp) };

        // Raise inexact
        unsafe { feraiseexcept(0x20) };

        // feupdateenv restores env but re-raises pending exceptions
        assert_eq!(unsafe { feupdateenv(envp.cast_const()) }, 0);
        assert_ne!(unsafe { fetestexcept(0x20) } & 0x20, 0);

        unsafe { feclearexcept(0x3F) };
    }

    #[test]
    fn null_pointer_guards() {
        assert_eq!(unsafe { fegetexceptflag(std::ptr::null_mut(), 0x3F) }, -1);
        assert_eq!(unsafe { fesetexceptflag(std::ptr::null(), 0x3F) }, -1);
        assert_eq!(unsafe { fegetenv(std::ptr::null_mut()) }, -1);
        assert_eq!(unsafe { fesetenv(std::ptr::null()) }, -1);
        assert_eq!(unsafe { feholdexcept(std::ptr::null_mut()) }, -1);
    }
}
