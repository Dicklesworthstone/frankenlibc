//! Shared `dlsym` oracle resolution for the `conformance_diff_*` suite (bd-v0388t).
//!
//! ## Why this exists
//!
//! 416 of the differential gates reach glibc through a link-time declaration:
//!
//! ```ignore
//! unsafe extern "C" { fn memccpy(dst: *mut c_void, ..) -> *mut c_void; }
//! ```
//!
//! That is only an oracle if the reference binds to `libc.so.6`. It does not
//! always. Two confirmed cases, both in a plain `cargo test`:
//!
//! - `fma` — the link-time arm did not reach glibc, which is what started the
//!   audit;
//! - `catopen` — converting its arm to `dlsym` turned the gate RED immediately
//!   with `catopen("") errno: fl=22 (EINVAL) glibc=2 (ENOENT)`. glibc's errno
//!   for that call had not changed, so had the arm been reaching glibc the gate
//!   would have been red all along. It was green. **The hollow arm had been
//!   hiding a live divergence.**
//!
//! The audit's running rate is 2 real problems in 8 gates examined. Applied to
//! 416 gates that is not a bookkeeping exercise.
//!
//! ## Why `dlsym` and not a provenance registry
//!
//! An earlier attempt (`conformance_diff_oracle_arm_provenance`) probed symbol
//! provenance with `dladdr` from one test binary. That approach is structurally
//! limited: **resolution is per-binary**, so a registry can only ever certify
//! the binary it lives in, and nothing at runtime can enumerate which other test
//! binaries declare which symbols. Per-gate `dlsym` has no such limit — it is
//! correct in every binary and every build profile, and there is no list to keep
//! in step with the suite.
//!
//! Note also that `dladdr` cannot answer the question on its own: taking the
//! address of an imported function can yield a **PLT stub**, which lives in the
//! executable, so "same object as fl" does not mean "is fl". Only comparing the
//! resolved ADDRESS against fl's own definition settles it, which is what
//! [`host_fn`] does.
//!
//! ## Usage
//!
//! ```ignore
//! #[path = "common/dlsym_oracle.rs"]
//! mod dlsym_oracle;
//! use dlsym_oracle::host_fn;
//!
//! type Memccpy = unsafe extern "C" fn(*mut c_void, *const c_void, c_int, usize) -> *mut c_void;
//!
//! let glibc_memccpy: Memccpy = unsafe {
//!     host_fn(c"memccpy", frankenlibc_abi::string_abi::memccpy as *const ())
//! };
//! ```
//!
//! The second argument is fl's own definition of the same symbol. Passing it is
//! not optional bookkeeping: it is what makes a silently-collapsed oracle fail
//! loudly instead of comparing fl against itself.

#![allow(dead_code)] // each gate uses only the entry points it needs

use std::ffi::{CStr, c_void};

/// Open the object that owns libc's entry points.
///
/// Modern glibc folds libm into `libc.so.6`, but older layouts keep `libm.so.6`
/// separate, so math symbols may live in either. Callers get whichever object
/// actually exports the symbol they asked for.
fn handles() -> [*mut c_void; 2] {
    let mut out = [std::ptr::null_mut(); 2];
    for (slot, name) in out.iter_mut().zip([c"libc.so.6", c"libm.so.6"]) {
        // SAFETY: name is a NUL-terminated constant; RTLD_LOCAL keeps the handle
        // out of the global namespace so it cannot perturb later resolution.
        *slot = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    }
    assert!(
        !out[0].is_null(),
        "dlopen(libc.so.6) failed — the host oracle is unavailable, so this gate \
         cannot run. Treat this as a broken probe, NOT as evidence about fl."
    );
    out
}

/// Resolve `name` in host glibc and return it as a raw code address.
///
/// Panics rather than returning `None` on failure: an unresolvable oracle is a
/// broken probe, and a gate that silently degraded to "no comparison" would be
/// the exact green-while-proving-nothing failure this module exists to prevent.
///
/// `fl_definition` is fl's own export of the same symbol. If the resolved
/// address equals it, the "glibc" arm IS fl and every comparison built on it
/// would pass unconditionally, so that case aborts with an explicit message.
///
/// # Safety
///
/// The caller must transmute the returned address to a function type matching
/// the C declaration of `name`; nothing here can check that.
pub unsafe fn host_addr(name: &CStr, fl_definition: *const ()) -> *mut c_void {
    let mut resolved = std::ptr::null_mut();
    for h in handles() {
        if h.is_null() {
            continue;
        }
        // SAFETY: `h` came from dlopen and `name` is NUL-terminated.
        let sym = unsafe { libc::dlsym(h, name.as_ptr()) };
        if !sym.is_null() {
            resolved = sym;
            break;
        }
    }
    assert!(
        !resolved.is_null(),
        "dlsym({name:?}) found nothing in libc.so.6 or libm.so.6 — the oracle is \
         unavailable, so this gate cannot run"
    );
    assert_ne!(
        resolved as usize, fl_definition as usize,
        "the resolved oracle for {name:?} IS fl's own definition — this gate would \
         compare fl against itself and pass unconditionally (bd-v0388t)"
    );
    resolved
}

/// Resolve `name` in host glibc as a callable function pointer of type `F`.
///
/// # Safety
///
/// `F` must be an `unsafe extern "C" fn` type matching the C declaration of
/// `name` exactly. A mismatch is undefined behaviour, and no check here can
/// catch it — this is the one thing the caller must get right by inspection.
pub unsafe fn host_fn<F: Copy>(name: &CStr, fl_definition: *const ()) -> F {
    assert_eq!(
        std::mem::size_of::<F>(),
        std::mem::size_of::<*mut c_void>(),
        "host_fn::<F> requires a plain function pointer, not a fat pointer or a closure"
    );
    // SAFETY: caller guarantees `F` matches the symbol's C signature, and the
    // size assertion above rejects anything that is not a thin pointer.
    unsafe {
        let addr = host_addr(name, fl_definition);
        *(&raw const addr).cast::<F>()
    }
}
