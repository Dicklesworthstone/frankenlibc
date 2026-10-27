//! ABI layer for `<errno.h>` — thread-local errno storage.
//!
//! No membrane routing for errno: this is a pure thread-local accessor
//! with no security surface.

use std::ffi::c_int;

// `_Fork` is required to set errno even when it is called from a signal
// handler. Rust `thread_local!` is unsuitable for that path: first access may
// enter the TLS runtime, and its teardown fallback allocated behind a mutex.
//
// The interpose build therefore addresses glibc's existing static
// `errno@GLIBC_PRIVATE` TLS object directly with the initial-exec model. The
// standalone build owns an equivalent four-byte `.tbss` object. Both variants
// expose the same hidden leaf, with no PLT call, allocator, resolver, or lock.
#[cfg(all(target_arch = "x86_64", not(feature = "standalone")))]
core::arch::global_asm!(
    ".globl __frankenlibc_host_errno",
    ".symver __frankenlibc_host_errno,errno@GLIBC_PRIVATE",
    ".pushsection .text.frankenlibc_errno,\"ax\",@progbits",
    ".p2align 4",
    ".globl frankenlibc_errno_location_async",
    ".hidden frankenlibc_errno_location_async",
    ".type frankenlibc_errno_location_async,@function",
    "frankenlibc_errno_location_async:",
    "movq __frankenlibc_host_errno@GOTTPOFF(%rip), %rax",
    "addq %fs:0, %rax",
    "ret",
    ".size frankenlibc_errno_location_async, . - frankenlibc_errno_location_async",
    ".popsection",
    options(att_syntax),
);

#[cfg(all(target_arch = "x86_64", feature = "standalone"))]
core::arch::global_asm!(
    ".pushsection .tbss.frankenlibc_errno,\"awT\",@nobits",
    ".p2align 2",
    ".hidden __frankenlibc_errno_tls",
    ".type __frankenlibc_errno_tls,@object",
    ".size __frankenlibc_errno_tls,4",
    "__frankenlibc_errno_tls:",
    ".zero 4",
    ".popsection",
    ".pushsection .text.frankenlibc_errno,\"ax\",@progbits",
    ".p2align 4",
    ".globl frankenlibc_errno_location_async",
    ".hidden frankenlibc_errno_location_async",
    ".type frankenlibc_errno_location_async,@function",
    "frankenlibc_errno_location_async:",
    "movq __frankenlibc_errno_tls@GOTTPOFF(%rip), %rax",
    "addq %fs:0, %rax",
    "ret",
    ".size frankenlibc_errno_location_async, . - frankenlibc_errno_location_async",
    ".popsection",
    options(att_syntax),
);

#[cfg(all(target_arch = "aarch64", not(feature = "standalone")))]
core::arch::global_asm!(
    ".globl __frankenlibc_host_errno",
    ".symver __frankenlibc_host_errno,errno@GLIBC_PRIVATE",
    ".pushsection .text.frankenlibc_errno,\"ax\",@progbits",
    ".p2align 4",
    ".globl frankenlibc_errno_location_async",
    ".hidden frankenlibc_errno_location_async",
    ".type frankenlibc_errno_location_async,%function",
    "frankenlibc_errno_location_async:",
    "adrp x1, :gottprel:__frankenlibc_host_errno",
    "ldr x1, [x1, #:gottprel_lo12:__frankenlibc_host_errno]",
    "mrs x0, tpidr_el0",
    "add x0, x0, x1",
    "ret",
    ".size frankenlibc_errno_location_async, . - frankenlibc_errno_location_async",
    ".popsection",
);

#[cfg(all(target_arch = "aarch64", feature = "standalone"))]
core::arch::global_asm!(
    ".pushsection .tbss.frankenlibc_errno,\"awT\",@nobits",
    ".p2align 2",
    ".hidden __frankenlibc_errno_tls",
    ".type __frankenlibc_errno_tls,%object",
    ".size __frankenlibc_errno_tls,4",
    "__frankenlibc_errno_tls:",
    ".zero 4",
    ".popsection",
    ".pushsection .text.frankenlibc_errno,\"ax\",@progbits",
    ".p2align 4",
    ".globl frankenlibc_errno_location_async",
    ".hidden frankenlibc_errno_location_async",
    ".type frankenlibc_errno_location_async,%function",
    "frankenlibc_errno_location_async:",
    "adrp x1, :gottprel:__frankenlibc_errno_tls",
    "ldr x1, [x1, #:gottprel_lo12:__frankenlibc_errno_tls]",
    "mrs x0, tpidr_el0",
    "add x0, x0, x1",
    "ret",
    ".size frankenlibc_errno_location_async, . - frankenlibc_errno_location_async",
    ".popsection",
);

unsafe extern "C" {
    fn frankenlibc_errno_location_async() -> *mut c_int;
}

#[inline]
fn errno_location() -> *mut c_int {
    if let Some(handle) = frankenlibc_core::pthread::thread::current_thread_handle() {
        // SAFETY: only this native thread and its signal handlers can access
        // its errno cell. The handle stays registered throughout destructors;
        // exit blocks signals before removing or reclaiming it.
        return unsafe { (*handle).errno.get() };
    }
    // SAFETY: the hidden leaf addresses the caller's canonical static TLS slot
    // without a resolver, allocation, Rust TLS initialization or locking.
    unsafe { frankenlibc_errno_location_async() }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    errno_location()
}

/// Set the thread-local errno value.
///
/// Native clone threads use their ThreadHandle's private cell. Other interpose
/// threads use glibc's canonical static TLS slot; standalone fallback threads
/// use FrankenLibC's owned TLS slot.
///
/// Uses volatile write to prevent the LTO optimizer from eliminating the store.
#[inline]
pub unsafe fn set_abi_errno(val: c_int) {
    unsafe { set_abi_errno_local(val) };
}

/// Set errno without host symbol lookup, Rust TLS, allocation, or locking.
///
/// This is the errno path used by async-signal-safe ABI entries such as
/// `_Fork`. Native ownership lookup uses only a raw TID syscall and atomic
/// table reads; the fallback assembly leaf is initial-exec TLS in both modes.
#[inline]
pub(crate) unsafe fn set_abi_errno_local(val: c_int) {
    let p = errno_location();
    unsafe { std::ptr::write_volatile(p, val) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_slot_is_stable_and_isolated_across_threads() {
        let main_ptr = unsafe { __errno_location() };
        assert_eq!(main_ptr, unsafe { __errno_location() });
        let other_ptr = std::thread::spawn(|| unsafe { __errno_location() } as usize)
            .join()
            .unwrap();
        assert_ne!(main_ptr as usize, other_ptr);
    }

    #[test]
    #[cfg(not(feature = "standalone"))]
    fn interpose_errno_accessor_is_the_host_tls_slot() {
        let ours = unsafe { __errno_location() };
        let host = unsafe { libc::__errno_location() };
        assert_eq!(ours, host);

        let original = unsafe { std::ptr::read_volatile(host) };
        unsafe { set_abi_errno_local(libc::EAGAIN) };
        assert_eq!(unsafe { std::ptr::read_volatile(host) }, libc::EAGAIN);
        unsafe { set_abi_errno_local(original) };
    }

    #[test]
    fn set_abi_errno_updates_thread_local_slot() {
        let ptr = unsafe { __errno_location() };
        let original = unsafe { std::ptr::read_volatile(ptr) };

        unsafe { set_abi_errno(libc::ENOENT) };
        assert_eq!(unsafe { std::ptr::read_volatile(ptr) }, libc::ENOENT);

        unsafe { set_abi_errno(original) };
    }
}
