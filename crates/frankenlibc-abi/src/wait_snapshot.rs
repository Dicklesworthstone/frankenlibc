//! Owned controls for ppoll/pselect-style waits.
//!
//! Hardened imports use the shared fault-checked kernel copier, never a Rust
//! reference to caller memory. Timeout storage is mutable because Linux may
//! write remaining time even though the libc interface promises a const input.
//! This does not pin caller allocations or make the two imports atomic.

use std::ffi::c_int;
use std::mem::size_of;
use std::ptr;

use super::iov_snapshot::copy_user_bytes;

// Both supported Linux ABIs use a 64-bit kernel signal set. libc::sigset_t is
// larger; its unused tail must not be read (including across a guard page).
pub(super) const KERNEL_SIGSET_BYTES: usize = size_of::<u64>();

enum Mask {
    Original(*const libc::sigset_t),
    Owned(u64),
}

pub(super) struct PreparedWait {
    timeout: Option<libc::timespec>,
    mask: Mask,
}

impl PreparedWait {
    /// Import exactly the controls consumed by Linux. Strict retains the
    /// existing libc-style timeout copy and original kernel mask argument.
    ///
    /// # Safety
    /// Readable caller bytes must be initialized. In strict mode a non-null
    /// timeout must also be aligned and valid for a Rust read, as before.
    pub(super) unsafe fn prepare(
        timeout: *const libc::timespec,
        sigmask: *const libc::sigset_t,
        hardened: bool,
    ) -> Result<Self, c_int> {
        let mut prepared = Self { timeout: None, mask: Mask::Original(sigmask) };
        if !timeout.is_null() {
            let mut value = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            if hardened {
                // SAFETY: owned, initialized destination; arbitrary source
                // alignment/permissions/known bounds are checked by the copier.
                unsafe {
                    copy_user_bytes(timeout.cast(), (&mut value as *mut libc::timespec).cast(),
                        size_of::<libc::timespec>())?;
                }
            } else {
                // SAFETY: strict preserves the original valid-pointer contract.
                value = unsafe { *timeout };
            }
            prepared.timeout = Some(value);
            // ppoll/pselect6 validate the timespec before reading the mask.
            // Leave malformed time syntax to Linux, without inventing a mask
            // access (or letting its EFAULT replace the timeout's EINVAL).
            if value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1_000_000_000 {
                return Ok(prepared);
            }
        }
        if hardened && !sigmask.is_null() {
            let mut bits = 0u64;
            // SAFETY: all u64 bit patterns are valid. The target consumes only
            // these eight bytes, not the full public libc::sigset_t object.
            unsafe {
                copy_user_bytes(sigmask.cast(), (&mut bits as *mut u64).cast(),
                    KERNEL_SIGSET_BYTES)?;
            }
            prepared.mask = Mask::Owned(bits);
        }
        Ok(prepared)
    }

    /// Resolve pointers only after the owner reaches its final stack location.
    /// A mutable borrow is essential: ppoll/pselect6 can write through this
    /// raw address. Caller timeout storage is never submitted or published to.
    pub(super) fn kernel_args(&mut self) -> (*const u8, *const u8) {
        let timeout = self.timeout.as_mut().map_or(ptr::null(), |value| {
            (value as *mut libc::timespec).cast::<u8>().cast_const()
        });
        let mask = match &self.mask {
            Mask::Original(original) => original.cast(),
            Mask::Owned(bits) => (bits as *const u64).cast(),
        };
        (timeout, mask)
    }
}
