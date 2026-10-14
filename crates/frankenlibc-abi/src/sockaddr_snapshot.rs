//! Owned output capacities for hardened socket operations.
//!
//! Import socklen_t through the shared kernel copier, validate against that
//! import, and submit the same owned capacity. Optional address results and
//! required getter lengths have distinct null-pointer contracts. This does
//! not pin caller allocations against concurrent free.

use std::ffi::{c_int, c_void};
use std::mem::size_of;

use frankenlibc_core::syscall;

use super::iov_snapshot::copy_user_bytes;
use crate::malloc_abi::known_remaining;

// Linux asm-generic/socket.h; shared by the supported x86_64/aarch64 ABIs.
// Keep this local so building against an older libc crate remains possible.
const SO_PEERPIDFD: c_int = 77;

pub(super) struct PreparedSockaddr {
    original: *mut libc::socklen_t,
    length: libc::socklen_t,
    imported: bool,
}

impl PreparedSockaddr {
    /// Strict, or a null optional address: retain the original kernel inputs.
    pub(super) fn original(length: *mut libc::socklen_t) -> Self {
        Self { original: length, length: 0, imported: false }
    }

    pub(super) fn prepare(
        address: *mut libc::sockaddr,
        length: *mut libc::socklen_t,
    ) -> Result<Self, c_int> {
        // Only accept/accept4/recvfrom may ignore length with a null address.
        if address.is_null() {
            return Ok(Self::original(length));
        }
        Self::prepare_required(address.cast(), length)
    }

    /// Name/option getters always access their length word, even when their
    /// output buffer is null. Never let null buffer syntax bypass scalar
    /// tracking, fault checking, or the owned-capacity submission invariant.
    pub(super) fn prepare_required(
        buffer: *mut c_void,
        length: *mut libc::socklen_t,
    ) -> Result<Self, c_int> {
        let mut prepared = Self { original: length, length: 0, imported: true };
        // SAFETY: destination is our initialized scalar. Caller storage is
        // a kernel-copy address, never a Rust dereference or aligned reference.
        unsafe {
            copy_user_bytes(
                length.cast(),
                (&mut prepared.length as *mut libc::socklen_t).cast(),
                size_of::<libc::socklen_t>(),
            )
        }?;
        // Linux treats this word as a signed length. Leave negative syntax to
        // the syscall rather than treating it as a huge positive buffer span.
        // Null buffers retain each option/syscall's own kernel semantics.
        if !buffer.is_null() && prepared.length <= c_int::MAX as libc::socklen_t {
            let bytes = prepared.length as usize;
            if (buffer as usize).checked_add(bytes).is_none()
                || known_remaining(buffer as usize).is_some_and(|available| bytes > available)
            {
                return Err(libc::EFAULT);
            }
        }
        Ok(prepared)
    }

    /// Resolve the owned scalar's address only after this object stops moving.
    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::socklen_t {
        if self.imported { &mut self.length } else { self.original }
    }

    /// Publish a returned length without a speculative caller write.
    ///
    /// # Safety
    /// Writable caller bytes must permit writes for this call. The copier
    /// checks permissions, alignment-independent addresses and tracked bounds.
    pub(super) unsafe fn publish(&self) -> Result<(), c_int> {
        if !self.imported {
            return Ok(());
        }
        // SAFETY: source is the initialized scalar returned by the kernel;
        // destination remains an untrusted, fault-checked kernel-copy address.
        unsafe {
            copy_user_bytes(
                (&self.length as *const libc::socklen_t).cast(),
                self.original.cast(),
                size_of::<libc::socklen_t>(),
            )
        }
    }
}

struct ReturnedFd(Option<c_int>);

impl Drop for ReturnedFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            // SAFETY: this descriptor was installed into our owned scalar by
            // SO_PEERPIDFD and has not been transferred on a successful return.
            // Raw close preserves the publication error. Never retry EINTR.
            unsafe { syscall::syscall1(libc::SYS_close as usize, fd as usize) };
        }
    }
}

/// Submit getsockopt with an immutable imported capacity. Preserve required-
/// size outputs on ERANGE as well as ordinary successful output publication.
///
/// # Safety
/// Accessible caller bytes must obey the getsockopt input/output contract.
/// Caller addresses are only passed to fault-checked kernel copy operations.
#[allow(dead_code)] // also included by the standalone sockaddr importer tests
pub(super) unsafe fn getsockopt_hardened(
    fd: c_int,
    level: c_int,
    option: c_int,
    value: *mut c_void,
    length: *mut libc::socklen_t,
) -> Result<(), c_int> {
    let mut output = PreparedSockaddr::prepare_required(value, length)?;
    let capacity = output.length;

    if level == libc::SOL_SOCKET && option == SO_PEERPIDFD && capacity <= c_int::MAX as u32 {
        // A truncated descriptor cannot be safely handed off. Hardened mode
        // rejects it before creating a resource; strict keeps native semantics.
        if capacity < size_of::<c_int>() as u32 {
            return Err(libc::EINVAL);
        }
        if value.is_null() {
            return Err(libc::EFAULT);
        }
        let mut received: c_int = -1;
        // SAFETY: SO_PEERPIDFD writes at most one int, then installs that fd.
        // Both output addresses are owned, live, initialized scalar storage.
        unsafe {
            syscall::sys_getsockopt(
                fd,
                level,
                option,
                (&mut received as *mut c_int).cast(),
                output.as_mut_ptr(),
            )
        }?;
        let mut owned = ReturnedFd(Some(received));
        // SAFETY: publish in Linux's value-before-length order. Any fault after
        // descriptor creation retains ownership and closes it through the guard.
        unsafe {
            copy_user_bytes(
                (&received as *const c_int).cast(),
                value.cast(),
                size_of::<c_int>(),
            )?;
            output.publish()?;
        }
        owned.0 = None;
        return Ok(());
    }

    // SAFETY: caller buffer was checked against the exact submitted capacity;
    // Linux validates permissions and option-specific input/output semantics.
    let result = unsafe {
        syscall::sys_getsockopt(fd, level, option, value.cast(), output.as_mut_ptr())
    };
    // SO_PEERGROUPS and SO_PEERSEC report the required size on ERANGE. Other
    // options may update their length before failing too. Preserve changed
    // outputs, but do not invent stores after errors such as EBADF that leave
    // the length untouched. Publication faults take precedence as in Linux.
    if result.is_ok() || output.length != capacity || matches!(result, Err(libc::ERANGE)) {
        // SAFETY: source is the syscall's owned result; destination is checked.
        unsafe { output.publish()? };
    }
    result
}
