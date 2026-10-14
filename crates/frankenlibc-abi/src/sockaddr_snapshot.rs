//! Owned output capacities for hardened socket-address operations.
//!
//! Import the caller's socklen_t through the shared kernel copier. Validate
//! the address buffer against that imported capacity and give the kernel the
//! same owned capacity, not a caller word that can change after validation.
//! This does not pin the address/length allocations against concurrent free.

use std::ffi::c_int;
use std::mem::size_of;

use super::iov_snapshot::copy_user_bytes;
use crate::malloc_abi::known_remaining;

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
        // accept/recvfrom ignore addrlen when no address is requested. Other
        // address operations must retain their own kernel null-address rules.
        if address.is_null() {
            return Ok(Self::original(length));
        }
        let mut prepared = Self { original: length, length: 0, imported: true };
        // SAFETY: the destination is our initialized scalar. Caller storage is
        // a kernel-copy address, never a Rust dereference or aligned reference.
        unsafe {
            copy_user_bytes(length.cast(), (&mut prepared.length as *mut libc::socklen_t).cast(),
                size_of::<libc::socklen_t>())
        }?;
        // Linux treats this word as a signed length. A negative length is
        // rejected by the target syscall without writing the address buffer;
        // do not misclassify it as a huge positive access and return EFAULT.
        if prepared.length <= c_int::MAX as libc::socklen_t {
            let bytes = prepared.length as usize;
            if (address as usize).checked_add(bytes).is_none()
                || known_remaining(address as usize).is_some_and(|available| bytes > available)
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

    /// Called only after target success. The address/data may already have
    /// been written if publication fails. No speculative caller write is made.
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
            copy_user_bytes((&self.length as *const libc::socklen_t).cast(), self.original.cast(),
                size_of::<libc::socklen_t>())
        }
    }
}
