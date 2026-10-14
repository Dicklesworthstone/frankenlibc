//! Owned socket-message descriptors for the hardened ABI path.
//!
//! A stack msghdr/iovec must not hide tracked payload, address or ancillary
//! bounds. Import the header and vector once, validate that import, and submit
//! that same graph. Payload bytes are not copied or pinned against concurrent
//! free. This does not promise an atomic snapshot of concurrent user writes.

use std::ffi::{c_int, c_void};
use std::mem::size_of;

use super::iov_snapshot::{MAX_IOVECS, PreparedIovecs, copy_user_bytes};
use crate::malloc_abi::known_remaining;

pub(super) struct PreparedMessage {
    header: libc::msghdr,
    vectors: PreparedIovecs,
}

fn optional_region_fits(pointer: *const c_void, bytes: usize) -> bool {
    // Null optional pointers and zero lengths keep their kernel semantics.
    // In particular a null msg_name need not have a zero msg_namelen.
    bytes == 0 || pointer.is_null()
        || ((pointer as usize).checked_add(bytes).is_some()
            && known_remaining(pointer as usize).is_none_or(|available| bytes <= available))
}

impl PreparedMessage {
    pub(super) fn prepare(original: *const libc::msghdr) -> Result<Self, c_int> {
        // SAFETY: all fields of msghdr accept the all-zero representation.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        // SAFETY: destination is our live initialized header. Caller memory is
        // a kernel-copy address, never dereferenced or assumed aligned in Rust.
        unsafe {
            copy_user_bytes(original.cast(), (&mut header as *mut libc::msghdr).cast(),
                size_of::<libc::msghdr>())
        }?;
        // Linux's socket-message count error is EMSGSIZE, not readv's EINVAL.
        // Do not narrow size_t, allocate scratch, or examine an invalid vector.
        if header.msg_iovlen > MAX_IOVECS {
            return Err(libc::EMSGSIZE);
        }
        let vectors = PreparedIovecs::prepare_unsigned(header.msg_iov, header.msg_iovlen, true)?;
        if !optional_region_fits(header.msg_name.cast_const(), header.msg_namelen as usize)
            || !optional_region_fits(header.msg_control.cast_const(), header.msg_controllen)
        {
            return Err(libc::EFAULT);
        }
        Ok(Self { header, vectors })
    }

    /// Refresh the interior pointer only after the owner has reached its final
    /// location. Do not cache it in prepare: moving inline iovecs changes their
    /// address. The returned pointer is valid only until this owner moves/drops.
    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::msghdr {
        self.header.msg_iov = self.vectors.as_ptr().cast_mut();
        &mut self.header
    }
}
