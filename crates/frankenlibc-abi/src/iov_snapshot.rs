//! Hardened vectored-I/O descriptor import.
//!
//! Descriptor placement is independent of the lifetime of the pointed-to buffers:
//! stack iovecs can point into tracked allocations. Import once through the kernel,
//! validate the imported values, and pass that same owned import to the I/O syscall.
//! Never form a Rust reference to a caller-supplied descriptor array.
//!
//! This is not a pin on the payload allocations and does not make concurrent free
//! or arbitrary concurrent payload mutation safe. Strict mode keeps the original
//! kernel path. If self process_vm_readv is unavailable or permission-denied,
//! a private nonblocking pipe provides kernel-checked copy_from_user instead.
//! Both methods fail closed: neither submits the unchecked original array.
//! Hardened mode needs one of these copy routes allowed by the syscall policy;
//! a seccomp policy that kills on an attempted syscall cannot be recovered from.

use std::ffi::{c_int, c_void};
use std::mem::size_of;
use std::ptr;

use frankenlibc_core::{errno, syscall};

const INLINE_IOVECS: usize = 8;
// Linux UIO_MAXIOV, on the x86_64 and aarch64 targets supported by the raw veneer.
pub(super) const MAX_IOVECS: usize = 1024;
const EMPTY_IOVEC: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};

/// Owns the actual descriptors submitted to the kernel, through cancellation and
/// error paths. Large imports use a raw anonymous mapping, not malloc or TLS:
/// importing readv/writev must not acquire an allocator lock or reuse a signal-
/// interrupted outer call's scratch storage.
pub(super) struct PreparedIovecs {
    storage: Storage,
    count: usize,
}

enum Storage {
    Original(*const libc::iovec),
    Inline([libc::iovec; INLINE_IOVECS]),
    Mapped(Mapping),
}

struct Mapping {
    base: *mut libc::iovec,
    bytes: usize,
}

#[inline]
fn kernel_result(raw: usize) -> Result<usize, c_int> {
    let signed = raw as isize;
    if (-4095..0).contains(&signed) {
        Err((-signed) as c_int)
    } else {
        Ok(raw)
    }
}

impl Mapping {
    fn new(bytes: usize) -> Result<Self, c_int> {
        // SAFETY: request a new private, zero-filled, readable/writable mapping.
        // No caller address is used, and no exported libc symbol is called.
        let base = kernel_result(unsafe {
            syscall::syscall6(
                libc::SYS_mmap as usize,
                0,
                bytes,
                (libc::PROT_READ | libc::PROT_WRITE) as usize,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as usize,
                usize::MAX,
                0,
            )
        })?;
        // A null mapping cannot back Rust slices, even though Linux can in
        // principle permit address zero. Relinquish it rather than using it.
        if base == 0 {
            // SAFETY: this is exactly the mapping just returned by mmap.
            unsafe { syscall::syscall2(libc::SYS_munmap as usize, base, bytes) };
            return Err(errno::ENOMEM);
        }
        Ok(Self {
            base: base as *mut libc::iovec,
            bytes,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object owns the mapping, it has not been exposed for
        // retention, and all borrowed views end before this destructor runs.
        // The raw veneer does not overwrite ABI errno on an I/O error path.
        unsafe { syscall::syscall2(libc::SYS_munmap as usize, self.base as usize, self.bytes) };
    }
}

impl PreparedIovecs {
    /// Invalid/empty counts and null arrays are left to the original syscall,
    /// preserving zero-count FD checks and kernel count/null error handling.
    pub(super) fn prepare(
        iov: *const libc::iovec,
        count: c_int,
        hardened: bool,
    ) -> Result<Self, c_int> {
        if !hardened || count <= 0 || count as usize > MAX_IOVECS || iov.is_null() {
            return Ok(Self {
                storage: Storage::Original(iov),
                count: 0,
            });
        }
        Self::snapshot_with(iov, count as usize, crate::malloc_abi::known_remaining)
    }

    /// vmsplice's count is size_t, not readv's signed int. Preserve oversized
    /// values for the original syscall instead of truncating them into a valid
    /// import count (or zero). The caller passes the unchanged count to Linux.
    pub(super) fn prepare_unsigned(
        iov: *const libc::iovec,
        count: usize,
        hardened: bool,
    ) -> Result<Self, c_int> {
        if count > MAX_IOVECS {
            return Ok(Self {
                storage: Storage::Original(iov),
                count: 0,
            });
        }
        Self::prepare(iov, count as c_int, hardened)
    }

    fn snapshot_with(
        iov: *const libc::iovec,
        count: usize,
        remaining: impl Fn(usize) -> Option<usize>,
    ) -> Result<Self, c_int> {
        // Keep this constructor total even if a future caller skips prepare.
        if iov.is_null() || count == 0 || count > MAX_IOVECS {
            return Err(errno::EINVAL);
        }
        let bytes = count
            .checked_mul(size_of::<libc::iovec>())
            .ok_or(errno::EINVAL)?;
        if (iov as usize).checked_add(bytes).is_none()
            || remaining(iov as usize).is_some_and(|available| bytes > available)
        {
            return Err(errno::EFAULT);
        }
        let mut imported = Self {
            storage: if count <= INLINE_IOVECS {
                Storage::Inline([EMPTY_IOVEC; INLINE_IOVECS])
            } else {
                Storage::Mapped(Mapping::new(bytes)?)
            },
            count,
        };
        let destination = match &mut imported.storage {
            Storage::Inline(entries) => entries.as_mut_ptr(),
            Storage::Mapped(mapping) => mapping.base,
            Storage::Original(_) => unreachable!("snapshot owns its storage"),
        };
        // SAFETY: destination is exclusively owned, aligned, initialized storage
        // for count iovecs. All bit patterns are valid for the two iovec fields.
        // Caller memory is only a remote kernel-copy source, never a Rust slice.
        unsafe { copy_descriptors(iov, destination, bytes) }?;

        // Validate Linux's aggregate-length limit before any buffer-bounds check
        // or target I/O. In particular, wrapping sums must not become small I/O.
        let entries = imported.entries();
        let mut total = 0usize;
        for entry in entries {
            total = total
                .checked_add(entry.iov_len)
                .filter(|&length| length <= isize::MAX as usize)
                .ok_or(errno::EINVAL)?;
        }
        for entry in entries {
            // A zero-length element does not authorize or perform an access.
            if entry.iov_len == 0 {
                continue;
            }
            let base = entry.iov_base as usize;
            if entry.iov_base.is_null()
                || base.checked_add(entry.iov_len).is_none()
                || remaining(base).is_some_and(|available| entry.iov_len > available)
            {
                return Err(errno::EFAULT);
            }
        }
        Ok(imported)
    }

    #[inline]
    pub(super) fn as_ptr(&self) -> *const libc::iovec {
        match &self.storage {
            Storage::Original(original) => *original,
            Storage::Inline(entries) => entries.as_ptr(),
            Storage::Mapped(mapping) => mapping.base.cast_const(),
        }
    }

    fn entries(&self) -> &[libc::iovec] {
        match &self.storage {
            Storage::Original(_) => &[],
            Storage::Inline(entries) => &entries[..self.count],
            Storage::Mapped(mapping) => {
                // SAFETY: count descriptors were initialized by mmap and a
                // complete import; the owned mapping outlives this shared view.
                unsafe { std::slice::from_raw_parts(mapping.base, self.count) }
            }
        }
    }
}

/// Copy descriptor bytes through the existing fault-checked kernel routes.
/// Both ends may be untrusted user addresses. No Rust reference is formed to
/// either extent. Short copies are errors and can have partially written the
/// destination, just as with kernel copy_to_user; this is not an atomic store.
///
/// # Safety
/// Any readable source bytes must be initialized. Any writable destination must
/// permit byte writes for the duration of this call, without violating Rust
/// aliasing; permission faults are reported rather than dereferenced in Rust.
#[allow(dead_code)] // also compiled by the file-I/O parent, which imports only iovecs
pub(super) unsafe fn copy_user_bytes(
    source: *const u8,
    destination: *mut u8,
    bytes: usize,
) -> Result<(), c_int> {
    if bytes == 0 {
        return Ok(());
    }
    for address in [source as usize, destination as usize] {
        if address == 0
            || address.checked_add(bytes).is_none()
            || crate::malloc_abi::known_remaining(address)
                .is_some_and(|available| bytes > available)
        {
            return Err(errno::EFAULT);
        }
    }
    // SAFETY: the casts only carry addresses. The copy helpers do not form
    // iovec references or require iovec alignment/a multiple-of-iovec size.
    unsafe { copy_descriptors(source.cast(), destination.cast(), bytes) }
}

/// Fault-safe descriptor import. Short copies are errors; no incomplete array
/// may reach validation or the target I/O syscall. No host errno side effects.
unsafe fn copy_descriptors(
    source: *const libc::iovec,
    destination: *mut libc::iovec,
    bytes: usize,
) -> Result<(), c_int> {
    let local = libc::iovec {
        iov_base: destination.cast::<c_void>(),
        iov_len: bytes,
    };
    let remote = libc::iovec {
        iov_base: source.cast_mut().cast::<c_void>(),
        iov_len: bytes,
    };
    // SAFETY: getpid has no pointer arguments. Read it afresh, never cache a PID
    // across fork, and propagate policy errors rather than reinterpret an errno.
    let pid = match kernel_result(unsafe { syscall::syscall0(libc::SYS_getpid as usize) }) {
        Ok(pid) => pid,
        Err(errno::ENOSYS | errno::EPERM | errno::EACCES) => {
            // SAFETY: the fallback uses the same kernel-checked byte extents.
            return unsafe { copy_descriptors_with_pipe(source, destination, bytes) };
        }
        Err(error) => return Err(error),
    };
    // SAFETY: local/remote are live initialized descriptors. Linux validates
    // both the local write extent and the remote read extent, returning EFAULT
    // instead of dereferencing a possibly-invalid user address in Rust.
    let copied = kernel_result(unsafe {
        syscall::syscall6(
            libc::SYS_process_vm_readv as usize,
            pid,
            &local as *const libc::iovec as usize,
            1,
            &remote as *const libc::iovec as usize,
            1,
            0,
        )
    });
    match copied {
        Ok(count) if count == bytes => Ok(()),
        Ok(_) => Err(errno::EFAULT),
        // These errors describe the copy mechanism, not a bad source address.
        // Do not cache availability globally: syscall policy can differ by
        // thread, and process identity/policy can change across fork.
        Err(errno::ENOSYS | errno::EPERM | errno::EACCES) => {
            // SAFETY: identical kernel-checked source and destination extents.
            unsafe { copy_descriptors_with_pipe(source, destination, bytes) }
        }
        Err(error) => Err(error),
    }
}

struct CopyPipe([c_int; 2]);

impl CopyPipe {
    fn new() -> Result<Self, c_int> {
        let mut fds = [-1; 2];
        // SAFETY: fds is a writable array of two descriptors. CLOEXEC prevents
        // exec leaks. NONBLOCK and PIPE_BUF-sized chunks avoid pipe-capacity
        // waits, even when the process's default pipe capacity is reduced.
        kernel_result(unsafe {
            syscall::syscall2(
                libc::SYS_pipe2 as usize,
                fds.as_mut_ptr() as usize,
                (libc::O_CLOEXEC | libc::O_NONBLOCK) as usize,
            )
        })?;
        Ok(Self(fds))
    }
}

impl Drop for CopyPipe {
    fn drop(&mut self) {
        for fd in self.0 {
            // SAFETY: these are the private descriptors created above. Never
            // retry close on EINTR: Linux has already released the fd number.
            unsafe { syscall::syscall1(libc::SYS_close as usize, fd as usize) };
        }
    }
}

/// Fallback for kernels/sandboxes that deny self process_vm_readv. Only raw
/// kernel I/O is used, so exported read/write, cancellation wrappers, malloc,
/// and descriptor validators cannot recurse into this import. A failed import
/// can affect only the private pipe, never the caller's target descriptor.
unsafe fn copy_descriptors_with_pipe(
    source: *const libc::iovec,
    destination: *mut libc::iovec,
    bytes: usize,
) -> Result<(), c_int> {
    const CHUNK: usize = 4096; // Linux PIPE_BUF on both supported targets.
    let pipe = CopyPipe::new()?;
    let mut offset = 0;
    while offset < bytes {
        let wanted = (bytes - offset).min(CHUNK);
        // SAFETY: source remains an untrusted kernel-copy address; wrapping
        // arithmetic creates no in-bounds Rust reference to caller storage.
        let written = kernel_result(unsafe {
            syscall::syscall3(
                libc::SYS_write as usize,
                pipe.0[1] as usize,
                source.cast::<u8>().wrapping_add(offset) as usize,
                wanted,
            )
        })?;
        if written == 0 || written > wanted {
            return Err(errno::EIO);
        }
        let mut drained = 0;
        while drained < written {
            // SAFETY: destination is only a kernel-copy address. Wrapping
            // arithmetic forms no Rust reference to possibly-invalid storage.
            let read = kernel_result(unsafe {
                syscall::syscall3(
                    libc::SYS_read as usize,
                    pipe.0[0] as usize,
                    destination.cast::<u8>().wrapping_add(offset + drained) as usize,
                    written - drained,
                )
            })?;
            if read == 0 || read > written - drained {
                return Err(errno::EIO);
            }
            drained += read;
        }
        offset += written;
    }
    Ok(())
}

#[cfg(test)]
#[path = "iov_snapshot_tests.rs"]
mod tests;
