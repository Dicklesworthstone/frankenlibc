//! Named semaphore creation and process-local mapping ownership.
//!
//! Initialize an unlinked candidate before publishing its name atomically.
//! Opening an existing semaphore never writes its value or waiter state.
//! Mapping identity is (device, inode), not a pathname that can be replaced.
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::sync::Mutex;

use frankenlibc_core::syscall;

const LENGTH: usize = 32;
const SHARED_MARK: u32 = 0x5345_4d53;
const MAX_VALUE: u32 = i32::MAX as u32;

struct Descriptor(c_int);
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = syscall::sys_close(self.0);
    }
}
struct Temporary(CString);
impl Drop for Temporary {
    fn drop(&mut self) {
        // SAFETY: this path belongs exclusively to our O_EXCL-created candidate.
        let _ = unsafe { syscall::sys_unlinkat(libc::AT_FDCWD, self.0.as_ptr().cast(), 0) };
    }
}
struct Mapping {
    address: usize,
    device: u64,
    inode: u64,
    references: usize,
}
struct Pending(Mapping);
impl Drop for Pending {
    fn drop(&mut self) {
        // SAFETY: this candidate has not been transferred to the mapping table.
        let _ = unsafe { syscall::sys_munmap(self.0.address as *mut u8, LENGTH) };
    }
}
static MAPPINGS: Mutex<Vec<Mapping>> = Mutex::new(Vec::new());

unsafe fn path(name: *const c_char) -> Result<CString, c_int> {
    if name.is_null() {
        return Err(libc::EINVAL);
    }
    // SAFETY: the C caller supplies a live string; preserve the ABI boundary's
    // allocation-aware scan rather than walking past known allocation bounds.
    let (len, terminated) = unsafe {
        crate::util::scan_c_string(name, crate::malloc_abi::known_remaining(name as usize))
    };
    if !terminated {
        return Err(libc::EINVAL);
    }
    let bytes = unsafe { std::slice::from_raw_parts(name.cast::<u8>(), len) };
    let first = bytes.iter().position(|byte| *byte != b'/').unwrap_or(len);
    let name = &bytes[first..];
    if name.is_empty() || name.contains(&b'/') {
        return Err(libc::EINVAL);
    }
    if name.len() > 251 {
        return Err(libc::ENAMETOOLONG);
    }
    let mut full = b"/dev/shm/sem.".to_vec();
    full.extend_from_slice(name);
    CString::new(full).map_err(|_| libc::EINVAL)
}

fn descriptor(path: &CString, flags: c_int, mode: libc::mode_t) -> Result<Descriptor, c_int> {
    // SAFETY: path is terminated; no creation/truncation flags are inherited
    // from unrelated caller bits, and special files cannot block the opener.
    unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            path.as_ptr().cast(),
            flags | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            mode,
        )
    }
    .map(Descriptor)
}

fn map(fd: &Descriptor) -> Result<Pending, c_int> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and has the supported Linux native stat layout.
    unsafe { syscall::sys_fstat(fd.0, (&mut stat as *mut libc::stat).cast())? };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < LENGTH as i64 {
        return Err(libc::EINVAL);
    }
    let address = unsafe {
        syscall::sys_mmap(
            std::ptr::null_mut(),
            LENGTH,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.0,
            0,
        )?
    };
    Ok(Pending(Mapping {
        address: address as usize,
        device: stat.st_dev,
        inode: stat.st_ino,
        references: 1,
    }))
}

fn retain(candidate: Pending) -> Result<*mut c_void, c_int> {
    let mut mappings = MAPPINGS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mapping) = mappings
        .iter_mut()
        .find(|entry| (entry.device, entry.inode) == (candidate.0.device, candidate.0.inode))
    {
        mapping.references = mapping.references.checked_add(1).ok_or(libc::EMFILE)?;
        return Ok(mapping.address as *mut c_void);
    }
    mappings.try_reserve(1).map_err(|_| libc::ENOMEM)?;
    let address = candidate.0.address;
    mappings.push(Mapping {
        address,
        device: candidate.0.device,
        inode: candidate.0.inode,
        references: 1,
    });
    std::mem::forget(candidate);
    Ok(address as *mut c_void)
}

fn temporary(mode: libc::mode_t, value: u32) -> Result<(Temporary, Descriptor), c_int> {
    for _ in 0..128 {
        let mut random = [0u8; 16];
        let mut offset = 0;
        while offset < random.len() {
            // SAFETY: the remaining part of random is live writable storage.
            match unsafe {
                syscall::sys_getrandom(random[offset..].as_mut_ptr(), random.len() - offset, 0)
            } {
                Ok(n) if n > 0 => offset += n as usize,
                Err(libc::EINTR) => continue,
                Err(error) => return Err(error),
                _ => return Err(libc::EIO),
            }
        }
        let name = CString::new(format!(
            "/dev/shm/sem.fl-tmp-{:032x}",
            u128::from_ne_bytes(random)
        ))
        .map_err(|_| libc::EINVAL)?;
        let fd = match descriptor(&name, libc::O_CREAT | libc::O_EXCL, mode) {
            Ok(fd) => fd,
            Err(libc::EEXIST) => continue,
            Err(error) => return Err(error),
        };
        let temporary = Temporary(name);
        let mut bytes = [0u8; LENGTH];
        bytes[..4].copy_from_slice(&value.to_ne_bytes());
        bytes[8..12].copy_from_slice(&SHARED_MARK.to_ne_bytes());
        let mut offset = 0;
        while offset < LENGTH {
            // SAFETY: fd names our private candidate, initialized before linkat.
            match unsafe { syscall::sys_write(fd.0, bytes[offset..].as_ptr(), LENGTH - offset) } {
                Ok(0) => return Err(libc::EIO),
                Ok(n) => offset += n,
                Err(libc::EINTR) => continue,
                Err(error) => return Err(error),
            }
        }
        return Ok((temporary, fd));
    }
    Err(libc::EEXIST)
}

fn open_path(
    path: &CString,
    flags: c_int,
    mode: libc::mode_t,
    value: u32,
) -> Result<*mut c_void, c_int> {
    let create = flags & libc::O_CREAT != 0;
    let exclusive = create && flags & libc::O_EXCL != 0;
    loop {
        if !exclusive {
            match descriptor(path, 0, 0) {
                Ok(fd) => return retain(map(&fd)?),
                Err(libc::ENOENT) if create => {}
                Err(error) => return Err(error),
            }
        }
        // The value and mode are creation arguments, ignored on an existing
        // nonexclusive open. Validate only when creating a new candidate.
        if value > MAX_VALUE {
            return Err(libc::EINVAL);
        }
        let (temporary, fd) = temporary(mode, value)?;
        let candidate = map(&fd)?;
        // SAFETY: both C paths remain alive. linkat never replaces the winner
        // of a competing creation, and no public name ever exposes zero length.
        match unsafe {
            syscall::sys_linkat(
                libc::AT_FDCWD,
                temporary.0.as_ptr().cast(),
                libc::AT_FDCWD,
                path.as_ptr().cast(),
                0,
            )
        } {
            Ok(()) => return retain(candidate),
            Err(libc::EEXIST) if !exclusive => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Shared body for the variadic entry and the exported unistd ABI.
/// # Safety
/// `name` is a live C string; creation arguments have their declared C types.
pub(crate) unsafe fn open_values(
    name: *const c_char,
    flags: c_int,
    mode: libc::mode_t,
    value: c_uint,
) -> *mut c_void {
    let result = unsafe { path(name) }.and_then(|path| open_path(&path, flags, mode, value));
    match result {
        Ok(address) => address,
        Err(error) => {
            unsafe { crate::errno_abi::set_abi_errno(error) };
            libc::SEM_FAILED.cast()
        }
    }
}

/// # Safety
/// `name` is a C string. O_CREAT requires mode_t and unsigned int variadic arguments.
pub unsafe extern "C" fn open(name: *const c_char, flags: c_int, mut args: ...) -> *mut c_void {
    let (mode, value) = if flags & libc::O_CREAT != 0 {
        unsafe { (args.next_arg::<libc::mode_t>(), args.next_arg::<c_uint>()) }
    } else {
        (0, 0)
    };
    unsafe { open_values(name, flags, mode, value) }
}

/// # Safety
/// `semaphore` must be a still-open named handle. Unknown addresses are rejected
/// without reading or unmapping caller memory.
pub unsafe extern "C" fn close(semaphore: *mut c_void) -> c_int {
    let mut mappings = MAPPINGS.lock().unwrap_or_else(|e| e.into_inner());
    let result = if let Some(index) = mappings
        .iter()
        .position(|entry| entry.address == semaphore as usize)
    {
        if mappings[index].references > 1 {
            mappings[index].references -= 1;
            Ok(())
        } else {
            match unsafe { syscall::sys_munmap(semaphore.cast(), LENGTH) } {
                Ok(()) => {
                    mappings.swap_remove(index);
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
    } else {
        Err(libc::EINVAL)
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            unsafe { crate::errno_abi::set_abi_errno(error) };
            -1
        }
    }
}

/// # Safety
/// `name` is a live C string. Existing mappings survive unlink and recreation.
pub unsafe extern "C" fn unlink(name: *const c_char) -> c_int {
    let result = unsafe { path(name) }
        .and_then(|path| unsafe { syscall::sys_unlinkat(libc::AT_FDCWD, path.as_ptr().cast(), 0) });
    match result {
        Ok(()) => 0,
        Err(error) => {
            unsafe { crate::errno_abi::set_abi_errno(error) };
            -1
        }
    }
}
