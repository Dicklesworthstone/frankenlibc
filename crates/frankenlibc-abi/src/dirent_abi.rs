//! ABI layer for `<dirent.h>` functions (`opendir`, `readdir`, `closedir`).
//!
//! Manages stateful `DIR` streams backed by `SYS_getdents64` via `libc`.
//! Parsing of raw kernel dirent buffers delegates to `frankenlibc_core::dirent`.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;
use std::sync::Mutex;

use frankenlibc_core::dirent as dirent_core;
use frankenlibc_core::errno;
use frankenlibc_core::syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

/// Internal directory stream state.
struct DirState {
    fd: c_int,
    buffer: Vec<u8>,
    offset: usize,
    valid_bytes: usize,
    eof: bool,
    /// Kernel d_off of the last returned entry (for telldir/seekdir).
    last_d_off: i64,
}

/// Extract the kernel `d_off` field from a raw linux_dirent64 at the given buffer offset.
/// Layout: d_ino(8) | d_off(8) | d_reclen(2) | d_type(1) | d_name(...)
#[inline]
fn extract_d_off(buffer: &[u8], offset: usize) -> i64 {
    if offset + 16 > buffer.len() {
        return 0;
    }
    i64::from_ne_bytes(buffer[offset + 8..offset + 16].try_into().unwrap_or([0; 8]))
}

/// Global registry of open directory streams, keyed by a unique handle.
static DIR_REGISTRY: Mutex<Option<HashMap<usize, DirState>>> = Mutex::new(None);

fn next_handle() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Opaque DIR pointer passed to C callers.
/// We use the handle value as the pointer value for identification.
#[repr(C)]
pub struct DIR {
    _opaque: [u8; 0],
}

const GETDENTS_BUF_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// opendir
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn opendir(name: *const c_char) -> *mut DIR {
    let (mode, decision) = runtime_policy::decide(ApiFamily::IoFd, 0, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if name.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let fd = match unsafe {
        syscall::sys_openat(
            libc::AT_FDCWD,
            name as *const u8,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
    } {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
            return std::ptr::null_mut();
        }
    };

    let handle = next_handle();
    let state = DirState {
        fd,
        buffer: vec![0u8; GETDENTS_BUF_SIZE],
        offset: 0,
        valid_bytes: 0,
        eof: false,
        last_d_off: 0,
    };

    let mut registry = DIR_REGISTRY.lock().unwrap();
    let map = registry.get_or_insert_with(HashMap::new);
    map.insert(handle, state);

    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, false);
    handle as *mut DIR
}

// ---------------------------------------------------------------------------
// readdir
// ---------------------------------------------------------------------------

/// POSIX `readdir` — returns a pointer to a static `dirent` struct.
///
/// We use a thread-local buffer for the returned `dirent` to avoid lifetime issues.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readdir(dirp: *mut DIR) -> *mut libc::dirent {
    thread_local! {
        static ENTRY_BUF: std::cell::UnsafeCell<libc::dirent> = const {
            std::cell::UnsafeCell::new(unsafe { std::mem::zeroed() })
        };
    }

    let (_mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, dirp as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if dirp.is_null() {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let handle = dirp as usize;
    let mut registry = DIR_REGISTRY.lock().unwrap();
    let map = match registry.as_mut() {
        Some(m) => m,
        None => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
    };

    let state = match map.get_mut(&handle) {
        Some(s) => s,
        None => {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
    };

    // Try to parse from current buffer
    if state.offset < state.valid_bytes
        && let Some((entry, next_off)) =
            dirent_core::parse_dirent64(&state.buffer[..state.valid_bytes], state.offset)
    {
        state.last_d_off = extract_d_off(&state.buffer, state.offset);
        state.offset = next_off;
        return ENTRY_BUF.with(|cell| {
            let ptr = cell.get();
            unsafe {
                (*ptr).d_ino = entry.d_ino;
                (*ptr).d_type = entry.d_type;
                // Copy name, ensuring NUL termination
                let name_dst = &mut (&mut (*ptr).d_name)[..];
                let copy_len = entry.d_name.len().min(name_dst.len() - 1);
                for (i, &b) in entry.d_name[..copy_len].iter().enumerate() {
                    name_dst[i] = b as i8;
                }
                name_dst[copy_len] = 0;
            }
            ptr
        });
    }

    if state.eof {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, false);
        return std::ptr::null_mut();
    }

    // Refill buffer via SYS_getdents64
    let nread = match unsafe {
        syscall::sys_getdents64(state.fd, state.buffer.as_mut_ptr(), state.buffer.len())
    } {
        Ok(n) => n,
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
            return std::ptr::null_mut();
        }
    };
    if nread == 0 {
        state.eof = true;
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
        return std::ptr::null_mut();
    }

    state.valid_bytes = nread;
    state.offset = 0;

    if let Some((entry, next_off)) =
        dirent_core::parse_dirent64(&state.buffer[..state.valid_bytes], 0)
    {
        state.last_d_off = extract_d_off(&state.buffer, 0);
        state.offset = next_off;
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
        return ENTRY_BUF.with(|cell| {
            let ptr = cell.get();
            unsafe {
                (*ptr).d_ino = entry.d_ino;
                (*ptr).d_type = entry.d_type;
                let name_dst = &mut (&mut (*ptr).d_name)[..];
                let copy_len = entry.d_name.len().min(name_dst.len() - 1);
                for (i, &b) in entry.d_name[..copy_len].iter().enumerate() {
                    name_dst[i] = b as i8;
                }
                name_dst[copy_len] = 0;
            }
            ptr
        });
    }

    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// closedir
// ---------------------------------------------------------------------------

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn closedir(dirp: *mut DIR) -> c_int {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::IoFd, dirp as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if dirp.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, false);
            return 0;
        }
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let handle = dirp as usize;
    let mut registry = DIR_REGISTRY.lock().unwrap();
    let state = registry.as_mut().and_then(|m| m.remove(&handle));

    match state {
        Some(s) => {
            let rc = match syscall::sys_close(s.fd) {
                Ok(()) => 0,
                Err(e) => {
                    unsafe { set_abi_errno(e) };
                    -1
                }
            };
            let adverse = rc != 0;
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
            rc
        }
        None => {
            if mode.heals_enabled() {
                runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, false);
                0
            } else {
                unsafe { set_abi_errno(errno::EBADF) };
                runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
                -1
            }
        }
    }
}

// ---------------------------------------------------------------------------
// seekdir — native implementation using our DIR registry
// ---------------------------------------------------------------------------

/// POSIX `seekdir` — set position in directory stream.
///
/// Uses lseek on the underlying fd to restore the kernel position,
/// then resets the buffer so the next readdir refills from that point.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn seekdir(dirp: *mut DIR, loc: c_long) {
    if dirp.is_null() {
        return;
    }
    let handle = dirp as usize;
    let mut registry = DIR_REGISTRY.lock().unwrap();
    if let Some(map) = registry.as_mut()
        && let Some(state) = map.get_mut(&handle)
    {
        let _ = syscall::sys_lseek(state.fd, loc, libc::SEEK_SET);
        state.offset = 0;
        state.valid_bytes = 0;
        state.eof = false;
        state.last_d_off = loc;
    }
}

// ---------------------------------------------------------------------------
// telldir — native implementation using tracked d_off
// ---------------------------------------------------------------------------

/// POSIX `telldir` — get current position in directory stream.
///
/// Returns the kernel d_off of the last entry returned by readdir.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn telldir(dirp: *mut DIR) -> c_long {
    if dirp.is_null() {
        return -1;
    }
    let handle = dirp as usize;
    let registry = DIR_REGISTRY.lock().unwrap();
    match registry.as_ref().and_then(|m| m.get(&handle)) {
        Some(state) => state.last_d_off,
        None => -1,
    }
}

// ---------------------------------------------------------------------------
// rewinddir — native implementation
// ---------------------------------------------------------------------------

/// POSIX `rewinddir` — reset directory stream to beginning.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rewinddir(dirp: *mut DIR) {
    if dirp.is_null() {
        return;
    }
    let handle = dirp as usize;
    let mut registry = DIR_REGISTRY.lock().unwrap();
    if let Some(map) = registry.as_mut()
        && let Some(state) = map.get_mut(&handle)
    {
        let _ = syscall::sys_lseek(state.fd, 0, libc::SEEK_SET);
        state.offset = 0;
        state.valid_bytes = 0;
        state.eof = false;
        state.last_d_off = 0;
    }
}

// ---------------------------------------------------------------------------
// readdir_r — native implementation (deprecated but widely used)
// ---------------------------------------------------------------------------

/// POSIX `readdir_r` — reentrant directory read.
///
/// Reads the next entry into the caller-provided `entry` buffer.
/// Sets `*result` to `entry` on success, or null at end-of-directory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readdir_r(
    dirp: *mut DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> c_int {
    if dirp.is_null() || entry.is_null() || result.is_null() {
        return libc::EINVAL;
    }
    // readdir returns a thread-local pointer; copy into caller's buffer.
    let ptr = unsafe { readdir(dirp) };
    if ptr.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        0 // End of directory — not an error
    } else {
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, entry, 1);
            *result = entry;
        }
        0
    }
}

// ---------------------------------------------------------------------------
// readdir64 — on 64-bit Linux, identical layout to readdir
// ---------------------------------------------------------------------------

/// `readdir64` — 64-bit variant of readdir.
///
/// On 64-bit Linux, `struct dirent` and `struct dirent64` have identical
/// layouts (both use 64-bit d_ino). Delegates to our native readdir.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn readdir64(dirp: *mut DIR) -> *mut c_void {
    unsafe { readdir(dirp) as *mut c_void }
}

// ---------------------------------------------------------------------------
// alphasort — pure comparison function
// ---------------------------------------------------------------------------

/// POSIX `alphasort` — compare two directory entries by name.
///
/// Implements strcmp semantics on d_name for use with scandir.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn alphasort(
    a: *mut *const libc::dirent,
    b: *mut *const libc::dirent,
) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    let da = unsafe { *a };
    let db = unsafe { *b };
    if da.is_null() || db.is_null() {
        return 0;
    }
    let na = unsafe { &(*da).d_name };
    let nb = unsafe { &(*db).d_name };
    for i in 0..na.len().min(nb.len()) {
        let ca = na[i] as u8;
        let cb = nb[i] as u8;
        if ca != cb {
            return (ca as c_int) - (cb as c_int);
        }
        if ca == 0 {
            return 0;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// scandir — native implementation using our opendir/readdir
// ---------------------------------------------------------------------------

/// POSIX `scandir` — scan a directory for matching entries.
///
/// Opens the directory at `path`, reads all entries (applying `filter`
/// if provided), sorts with `compar` if provided, and returns the
/// result in a malloc-allocated array that the caller must free.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scandir(
    path: *const c_char,
    namelist: *mut *mut *mut libc::dirent,
    filter: Option<unsafe extern "C" fn(*const libc::dirent) -> c_int>,
    compar: Option<
        unsafe extern "C" fn(*mut *const libc::dirent, *mut *const libc::dirent) -> c_int,
    >,
) -> c_int {
    if path.is_null() || namelist.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let dir = unsafe { opendir(path) };
    if dir.is_null() {
        return -1; // errno set by opendir
    }

    let mut entries: Vec<*mut libc::dirent> = Vec::new();

    loop {
        let entry = unsafe { readdir(dir) };
        if entry.is_null() {
            break;
        }

        let include = match filter {
            Some(f) => {
                let r = unsafe { f(entry) };
                r != 0
            }
            None => true,
        };

        if include {
            let size = std::mem::size_of::<libc::dirent>();
            let copy = unsafe { libc::malloc(size) } as *mut libc::dirent;
            if copy.is_null() {
                for &e in &entries {
                    unsafe { libc::free(e as *mut c_void) };
                }
                unsafe { closedir(dir) };
                unsafe { set_abi_errno(errno::ENOMEM) };
                return -1;
            }
            unsafe { std::ptr::copy_nonoverlapping(entry, copy, 1) };
            entries.push(copy);
        }
    }

    unsafe { closedir(dir) };

    let count = entries.len();

    // Allocate the namelist array
    if count == 0 {
        // Empty result — allocate a minimal array
        let array = unsafe { libc::malloc(std::mem::size_of::<*mut libc::dirent>()) }
            as *mut *mut libc::dirent;
        if array.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return -1;
        }
        unsafe { *namelist = array };
        return 0;
    }

    let array_size = count * std::mem::size_of::<*mut libc::dirent>();
    let array = unsafe { libc::malloc(array_size) } as *mut *mut libc::dirent;
    if array.is_null() {
        for &e in &entries {
            unsafe { libc::free(e as *mut c_void) };
        }
        unsafe { set_abi_errno(errno::ENOMEM) };
        return -1;
    }

    for (i, &e) in entries.iter().enumerate() {
        unsafe { *array.add(i) = e };
    }

    // Sort if comparator provided
    if let Some(cmp) = compar {
        let slice = unsafe { std::slice::from_raw_parts_mut(array, count) };
        slice.sort_unstable_by(|a, b| {
            let pa = a as *const *mut libc::dirent as *mut *const libc::dirent;
            let pb = b as *const *mut libc::dirent as *mut *const libc::dirent;
            let r = unsafe { cmp(pa, pb) };
            r.cmp(&0)
        });
    }

    unsafe { *namelist = array };
    count as c_int
}

// ---------------------------------------------------------------------------
// scandir64 — on 64-bit Linux, identical to scandir
// ---------------------------------------------------------------------------

/// `scandir64` — 64-bit variant of scandir.
///
/// On 64-bit Linux, dirent and dirent64 have identical layouts.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn scandir64(
    path: *const c_char,
    namelist: *mut *mut *mut c_void,
    filter: Option<unsafe extern "C" fn(*const c_void) -> c_int>,
    compar: Option<unsafe extern "C" fn(*mut *const c_void, *mut *const c_void) -> c_int>,
) -> c_int {
    // On 64-bit Linux, dirent64 == dirent. Transmute function pointers.
    unsafe {
        scandir(
            path,
            namelist as *mut *mut *mut libc::dirent,
            std::mem::transmute::<
                Option<unsafe extern "C" fn(*const c_void) -> c_int>,
                Option<unsafe extern "C" fn(*const libc::dirent) -> c_int>,
            >(filter),
            std::mem::transmute::<
                Option<unsafe extern "C" fn(*mut *const c_void, *mut *const c_void) -> c_int>,
                Option<
                    unsafe extern "C" fn(
                        *mut *const libc::dirent,
                        *mut *const libc::dirent,
                    ) -> c_int,
                >,
            >(compar),
        )
    }
}
