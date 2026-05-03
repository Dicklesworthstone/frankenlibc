//! ABI layer for `<dirent.h>` functions (`opendir`, `readdir`, `closedir`).
//!
//! Manages stateful `DIR` streams backed by `SYS_getdents64` via `libc`.
//! Parsing of raw kernel dirent buffers delegates to `frankenlibc_core::dirent`.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;
use std::sync::{Arc, Mutex, MutexGuard};

use frankenlibc_core::dirent as dirent_core;
use frankenlibc_core::errno;
use frankenlibc_core::syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

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

/// Global registry of open directory streams, keyed by a unique handle.
type SharedDirState = Arc<Mutex<DirState>>;

static DIR_REGISTRY: Mutex<Option<HashMap<usize, SharedDirState>>> = Mutex::new(None);

fn lock_registry() -> MutexGuard<'static, Option<HashMap<usize, SharedDirState>>> {
    DIR_REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_state(state: &SharedDirState) -> MutexGuard<'_, DirState> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

fn lookup_dir_state(handle: usize) -> Option<SharedDirState> {
    lock_registry()
        .as_ref()
        .and_then(|map| map.get(&handle).cloned())
}

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

fn write_dirent(dst: *mut libc::dirent, entry: &dirent_core::DirEntry, d_reclen: libc::c_ushort) {
    // SAFETY: caller provides a valid writable dirent slot.
    unsafe {
        std::ptr::write_bytes(dst, 0, 1);
        (*dst).d_ino = entry.d_ino;
        (*dst).d_off = entry.d_off;
        (*dst).d_reclen = d_reclen;
        (*dst).d_type = entry.d_type;
        let name_dst = &mut (&mut (*dst).d_name)[..];
        let copy_len = entry.d_name.len().min(name_dst.len().saturating_sub(1));
        for (i, &b) in entry.d_name[..copy_len].iter().enumerate() {
            name_dst[i] = b as i8;
        }
        if let Some(last) = name_dst.get_mut(copy_len) {
            *last = 0;
        }
    }
}

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

    let mut registry = lock_registry();
    let map = registry.get_or_insert_with(HashMap::new);
    map.insert(handle, Arc::new(Mutex::new(state)));

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
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    if dirp.is_null() {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let handle = dirp as usize;
    let state = match lookup_dir_state(handle) {
        Some(s) => s,
        None => {
            unsafe { set_abi_errno(errno::EBADF) };
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return std::ptr::null_mut();
        }
    };
    let mut state = lock_state(&state);

    if state.offset < state.valid_bytes
        && let Some((entry, next_off)) =
            dirent_core::parse_dirent64(&state.buffer[..state.valid_bytes], state.offset)
    {
        let d_reclen = (next_off - state.offset) as libc::c_ushort;
        state.last_d_off = entry.d_off;
        state.offset = next_off;
        return ENTRY_BUF.with(|cell| {
            let ptr = cell.get();
            write_dirent(ptr, &entry, d_reclen);
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
        let d_reclen = next_off as libc::c_ushort;
        state.last_d_off = entry.d_off;
        state.offset = next_off;
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
        return ENTRY_BUF.with(|cell| {
            let ptr = cell.get();
            write_dirent(ptr, &entry, d_reclen);
            ptr
        });
    }

    unsafe { set_abi_errno(errno::EIO) };
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
        unsafe { set_abi_errno(errno::EBADF) };
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
    let state = {
        let mut registry = lock_registry();
        registry.as_mut().and_then(|m| m.remove(&handle))
    };

    match state {
        Some(state) => {
            let state = lock_state(&state);
            let rc = match syscall::sys_close(state.fd) {
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
    if let Some(state) = lookup_dir_state(handle) {
        let mut state = lock_state(&state);
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
        unsafe { set_abi_errno(errno::EBADF) };
        return -1;
    }
    let handle = dirp as usize;
    match lookup_dir_state(handle) {
        Some(state) => lock_state(&state).last_d_off,
        None => {
            unsafe { set_abi_errno(errno::EBADF) };
            -1
        }
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
    if let Some(state) = lookup_dir_state(handle) {
        let mut state = lock_state(&state);
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
    // To distinguish EOF from error without modifying the caller's errno.
    let old_errno = unsafe { *super::errno_abi::__errno_location() };
    unsafe { set_abi_errno(0) };
    let ptr = unsafe { readdir(dirp) };
    if ptr.is_null() {
        unsafe { *result = std::ptr::null_mut() };
        let e = unsafe { *super::errno_abi::__errno_location() };
        unsafe { set_abi_errno(old_errno) };
        if e != 0 {
            e
        } else {
            0 // End of directory
        }
    } else {
        unsafe { set_abi_errno(old_errno) };
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, entry, 1);
            *result = entry;
        }
        0
    }
}

/// glibc reserved-namespace alias for [`opendir`].
///
/// # Safety
///
/// Same as [`opendir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __opendir(name: *const c_char) -> *mut DIR {
    unsafe { opendir(name) }
}

/// glibc reserved-namespace alias for [`closedir`].
///
/// # Safety
///
/// Same as [`closedir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __closedir(dirp: *mut DIR) -> c_int {
    unsafe { closedir(dirp) }
}

/// glibc reserved-namespace alias for [`readdir`].
///
/// # Safety
///
/// Same as [`readdir`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readdir(dirp: *mut DIR) -> *mut libc::dirent {
    unsafe { readdir(dirp) }
}

/// glibc reserved-namespace alias for [`readdir_r`].
///
/// # Safety
///
/// Same as [`readdir_r`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __readdir_r(
    dirp: *mut DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> c_int {
    unsafe { readdir_r(dirp, entry, result) }
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
    // Compare d_name fields using strcmp semantics.
    let na = unsafe { (*da).d_name.as_ptr() };
    let nb = unsafe { (*db).d_name.as_ptr() };

    let mut i = 0usize;
    loop {
        let ca = unsafe { *na.add(i) } as u8;
        let cb = unsafe { *nb.add(i) } as u8;
        if ca != cb {
            return (ca as c_int) - (cb as c_int);
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
        // dirent name is bounded by 256 in libc::dirent
        if i >= 256 {
            return 0;
        }
    }
}

// ---------------------------------------------------------------------------
// versionsort — Implemented
// ---------------------------------------------------------------------------

/// GNU extension `versionsort` — version-aware directory entry comparator.
///
/// Like `alphasort` but uses `strverscmp` for version-aware ordering.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn versionsort(
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
    // Compare d_name fields using strverscmp semantics.
    let na = unsafe { (*da).d_name.as_ptr() };
    let nb = unsafe { (*db).d_name.as_ptr() };
    unsafe { crate::string_abi::strverscmp(na, nb) }
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
            // POSIX scandir(3) contract: "The caller should free the memory
            // allocated for each of the returned directory entries and the
            // array itself". Route through FrankenLibC's allocator entrypoint
            // so replacement builds do not retain a host libc escape hatch.
            let copy = unsafe { crate::malloc_abi::malloc(size) } as *mut libc::dirent;
            if copy.is_null() {
                for &e in &entries {
                    unsafe { crate::malloc_abi::free(e as *mut c_void) };
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

    // Prevent integer overflow in array size calculation.
    // libc::dirent is large (~280 bytes), and namelist is an array of pointers.
    if count > (usize::MAX / std::mem::size_of::<*mut libc::dirent>()) {
        for &e in &entries {
            unsafe { crate::malloc_abi::free(e as *mut c_void) };
        }
        unsafe { set_abi_errno(errno::ENOMEM) };
        return -1;
    }

    // Allocate the namelist array through our allocator so replacement-mode
    // scans stay free of direct host libc calls.
    if count == 0 {
        // Empty result — allocate a minimal array
        let array = unsafe { crate::malloc_abi::malloc(std::mem::size_of::<*mut libc::dirent>()) }
            as *mut *mut libc::dirent;
        if array.is_null() {
            unsafe { set_abi_errno(errno::ENOMEM) };
            return -1;
        }
        unsafe { *namelist = array };
        return 0;
    }

    let array_size = count * std::mem::size_of::<*mut libc::dirent>();
    let array = unsafe { crate::malloc_abi::malloc(array_size) } as *mut *mut libc::dirent;
    if array.is_null() {
        for &e in &entries {
            unsafe { crate::malloc_abi::free(e as *mut c_void) };
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

// ---------------------------------------------------------------------------
// fdopendir / dirfd
// ---------------------------------------------------------------------------

/// POSIX `fdopendir` — open directory stream from file descriptor.
///
/// Native implementation: creates a DirState from the given fd and registers
/// it in our DIR_REGISTRY, returning an opaque handle.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut libc::DIR {
    if fd < 0 {
        unsafe { set_abi_errno(errno::EBADF) };
        return std::ptr::null_mut();
    }

    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { crate::unistd_abi::fstat(fd, stat.as_mut_ptr()) } != 0 {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        unsafe { set_abi_errno(libc::ENOTDIR) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return std::ptr::null_mut();
    }

    let handle = next_handle();
    let state = DirState {
        fd,
        buffer: vec![0u8; GETDENTS_BUF_SIZE],
        offset: 0,
        valid_bytes: 0,
        eof: false,
        last_d_off: 0,
    };

    let mut registry = lock_registry();
    let map = registry.get_or_insert_with(HashMap::new);
    map.insert(handle, Arc::new(Mutex::new(state)));

    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, false);
    handle as *mut libc::DIR
}

/// POSIX `dirfd` — get file descriptor from directory stream.
///
/// Native implementation: looks up the fd from our DIR_REGISTRY.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn dirfd(dirp: *mut libc::DIR) -> c_int {
    if dirp.is_null() {
        unsafe { set_abi_errno(errno::EINVAL) };
        return -1;
    }

    let handle = dirp as usize;
    match lookup_dir_state(handle) {
        Some(state) => lock_state(&state).fd,
        None => {
            unsafe { set_abi_errno(errno::EBADF) };
            -1
        }
    }
}
