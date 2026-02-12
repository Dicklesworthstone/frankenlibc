//! ABI layer for `<dirent.h>` functions (`opendir`, `readdir`, `closedir`).
//!
//! Manages stateful `DIR` streams backed by `SYS_getdents64` via `libc`.
//! Parsing of raw kernel dirent buffers delegates to `frankenlibc_core::dirent`.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::sync::Mutex;

use frankenlibc_core::dirent as dirent_core;
use frankenlibc_core::errno;
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

#[unsafe(no_mangle)]
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

    let fd = unsafe { libc::open(name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        unsafe { set_abi_errno(errno::ENOENT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 15, true);
        return std::ptr::null_mut();
    }

    let handle = next_handle();
    let state = DirState {
        fd,
        buffer: vec![0u8; GETDENTS_BUF_SIZE],
        offset: 0,
        valid_bytes: 0,
        eof: false,
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
#[unsafe(no_mangle)]
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
    let nread = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            state.fd,
            state.buffer.as_mut_ptr() as *mut c_void,
            state.buffer.len(),
        )
    };

    if nread < 0 {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, true);
        return std::ptr::null_mut();
    }
    if nread == 0 {
        state.eof = true;
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, false);
        return std::ptr::null_mut();
    }

    state.valid_bytes = nread as usize;
    state.offset = 0;

    if let Some((entry, next_off)) =
        dirent_core::parse_dirent64(&state.buffer[..state.valid_bytes], 0)
    {
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

#[unsafe(no_mangle)]
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
            let rc = unsafe { libc::close(s.fd) };
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
