#![no_main]
//! Structure-aware fuzz target for the mount and new Linux mount API surface.
//!
//! The target intentionally keeps paths null, empty, or missing so it exercises
//! argument validation and errno paths without mounting or unmounting real
//! filesystems. File descriptors returned by the new mount API are closed
//! immediately.
//!
//! Beads: bd-4z5o3, bd-xn6p8.1

use std::ffi::{CString, c_void};

use arbitrary::Arbitrary;
use frankenlibc_abi::unistd_abi::{
    fsconfig, fsmount, fsopen, fspick, mount, mount_setattr, move_mount, open_tree, umount,
    umount2,
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_BYTES: usize = 128;

#[derive(Debug, Arbitrary)]
struct MountInput {
    op: u8,
    path_kind: u8,
    fs_kind: u8,
    dirfd_kind: u8,
    flags: u32,
    attr_flags: u32,
    aux: i32,
    attr_size: u8,
    null_source: bool,
    null_target: bool,
    null_fs: bool,
    null_key: bool,
    null_value: bool,
    fs_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
    value_bytes: Vec<u8>,
    attr_bytes: Vec<u8>,
}

fn cstring_bytes(bytes: &[u8]) -> CString {
    CString::new(bytes).unwrap_or_default()
}

fn bounded_cstring(bytes: &[u8], fallback: &'static [u8]) -> CString {
    if bytes.len() > MAX_FUZZ_BYTES {
        return cstring_bytes(fallback);
    }
    CString::new(bytes).unwrap_or_else(|_| cstring_bytes(fallback))
}

fn path_arg(input: &MountInput) -> CString {
    match input.path_kind % 3 {
        0 => cstring_bytes(b""),
        1 => cstring_bytes(b"/definitely-missing-frankenlibc-fuzz-mount-target"),
        _ => cstring_bytes(b"/proc/self/fd/-1"),
    }
}

fn fs_arg(input: &MountInput) -> CString {
    match input.fs_kind % 4 {
        0 => cstring_bytes(b""),
        1 => cstring_bytes(b"tmpfs"),
        2 => cstring_bytes(b"definitely_missing_fstype"),
        _ => bounded_cstring(&input.fs_bytes, b"definitely_missing_fstype"),
    }
}

fn dirfd(kind: u8) -> libc::c_int {
    match kind % 3 {
        0 => libc::AT_FDCWD,
        1 => -1,
        _ => libc::c_int::MAX,
    }
}

fn close_if_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn assert_unit_rc(op: u8, rc: libc::c_int) {
    assert!(rc == 0 || rc == -1, "op={op} returned invalid rc={rc}");
}

fn assert_fd_rc(op: u8, rc: libc::c_int) {
    assert!(rc >= -1, "op={op} returned invalid fd rc={rc}");
}

fuzz_target!(|input: MountInput| {
    if input.fs_bytes.len() > MAX_FUZZ_BYTES
        || input.key_bytes.len() > MAX_FUZZ_BYTES
        || input.value_bytes.len() > MAX_FUZZ_BYTES
        || input.attr_bytes.len() > MAX_FUZZ_BYTES
    {
        return;
    }

    let path = path_arg(&input);
    let fs = fs_arg(&input);
    let key = bounded_cstring(&input.key_bytes, b"source");
    let value = bounded_cstring(&input.value_bytes, b"none");
    let mut attr = input.attr_bytes.clone();
    attr.resize((input.attr_size as usize).min(MAX_FUZZ_BYTES), 0);

    let path_ptr = if input.null_target {
        std::ptr::null()
    } else {
        path.as_ptr()
    };
    let source_ptr = if input.null_source {
        std::ptr::null()
    } else {
        path.as_ptr()
    };
    let fs_ptr = if input.null_fs {
        std::ptr::null()
    } else {
        fs.as_ptr()
    };
    let key_ptr = if input.null_key {
        std::ptr::null()
    } else {
        key.as_ptr()
    };
    let value_ptr = if input.null_value {
        std::ptr::null()
    } else {
        value.as_ptr() as *const c_void
    };
    let attr_ptr = if attr.is_empty() {
        std::ptr::null_mut()
    } else {
        attr.as_mut_ptr().cast()
    };

    let op = input.op % 10;
    match op {
        0 => {
            let rc = unsafe {
                mount(
                    source_ptr,
                    path_ptr,
                    fs_ptr,
                    input.flags as libc::c_ulong,
                    std::ptr::null(),
                )
            };
            assert_unit_rc(op, rc);
        }
        1 => {
            let rc = unsafe { umount(path_ptr) };
            assert_unit_rc(op, rc);
        }
        2 => {
            let rc = unsafe { umount2(path_ptr, input.flags as libc::c_int) };
            assert_unit_rc(op, rc);
        }
        3 => {
            let fd = unsafe { fsopen(fs_ptr, input.flags) };
            assert_fd_rc(op, fd);
            close_if_fd(fd);
        }
        4 => {
            let fd = unsafe { fsmount(-1, input.flags, input.attr_flags) };
            assert_fd_rc(op, fd);
            close_if_fd(fd);
        }
        5 => {
            let rc = unsafe { fsconfig(-1, input.flags, key_ptr, value_ptr, input.aux) };
            assert_unit_rc(op, rc);
        }
        6 => {
            let fd = unsafe { fspick(dirfd(input.dirfd_kind), path_ptr, input.flags) };
            assert_fd_rc(op, fd);
            close_if_fd(fd);
        }
        7 => {
            let fd = unsafe { open_tree(dirfd(input.dirfd_kind), path_ptr, input.flags) };
            assert_fd_rc(op, fd);
            close_if_fd(fd);
        }
        8 => {
            let rc = unsafe {
                move_mount(
                    dirfd(input.dirfd_kind),
                    path_ptr,
                    -1,
                    std::ptr::null(),
                    input.flags,
                )
            };
            assert_unit_rc(op, rc);
        }
        _ => {
            let rc = unsafe { mount_setattr(-1, path_ptr, input.flags, attr_ptr, attr.len()) };
            assert_unit_rc(op, rc);
        }
    }
});
