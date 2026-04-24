#![no_main]
//! Differential errno-precedence fuzz target for Linux syscall wrappers.
//!
//! Exercises overlapping invalid-input axes across a small set of Linux-only
//! entrypoints and asserts exact host-vs-ABI parity for both success/failure
//! and errno precedence.
//!
//! Bead: bd-5cv2p

use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const OP_RENAMEAT2: u8 = 0;
const OP_SIGNALFD4: u8 = 1;
const OP_CLOSE_RANGE: u8 = 2;
const OP_EVENTFD_WRITE: u8 = 3;
const OP_FSCONFIG: u8 = 4;

const FSCONFIG_SET_FLAG_CMD: libc::c_uint = 0;
const FSCONFIG_SET_STRING_CMD: libc::c_uint = 1;
const HIGH_FD_BASE: u32 = 1_000_000;

static TEMP_ROOT: OnceLock<PathBuf> = OnceLock::new();
static CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Arbitrary)]
struct ErrnoPrecedenceInput {
    op: u8,
    dirfd_bits: u8,
    path_bits: u8,
    flag_bits: u32,
    first: u16,
    last: u16,
    aux: i32,
    value: u64,
    command_bits: u8,
    mask_bits: u64,
    key: Vec<u8>,
    payload: Vec<u8>,
    null_bits: u8,
}

struct RenameCase {
    olddirfd_abi: libc::c_int,
    newdirfd_abi: libc::c_int,
    olddirfd_host: libc::c_int,
    newdirfd_host: libc::c_int,
    oldpath_abi: Option<CString>,
    newpath_abi: Option<CString>,
    oldpath_host: Option<CString>,
    newpath_host: Option<CString>,
    cleanup_roots: Vec<PathBuf>,
}

struct FdSetup {
    abi_fd: libc::c_int,
    host_fd: libc::c_int,
    close_abi_fd: bool,
    close_host_fd: bool,
}

fuzz_target!(|input: ErrnoPrecedenceInput| {
    if input.key.len() > 32 || input.payload.len() > 32 {
        return;
    }

    match input.op % 5 {
        OP_RENAMEAT2 => fuzz_renameat2(&input),
        OP_SIGNALFD4 => fuzz_signalfd4(&input),
        OP_CLOSE_RANGE => fuzz_close_range(&input),
        OP_EVENTFD_WRITE => fuzz_eventfd_write(&input),
        OP_FSCONFIG => fuzz_fsconfig(&input),
        _ => unreachable!(),
    }
});

fn fuzz_renameat2(input: &ErrnoPrecedenceInput) {
    let case_id = CASE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let Some(case) = build_rename_case(case_id, input.dirfd_bits, input.path_bits) else {
        return;
    };

    let flags = rename_flags(input.flag_bits);
    let oldpath_abi = case
        .oldpath_abi
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr());
    let newpath_abi = case
        .newpath_abi
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr());
    let oldpath_host = case
        .oldpath_host
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr());
    let newpath_host = case
        .newpath_host
        .as_ref()
        .map_or(ptr::null(), |s| s.as_ptr());

    let (abi_rc, abi_errno) = call_abi_renameat2(
        case.olddirfd_abi,
        oldpath_abi,
        case.newdirfd_abi,
        newpath_abi,
        flags,
    );
    let (host_rc, host_errno) = call_host_renameat2(
        case.olddirfd_host,
        oldpath_host,
        case.newdirfd_host,
        newpath_host,
        flags,
    );
    assert_equivalent("renameat2", abi_rc, abi_errno, host_rc, host_errno);

    cleanup_rename_case(&case);
}

fn fuzz_signalfd4(input: &ErrnoPrecedenceInput) {
    let flags = signalfd_flags(input.flag_bits);
    let mask_word = input.mask_bits;
    let null_mask = input.null_bits & 0b0001 != 0;
    let (setup, extra_abi, extra_host) = match signalfd_fd_setup(input.dirfd_bits % 3, mask_word) {
        Some(value) => value,
        None => return,
    };

    let mask_ptr = if null_mask {
        ptr::null()
    } else {
        (&mask_word as *const u64).cast::<libc::c_void>()
    };

    let (abi_rc, abi_errno) = call_abi_signalfd4(setup.abi_fd, mask_ptr, flags);
    let (host_rc, host_errno) = call_host_signalfd4(setup.host_fd, mask_ptr.cast(), flags);
    assert_equivalent("signalfd4", abi_rc, abi_errno, host_rc, host_errno);

    cleanup_optional_fd(abi_rc, extra_abi);
    cleanup_optional_fd(host_rc, extra_host);
    cleanup_setup_fds(&setup);
}

fn fuzz_close_range(input: &ErrnoPrecedenceInput) {
    let first = HIGH_FD_BASE + u32::from(input.first);
    let last = HIGH_FD_BASE + u32::from(input.last);
    let (first, last) = if input.flag_bits & 0b1000 != 0 {
        (last, first)
    } else {
        (first, last)
    };
    let flags = close_range_flags(input.flag_bits);

    let (abi_rc, abi_errno) = call_abi_close_range(first, last, flags);
    let (host_rc, host_errno) = call_host_close_range(first, last, flags);
    assert_equivalent("close_range", abi_rc, abi_errno, host_rc, host_errno);
}

fn fuzz_eventfd_write(input: &ErrnoPrecedenceInput) {
    let mode = input.dirfd_bits % 4;
    let Some(setup) = eventfd_fd_setup(mode) else {
        return;
    };
    let value = eventfd_value(input.value, input.flag_bits);
    if mode == 3 {
        assert_eq!(
            unsafe { libc::eventfd_write(setup.host_fd, u64::MAX - 1) },
            0
        );
        assert_eq!(
            unsafe { libc::eventfd_write(setup.abi_fd, u64::MAX - 1) },
            0
        );
    }

    let (abi_rc, abi_errno) = call_abi_eventfd_write(setup.abi_fd, value);
    let (host_rc, host_errno) = call_host_eventfd_write(setup.host_fd, value);
    assert_equivalent("eventfd_write", abi_rc, abi_errno, host_rc, host_errno);

    cleanup_setup_fds(&setup);
}

fn fuzz_fsconfig(input: &ErrnoPrecedenceInput) {
    let fs_fd = match input.dirfd_bits % 2 {
        0 => -1,
        _ => 0x3fff,
    };
    let cmd = fsconfig_cmd(input.command_bits);
    let null_key = input.null_bits & 0b0010 != 0;
    let null_value = input.null_bits & 0b0100 != 0;
    let key = sanitize_cstring(&input.key, b"k");
    let payload = sanitize_cstring(&input.payload, b"v");

    let key_ptr = if null_key { ptr::null() } else { key.as_ptr() };
    let value_ptr = if null_value {
        ptr::null()
    } else {
        payload.as_ptr().cast::<libc::c_void>()
    };

    let (abi_rc, abi_errno) = call_abi_fsconfig(fs_fd, cmd, key_ptr, value_ptr, input.aux);
    let (host_rc, host_errno) = call_host_fsconfig(fs_fd, cmd, key_ptr, value_ptr, input.aux);
    assert_equivalent("fsconfig", abi_rc, abi_errno, host_rc, host_errno);
}

fn build_rename_case(case_id: u64, dirfd_bits: u8, path_bits: u8) -> Option<RenameCase> {
    let base = temp_root().join(format!("errno-precedence-{case_id}"));
    let abi_root = base.join("abi");
    let host_root = base.join("host");
    let abi_work = abi_root.join("work");
    let host_work = host_root.join("work");

    fs::create_dir_all(&abi_work).ok()?;
    fs::create_dir_all(&host_work).ok()?;
    fs::write(abi_work.join("old"), b"old").ok()?;
    fs::write(host_work.join("old"), b"old").ok()?;
    fs::write(abi_work.join("new"), b"new").ok()?;
    fs::write(host_work.join("new"), b"new").ok()?;
    fs::create_dir_all(abi_work.join("dir")).ok()?;
    fs::create_dir_all(host_work.join("dir")).ok()?;

    let olddirfd_mode = dirfd_bits % 3;
    let newdirfd_mode = (dirfd_bits / 3) % 3;
    let oldpath_mode = path_bits % 6;
    let newpath_mode = (path_bits / 6) % 6;

    let olddirfd_abi = open_dirfd_for_mode(&abi_work, olddirfd_mode)?;
    let olddirfd_host = open_dirfd_for_mode(&host_work, olddirfd_mode)?;
    let newdirfd_abi = open_dirfd_for_mode(&abi_work, newdirfd_mode)?;
    let newdirfd_host = open_dirfd_for_mode(&host_work, newdirfd_mode)?;

    let oldpath_abi = rename_path_for_mode(&abi_work, oldpath_mode, olddirfd_mode, b"old")?;
    let oldpath_host = rename_path_for_mode(&host_work, oldpath_mode, olddirfd_mode, b"old")?;
    let newpath_abi = rename_path_for_mode(&abi_work, newpath_mode, newdirfd_mode, b"new")?;
    let newpath_host = rename_path_for_mode(&host_work, newpath_mode, newdirfd_mode, b"new")?;

    Some(RenameCase {
        olddirfd_abi,
        newdirfd_abi,
        olddirfd_host,
        newdirfd_host,
        oldpath_abi,
        newpath_abi,
        oldpath_host,
        newpath_host,
        cleanup_roots: vec![base],
    })
}

fn temp_root() -> &'static PathBuf {
    TEMP_ROOT.get_or_init(|| {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-fuzz-errno-precedence-{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create errno-precedence fuzz root");
        path
    })
}

fn open_dirfd_for_mode(work: &Path, mode: u8) -> Option<libc::c_int> {
    match mode {
        0 => Some(libc::AT_FDCWD),
        1 => {
            let bytes = work.as_os_str().as_bytes();
            let path = CString::new(bytes).ok()?;
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            (fd >= 0).then_some(fd)
        }
        _ => Some(-1),
    }
}

fn rename_path_for_mode(
    work: &Path,
    mode: u8,
    dirfd_mode: u8,
    existing_name: &[u8],
) -> Option<Option<CString>> {
    let relative_mode = dirfd_mode != 0;
    let cstr = match mode {
        0 => return Some(None),
        1 => CString::new(Vec::<u8>::new()).ok()?,
        2 => CString::new(".").ok()?,
        3 => named_path_cstring(work, existing_name, relative_mode)?,
        4 => named_path_cstring(work, b"missing", relative_mode)?,
        _ => named_path_cstring(work, b"dir", relative_mode)?,
    };
    Some(Some(cstr))
}

fn named_path_cstring(work: &Path, name: &[u8], relative_mode: bool) -> Option<CString> {
    if relative_mode {
        CString::new(name.to_vec()).ok()
    } else {
        let path = work.join(OsStr::from_bytes(name));
        CString::new(path.as_os_str().as_bytes()).ok()
    }
}

fn rename_flags(bits: u32) -> libc::c_uint {
    let mut flags = 0_u32;
    if bits & 0b0001 != 0 {
        flags |= libc::RENAME_NOREPLACE;
    }
    if bits & 0b0010 != 0 {
        flags |= libc::RENAME_EXCHANGE;
    }
    if bits & 0b0100 != 0 {
        flags |= 0x8000_0000;
    }
    flags
}

fn signalfd_flags(bits: u32) -> libc::c_int {
    let mut flags = 0_i32;
    if bits & 0b0001 != 0 {
        flags |= libc::SFD_CLOEXEC;
    }
    if bits & 0b0010 != 0 {
        flags |= libc::SFD_NONBLOCK;
    }
    if bits & 0b0100 != 0 {
        flags |= 0x4000_0000_u32 as i32;
    }
    flags
}

fn signalfd_fd_setup(
    mode: u8,
    mask_word: u64,
) -> Option<(FdSetup, Option<libc::c_int>, Option<libc::c_int>)> {
    match mode {
        0 => Some((
            FdSetup {
                abi_fd: -1,
                host_fd: -1,
                close_abi_fd: false,
                close_host_fd: false,
            },
            None,
            None,
        )),
        1 => Some((
            FdSetup {
                abi_fd: 0x3fff,
                host_fd: 0x3fff,
                close_abi_fd: false,
                close_host_fd: false,
            },
            None,
            None,
        )),
        _ => {
            let abi_fd = create_signalfd(mask_word)?;
            let host_fd = create_signalfd(mask_word)?;
            Some((
                FdSetup {
                    abi_fd,
                    host_fd,
                    close_abi_fd: true,
                    close_host_fd: true,
                },
                Some(abi_fd),
                Some(host_fd),
            ))
        }
    }
}

fn create_signalfd(mask_word: u64) -> Option<libc::c_int> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_signalfd4,
            -1,
            (&mask_word as *const u64).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
            libc::SFD_CLOEXEC,
        ) as libc::c_int
    };
    (rc >= 0).then_some(rc)
}

fn close_range_flags(bits: u32) -> libc::c_uint {
    let mut flags = 0_u32;
    if bits & 0b0001 != 0 {
        flags |= libc::CLOSE_RANGE_CLOEXEC;
    }
    if bits & 0b0010 != 0 {
        flags |= libc::CLOSE_RANGE_UNSHARE;
    }
    if bits & 0b0100 != 0 {
        flags |= 0x8000_0000;
    }
    flags
}

fn eventfd_fd_setup(mode: u8) -> Option<FdSetup> {
    match mode {
        0 => Some(FdSetup {
            abi_fd: -1,
            host_fd: -1,
            close_abi_fd: false,
            close_host_fd: false,
        }),
        1 => Some(FdSetup {
            abi_fd: 0x3fff,
            host_fd: 0x3fff,
            close_abi_fd: false,
            close_host_fd: false,
        }),
        2 => {
            let abi_fd = unsafe { libc::eventfd(0, 0) };
            let host_fd = unsafe { libc::eventfd(0, 0) };
            if abi_fd < 0 || host_fd < 0 {
                cleanup_fd(abi_fd);
                cleanup_fd(host_fd);
                return None;
            }
            Some(FdSetup {
                abi_fd,
                host_fd,
                close_abi_fd: true,
                close_host_fd: true,
            })
        }
        _ => {
            let abi_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
            let host_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
            if abi_fd < 0 || host_fd < 0 {
                cleanup_fd(abi_fd);
                cleanup_fd(host_fd);
                return None;
            }
            Some(FdSetup {
                abi_fd,
                host_fd,
                close_abi_fd: true,
                close_host_fd: true,
            })
        }
    }
}

fn eventfd_value(raw: u64, bits: u32) -> u64 {
    match bits & 0b11 {
        0 => 0,
        1 => 1,
        2 => u64::MAX,
        _ => raw,
    }
}

fn fsconfig_cmd(bits: u8) -> libc::c_uint {
    match bits % 4 {
        0 => FSCONFIG_SET_FLAG_CMD,
        1 => FSCONFIG_SET_STRING_CMD,
        2 => 0x8000_0000,
        _ => u32::from(bits),
    }
}

fn sanitize_cstring(bytes: &[u8], fallback: &[u8]) -> CString {
    let mut sanitized = Vec::with_capacity(bytes.len().min(16).max(fallback.len()));
    for &byte in bytes.iter().take(16) {
        sanitized.push(if byte == 0 { b'_' } else { byte });
    }
    if sanitized.is_empty() {
        sanitized.extend_from_slice(fallback);
    }
    CString::new(sanitized).expect("sanitized bytes must be NUL-free")
}

fn assert_equivalent(
    op: &str,
    abi_rc: libc::c_int,
    abi_errno: libc::c_int,
    host_rc: libc::c_int,
    host_errno: libc::c_int,
) {
    assert_eq!(
        abi_rc >= 0,
        host_rc >= 0,
        "{op} success divergence: abi_rc={abi_rc} abi_errno={abi_errno} host_rc={host_rc} host_errno={host_errno}"
    );
    if abi_rc < 0 && host_rc < 0 {
        assert_eq!(
            abi_errno, host_errno,
            "{op} errno divergence: abi_errno={abi_errno} host_errno={host_errno}"
        );
    }
}

fn call_abi_renameat2(
    olddirfd: libc::c_int,
    oldpath: *const libc::c_char,
    newdirfd: libc::c_int,
    newpath: *const libc::c_char,
    flags: libc::c_uint,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = unsafe {
        frankenlibc_abi::unistd_abi::renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
    };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host_renameat2(
    olddirfd: libc::c_int,
    oldpath: *const libc::c_char,
    newdirfd: libc::c_int,
    newpath: *const libc::c_char,
    flags: libc::c_uint,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags as libc::c_ulong,
        ) as libc::c_int
    };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn call_abi_signalfd4(
    fd: libc::c_int,
    mask: *const libc::c_void,
    flags: libc::c_int,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = unsafe { frankenlibc_abi::unistd_abi::signalfd4(fd, mask, flags) };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host_signalfd4(
    fd: libc::c_int,
    mask: *const libc::c_void,
    flags: libc::c_int,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_signalfd4,
            fd,
            mask,
            std::mem::size_of::<u64>(),
            flags,
        ) as libc::c_int
    };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn call_abi_close_range(first: u32, last: u32, flags: libc::c_uint) -> (libc::c_int, libc::c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = unsafe { frankenlibc_abi::unistd_abi::close_range(first, last, flags) };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host_close_range(first: u32, last: u32, flags: libc::c_uint) -> (libc::c_int, libc::c_int) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            first as libc::c_ulong,
            last as libc::c_ulong,
            flags as libc::c_ulong,
        ) as libc::c_int
    };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn call_abi_eventfd_write(fd: libc::c_int, value: u64) -> (libc::c_int, libc::c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = unsafe { frankenlibc_abi::unistd_abi::eventfd_write(fd, value) };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host_eventfd_write(fd: libc::c_int, value: u64) -> (libc::c_int, libc::c_int) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = unsafe { libc::eventfd_write(fd, value) };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn call_abi_fsconfig(
    fs_fd: libc::c_int,
    cmd: libc::c_uint,
    key: *const libc::c_char,
    value: *const libc::c_void,
    aux: libc::c_int,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = unsafe { frankenlibc_abi::unistd_abi::fsconfig(fs_fd, cmd, key, value, aux) };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host_fsconfig(
    fs_fd: libc::c_int,
    cmd: libc::c_uint,
    key: *const libc::c_char,
    value: *const libc::c_void,
    aux: libc::c_int,
) -> (libc::c_int, libc::c_int) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd,
            cmd as libc::c_uint,
            key,
            value,
            aux,
        ) as libc::c_int
    };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn cleanup_setup_fds(setup: &FdSetup) {
    if setup.close_abi_fd {
        cleanup_fd(setup.abi_fd);
    }
    if setup.close_host_fd {
        cleanup_fd(setup.host_fd);
    }
}

fn cleanup_rename_case(case: &RenameCase) {
    cleanup_fd(case.olddirfd_abi);
    cleanup_fd(case.newdirfd_abi);
    cleanup_fd(case.olddirfd_host);
    cleanup_fd(case.newdirfd_host);
    cleanup_roots(&case.cleanup_roots);
}

fn cleanup_optional_fd(rc: libc::c_int, original: Option<libc::c_int>) {
    if rc < 0 {
        return;
    }
    if original.is_some_and(|fd| fd == rc) {
        return;
    }
    cleanup_fd(rc);
}

fn cleanup_fd(fd: libc::c_int) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn cleanup_roots(paths: &[PathBuf]) {
    for path in paths {
        let _ = fs::remove_dir_all(path);
    }
}
