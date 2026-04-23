#![no_main]
//! Differential + crash-detector fuzz target for FrankenLibC open-family syscalls.
//!
//! Exercises `open`, `openat`, and `creat` across path classes, flag mixes,
//! and directory-fd routing. The target compares FrankenLibC against host libc
//! on mirrored filesystem state and enforces the no-panic / errno-contract
//! invariants for every call.
//!
//! Bead: bd-o4yda

use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct OpenFuzzInput {
    path: Vec<u8>,
    flags: i32,
    mode: u16,
    op: u8,
    path_case: u8,
    at_fd_kind: u8,
    null_path: bool,
}

struct TestRoots {
    ours_root: PathBuf,
    host_root: PathBuf,
    ours_work: PathBuf,
    host_work: PathBuf,
    ours_work_fd: i32,
    host_work_fd: i32,
}

struct CasePaths {
    ours_absolute: Option<CString>,
    host_absolute: Option<CString>,
    ours_relative: Option<CString>,
    host_relative: Option<CString>,
    cleanup_paths: Vec<(PathBuf, bool)>,
}

static TEST_ROOTS: OnceLock<TestRoots> = OnceLock::new();
static CASE_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_PATH_BYTES: usize = 256;
const PATH_EXISTING: u8 = 0;
const PATH_MISSING: u8 = 1;
const PATH_DIRECTORY: u8 = 2;
const PATH_PARENT_ESCAPE: u8 = 3;
const PATH_DEV_NULL: u8 = 4;
const PATH_RAW_COMPONENT: u8 = 5;
const PATH_EMPTY: u8 = 6;

const ATFD_CWD: u8 = 0;
const ATFD_WORK_DIR: u8 = 1;
const ATFD_BAD_FD: u8 = 2;

const OP_OPEN: u8 = 0;
const OP_OPENAT: u8 = 1;
const OP_CREAT: u8 = 2;

const ALLOWED_ERRNOS: &[i32] = &[
    libc::EACCES,
    libc::EBADF,
    libc::EEXIST,
    libc::EFAULT,
    libc::EINVAL,
    libc::EISDIR,
    libc::ELOOP,
    libc::EMFILE,
    libc::ENAMETOOLONG,
    libc::ENFILE,
    libc::ENOENT,
    libc::ENOMEM,
    libc::ENOSPC,
    libc::ENOTDIR,
    libc::EPERM,
    libc::EROFS,
];

fuzz_target!(|input: OpenFuzzInput| {
    if input.path.len() > MAX_PATH_BYTES {
        return;
    }

    let roots = test_roots();
    let case_id = CASE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mode = libc::mode_t::from(input.mode & 0o7777);
    let flags = normalize_flags(input.flags);
    let op = input.op % 3;
    let path_case = input.path_case % 7;
    let at_fd_kind = input.at_fd_kind % 3;

    let Some(paths) = build_case_paths(roots, case_id, path_case, &input.path) else {
        return;
    };

    let compare_host = !input.null_path;
    let use_relative =
        op == OP_OPENAT && at_fd_kind != ATFD_CWD && path_case != PATH_DEV_NULL && !input.null_path;

    let ours_path = if input.null_path {
        std::ptr::null()
    } else if use_relative {
        match paths.ours_relative.as_ref() {
            Some(path) => path.as_ptr(),
            None => return,
        }
    } else {
        match paths.ours_absolute.as_ref() {
            Some(path) => path.as_ptr(),
            None => return,
        }
    };

    let host_path = if use_relative {
        match paths.host_relative.as_ref() {
            Some(path) => path.as_ptr(),
            None => return,
        }
    } else {
        match paths.host_absolute.as_ref() {
            Some(path) => path.as_ptr(),
            None => return,
        }
    };

    let ours_dirfd = match at_fd_kind {
        ATFD_CWD => libc::AT_FDCWD,
        ATFD_WORK_DIR => roots.ours_work_fd,
        ATFD_BAD_FD => -1,
        _ => libc::AT_FDCWD,
    };
    let host_dirfd = match at_fd_kind {
        ATFD_CWD => libc::AT_FDCWD,
        ATFD_WORK_DIR => roots.host_work_fd,
        ATFD_BAD_FD => -1,
        _ => libc::AT_FDCWD,
    };

    let (our_rc, our_errno) = call_abi(op, ours_dirfd, ours_path, flags, mode);
    assert!(
        our_rc >= 0 || ALLOWED_ERRNOS.contains(&our_errno),
        "unexpected errno {our_errno} for op={op} flags={flags:#x} path_case={path_case} at_fd_kind={at_fd_kind}",
    );
    if our_rc >= 0 {
        close_fd(our_rc);
    }

    if compare_host {
        let (host_rc, host_errno) = call_host(op, host_dirfd, host_path, flags, mode);
        if host_rc >= 0 {
            close_fd(host_rc);
        }
        assert_eq!(
            our_rc >= 0,
            host_rc >= 0,
            "success divergence op={op} flags={flags:#x} path_case={path_case} at_fd_kind={at_fd_kind} abi_errno={our_errno} host_errno={host_errno}",
        );
        if our_rc < 0 && host_rc < 0 {
            assert_eq!(
                our_errno, host_errno,
                "errno divergence op={op} flags={flags:#x} path_case={path_case} at_fd_kind={at_fd_kind}",
            );
        }
    }

    cleanup_case(&paths.cleanup_paths);
});

fn test_roots() -> &'static TestRoots {
    TEST_ROOTS.get_or_init(|| {
        let base =
            std::env::temp_dir().join(format!("frankenlibc-fuzz-open-{}", std::process::id()));
        let ours_root = base.join("ours");
        let host_root = base.join("host");
        let ours_work = ours_root.join("work");
        let host_work = host_root.join("work");

        fs::create_dir_all(&ours_work).expect("create ours fuzz root");
        fs::create_dir_all(&host_work).expect("create host fuzz root");

        let ours_work_fd = open_directory_fd(&ours_work);
        let host_work_fd = open_directory_fd(&host_work);

        TestRoots {
            ours_root,
            host_root,
            ours_work,
            host_work,
            ours_work_fd,
            host_work_fd,
        }
    })
}

fn open_directory_fd(path: &Path) -> i32 {
    let bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(bytes).expect("directory path must be NUL-free");
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(fd >= 0, "failed to open fuzz root directory");
    fd
}

fn normalize_flags(raw: i32) -> i32 {
    let access_mode = match raw & libc::O_ACCMODE {
        libc::O_WRONLY => libc::O_WRONLY,
        libc::O_RDWR => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };
    let mut flags = access_mode;
    let valid_mask = libc::O_APPEND
        | libc::O_CLOEXEC
        | libc::O_CREAT
        | libc::O_DIRECTORY
        | libc::O_EXCL
        | libc::O_NOCTTY
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | libc::O_SYNC
        | libc::O_TRUNC;
    #[cfg(target_os = "linux")]
    let valid_mask = valid_mask | libc::O_DSYNC;
    flags |= raw & valid_mask;
    flags
}

fn build_case_paths(
    roots: &TestRoots,
    case_id: u64,
    path_case: u8,
    raw_path: &[u8],
) -> Option<CasePaths> {
    match path_case {
        PATH_EXISTING => build_named_case(roots, named_bytes(b"existing", case_id), |path| {
            fs::write(path, b"seed").ok()?;
            Some(true)
        }),
        PATH_MISSING => build_named_case(roots, named_bytes(b"missing", case_id), |_| Some(false)),
        PATH_DIRECTORY => build_named_case(roots, named_bytes(b"dir", case_id), |path| {
            fs::create_dir_all(path).ok()?;
            Some(false)
        }),
        PATH_PARENT_ESCAPE => build_parent_escape_case(roots, case_id),
        PATH_DEV_NULL => Some(CasePaths {
            ours_absolute: Some(CString::new("/dev/null").expect("literal has no NUL")),
            host_absolute: Some(CString::new("/dev/null").expect("literal has no NUL")),
            ours_relative: None,
            host_relative: None,
            cleanup_paths: Vec::new(),
        }),
        PATH_RAW_COMPONENT => {
            let component = raw_component(raw_path, case_id)?;
            build_named_case(roots, component, |_| Some(false))
        }
        PATH_EMPTY => Some(CasePaths {
            ours_absolute: Some(CString::new(Vec::<u8>::new()).expect("empty CString is valid")),
            host_absolute: Some(CString::new(Vec::<u8>::new()).expect("empty CString is valid")),
            ours_relative: Some(CString::new(Vec::<u8>::new()).expect("empty CString is valid")),
            host_relative: Some(CString::new(Vec::<u8>::new()).expect("empty CString is valid")),
            cleanup_paths: Vec::new(),
        }),
        _ => None,
    }
}

fn build_named_case<F>(roots: &TestRoots, name_bytes: Vec<u8>, setup: F) -> Option<CasePaths>
where
    F: Fn(&Path) -> Option<bool>,
{
    let name = OsStr::from_bytes(&name_bytes);

    let ours_path = roots.ours_work.join(name);
    let host_path = roots.host_work.join(name);

    let ours_is_file = setup(&ours_path)?;
    let host_is_file = setup(&host_path)?;

    let relative = CString::new(name_bytes).ok()?;
    let ours_absolute = CString::new(ours_path.as_os_str().as_bytes()).ok()?;
    let host_absolute = CString::new(host_path.as_os_str().as_bytes()).ok()?;

    let cleanup_paths = vec![(ours_path, ours_is_file), (host_path, host_is_file)];
    Some(CasePaths {
        ours_absolute: Some(ours_absolute),
        host_absolute: Some(host_absolute),
        ours_relative: Some(relative.clone()),
        host_relative: Some(relative),
        cleanup_paths,
    })
}

fn build_parent_escape_case(roots: &TestRoots, case_id: u64) -> Option<CasePaths> {
    let file_name = format!("outside_{case_id}");
    let ours_path = roots.ours_root.join(&file_name);
    let host_path = roots.host_root.join(&file_name);
    fs::write(&ours_path, b"outside").ok()?;
    fs::write(&host_path, b"outside").ok()?;

    let relative = CString::new(format!("../{file_name}").into_bytes()).ok()?;
    let ours_absolute = CString::new(ours_path.as_os_str().as_bytes()).ok()?;
    let host_absolute = CString::new(host_path.as_os_str().as_bytes()).ok()?;

    Some(CasePaths {
        ours_absolute: Some(ours_absolute),
        host_absolute: Some(host_absolute),
        ours_relative: Some(relative.clone()),
        host_relative: Some(relative),
        cleanup_paths: vec![(ours_path, true), (host_path, true)],
    })
}

fn raw_component(raw: &[u8], case_id: u64) -> Option<Vec<u8>> {
    if raw.iter().any(|&byte| byte == 0) {
        return None;
    }
    let mut component = Vec::with_capacity(raw.len().min(64) + 24);
    for &byte in raw.iter().take(64) {
        component.push(if byte == b'/' { b'_' } else { byte });
    }
    if component.is_empty() {
        component.extend_from_slice(b"raw");
    }
    component.extend_from_slice(format!("_{case_id}").as_bytes());
    Some(component)
}

fn named_bytes(prefix: &[u8], case_id: u64) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(format!("_{case_id}").as_bytes());
    bytes
}

fn cleanup_case(paths: &[(PathBuf, bool)]) {
    for (path, is_file) in paths {
        let _ = if *is_file {
            fs::remove_file(path)
        } else {
            fs::remove_dir_all(path)
        };
    }
}

fn call_abi(
    op: u8,
    dirfd: i32,
    path: *const libc::c_char,
    flags: i32,
    mode: libc::mode_t,
) -> (i32, i32) {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let rc = match op {
        OP_OPEN => unsafe { frankenlibc_abi::unistd_abi::open(path, flags, mode) },
        OP_OPENAT => unsafe { frankenlibc_abi::unistd_abi::openat(dirfd, path, flags, mode) },
        OP_CREAT => unsafe { frankenlibc_abi::unistd_abi::creat(path, mode) },
        _ => return (-1, libc::EINVAL),
    };
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    (rc, errno)
}

fn call_host(
    op: u8,
    dirfd: i32,
    path: *const libc::c_char,
    flags: i32,
    mode: libc::mode_t,
) -> (i32, i32) {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let rc = match op {
        OP_OPEN => unsafe { libc::open(path, flags, mode) },
        OP_OPENAT => unsafe { libc::openat(dirfd, path, flags, mode) },
        OP_CREAT => unsafe { libc::creat(path, mode) },
        _ => return (-1, libc::EINVAL),
    };
    let errno = unsafe { *libc::__errno_location() };
    (rc, errno)
}

fn close_fd(fd: i32) {
    let rc = unsafe { libc::close(fd) };
    assert_eq!(rc, 0, "close({fd}) failed");
}
