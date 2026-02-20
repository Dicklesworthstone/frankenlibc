#![cfg(target_os = "linux")]

//! Integration tests for `<stdlib.h>` ABI entrypoints.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::stdlib_abi::{
    atoll, clearenv, getenv, mkostemp, mkostemps, mkstemps, reallocarray, setenv, strtold, strtoll,
    strtoull,
};
use frankenlibc_abi::unistd_abi::{
    confstr, creat64, ctermid, ether_aton, ether_aton_r, ether_ntoa, ether_ntoa_r, fpathconf,
    fstat64, fstatat64, ftruncate64, get_avphys_pages, get_nprocs, get_nprocs_conf, get_phys_pages,
    getdomainname, gethostid, getlogin, getlogin_r, getopt, getopt_long, getpagesize, grantpt,
    herror, hstrerror, lockf, lseek64, lstat64, mkdtemp, mq_close, mq_getattr, mq_open, mq_receive,
    mq_send, mq_setattr, mq_unlink, msgctl, msgget, msgrcv, msgsnd, nice, open64, pathconf,
    posix_fallocate, posix_madvise, posix_openpt, pread64, ptsname, pwrite64,
    sched_get_priority_max, sched_get_priority_min, sched_getparam, sched_getscheduler,
    sched_rr_get_interval, sched_setparam, sched_setscheduler, semctl, semget, semop,
    setdomainname, sethostname, shm_open, shm_unlink, shmat, shmctl, shmdt, shmget, sigqueue,
    sigtimedwait, sigwaitinfo, stat64, sysconf, timer_create, timer_delete, timer_getoverrun,
    timer_gettime, timer_settime, truncate64, ttyname, ttyname_r, unlockpt,
};
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

unsafe extern "C" {
    #[link_name = "optarg"]
    static mut OPTARG_TEST: *mut libc::c_char;
    #[link_name = "optind"]
    static mut OPTIND_TEST: libc::c_int;
    #[link_name = "opterr"]
    static mut OPTERR_TEST: libc::c_int;
    #[link_name = "optopt"]
    static mut OPTOPT_TEST: libc::c_int;

    fn __h_errno_location() -> *mut libc::c_int;
}

unsafe fn reset_getopt_globals() {
    unsafe {
        OPTARG_TEST = ptr::null_mut();
        OPTIND_TEST = 1;
        OPTERR_TEST = 0;
        OPTOPT_TEST = 0;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SysvMsg {
    mtype: libc::c_long,
    mtext: [u8; 64],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EtherAddr {
    octet: [u8; 6],
}

static SHM_NAME_NONCE: AtomicU64 = AtomicU64::new(1);
static MQ_NAME_NONCE: AtomicU64 = AtomicU64::new(1);

fn unique_shm_name(prefix: &str) -> CString {
    let n = SHM_NAME_NONCE.fetch_add(1, Ordering::Relaxed);
    CString::new(format!("/{prefix}-{}-{n}", std::process::id())).expect("valid shm name")
}

fn unique_mq_name(prefix: &str) -> CString {
    let n = MQ_NAME_NONCE.fetch_add(1, Ordering::Relaxed);
    CString::new(format!("/{prefix}-{}-{n}", std::process::id())).expect("valid mq name")
}

fn open_test_timer() -> Option<*mut libc::c_void> {
    let mut timer_id: *mut libc::c_void = ptr::null_mut();
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }

    // SAFETY: timer_create accepts a null sigevent pointer and a writable timer-id output.
    let rc = unsafe {
        timer_create(
            libc::CLOCK_MONOTONIC,
            ptr::null_mut(),
            (&mut timer_id as *mut *mut libc::c_void).cast(),
        )
    };
    if rc == 0 {
        return Some(timer_id);
    }

    // SAFETY: read errno after call.
    let err = unsafe { *__errno_location() };
    if matches!(
        err,
        libc::ENOSYS | libc::EPERM | libc::EACCES | libc::ENOTSUP
    ) {
        return None;
    }

    panic!("timer_create failed unexpectedly with errno={err}");
}

#[test]
fn atoll_parses_i64_limits() {
    // SAFETY: both pointers reference static NUL-terminated C strings.
    let max = unsafe { atoll(c"9223372036854775807".as_ptr()) };
    // SAFETY: both pointers reference static NUL-terminated C strings.
    let min = unsafe { atoll(c"-9223372036854775808".as_ptr()) };

    assert_eq!(max, i64::MAX);
    assert_eq!(min, i64::MIN);
}

#[test]
fn strtoll_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtoll(c"123x".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, 123);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"123x".as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn strtoull_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtoull(c"18446744073709551615!".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, u64::MAX);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"18446744073709551615!".as_ptr()) };
    assert_eq!(offset, 20);
}

#[test]
fn reallocarray_allocates_and_can_reallocate() {
    // SAFETY: null + valid size requests a fresh allocation.
    let ptr = unsafe { reallocarray(ptr::null_mut(), 4, 16) } as *mut u8;
    assert!(!ptr.is_null());

    // SAFETY: allocation is at least 64 bytes as requested.
    unsafe {
        for i in 0..64 {
            *ptr.add(i) = i as u8;
        }
    }

    // SAFETY: pointer came from reallocarray and requested larger valid size.
    let grown = unsafe { reallocarray(ptr.cast(), 8, 16) } as *mut u8;
    assert!(!grown.is_null());

    // SAFETY: realloc preserves prefix bytes of the old allocation.
    unsafe {
        for i in 0..64 {
            assert_eq!(*grown.add(i), i as u8);
        }
        libc::free(grown.cast());
    }
}

#[test]
fn reallocarray_overflow_sets_enomem() {
    // SAFETY: __errno_location points to this thread's errno.
    unsafe {
        *__errno_location() = 0;
    }

    // SAFETY: null pointer with overflowing product should fail with ENOMEM.
    let out = unsafe { reallocarray(ptr::null_mut(), usize::MAX, 2) };
    assert!(out.is_null());

    // SAFETY: read thread-local errno after call.
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::ENOMEM);
}

#[test]
fn strtold_sets_endptr_to_first_unparsed_byte() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtold(c"12.5x".as_ptr(), &mut endptr) };
    assert!((value - 12.5).abs() < f64::EPSILON);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"12.5x".as_ptr()) };
    assert_eq!(offset, 4);
}

#[test]
fn clearenv_removes_newly_set_variable() {
    let name = c"FRANKENLIBC_CLEAR_TEST_VAR";
    let value = c"present";

    // SAFETY: pointers are valid NUL-terminated C strings.
    assert_eq!(unsafe { setenv(name.as_ptr(), value.as_ptr(), 1) }, 0);
    // SAFETY: pointer is a valid NUL-terminated C string.
    assert!(!unsafe { getenv(name.as_ptr()) }.is_null());

    // SAFETY: clearenv has no pointer parameters.
    assert_eq!(unsafe { clearenv() }, 0);

    // SAFETY: pointer is a valid NUL-terminated C string.
    assert!(unsafe { getenv(name.as_ptr()) }.is_null());
}

fn temp_template(prefix: &str, suffix: &str) -> Vec<u8> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    format!("/tmp/frankenlibc-{prefix}-{stamp}-XXXXXX{suffix}\0").into_bytes()
}

const LOCKF_ULOCK: i32 = 0;
const LOCKF_TLOCK: i32 = 2;
const LOCKF_TEST: i32 = 3;

#[test]
fn mkostemp_creates_unique_file_and_honors_cloexec() {
    let mut template = temp_template("mkostemp", "");

    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe { mkostemp(template.as_mut_ptr().cast(), libc::O_CLOEXEC) };
    assert!(fd >= 0);

    // SAFETY: template remains a valid NUL-terminated string after mkostemp.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.contains("XXXXXX"));

    // SAFETY: fd is valid from mkostemp success path.
    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(fd_flags >= 0);
    assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);

    // SAFETY: close the descriptor we just opened.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn mkstemps_preserves_suffix_and_replaces_pattern() {
    let suffix = ".txt";
    let mut template = temp_template("mkstemps", suffix);

    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe { mkstemps(template.as_mut_ptr().cast(), suffix.len() as i32) };
    assert!(fd >= 0);

    // SAFETY: template remains a valid NUL-terminated string after mkstemps.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(path.ends_with(suffix));
    let stem = &path[..path.len() - suffix.len()];
    assert!(!stem.contains("XXXXXX"));

    // SAFETY: close the descriptor we just opened.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn mkostemps_rejects_invalid_flag_bits() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    let mut template = temp_template("mkostemps-invalid", ".bin");

    // O_TRUNC is not accepted by mkostemps flag contract in this implementation.
    // SAFETY: template is writable and NUL-terminated.
    let fd = unsafe {
        mkostemps(
            template.as_mut_ptr().cast(),
            4,
            libc::O_CLOEXEC | libc::O_TRUNC,
        )
    };
    assert_eq!(fd, -1);

    // SAFETY: read thread-local errno after call.
    let err = unsafe { *__errno_location() };
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn mkdtemp_creates_directory_and_rewrites_suffix() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    let mut template = format!("/tmp/frankenlibc-mkdtemp-{stamp}-XXXXXX\0").into_bytes();

    // SAFETY: template is writable and NUL-terminated.
    let out = unsafe { mkdtemp(template.as_mut_ptr().cast()) };
    assert!(!out.is_null());

    // SAFETY: mkdtemp rewrites template in place as a valid C string.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    assert!(!path.ends_with("XXXXXX"));

    let meta = std::fs::metadata(&path).expect("mkdtemp should create directory");
    assert!(meta.is_dir());
    let _ = std::fs::remove_dir(path);
}

#[test]
fn lockf_tlock_test_and_unlock_roundtrip() {
    let template = temp_template("lockf", ".tmp");
    // SAFETY: template is NUL-terminated by construction.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("create temp file for lockf");
    let fd = file.as_raw_fd();

    // SAFETY: fd is a valid open descriptor.
    assert_eq!(unsafe { lockf(fd, LOCKF_TLOCK, 0) }, 0);
    // SAFETY: fd is valid and uses same lock region.
    assert_eq!(unsafe { lockf(fd, LOCKF_TEST, 0) }, 0);
    // SAFETY: fd is valid and unlocks the same region.
    assert_eq!(unsafe { lockf(fd, LOCKF_ULOCK, 0) }, 0);

    drop(file);
    let _ = std::fs::remove_file(path);
}

#[test]
fn posix_fallocate_validates_negative_ranges() {
    let template = temp_template("posix-fallocate", ".tmp");
    // SAFETY: template is NUL-terminated by construction.
    let path = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("create temp file for posix_fallocate");
    let fd = file.as_raw_fd();

    // SAFETY: fd is valid; negative offset/len are invalid by contract.
    assert_eq!(unsafe { posix_fallocate(fd, -1, 16) }, libc::EINVAL);
    // SAFETY: fd is valid; negative offset/len are invalid by contract.
    assert_eq!(unsafe { posix_fallocate(fd, 0, -1) }, libc::EINVAL);
    drop(file);
    let _ = std::fs::remove_file(path);
}

#[test]
fn posix_madvise_returns_error_code_without_touching_errno() {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    assert!(page_size > 0);

    // SAFETY: request anonymous private mapping for one page.
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);

    // SAFETY: set and then read thread-local errno around a posix_madvise call.
    unsafe {
        *__errno_location() = 0;
    }

    // POSIX madvise returns error codes directly and should not modify errno.
    // SAFETY: mapped range is valid; advice intentionally invalid.
    let invalid_rc = unsafe { posix_madvise(mapping, page_size, 0x7fff) };
    assert_eq!(invalid_rc, libc::EINVAL);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, 0);

    // SAFETY: mapped range is valid; advice value 0 maps to NORMAL behavior.
    assert_eq!(unsafe { posix_madvise(mapping, page_size, 0) }, 0);

    // SAFETY: unmap the mapping allocated above.
    assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
}

#[test]
fn confstr_path_reports_required_length_and_copies_value() {
    // SAFETY: read-only query with null destination is valid.
    let needed = unsafe { confstr(libc::_CS_PATH, ptr::null_mut(), 0) };
    assert!(needed >= 2);

    let mut buf = vec![0_i8; needed];
    // SAFETY: destination buffer is writable and size matches call contract.
    let returned = unsafe { confstr(libc::_CS_PATH, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(returned, needed);

    // SAFETY: confstr writes a C string for _CS_PATH.
    let value = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert!(value.contains("/bin"));
}

#[test]
fn confstr_rejects_unknown_name_with_einval() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }

    let mut buf = [0_i8; 16];
    // SAFETY: destination buffer is writable.
    let rc = unsafe { confstr(-1, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}

#[test]
fn pathconf_and_fpathconf_validate_inputs() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null path is invalid.
    assert_eq!(unsafe { pathconf(ptr::null(), libc::_PC_PATH_MAX) }, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);

    let path = c"/tmp";
    // SAFETY: valid NUL-terminated path literal.
    let path_max = unsafe { pathconf(path.as_ptr(), libc::_PC_PATH_MAX) };
    assert!(path_max > 0);

    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: bad fd should fail.
    assert_eq!(unsafe { fpathconf(-1, libc::_PC_PATH_MAX) }, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EBADF);
}

#[test]
fn nice_zero_increment_matches_getpriority_state() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: nice accepts integer increments; zero is side-effect free.
    let observed = unsafe { nice(0) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: getpriority query for current process.
    let expected = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    // SAFETY: read errno after call.
    let expected_errno = unsafe { *__errno_location() };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
}

#[test]
fn getpagesize_matches_sysconf_table_value() {
    // SAFETY: getpagesize has no pointer preconditions.
    let page_size = unsafe { getpagesize() };
    assert!(page_size > 0);
    assert_eq!(page_size as libc::c_long, 4096);
}

#[test]
fn getdomainname_matches_uname_and_supports_truncation() {
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: provides writable pointer for uname output.
    assert_eq!(unsafe { libc::uname(uts.as_mut_ptr()) }, 0);
    // SAFETY: uname succeeded and initialized `uts`.
    let uts = unsafe { uts.assume_init() };
    let expected_len = uts
        .domainname
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(uts.domainname.len());

    let mut full = [0_i8; 65];
    // SAFETY: destination buffer is valid and writable.
    assert_eq!(unsafe { getdomainname(full.as_mut_ptr(), full.len()) }, 0);

    if expected_len < full.len() {
        assert_eq!(full[expected_len], 0);
    }

    if expected_len > 0 {
        assert_eq!(full[0], uts.domainname[0]);
    }

    let mut truncated = [0_i8; 1];
    // SAFETY: destination buffer is valid and writable.
    assert_eq!(
        unsafe { getdomainname(truncated.as_mut_ptr(), truncated.len()) },
        0
    );
    if expected_len > 0 {
        assert_eq!(truncated[0], uts.domainname[0]);
    }
}

#[test]
fn gethostid_is_deterministic() {
    // SAFETY: gethostid has no pointer preconditions.
    let first = unsafe { gethostid() };
    // SAFETY: gethostid has no pointer preconditions.
    let second = unsafe { gethostid() };
    assert_eq!(first, second);
}

#[test]
fn sched_priority_bounds_match_kernel_syscalls() {
    let policies = [libc::SCHED_OTHER, libc::SCHED_FIFO, libc::SCHED_RR];
    let mut compared = 0;

    for policy in policies {
        // SAFETY: direct raw syscall with integer policy argument.
        let expected_min =
            unsafe { libc::syscall(libc::SYS_sched_get_priority_min, policy) as libc::c_int };
        // SAFETY: direct raw syscall with integer policy argument.
        let expected_max =
            unsafe { libc::syscall(libc::SYS_sched_get_priority_max, policy) as libc::c_int };

        if expected_min < 0 || expected_max < 0 {
            continue;
        }

        // SAFETY: exported ABI wrappers accept any integer policy.
        let observed_min = unsafe { sched_get_priority_min(policy) };
        // SAFETY: exported ABI wrappers accept any integer policy.
        let observed_max = unsafe { sched_get_priority_max(policy) };

        assert_eq!(observed_min, expected_min);
        assert_eq!(observed_max, expected_max);
        assert!(observed_min <= observed_max);
        compared += 1;
    }

    assert!(
        compared > 0,
        "expected at least one scheduler policy to report priority bounds"
    );
}

#[test]
fn sched_priority_bounds_invalid_policy_set_errno() {
    let invalid_policy = libc::c_int::MAX;

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid policy is accepted as input and should fail with EINVAL.
    let min = unsafe { sched_get_priority_min(invalid_policy) };
    assert_eq!(min, -1);
    // SAFETY: read errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid policy is accepted as input and should fail with EINVAL.
    let max = unsafe { sched_get_priority_max(invalid_policy) };
    assert_eq!(max, -1);
    // SAFETY: read errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}

#[test]
fn sched_getscheduler_matches_kernel_syscall() {
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: pid 0 targets current thread group per Linux scheduler APIs.
    let observed = unsafe { sched_getscheduler(0) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: direct kernel syscall with same arguments for parity check.
    let expected = unsafe { libc::syscall(libc::SYS_sched_getscheduler, 0) as libc::c_int };
    // SAFETY: read errno after call.
    let expected_errno = unsafe { *__errno_location() };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
}

#[test]
fn sched_getparam_matches_kernel_syscall() {
    let mut observed_param = libc::sched_param { sched_priority: -1 };
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: param pointer is valid and writable.
    let observed =
        unsafe { sched_getparam(0, (&mut observed_param as *mut libc::sched_param).cast()) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    let mut expected_param = libc::sched_param { sched_priority: -1 };
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: direct kernel syscall with same arguments for parity check.
    let expected = unsafe {
        libc::syscall(
            libc::SYS_sched_getparam,
            0,
            &mut expected_param as *mut libc::sched_param,
        ) as libc::c_int
    };
    // SAFETY: read errno after call.
    let expected_errno = unsafe { *__errno_location() };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
    if observed == 0 {
        assert_eq!(observed_param.sched_priority, expected_param.sched_priority);
    }
}

#[test]
fn sched_setparam_invalid_pid_sets_einval() {
    let param = libc::sched_param { sched_priority: 0 };

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid pid and valid param pointer for parity check.
    let observed = unsafe { sched_setparam(-1, (&param as *const libc::sched_param).cast()) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_setscheduler_invalid_pid_sets_einval() {
    let param = libc::sched_param { sched_priority: 0 };

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid pid and valid policy/param pointer for parity check.
    let observed = unsafe {
        sched_setscheduler(
            -1,
            libc::SCHED_OTHER,
            (&param as *const libc::sched_param).cast(),
        )
    };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_rr_get_interval_matches_kernel_syscall() {
    let mut observed_tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: pointer is valid and writable.
    let observed = unsafe { sched_rr_get_interval(0, &mut observed_tp) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    let mut expected_tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: direct kernel syscall with same arguments for parity check.
    let expected = unsafe {
        libc::syscall(
            libc::SYS_sched_rr_get_interval,
            0,
            &mut expected_tp as *mut libc::timespec,
        ) as libc::c_int
    };
    // SAFETY: read errno after call.
    let expected_errno = unsafe { *__errno_location() };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
    if observed == 0 {
        assert_eq!(observed_tp.tv_sec, expected_tp.tv_sec);
        assert_eq!(observed_tp.tv_nsec, expected_tp.tv_nsec);
    }
}

#[test]
fn sched_rr_get_interval_null_pointer_sets_efault() {
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null timespec pointer intentionally exercises failure path.
    let observed = unsafe { sched_rr_get_interval(0, ptr::null_mut()) };
    // SAFETY: read errno after call.
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EFAULT);
}

#[test]
fn timer_settime_gettime_getoverrun_and_delete_roundtrip() {
    let Some(timer_id) = open_test_timer() else {
        return;
    };

    let new_value = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        },
    };
    let mut old_value: libc::itimerspec = unsafe { std::mem::zeroed() };
    // SAFETY: timer id was created successfully, and pointers are valid.
    let set_rc = unsafe {
        timer_settime(
            timer_id,
            0,
            (&new_value as *const libc::itimerspec).cast(),
            (&mut old_value as *mut libc::itimerspec).cast(),
        )
    };
    assert_eq!(set_rc, 0);

    let mut current: libc::itimerspec = unsafe { std::mem::zeroed() };
    // SAFETY: timer id is valid and output pointer is writable.
    assert_eq!(
        unsafe { timer_gettime(timer_id, (&mut current as *mut libc::itimerspec).cast()) },
        0
    );
    assert!(current.it_value.tv_sec >= 0);
    assert!(current.it_value.tv_nsec >= 0);
    assert!(current.it_value.tv_nsec < 1_000_000_000);

    // SAFETY: timer id is valid.
    let overrun = unsafe { timer_getoverrun(timer_id) };
    assert!(overrun >= 0);

    // SAFETY: timer id is valid and must be cleaned up.
    assert_eq!(unsafe { timer_delete(timer_id) }, 0);
}

#[test]
fn timer_invalid_inputs_match_kernel_syscalls() {
    let invalid_timer = (-1_isize) as *mut libc::c_void;
    let mut observed_curr: libc::itimerspec = unsafe { std::mem::zeroed() };
    let new_value = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 1,
        },
    };

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid timer id + valid output pointer intentionally exercises kernel error path.
    let observed_get = unsafe {
        timer_gettime(
            invalid_timer,
            (&mut observed_curr as *mut libc::itimerspec).cast(),
        )
    };
    // SAFETY: read errno after call.
    let observed_get_errno = unsafe { *__errno_location() };

    assert_eq!(observed_get, -1);
    assert_eq!(observed_get_errno, libc::EINVAL);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid timer id + valid new-value pointer intentionally exercises kernel error path.
    let observed_set = unsafe {
        timer_settime(
            invalid_timer,
            0,
            (&new_value as *const libc::itimerspec).cast(),
            ptr::null_mut(),
        )
    };
    // SAFETY: read errno after call.
    let observed_set_errno = unsafe { *__errno_location() };

    assert_eq!(observed_set, -1);
    assert_eq!(observed_set_errno, libc::EINVAL);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid timer id intentionally exercises kernel error path.
    let observed_delete = unsafe { timer_delete(invalid_timer) };
    // SAFETY: read errno after call.
    let observed_delete_errno = unsafe { *__errno_location() };

    assert_eq!(observed_delete, -1);
    assert_eq!(observed_delete_errno, libc::EINVAL);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid timer id intentionally exercises kernel error path.
    let observed_overrun = unsafe { timer_getoverrun(invalid_timer) };
    // SAFETY: read errno after call.
    let observed_overrun_errno = unsafe { *__errno_location() };

    assert_eq!(observed_overrun, -1);
    assert_eq!(observed_overrun_errno, libc::EINVAL);

    let mut observed_timer_id: *mut libc::c_void = ptr::null_mut();
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid clock id intentionally exercises kernel error path.
    let observed_create = unsafe {
        timer_create(
            libc::clockid_t::MAX,
            ptr::null_mut(),
            (&mut observed_timer_id as *mut *mut libc::c_void).cast(),
        )
    };
    // SAFETY: read errno after call.
    let observed_create_errno = unsafe { *__errno_location() };

    assert_eq!(observed_create, -1);
    assert_eq!(observed_create_errno, libc::EINVAL);
}

#[test]
fn sigtimedwait_and_sigwaitinfo_invalid_inputs_match_kernel_syscalls() {
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null sigset/info pointers intentionally exercise kernel failure path.
    let observed_timed = unsafe { sigtimedwait(ptr::null(), ptr::null_mut(), &timeout) };
    // SAFETY: read errno after call.
    let observed_timed_errno = unsafe { *__errno_location() };

    assert_eq!(observed_timed, -1);
    assert_eq!(observed_timed_errno, libc::EINVAL);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null sigset/info pointers intentionally exercise kernel failure path.
    let observed_wait = unsafe { sigwaitinfo(ptr::null(), ptr::null_mut()) };
    // SAFETY: read errno after call.
    let observed_wait_errno = unsafe { *__errno_location() };

    assert_eq!(observed_wait, -1);
    assert_eq!(observed_wait_errno, libc::EINVAL);
}

#[test]
fn sigqueue_invalid_signal_sets_einval() {
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: getpid has no pointer preconditions.
    let pid = unsafe { libc::getpid() };
    // SAFETY: invalid signal number should deterministically fail.
    let rc = unsafe { sigqueue(pid, -1, ptr::null()) };
    // SAFETY: read errno after call.
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn getlogin_and_getlogin_r_match_pwd_lookup() {
    // SAFETY: geteuid has no pointer preconditions.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: getpwuid has no pointer preconditions.
    let pwd = unsafe { frankenlibc_abi::pwd_abi::getpwuid(uid) };
    assert!(
        !pwd.is_null(),
        "getpwuid should resolve current effective uid"
    );

    // SAFETY: `pwd` is non-null and points to libc::passwd storage.
    let name_ptr = unsafe { (*pwd).pw_name };
    assert!(!name_ptr.is_null(), "pw_name should be present");
    // SAFETY: passwd entry contains a NUL-terminated username.
    let expected = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
        .to_string_lossy()
        .into_owned();

    // SAFETY: getlogin has no pointer preconditions.
    let login_ptr = unsafe { getlogin() };
    assert!(!login_ptr.is_null(), "getlogin should resolve current user");
    // SAFETY: getlogin result is expected to be a NUL-terminated username.
    let login = unsafe { std::ffi::CStr::from_ptr(login_ptr) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(login, expected);

    let mut buf = vec![0_i8; expected.len() + 1];
    // SAFETY: buffer pointer is writable and length matches the provided capacity.
    assert_eq!(unsafe { getlogin_r(buf.as_mut_ptr(), buf.len()) }, 0);
    // SAFETY: successful getlogin_r writes a NUL-terminated username.
    let login_r = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(login_r, expected);
}

#[test]
fn getlogin_r_validates_buffer_and_reports_erange() {
    // SAFETY: null destination is invalid.
    assert_eq!(unsafe { getlogin_r(ptr::null_mut(), 8) }, libc::EINVAL);

    // SAFETY: geteuid has no pointer preconditions.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: getpwuid has no pointer preconditions.
    let pwd = unsafe { frankenlibc_abi::pwd_abi::getpwuid(uid) };
    assert!(
        !pwd.is_null(),
        "getpwuid should resolve current effective uid"
    );
    // SAFETY: `pwd` is non-null and points to libc::passwd storage.
    let name_ptr = unsafe { (*pwd).pw_name };
    assert!(!name_ptr.is_null(), "pw_name should be present");
    // SAFETY: passwd entry contains a NUL-terminated username.
    let required_len = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
        .to_bytes_with_nul()
        .len();

    if required_len > 1 {
        let mut tiny = [0_i8; 1];
        // SAFETY: tiny is writable but intentionally too small.
        assert_eq!(
            unsafe { getlogin_r(tiny.as_mut_ptr(), tiny.len()) },
            libc::ERANGE
        );
    }
}

#[test]
fn getopt_parses_short_options_and_required_argument() {
    let args = [
        std::ffi::CString::new("prog").expect("valid argv"),
        std::ffi::CString::new("-a").expect("valid argv"),
        std::ffi::CString::new("-b").expect("valid argv"),
        std::ffi::CString::new("value").expect("valid argv"),
    ];
    let mut argv: Vec<*mut libc::c_char> = args
        .iter()
        .map(|arg| arg.as_ptr() as *mut libc::c_char)
        .collect();
    let argc = argv.len() as libc::c_int;
    argv.push(ptr::null_mut());

    // SAFETY: reset shared getopt globals before deterministic assertions.
    unsafe { reset_getopt_globals() };

    // SAFETY: argv/optstring pointers are valid.
    assert_eq!(
        unsafe { getopt(argc, argv.as_ptr(), c"ab:".as_ptr()) },
        b'a' as libc::c_int
    );
    // SAFETY: inspect getopt globals after parse.
    assert!(unsafe { OPTARG_TEST.is_null() });
    // SAFETY: inspect getopt globals after parse.
    assert_eq!(unsafe { OPTIND_TEST }, 2);

    // SAFETY: argv/optstring pointers are valid.
    assert_eq!(
        unsafe { getopt(argc, argv.as_ptr(), c"ab:".as_ptr()) },
        b'b' as libc::c_int
    );
    // SAFETY: getopt set optarg to the required argument.
    let optarg = unsafe { std::ffi::CStr::from_ptr(OPTARG_TEST) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(optarg, "value");
    // SAFETY: inspect getopt globals after parse.
    assert_eq!(unsafe { OPTIND_TEST }, 4);

    // SAFETY: parser is at end of option stream.
    assert_eq!(unsafe { getopt(argc, argv.as_ptr(), c"ab:".as_ptr()) }, -1);
}

#[test]
fn getopt_long_parses_named_options_and_inline_values() {
    let args = [
        std::ffi::CString::new("prog").expect("valid argv"),
        std::ffi::CString::new("--alpha").expect("valid argv"),
        std::ffi::CString::new("--beta=world").expect("valid argv"),
    ];
    let mut argv: Vec<*mut libc::c_char> = args
        .iter()
        .map(|arg| arg.as_ptr() as *mut libc::c_char)
        .collect();
    let argc = argv.len() as libc::c_int;
    argv.push(ptr::null_mut());

    let mut longindex: libc::c_int = -1;
    let alpha = c"alpha";
    let beta = c"beta";
    let longopts = [
        libc::option {
            name: alpha.as_ptr(),
            has_arg: 0,
            flag: ptr::null_mut(),
            val: b'a' as libc::c_int,
        },
        libc::option {
            name: beta.as_ptr(),
            has_arg: 1,
            flag: ptr::null_mut(),
            val: b'b' as libc::c_int,
        },
        libc::option {
            name: ptr::null(),
            has_arg: 0,
            flag: ptr::null_mut(),
            val: 0,
        },
    ];

    // SAFETY: reset shared getopt globals before deterministic assertions.
    unsafe { reset_getopt_globals() };

    // SAFETY: argv/optstring/longopts pointers are valid.
    assert_eq!(
        unsafe {
            getopt_long(
                argc,
                argv.as_ptr(),
                c"ab:".as_ptr(),
                longopts.as_ptr(),
                &mut longindex,
            )
        },
        b'a' as libc::c_int
    );
    assert_eq!(longindex, 0);
    // SAFETY: inspect getopt globals after parse.
    assert!(unsafe { OPTARG_TEST.is_null() });

    // SAFETY: argv/optstring/longopts pointers are valid.
    assert_eq!(
        unsafe {
            getopt_long(
                argc,
                argv.as_ptr(),
                c"ab:".as_ptr(),
                longopts.as_ptr(),
                &mut longindex,
            )
        },
        b'b' as libc::c_int
    );
    assert_eq!(longindex, 1);
    // SAFETY: getopt_long set optarg to inline value.
    let optarg = unsafe { std::ffi::CStr::from_ptr(OPTARG_TEST) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(optarg, "world");

    // SAFETY: parser is at end of option stream.
    assert_eq!(
        unsafe {
            getopt_long(
                argc,
                argv.as_ptr(),
                c"ab:".as_ptr(),
                longopts.as_ptr(),
                &mut longindex,
            )
        },
        -1
    );
}

#[test]
fn ttyname_and_ttyname_r_report_ebadf_for_invalid_fd() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: negative fd is invalid.
    let out = unsafe { ttyname(-1) };
    assert!(out.is_null());
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EBADF);

    let mut buf = [0_i8; 64];
    // SAFETY: destination buffer is valid; fd is intentionally invalid.
    assert_eq!(
        unsafe { ttyname_r(-1, buf.as_mut_ptr(), buf.len()) },
        libc::EBADF
    );
}

#[test]
fn ttyname_and_ttyname_r_report_enotty_for_regular_file() {
    let template = temp_template("ttyname", ".tmp");
    // SAFETY: template is NUL-terminated by construction.
    let path_c = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) };
    let path = path_c.to_string_lossy().into_owned();

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("create temp file for ttyname");
    let fd = file.as_raw_fd();

    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: fd is valid but does not refer to a terminal.
    let out = unsafe { ttyname(fd) };
    assert!(out.is_null());
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::ENOTTY);

    let mut buf = [0_i8; 256];
    // SAFETY: destination buffer is valid; fd is a regular file and should report ENOTTY.
    assert_eq!(
        unsafe { ttyname_r(fd, buf.as_mut_ptr(), buf.len()) },
        libc::ENOTTY
    );

    drop(file);
    let _ = std::fs::remove_file(path);
}

#[test]
fn posix_openpt_and_pts_helpers_roundtrip() {
    // SAFETY: request PTY master with valid flags.
    let fd = unsafe { posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(
        fd >= 0,
        "posix_openpt should open /dev/ptmx: errno={}",
        // SAFETY: read errno after failed call.
        unsafe { *__errno_location() }
    );

    // SAFETY: valid PTY master fd should succeed.
    assert_eq!(unsafe { grantpt(fd) }, 0);
    // SAFETY: valid PTY master fd should succeed.
    assert_eq!(unsafe { unlockpt(fd) }, 0);

    // SAFETY: valid PTY master fd should yield slave path pointer.
    let name_ptr = unsafe { ptsname(fd) };
    assert!(!name_ptr.is_null(), "ptsname should resolve slave device");
    // SAFETY: non-null pointer from ptsname references NUL-terminated path.
    let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }
        .to_string_lossy()
        .into_owned();
    assert!(name.starts_with("/dev/pts/"), "unexpected ptsname: {name}");

    // SAFETY: fd came from posix_openpt.
    unsafe {
        libc::close(fd);
    }
}

#[test]
fn pty_helpers_reject_invalid_fd() {
    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid fd should fail.
    assert_eq!(unsafe { grantpt(-1) }, -1);
    // SAFETY: read errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EBADF);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid fd should fail.
    assert_eq!(unsafe { unlockpt(-1) }, -1);
    // SAFETY: read errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EBADF);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid fd should fail.
    let name_ptr = unsafe { ptsname(-1) };
    assert!(name_ptr.is_null());
    // SAFETY: read errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EBADF);
}

#[test]
fn ether_aton_and_ether_ntoa_roundtrip() {
    // SAFETY: source is a valid NUL-terminated C string.
    let parsed = unsafe { ether_aton(c"00:1a:2B:3c:4D:5e".as_ptr()) };
    assert!(!parsed.is_null());

    // SAFETY: parser returns pointer to an internal six-octet ethernet address.
    let addr = unsafe { *(parsed.cast::<EtherAddr>()) };
    assert_eq!(addr.octet, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

    // SAFETY: parsed pointer came from successful ether_aton call.
    let rendered_ptr = unsafe { ether_ntoa(parsed) };
    assert!(!rendered_ptr.is_null());
    // SAFETY: successful formatter returns a NUL-terminated string.
    let rendered = unsafe { std::ffi::CStr::from_ptr(rendered_ptr) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(rendered, "00:1a:2b:3c:4d:5e");
}

#[test]
fn ether_r_variants_validate_inputs() {
    let mut out = EtherAddr { octet: [0; 6] };
    // SAFETY: source string and output pointer are valid.
    let parsed = unsafe {
        ether_aton_r(
            c"10:20:30:40:50:60".as_ptr(),
            (&mut out as *mut EtherAddr).cast::<libc::c_void>(),
        )
    };
    assert!(!parsed.is_null());
    assert_eq!(out.octet, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

    let mut buf = [0_i8; 18];
    // SAFETY: address and output buffer pointers are valid.
    let formatted = unsafe {
        ether_ntoa_r(
            (&out as *const EtherAddr).cast::<libc::c_void>(),
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(formatted, buf.as_mut_ptr());
    // SAFETY: successful formatter writes a NUL-terminated string.
    let rendered = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(rendered, "10:20:30:40:50:60");

    // SAFETY: invalid parse input is expected to return null.
    assert!(unsafe { ether_aton(c"00:11:22:33:44".as_ptr()) }.is_null());
    // SAFETY: invalid parse input is expected to return null.
    assert!(
        unsafe {
            ether_aton_r(
                c"00:11:22:33:44:gg".as_ptr(),
                (&mut out as *mut EtherAddr).cast::<libc::c_void>(),
            )
        }
        .is_null()
    );
    // SAFETY: null address pointer should return null.
    assert!(unsafe { ether_ntoa_r(ptr::null(), buf.as_mut_ptr()) }.is_null());
    // SAFETY: null destination pointer should return null.
    assert!(
        unsafe {
            ether_ntoa_r(
                (&out as *const EtherAddr).cast::<libc::c_void>(),
                ptr::null_mut(),
            )
        }
        .is_null()
    );
}

#[test]
fn hstrerror_reports_known_and_unknown_codes() {
    // SAFETY: hstrerror returns stable pointers to static NUL-terminated messages.
    let known = unsafe { hstrerror(1) };
    assert!(!known.is_null());
    // SAFETY: pointer was validated non-null.
    let known_text = unsafe { std::ffi::CStr::from_ptr(known) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(known_text, "Unknown host");

    // SAFETY: unknown code should still return a stable message pointer.
    let unknown = unsafe { hstrerror(9999) };
    assert!(!unknown.is_null());
    // SAFETY: pointer was validated non-null.
    let unknown_text = unsafe { std::ffi::CStr::from_ptr(unknown) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(unknown_text, "Resolver internal error");
}

#[test]
fn herror_writes_prefixed_message_to_stderr() {
    let mut pipe_fds = [0; 2];
    // SAFETY: provides writable space for pipe fd pair.
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    // SAFETY: duplicate current stderr so we can restore it after capture.
    let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
    assert!(saved_stderr >= 0);

    // SAFETY: redirect stderr to pipe writer for deterministic capture.
    assert_eq!(
        unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) },
        libc::STDERR_FILENO
    );

    // SAFETY: set thread-local h_errno and call herror with valid prefix string.
    unsafe {
        let h_err = __h_errno_location();
        assert!(!h_err.is_null());
        *h_err = 1;
        herror(c"lookup".as_ptr());
    }

    // SAFETY: restore stderr and release duplicated fds.
    assert_eq!(
        unsafe { libc::dup2(saved_stderr, libc::STDERR_FILENO) },
        libc::STDERR_FILENO
    );
    // SAFETY: close duplicated descriptor and write-end once restored.
    unsafe {
        libc::close(saved_stderr);
        libc::close(write_fd);
    }

    let mut capture = [0_u8; 128];
    // SAFETY: read into writable capture buffer from pipe read end.
    let nread = unsafe { libc::read(read_fd, capture.as_mut_ptr().cast(), capture.len()) };
    assert!(nread > 0);
    // SAFETY: release read-end descriptor after capture.
    unsafe {
        libc::close(read_fd);
    }

    let text = std::str::from_utf8(&capture[..nread as usize]).expect("stderr capture is utf-8");
    assert_eq!(text, "lookup: Unknown host\n");
}

#[test]
fn sethostname_null_pointer_returns_efault() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null pointer with nonzero len is invalid by API contract.
    let rc = unsafe { sethostname(ptr::null(), 1) };
    assert_eq!(rc, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);
}

#[test]
fn setdomainname_null_pointer_returns_efault() {
    // SAFETY: __errno_location points to this thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null pointer with nonzero len is invalid by API contract.
    let rc = unsafe { setdomainname(ptr::null(), 1) };
    assert_eq!(rc, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EFAULT);
}

#[test]
fn ctermid_null_returns_static_dev_tty() {
    // SAFETY: null pointer requests static storage from ctermid.
    let out = unsafe { ctermid(ptr::null_mut()) };
    assert!(!out.is_null());

    // SAFETY: ctermid returns a valid NUL-terminated pointer.
    let value = unsafe { std::ffi::CStr::from_ptr(out) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(value, "/dev/tty");
}

#[test]
fn ctermid_writes_into_caller_buffer() {
    let mut buf = [0_i8; 32];
    // SAFETY: caller-provided writable buffer is valid.
    let out = unsafe { ctermid(buf.as_mut_ptr()) };
    assert_eq!(out, buf.as_mut_ptr());

    // SAFETY: ctermid wrote a valid NUL-terminated string into `buf`.
    let value = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert_eq!(value, "/dev/tty");
}

#[test]
fn get_nprocs_helpers_match_sysconf_values() {
    // SAFETY: no pointer preconditions.
    let online = unsafe { get_nprocs() };
    // SAFETY: no pointer preconditions.
    let conf = unsafe { get_nprocs_conf() };

    assert!(online > 0);
    assert!(conf > 0);

    // SAFETY: sysconf has no pointer preconditions.
    let expected_online = unsafe { sysconf(libc::_SC_NPROCESSORS_ONLN) };
    // SAFETY: sysconf has no pointer preconditions.
    let expected_conf = unsafe { sysconf(libc::_SC_NPROCESSORS_CONF) };

    assert_eq!(online as libc::c_long, expected_online);
    assert_eq!(conf as libc::c_long, expected_conf);
}

#[test]
fn get_phys_and_avphys_pages_match_sysinfo_projection() {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    // SAFETY: valid writable pointer for kernel sysinfo payload.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_sysinfo, info.as_mut_ptr()) },
        0
    );
    // SAFETY: syscall succeeded and initialized `info`.
    let info = unsafe { info.assume_init() };

    // SAFETY: sysconf has no pointer preconditions.
    let page_size = unsafe { sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0);
    let page_size_u128 = page_size as u128;
    let mem_unit = if info.mem_unit == 0 {
        1_u128
    } else {
        info.mem_unit as u128
    };

    let expected_phys = ((info.totalram as u128).saturating_mul(mem_unit) / page_size_u128)
        .min(libc::c_long::MAX as u128) as libc::c_long;
    let expected_avphys = ((info.freeram as u128).saturating_mul(mem_unit) / page_size_u128)
        .min(libc::c_long::MAX as u128) as libc::c_long;

    // SAFETY: no pointer preconditions.
    assert_eq!(unsafe { get_phys_pages() }, expected_phys);
    // SAFETY: no pointer preconditions.
    assert_eq!(unsafe { get_avphys_pages() }, expected_avphys);
}

#[test]
fn lfs64_aliases_io_roundtrip_and_fd_truncate() {
    let template = temp_template("lfs64-io", ".tmp");
    // SAFETY: template is NUL-terminated by construction.
    let path_c = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) };
    let path = path_c.to_string_lossy().into_owned();

    // SAFETY: valid path + mode for file creation.
    let create_fd = unsafe { creat64(path_c.as_ptr(), 0o600) };
    assert!(create_fd >= 0);
    // SAFETY: close descriptor opened above.
    assert_eq!(unsafe { libc::close(create_fd) }, 0);

    // SAFETY: valid path and flags for reopen.
    let fd = unsafe { open64(path_c.as_ptr(), libc::O_RDWR, 0) };
    assert!(fd >= 0);

    let payload = *b"frank64!";
    // SAFETY: fd is valid and payload pointer/len are valid.
    assert_eq!(
        unsafe { pwrite64(fd, payload.as_ptr().cast(), payload.len(), 0) },
        payload.len() as isize
    );

    let mut out = [0_u8; 8];
    // SAFETY: fd is valid and output buffer is writable.
    assert_eq!(
        unsafe { pread64(fd, out.as_mut_ptr().cast(), out.len(), 0) },
        out.len() as isize
    );
    assert_eq!(out, payload);

    // SAFETY: valid fd and truncate length.
    assert_eq!(unsafe { ftruncate64(fd, 4) }, 0);
    // SAFETY: valid fd and whence.
    assert_eq!(unsafe { lseek64(fd, 0, libc::SEEK_END) }, 4);

    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid fd and writable stat buffer.
    assert_eq!(unsafe { fstat64(fd, st.as_mut_ptr().cast()) }, 0);
    // SAFETY: fstat64 succeeded.
    let st = unsafe { st.assume_init() };
    assert_eq!(st.st_size, 4);

    // SAFETY: close descriptor opened above.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let _ = std::fs::remove_file(path);
}

#[test]
fn lfs64_aliases_path_stat_and_truncate() {
    let template = temp_template("lfs64-path", ".tmp");
    // SAFETY: template is NUL-terminated by construction.
    let path_c = unsafe { std::ffi::CStr::from_ptr(template.as_ptr().cast()) };
    let path = path_c.to_string_lossy().into_owned();
    std::fs::write(&path, b"abcdef").expect("seed temp file");

    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid path and writable stat buffer.
    assert_eq!(
        unsafe { stat64(path_c.as_ptr(), st.as_mut_ptr().cast()) },
        0
    );
    // SAFETY: stat64 succeeded.
    let st = unsafe { st.assume_init() };
    assert_eq!(st.st_size, 6);

    let mut lst = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid path and writable stat buffer.
    assert_eq!(
        unsafe { lstat64(path_c.as_ptr(), lst.as_mut_ptr().cast()) },
        0
    );

    let mut at = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: valid arguments and writable stat buffer.
    assert_eq!(
        unsafe { fstatat64(libc::AT_FDCWD, path_c.as_ptr(), at.as_mut_ptr().cast(), 0,) },
        0
    );

    // SAFETY: valid path and target length.
    assert_eq!(unsafe { truncate64(path_c.as_ptr(), 2) }, 0);
    let shrunk = std::fs::metadata(&path).expect("metadata should exist after truncate64");
    assert_eq!(shrunk.len(), 2);

    let _ = std::fs::remove_file(path);
}

#[test]
fn msgsysv_roundtrip_and_cleanup() {
    // SAFETY: IPC_PRIVATE with create flags requests a new queue id.
    let msqid = unsafe { msgget(libc::IPC_PRIVATE, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
    if msqid < 0 {
        // SAFETY: read thread-local errno after syscall failure.
        let err = unsafe { *__errno_location() };
        if err == libc::ENOSYS {
            return;
        }
        panic!("msgget failed with errno={err}");
    }

    let payload = b"sysv-msg";
    let mut send = SysvMsg {
        mtype: 1,
        mtext: [0; 64],
    };
    send.mtext[..payload.len()].copy_from_slice(payload);

    // SAFETY: msqid is valid and pointer/size cover initialized payload bytes.
    assert_eq!(
        unsafe {
            msgsnd(
                msqid,
                (&send as *const SysvMsg).cast::<libc::c_void>(),
                payload.len(),
                0,
            )
        },
        0
    );

    let mut recv = SysvMsg {
        mtype: 0,
        mtext: [0; 64],
    };
    // SAFETY: receive buffer is writable and large enough.
    let received = unsafe {
        msgrcv(
            msqid,
            (&mut recv as *mut SysvMsg).cast::<libc::c_void>(),
            recv.mtext.len(),
            1,
            0,
        )
    };
    assert_eq!(received, payload.len() as isize);
    assert_eq!(recv.mtype, 1);
    assert_eq!(&recv.mtext[..payload.len()], payload);

    // SAFETY: remove queue id allocated in this test.
    assert_eq!(unsafe { msgctl(msqid, libc::IPC_RMID, ptr::null_mut()) }, 0);
}

#[test]
fn msgsysv_invalid_inputs_match_kernel_syscalls() {
    let msg = SysvMsg {
        mtype: 1,
        mtext: [0; 64],
    };

    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: intentionally invalid queue id for error-path contract.
    let observed_send =
        unsafe { msgsnd(-1, (&msg as *const SysvMsg).cast::<libc::c_void>(), 1, 0) };
    // SAFETY: read errno after wrapper call.
    let observed_send_errno = unsafe { *__errno_location() };

    assert_eq!(observed_send, -1);
    assert_eq!(observed_send_errno, libc::EINVAL);

    let mut recv = SysvMsg {
        mtype: 0,
        mtext: [0; 64],
    };
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: intentionally invalid queue id for error-path contract.
    let observed_recv = unsafe {
        msgrcv(
            -1,
            (&mut recv as *mut SysvMsg).cast::<libc::c_void>(),
            1,
            0,
            0,
        )
    };
    // SAFETY: read errno after wrapper call.
    let observed_recv_errno = unsafe { *__errno_location() };

    assert_eq!(observed_recv, -1);
    assert_eq!(observed_recv_errno, libc::EINVAL);

    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: intentionally invalid queue id for error-path contract.
    let observed_ctl = unsafe { msgctl(-1, libc::IPC_RMID, ptr::null_mut()) };
    // SAFETY: read errno after wrapper call.
    let observed_ctl_errno = unsafe { *__errno_location() };

    assert_eq!(observed_ctl, -1);
    assert_eq!(observed_ctl_errno, libc::EINVAL);
}

#[test]
fn shm_sysv_roundtrip_and_cleanup() {
    // SAFETY: IPC_PRIVATE with create flags requests a new segment id.
    let shmid = unsafe {
        shmget(
            libc::IPC_PRIVATE,
            4096,
            libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
        )
    };
    if shmid < 0 {
        // SAFETY: read thread-local errno after syscall failure.
        let err = unsafe { *__errno_location() };
        if err == libc::ENOSYS {
            return;
        }
        panic!("shmget failed with errno={err}");
    }

    // SAFETY: attach newly created shared-memory segment.
    let addr = unsafe { shmat(shmid, ptr::null(), 0) };
    assert_ne!(addr, (-1_isize) as *mut libc::c_void);

    // SAFETY: attached address is writable for at least one byte.
    unsafe {
        *(addr as *mut u8) = 0x5a;
    }

    // SAFETY: detach and remove resources allocated in this test.
    assert_eq!(unsafe { shmdt(addr.cast()) }, 0);
    // SAFETY: remove segment id allocated in this test.
    assert_eq!(unsafe { shmctl(shmid, libc::IPC_RMID, ptr::null_mut()) }, 0);
}

#[test]
fn shm_sysv_invalid_inputs_match_kernel_syscalls() {
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: size=0 is invalid for new segment creation.
    let observed_get = unsafe { shmget(libc::IPC_PRIVATE, 0, libc::IPC_CREAT | 0o600) };
    // SAFETY: read errno after wrapper call.
    let observed_get_errno = unsafe { *__errno_location() };

    assert_eq!(observed_get, -1);
    assert_eq!(observed_get_errno, libc::EINVAL);

    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: intentionally invalid segment id.
    let observed_at = unsafe { shmat(-1, ptr::null(), 0) } as isize;
    // SAFETY: read errno after wrapper call.
    let observed_at_errno = unsafe { *__errno_location() };

    assert_eq!(observed_at, -1);
    assert_eq!(observed_at_errno, libc::EINVAL);
}

#[test]
fn sem_sysv_roundtrip_and_cleanup() {
    // SAFETY: IPC_PRIVATE with create flags requests a new semaphore set.
    let semid = unsafe {
        semget(
            libc::IPC_PRIVATE,
            1,
            libc::IPC_CREAT | libc::IPC_EXCL | 0o600,
        )
    };
    if semid < 0 {
        // SAFETY: read thread-local errno after syscall failure.
        let err = unsafe { *__errno_location() };
        if err == libc::ENOSYS {
            return;
        }
        panic!("semget failed with errno={err}");
    }

    // SAFETY: SETVAL command with explicit value argument.
    assert_eq!(
        unsafe { semctl(semid, 0, libc::SETVAL, 1 as libc::c_int) },
        0
    );

    let mut wait_op = libc::sembuf {
        sem_num: 0,
        sem_op: -1,
        sem_flg: 0,
    };
    // SAFETY: valid semaphore set id and operation buffer.
    assert_eq!(
        unsafe { semop(semid, (&mut wait_op as *mut libc::sembuf).cast(), 1) },
        0
    );

    let mut post_op = libc::sembuf {
        sem_num: 0,
        sem_op: 1,
        sem_flg: 0,
    };
    // SAFETY: valid semaphore set id and operation buffer.
    assert_eq!(
        unsafe { semop(semid, (&mut post_op as *mut libc::sembuf).cast(), 1) },
        0
    );

    // SAFETY: remove semaphore set allocated in this test.
    assert_eq!(unsafe { semctl(semid, 0, libc::IPC_RMID) }, 0);
}

#[test]
fn sem_sysv_invalid_inputs_match_kernel_syscalls() {
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: nsems=0 is invalid for creating new semaphore set.
    let observed_get = unsafe { semget(libc::IPC_PRIVATE, 0, libc::IPC_CREAT | 0o600) };
    // SAFETY: read errno after wrapper call.
    let observed_get_errno = unsafe { *__errno_location() };

    assert_eq!(observed_get, -1);
    assert_eq!(observed_get_errno, libc::EINVAL);

    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid semid and null op list intentionally exercise failure path.
    let observed_op = unsafe { semop(-1, ptr::null_mut(), 0) };
    // SAFETY: read errno after wrapper call.
    let observed_op_errno = unsafe { *__errno_location() };

    assert_eq!(observed_op, -1);
    assert_eq!(observed_op_errno, libc::EINVAL);
}

#[test]
fn semctl_invalid_inputs_match_kernel_syscalls() {
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid semid with no-arg command.
    let observed_getval = unsafe { semctl(-1, 0, libc::GETVAL) };
    // SAFETY: read errno after wrapper call.
    let observed_getval_errno = unsafe { *__errno_location() };

    assert_eq!(observed_getval, -1);
    assert_eq!(observed_getval_errno, libc::EINVAL);

    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid semid with arg-using command.
    let observed_setval = unsafe { semctl(-1, 0, libc::SETVAL, 1 as libc::c_int) };
    // SAFETY: read errno after wrapper call.
    let observed_setval_errno = unsafe { *__errno_location() };

    assert_eq!(observed_setval, -1);
    assert_eq!(observed_setval_errno, libc::EINVAL);
}

#[test]
fn shm_open_and_unlink_roundtrip() {
    let name = unique_shm_name("frankenlibc-shm");

    // SAFETY: valid POSIX shm object name and open flags.
    let fd = unsafe {
        shm_open(
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        )
    };
    if fd < 0 {
        // SAFETY: read thread-local errno after syscall failure.
        let err = unsafe { *__errno_location() };
        if matches!(err, libc::ENOENT | libc::ENOSYS) {
            return;
        }
        panic!("shm_open failed with errno={err}");
    }

    // SAFETY: close descriptor opened above.
    assert_eq!(unsafe { libc::close(fd) }, 0);
    // SAFETY: unlink object created above.
    assert_eq!(unsafe { shm_unlink(name.as_ptr()) }, 0);
}

#[test]
fn shm_open_rejects_invalid_names() {
    let invalid = CString::new("invalid").expect("valid C string");
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: missing leading slash is invalid per shm name contract.
    assert_eq!(unsafe { shm_open(invalid.as_ptr(), libc::O_RDONLY, 0) }, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);

    let nested = CString::new("/bad/name").expect("valid C string");
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: interior slash is invalid in this wrapper's shm namespace mapping.
    assert_eq!(unsafe { shm_open(nested.as_ptr(), libc::O_RDONLY, 0) }, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);

    let root = CString::new("/").expect("valid C string");
    // SAFETY: reset thread-local errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: root-only shm object names are invalid.
    assert_eq!(unsafe { shm_unlink(root.as_ptr()) }, -1);
    // SAFETY: read thread-local errno after call.
    assert_eq!(unsafe { *__errno_location() }, libc::EINVAL);
}

fn open_test_mq(tag: &str) -> Option<(libc::c_int, CString)> {
    let name = unique_mq_name(tag);
    let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
    attr.mq_flags = 0;
    attr.mq_maxmsg = 8;
    attr.mq_msgsize = 64;
    attr.mq_curmsgs = 0;

    // SAFETY: valid queue name, create flags, mode, and attr pointer.
    let mqd = unsafe {
        mq_open(
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
            &attr as *const libc::mq_attr,
        )
    };

    if mqd >= 0 {
        return Some((mqd, name));
    }

    // SAFETY: read thread-local errno after failed open.
    let err = unsafe { *__errno_location() };
    if matches!(
        err,
        libc::ENOSYS | libc::ENODEV | libc::ENOENT | libc::ENOTSUP | libc::EACCES | libc::EPERM
    ) {
        return None;
    }

    panic!("mq_open failed unexpectedly with errno={err}");
}

#[test]
fn mq_open_roundtrip_and_cleanup() {
    let Some((mqd, name)) = open_test_mq("frankenlibc-mq-open") else {
        return;
    };

    // SAFETY: descriptor returned from mq_open is valid.
    assert_eq!(unsafe { mq_close(mqd) }, 0);
    // SAFETY: name references queue created above.
    assert_eq!(unsafe { mq_unlink(name.as_ptr()) }, 0);
}

#[test]
fn mq_send_and_receive_roundtrip() {
    let Some((mqd, name)) = open_test_mq("frankenlibc-mq-io") else {
        return;
    };

    let payload = b"queue-msg";
    // SAFETY: valid descriptor and initialized payload buffer.
    assert_eq!(
        unsafe { mq_send(mqd, payload.as_ptr().cast(), payload.len(), 7) },
        0
    );

    let mut buf = [0_u8; 64];
    let mut prio: libc::c_uint = 0;
    // SAFETY: valid descriptor and writable output buffers.
    let n = unsafe { mq_receive(mqd, buf.as_mut_ptr().cast(), buf.len(), &mut prio) };
    assert_eq!(n, payload.len() as isize);
    assert_eq!(prio, 7);
    assert_eq!(&buf[..payload.len()], payload);

    // SAFETY: descriptor/name belong to queue created in this test.
    assert_eq!(unsafe { mq_close(mqd) }, 0);
    // SAFETY: descriptor/name belong to queue created in this test.
    assert_eq!(unsafe { mq_unlink(name.as_ptr()) }, 0);
}

#[test]
fn mq_getattr_and_setattr_roundtrip() {
    let Some((mqd, name)) = open_test_mq("frankenlibc-mq-attr") else {
        return;
    };

    let mut attr: libc::mq_attr = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and writable attr pointer.
    assert_eq!(
        unsafe { mq_getattr(mqd, (&mut attr as *mut libc::mq_attr).cast()) },
        0
    );
    assert!(attr.mq_maxmsg > 0);
    assert!(attr.mq_msgsize > 0);

    let mut requested = attr;
    requested.mq_flags = libc::O_NONBLOCK as _;
    let mut oldattr: libc::mq_attr = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and attr pointers.
    assert_eq!(
        unsafe {
            mq_setattr(
                mqd,
                (&requested as *const libc::mq_attr).cast(),
                (&mut oldattr as *mut libc::mq_attr).cast(),
            )
        },
        0
    );
    assert_eq!(oldattr.mq_msgsize, attr.mq_msgsize);

    // SAFETY: descriptor/name belong to queue created in this test.
    assert_eq!(unsafe { mq_close(mqd) }, 0);
    // SAFETY: descriptor/name belong to queue created in this test.
    assert_eq!(unsafe { mq_unlink(name.as_ptr()) }, 0);
}

#[test]
fn mq_close_and_unlink_invalid_inputs_report_expected_errno() {
    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid descriptor exercises failure path.
    let observed_close = unsafe { mq_close(-1) };
    // SAFETY: read errno after wrapper call.
    let observed_close_errno = unsafe { *__errno_location() };

    assert_eq!(observed_close, -1);
    assert_eq!(observed_close_errno, libc::EBADF);

    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null name exercises failure path.
    let observed_unlink = unsafe { mq_unlink(ptr::null()) };
    // SAFETY: read errno after wrapper call.
    let observed_unlink_errno = unsafe { *__errno_location() };

    assert_eq!(observed_unlink, -1);
    assert_eq!(observed_unlink_errno, libc::EFAULT);
}

#[test]
fn mq_getattr_and_setattr_invalid_inputs_report_expected_errno() {
    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid descriptor and null attr pointers.
    let observed_get = unsafe { mq_getattr(-1, ptr::null_mut()) };
    // SAFETY: read errno after wrapper call.
    let observed_get_errno = unsafe { *__errno_location() };

    assert_eq!(observed_get, -1);
    assert_eq!(observed_get_errno, libc::EBADF);

    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid descriptor and null attr pointers.
    let observed_set = unsafe { mq_setattr(-1, ptr::null(), ptr::null_mut()) };
    // SAFETY: read errno after wrapper call.
    let observed_set_errno = unsafe { *__errno_location() };

    assert_eq!(observed_set, -1);
    assert_eq!(observed_set_errno, libc::EBADF);
}

#[test]
fn mq_send_and_receive_invalid_inputs_report_expected_errno() {
    let payload = b"x";
    let mut recv = [0_u8; 8];
    let mut prio: libc::c_uint = 0;

    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid descriptor for send.
    let observed_send = unsafe { mq_send(-1, payload.as_ptr().cast(), payload.len(), 0) };
    // SAFETY: read errno after wrapper call.
    let observed_send_errno = unsafe { *__errno_location() };

    assert_eq!(observed_send, -1);
    assert_eq!(observed_send_errno, libc::EBADF);

    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: invalid descriptor for receive.
    let observed_recv = unsafe { mq_receive(-1, recv.as_mut_ptr().cast(), recv.len(), &mut prio) };
    // SAFETY: read errno after wrapper call.
    let observed_recv_errno = unsafe { *__errno_location() };

    assert_eq!(observed_recv, -1);
    assert_eq!(observed_recv_errno, libc::EBADF);
}

#[test]
fn mq_open_null_name_reports_expected_errno() {
    // SAFETY: reset errno before wrapper call.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null name intentionally exercises failure path.
    let observed = unsafe { mq_open(ptr::null(), libc::O_RDONLY) };
    // SAFETY: read errno after wrapper call.
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EFAULT);
}
