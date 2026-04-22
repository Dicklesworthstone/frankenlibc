#![cfg(target_os = "linux")]

//! Integration tests for `<stdlib.h>` ABI entrypoints.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::resolv_abi::__h_errno_location;
use frankenlibc_abi::stdlib_abi::{
    a64l, at_quick_exit, atoll, clearenv, confstr, drand48, ecvt, erand48, fcvt, gcvt,
    get_avphys_pages, get_nprocs, get_nprocs_conf, get_phys_pages, getenv, getsubopt, initstate,
    jrand48, l64a, lcong48, lrand48, mkostemp, mkostemps, mkstemps, mrand48, nrand48, on_exit,
    qsort_r, random, reallocarray, seed48, setenv, setstate, srand48, srandom, strtold, strtoll,
    strtoq, strtoull, strtouq, system, unsetenv,
};
use frankenlibc_abi::unistd_abi::{
    __sched_cpualloc, __sched_cpucount, __sched_cpufree, close_range, creat64, ctermid, ether_aton,
    ether_aton_r, ether_ntoa, ether_ntoa_r, eventfd_read, eventfd_write, fpathconf, fsconfig,
    fsmount, fsopen, fspick, fstat64, fstatat64, ftruncate64, getcpu, getdomainname, gethostid,
    getlogin, getlogin_r, getopt, getopt_long, getpagesize, grantpt, herror, hstrerror, lockf,
    lseek64, lstat64, mkdtemp, mount_setattr, move_mount, mq_close, mq_getattr, mq_open,
    mq_receive, mq_send, mq_setattr, mq_unlink, msgctl, msgget, msgrcv, msgsnd, nice, open_tree,
    open64, pathconf, pidfd_open, pidfd_send_signal, posix_fadvise, posix_fallocate, posix_madvise,
    posix_openpt, pread64, ptsname, pwrite64, renameat2, sched_get_priority_max,
    sched_get_priority_min, sched_getaffinity, sched_getcpu, sched_getparam, sched_getscheduler,
    sched_rr_get_interval, sched_setaffinity, sched_setparam, sched_setscheduler, semctl, semget,
    semop, setdomainname, sethostname, shm_open, shm_unlink, shmat, shmctl, shmdt, shmget,
    signalfd4, sigqueue, sigtimedwait, sigwaitinfo, stat64, sysconf, sysinfo, timer_create,
    timer_delete, timer_getoverrun, timer_gettime, timer_settime, truncate64, ttyname, ttyname_r,
    unlockpt,
};
use frankenlibc_core::syscall as raw_syscall;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::ptr;
use std::sync::Mutex;
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
static GETOPT_TEST_GUARD: Mutex<()> = Mutex::new(());
static SCHED_AFFINITY_TEST_GUARD: Mutex<()> = Mutex::new(());

const FSCONFIG_SET_FLAG_CMD: libc::c_uint = 0;

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
fn sched_getaffinity_returns_zero_on_success() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        sched_getaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            (&mut cpuset as *mut libc::cpu_set_t).cast(),
        )
    };
    assert_eq!(rc, 0, "sched_getaffinity should normalize success to 0");
}

#[test]
fn sched_setaffinity_accepts_current_mask() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            sched_getaffinity(
                0,
                std::mem::size_of::<libc::cpu_set_t>(),
                (&mut cpuset as *mut libc::cpu_set_t).cast(),
            )
        },
        0
    );
    let rc = unsafe {
        sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            (&cpuset as *const libc::cpu_set_t).cast(),
        )
    };
    assert_eq!(rc, 0, "sched_setaffinity should accept the current mask");
}

#[test]
fn sched_getaffinity_invalid_pid_valid_mask_sets_esrch() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe {
        sched_getaffinity(
            -1,
            std::mem::size_of::<libc::cpu_set_t>(),
            (&mut cpuset as *mut libc::cpu_set_t).cast(),
        )
    };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::ESRCH);
}

#[test]
fn sched_getaffinity_invalid_pid_zero_size_sets_einval() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { sched_getaffinity(-1, 0, (&mut cpuset as *mut libc::cpu_set_t).cast()) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn sched_getaffinity_zero_size_valid_mask_sets_einval_like_host() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc =
        unsafe { libc::sched_getaffinity(0, 0, (&mut cpuset as *mut libc::cpu_set_t).cast()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_getaffinity(0, 0, (&mut cpuset as *mut libc::cpu_set_t).cast()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn sched_getaffinity_valid_size_null_mask_sets_efault_like_host() {
    let _guard = SCHED_AFFINITY_TEST_GUARD
        .lock()
        .expect("affinity test guard lock should succeed");
    let cpusetsize = std::mem::size_of::<libc::cpu_set_t>();

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_getaffinity(0, cpusetsize, ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_getaffinity(0, cpusetsize, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EFAULT);
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
fn strtoq_alias_tracks_native_strtoll_behavior() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtoq(c"-42rest".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, -42);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"-42rest".as_ptr()) };
    assert_eq!(offset, 3);
}

#[test]
fn strtouq_alias_tracks_native_strtoull_behavior() {
    let mut endptr = ptr::null_mut();

    // SAFETY: source is a static NUL-terminated C string and `endptr` is writable.
    let value = unsafe { strtouq(c"77suffix".as_ptr(), &mut endptr, 10) };
    assert_eq!(value, 77);
    assert!(!endptr.is_null());

    // SAFETY: returned endptr points into the source buffer by contract.
    let offset = unsafe { endptr.offset_from(c"77suffix".as_ptr()) };
    assert_eq!(offset, 2);
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

#[test]
fn system_inherits_environment() {
    let name = c"FRANKENLIBC_SYSTEM_ENV_TEST";
    let value = c"visible";
    let command = c"test \"$FRANKENLIBC_SYSTEM_ENV_TEST\" = visible";

    // SAFETY: pointers are valid NUL-terminated C strings.
    assert_eq!(unsafe { setenv(name.as_ptr(), value.as_ptr(), 1) }, 0);

    // SAFETY: command is a valid NUL-terminated C string.
    let status = unsafe { system(command.as_ptr()) };

    // SAFETY: cleanup uses a valid NUL-terminated name.
    assert_eq!(unsafe { unsetenv(name.as_ptr()) }, 0);

    assert_ne!(status, -1);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
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
        let expected_min = match raw_syscall::sys_sched_get_priority_min(policy) {
            Ok(priority) => priority,
            Err(_) => continue,
        };
        let expected_max = match raw_syscall::sys_sched_get_priority_max(policy) {
            Ok(priority) => priority,
            Err(_) => continue,
        };

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
fn sched_priority_bounds_sched_batch_are_zero() {
    unsafe {
        *__errno_location() = 0;
    }
    let min = unsafe { sched_get_priority_min(libc::SCHED_BATCH) };
    let min_errno = unsafe { *__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let max = unsafe { sched_get_priority_max(libc::SCHED_BATCH) };
    let max_errno = unsafe { *__errno_location() };

    assert_eq!(min, 0);
    assert_eq!(min_errno, 0);
    assert_eq!(max, 0);
    assert_eq!(max_errno, 0);
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
    let (expected, expected_errno) = match raw_syscall::sys_sched_getscheduler(0) {
        Ok(policy) => (policy, 0),
        Err(errno) => (-1, errno),
    };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
}

#[test]
fn sched_getscheduler_negative_pid_sets_einval() {
    unsafe {
        *__errno_location() = 0;
    }
    let observed = unsafe { sched_getscheduler(-1) };
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_getscheduler_nonexistent_pid_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_getscheduler(nonexistent_pid) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_getscheduler(nonexistent_pid) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
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
    let (expected, expected_errno) = match unsafe {
        raw_syscall::sys_sched_getparam(0, (&mut expected_param as *mut libc::sched_param).cast())
    } {
        Ok(()) => (0, 0),
        Err(errno) => (-1, errno),
    };

    assert_eq!(observed, expected);
    assert_eq!(observed_errno, expected_errno);
    if observed == 0 {
        assert_eq!(observed_param.sched_priority, expected_param.sched_priority);
    }
}

#[test]
fn sched_getparam_current_pid_null_output_sets_einval() {
    unsafe {
        *__errno_location() = 0;
    }
    let observed = unsafe { sched_getparam(0, ptr::null_mut()) };
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_getparam_negative_pid_null_output_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_getparam(-1, ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_getparam(-1, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn sched_getparam_nonexistent_pid_valid_output_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    let mut host_param = libc::sched_param { sched_priority: -1 };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::sched_getparam(
            nonexistent_pid,
            (&mut host_param as *mut libc::sched_param).cast(),
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    let mut abi_param = libc::sched_param { sched_priority: -1 };
    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        sched_getparam(
            nonexistent_pid,
            (&mut abi_param as *mut libc::sched_param).cast(),
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
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
fn sched_setparam_negative_pid_null_param_sets_einval() {
    unsafe {
        *__errno_location() = 0;
    }
    let observed = unsafe { sched_setparam(-1, ptr::null()) };
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_setparam_nonexistent_pid_valid_param_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    let param = libc::sched_param { sched_priority: 0 };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::sched_setparam(nonexistent_pid, (&param as *const libc::sched_param).cast())
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc =
        unsafe { sched_setparam(nonexistent_pid, (&param as *const libc::sched_param).cast()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
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
fn sched_setscheduler_negative_pid_null_param_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_setscheduler(-1, libc::SCHED_OTHER, ptr::null()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_setscheduler(-1, libc::SCHED_OTHER, ptr::null()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn sched_setscheduler_nonexistent_pid_valid_param_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    let param = libc::sched_param { sched_priority: 0 };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::sched_setscheduler(
            nonexistent_pid,
            libc::SCHED_OTHER,
            (&param as *const libc::sched_param).cast(),
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        sched_setscheduler(
            nonexistent_pid,
            libc::SCHED_OTHER,
            (&param as *const libc::sched_param).cast(),
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
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
    let (expected, expected_errno) = match unsafe {
        raw_syscall::sys_sched_rr_get_interval(0, (&mut expected_tp as *mut libc::timespec).cast())
    } {
        Ok(()) => (0, 0),
        Err(errno) => (-1, errno),
    };

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
fn sched_rr_get_interval_negative_pid_valid_output_sets_einval() {
    let mut observed_tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        *__errno_location() = 0;
    }
    let observed = unsafe { sched_rr_get_interval(-1, &mut observed_tp) };
    let observed_errno = unsafe { *__errno_location() };

    assert_eq!(observed, -1);
    assert_eq!(observed_errno, libc::EINVAL);
}

#[test]
fn sched_rr_get_interval_negative_pid_null_output_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_rr_get_interval(-1, ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_rr_get_interval(-1, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn sched_rr_get_interval_nonexistent_pid_valid_output_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    let mut host_tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_rr_get_interval(nonexistent_pid, &mut host_tp) };
    let host_err = unsafe { *libc::__errno_location() };

    let mut abi_tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_rr_get_interval(nonexistent_pid, &mut abi_tp) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
}

#[test]
fn sched_rr_get_interval_nonexistent_pid_null_output_sets_esrch_like_host() {
    let nonexistent_pid = libc::pid_t::MAX;
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::sched_rr_get_interval(nonexistent_pid, ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { sched_rr_get_interval(nonexistent_pid, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::ESRCH);
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
fn timer_settime_valid_timer_null_new_value_sets_einval_like_host() {
    let Some(host_timer_id) = open_test_timer() else {
        return;
    };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::timer_settime(host_timer_id, 0, ptr::null(), ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };
    assert_eq!(unsafe { libc::timer_delete(host_timer_id) }, 0);

    let Some(abi_timer_id) = open_test_timer() else {
        return;
    };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { timer_settime(abi_timer_id, 0, ptr::null(), ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };
    assert_eq!(unsafe { timer_delete(abi_timer_id) }, 0);

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn timer_gettime_valid_timer_null_output_sets_efault() {
    let Some(timer_id) = open_test_timer() else {
        return;
    };

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { timer_gettime(timer_id, ptr::null_mut()) };
    let err = unsafe { *__errno_location() };

    assert_eq!(unsafe { timer_delete(timer_id) }, 0);
    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn timer_gettime_deleted_timer_handle_sets_einval() {
    let Some(timer_id) = open_test_timer() else {
        return;
    };
    let mut current: libc::itimerspec = unsafe { std::mem::zeroed() };

    assert_eq!(unsafe { timer_delete(timer_id) }, 0);

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { timer_gettime(timer_id, (&mut current as *mut libc::itimerspec).cast()) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn timer_gettime_null_timer_handle_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::timer_gettime(ptr::null_mut(), ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { timer_gettime(ptr::null_mut(), ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from timer_gettime((timer_t)0, NULL): {abi_err}"
    );
}

#[test]
fn timer_delete_null_timer_handle_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::timer_delete(ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { timer_delete(ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from timer_delete((timer_t)0): {abi_err}"
    );
}

#[test]
fn timer_delete_deleted_timer_handle_sets_einval_like_host() {
    let Some(host_timer_id) = open_test_timer() else {
        return;
    };
    assert_eq!(unsafe { libc::timer_delete(host_timer_id) }, 0);

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::timer_delete(host_timer_id) };
    let host_err = unsafe { *libc::__errno_location() };

    let Some(abi_timer_id) = open_test_timer() else {
        return;
    };
    assert_eq!(unsafe { timer_delete(abi_timer_id) }, 0);

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { timer_delete(abi_timer_id) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn timer_getoverrun_deleted_timer_handle_sets_einval_like_host() {
    let Some(host_timer_id) = open_test_timer() else {
        return;
    };
    assert_eq!(unsafe { libc::timer_delete(host_timer_id) }, 0);

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::timer_getoverrun(host_timer_id) };
    let host_err = unsafe { *libc::__errno_location() };

    let Some(abi_timer_id) = open_test_timer() else {
        return;
    };
    assert_eq!(unsafe { timer_delete(abi_timer_id) }, 0);

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { timer_getoverrun(abi_timer_id) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
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
    assert_eq!(observed_timed_errno, libc::EFAULT);

    // SAFETY: __errno_location points to thread-local errno.
    unsafe {
        *__errno_location() = 0;
    }
    // SAFETY: null sigset/info pointers intentionally exercise kernel failure path.
    let observed_wait = unsafe { sigwaitinfo(ptr::null(), ptr::null_mut()) };
    // SAFETY: read errno after call.
    let observed_wait_errno = unsafe { *__errno_location() };

    assert_eq!(observed_wait, -1);
    assert_eq!(observed_wait_errno, libc::EFAULT);
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
    let rc = unsafe {
        sigqueue(
            pid,
            -1,
            libc::sigval {
                sival_ptr: ptr::null_mut(),
            },
        )
    };
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
    let _guard = GETOPT_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
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
    let _guard = GETOPT_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner());
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
    let online = get_nprocs();
    let conf = get_nprocs_conf();

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
        unsafe { raw_syscall::sys_sysinfo(info.as_mut_ptr().cast::<raw_syscall::Sysinfo>()) },
        Ok(())
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

    assert_eq!(get_phys_pages(), expected_phys);

    // Available pages fluctuate and `/proc/meminfo`'s `MemAvailable` (which includes
    // reclaimable page cache) is generally much higher than `sysinfo`'s `freeram`
    // (which does not). We just verify it's a sane positive number and >= freeram.
    let actual_avphys = get_avphys_pages();
    assert!(actual_avphys > 0, "get_avphys_pages() should be > 0");
    assert!(
        actual_avphys >= expected_avphys,
        "get_avphys_pages() ({actual_avphys}) should be >= sysinfo freeram ({expected_avphys})"
    );
}

#[test]
fn abi_sysinfo_reports_memory_and_uptime() {
    let mut info = std::mem::MaybeUninit::<libc::sysinfo>::zeroed();
    assert_eq!(unsafe { sysinfo(info.as_mut_ptr()) }, 0);
    let info = unsafe { info.assume_init() };

    let mem_unit = if info.mem_unit == 0 {
        1_u128
    } else {
        info.mem_unit as u128
    };
    let total_bytes = (info.totalram as u128) * mem_unit;
    let free_bytes = (info.freeram as u128) * mem_unit;

    assert!(info.uptime >= 0);
    assert!(total_bytes > 0);
    assert!(free_bytes <= total_bytes);
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

// ===========================================================================
// drand48 family tests
//
// `drand48()`/`srand48()` use global PRNG state. Tests that depend on
// deterministic seed→output mapping must be serialized to avoid interleaving.
// ===========================================================================

fn drand48_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("drand48 lock should not be poisoned")
}

#[test]
fn drand48_seeded_deterministic() {
    let _lock = drand48_lock();
    unsafe {
        srand48(42);
        let a = drand48();
        srand48(42);
        let b = drand48();
        assert_eq!(a, b);
    }
}

#[test]
fn drand48_returns_in_range() {
    let _lock = drand48_lock();
    unsafe {
        srand48(1);
        for _ in 0..50 {
            let v = drand48();
            assert!((0.0..1.0).contains(&v), "drand48 out of range: {v}");
        }
    }
}

#[test]
fn lrand48_returns_non_negative() {
    let _lock = drand48_lock();
    unsafe {
        srand48(1);
        for _ in 0..50 {
            let v = lrand48();
            assert!(v >= 0, "lrand48 negative: {v}");
        }
    }
}

#[test]
fn mrand48_returns_signed_long() {
    let _lock = drand48_lock();
    unsafe {
        srand48(1);
        let a = mrand48();
        let b = mrand48();
        assert_ne!(a, b);
    }
}

#[test]
fn erand48_uses_caller_state() {
    // erand48 uses caller-supplied state, not global — no lock needed.
    let mut state1 = [0x1234u16, 0x5678, 0x9ABC];
    let mut state2 = [0x1234u16, 0x5678, 0x9ABC];
    let a = unsafe { erand48(state1.as_mut_ptr()) };
    let b = unsafe { erand48(state2.as_mut_ptr()) };
    assert_eq!(a, b);
    assert_eq!(state1, state2);
}

#[test]
fn nrand48_uses_caller_state() {
    // nrand48 uses caller-supplied state, not global — no lock needed.
    let mut state = [0u16, 0, 1];
    let v = unsafe { nrand48(state.as_mut_ptr()) };
    assert!(v >= 0, "nrand48 negative: {v}");
}

#[test]
fn jrand48_uses_caller_state() {
    // jrand48 uses caller-supplied state, not global — no lock needed.
    let mut state = [0xFFFFu16, 0xFFFF, 0xFFFF];
    let _ = unsafe { jrand48(state.as_mut_ptr()) };
}

#[test]
fn seed48_returns_old_state() {
    let _lock = drand48_lock();
    unsafe {
        srand48(100);
        let _ = drand48();
        let mut new_seed = [0x1111u16, 0x2222, 0x3333];
        let old_ptr = seed48(new_seed.as_mut_ptr());
        assert!(!old_ptr.is_null());
    }
}

#[test]
fn lcong48_sets_custom_params() {
    let _lock = drand48_lock();
    unsafe {
        let mut params = [0u16, 0, 0, 1, 0, 0, 1];
        lcong48(params.as_mut_ptr());
        let v = drand48();
        let expected = 1.0 / ((1u64 << 48) as f64);
        assert!((v - expected).abs() < 1e-20, "lcong48 custom: {v}");
    }
}

// ===========================================================================
// random family tests
//
// `random()`/`srandom()` use global PRNG state. Tests that depend on
// deterministic seed→output mapping must be serialized to avoid interleaving.
// ===========================================================================

fn random_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("random lock should not be poisoned")
}

#[test]
fn random_seeded_deterministic() {
    let _lock = random_lock();
    unsafe {
        srandom(42);
        let a = random();
        srandom(42);
        let b = random();
        assert_eq!(a, b);
    }
}

#[test]
fn random_returns_non_negative() {
    let _lock = random_lock();
    unsafe {
        srandom(1);
        for _ in 0..50 {
            let v = random();
            assert!(v >= 0, "random negative: {v}");
        }
    }
}

#[test]
fn initstate_setstate_roundtrip() {
    let _lock = random_lock();
    unsafe {
        srandom(99);
        let mut buf = vec![0u8; 256];
        let _ = initstate(99, buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        let seq1: Vec<libc::c_long> = (0..5).map(|_| random()).collect();
        let _ = setstate(buf.as_mut_ptr() as *mut libc::c_char);
        let seq2: Vec<libc::c_long> = (0..5).map(|_| random()).collect();
        assert_eq!(seq1, seq2);
    }
}

// ===========================================================================
// qsort_r test
// ===========================================================================

unsafe extern "C" fn cmp_int_with_ctx(
    a: *const libc::c_void,
    b: *const libc::c_void,
    _ctx: *mut libc::c_void,
) -> libc::c_int {
    let va = unsafe { *(a as *const i32) };
    let vb = unsafe { *(b as *const i32) };
    va.cmp(&vb) as libc::c_int
}

#[test]
fn qsort_r_sorts_integers() {
    let mut arr = [5i32, 3, 8, 1, 4, 2, 7, 6];
    unsafe {
        qsort_r(
            arr.as_mut_ptr() as *mut libc::c_void,
            arr.len(),
            std::mem::size_of::<i32>(),
            Some(cmp_int_with_ctx),
            ptr::null_mut(),
        );
    }
    assert_eq!(arr, [1, 2, 3, 4, 5, 6, 7, 8]);
}

// ===========================================================================
// a64l / l64a tests
// ===========================================================================

#[test]
fn a64l_basic_values() {
    let dot = CString::new(".").unwrap();
    let slash = CString::new("/").unwrap();
    let zero = CString::new("0").unwrap();
    let cap_a = CString::new("A").unwrap();
    unsafe {
        assert_eq!(a64l(dot.as_ptr()), 0);
        assert_eq!(a64l(slash.as_ptr()), 1);
        assert_eq!(a64l(zero.as_ptr()), 2);
        assert_eq!(a64l(cap_a.as_ptr()), 12);
    }
}

#[test]
fn l64a_a64l_roundtrip() {
    for val in [1i64, 42, 100, 1000, 123456, 2_000_000_000] {
        unsafe {
            let encoded = l64a(val as libc::c_long);
            assert!(!encoded.is_null());
            let decoded = a64l(encoded);
            assert_eq!(decoded as i64, val, "roundtrip failed for {val}");
        }
    }
}

// ===========================================================================
// ecvt / fcvt / gcvt tests
// ecvt and fcvt share a process-wide static buffer, so tests must be
// serialized to avoid data races when cargo test runs them in parallel.
// ===========================================================================

fn ecvt_fcvt_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[test]
fn ecvt_basic_conversion() {
    let _guard = ecvt_fcvt_lock();
    let mut decpt: libc::c_int = 0;
    let mut sign: libc::c_int = 0;
    let result = unsafe { ecvt(123.456, 6, &mut decpt, &mut sign) };
    assert!(!result.is_null());
    assert_eq!(sign, 0);
    assert_eq!(decpt, 3);
    let s = unsafe { std::ffi::CStr::from_ptr(result) };
    assert_eq!(s.to_str().unwrap(), "123456");
}

#[test]
fn ecvt_negative_value() {
    let _guard = ecvt_fcvt_lock();
    let mut decpt: libc::c_int = 0;
    let mut sign: libc::c_int = 0;
    let _ = unsafe { ecvt(-42.0, 4, &mut decpt, &mut sign) };
    assert_eq!(sign, 1);
}

#[test]
fn fcvt_basic_conversion() {
    let _guard = ecvt_fcvt_lock();
    let mut decpt: libc::c_int = 0;
    let mut sign: libc::c_int = 0;
    let result = unsafe { fcvt(123.456, 3, &mut decpt, &mut sign) };
    assert!(!result.is_null());
    assert_eq!(sign, 0);
    assert_eq!(decpt, 3);
}

#[test]
fn gcvt_basic_conversion() {
    let mut buf = [0u8; 64];
    let result = unsafe { gcvt(3.25, 4, buf.as_mut_ptr() as *mut libc::c_char) };
    assert!(!result.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(result) };
    assert!(s.to_str().unwrap().contains("3.25"));
}

// ===========================================================================
// on_exit / at_quick_exit tests
// ===========================================================================

static ON_EXIT_CALLED: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn on_exit_handler(_status: libc::c_int, _arg: *mut libc::c_void) {
    ON_EXIT_CALLED.store(1, Ordering::SeqCst);
}

#[test]
fn on_exit_registration_succeeds() {
    unsafe {
        let result = on_exit(Some(on_exit_handler), ptr::null_mut());
        assert_eq!(result, 0);
    }
}

#[test]
fn on_exit_null_function_returns_error() {
    unsafe {
        let result = on_exit(None, ptr::null_mut());
        assert_eq!(result, -1);
    }
}

unsafe extern "C" fn quick_exit_handler_noop() {}

#[test]
fn at_quick_exit_registration_succeeds() {
    unsafe {
        let result = at_quick_exit(Some(quick_exit_handler_noop));
        assert_eq!(result, 0);
    }
}

#[test]
fn at_quick_exit_null_function_returns_error() {
    unsafe {
        let result = at_quick_exit(None);
        assert_eq!(result, -1);
    }
}

// ===========================================================================
// getsubopt test
// ===========================================================================

#[test]
fn getsubopt_parses_suboptions() {
    let tok_ro = CString::new("ro").unwrap();
    let tok_rw = CString::new("rw").unwrap();
    let tok_size = CString::new("size").unwrap();

    let tokens_raw: [*mut libc::c_char; 4] = [
        tok_ro.as_ptr() as *mut libc::c_char,
        tok_rw.as_ptr() as *mut libc::c_char,
        tok_size.as_ptr() as *mut libc::c_char,
        ptr::null_mut(),
    ];

    let input = CString::new("rw,size=1024,ro").unwrap();
    let mut buf: Vec<u8> = input.into_bytes_with_nul();
    let mut opt_ptr = buf.as_mut_ptr() as *mut libc::c_char;
    let mut valuep: *mut libc::c_char = ptr::null_mut();

    unsafe {
        let idx = getsubopt(&mut opt_ptr, tokens_raw.as_ptr(), &mut valuep);
        assert_eq!(idx, 1, "expected 'rw' at index 1");
        assert!(valuep.is_null(), "'rw' should have no value");

        let idx = getsubopt(&mut opt_ptr, tokens_raw.as_ptr(), &mut valuep);
        assert_eq!(idx, 2, "expected 'size' at index 2");
        assert!(!valuep.is_null());
        let val = std::ffi::CStr::from_ptr(valuep);
        assert_eq!(val.to_str().unwrap(), "1024");

        let idx = getsubopt(&mut opt_ptr, tokens_raw.as_ptr(), &mut valuep);
        assert_eq!(idx, 0, "expected 'ro' at index 0");
        assert!(valuep.is_null(), "'ro' should have no value");
    }
}

#[test]
fn getsubopt_unknown_token_returns_minus_one() {
    let tok_foo = CString::new("foo").unwrap();
    let tokens_raw: [*mut libc::c_char; 2] =
        [tok_foo.as_ptr() as *mut libc::c_char, ptr::null_mut()];
    let input = CString::new("bar").unwrap();
    let mut buf: Vec<u8> = input.into_bytes_with_nul();
    let mut opt_ptr = buf.as_mut_ptr() as *mut libc::c_char;
    let mut valuep: *mut libc::c_char = ptr::null_mut();

    unsafe {
        let idx = getsubopt(&mut opt_ptr, tokens_raw.as_ptr(), &mut valuep);
        assert_eq!(idx, -1);
        assert_eq!(std::ffi::CStr::from_ptr(valuep).to_bytes(), b"bar");
    }
}

#[test]
fn getsubopt_unknown_value_returns_entire_suboption() {
    let tok_foo = CString::new("foo").unwrap();
    let tokens_raw: [*mut libc::c_char; 2] =
        [tok_foo.as_ptr() as *mut libc::c_char, ptr::null_mut()];
    let input = CString::new("bar=baz,foo").unwrap();
    let mut buf: Vec<u8> = input.into_bytes_with_nul();
    let mut opt_ptr = buf.as_mut_ptr() as *mut libc::c_char;
    let mut valuep: *mut libc::c_char = ptr::null_mut();

    unsafe {
        let idx = getsubopt(&mut opt_ptr, tokens_raw.as_ptr(), &mut valuep);
        assert_eq!(idx, -1);
        assert_eq!(std::ffi::CStr::from_ptr(valuep).to_bytes(), b"bar=baz");
        assert_eq!(std::ffi::CStr::from_ptr(opt_ptr).to_bytes(), b"foo");
    }
}

// ===========================================================================
// on_exit handler invocation via fork+exit
// ===========================================================================

#[test]
fn on_exit_handler_called_during_exit_in_child() {
    // Fork a child, register an on_exit handler that writes a byte to a pipe,
    // call exit(0), and verify the parent reads the byte.
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() failed");

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork() failed");

    if pid == 0 {
        // Child: close read end, register on_exit handler, call exit.
        unsafe { libc::close(fds[0]) };

        unsafe extern "C" fn write_pipe(status: libc::c_int, arg: *mut libc::c_void) {
            let fd = arg as usize as i32;
            let byte = [status as u8];
            unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
        }

        let write_fd = fds[1] as usize as *mut libc::c_void;
        unsafe { on_exit(Some(write_pipe), write_fd) };
        // Must use exit() (not _exit) — on_exit handlers only run via exit().
        unsafe { frankenlibc_abi::stdlib_abi::exit(42) };
    }

    // Parent: close write end, read the byte.
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr().cast(), 1) };
    unsafe { libc::close(fds[0]) };

    // Reap child.
    let mut wstatus = 0i32;
    unsafe { libc::waitpid(pid, &mut wstatus, 0) };

    assert_eq!(n, 1, "on_exit handler should write 1 byte to pipe");
    assert_eq!(buf[0], 42, "on_exit handler should receive exit status 42");
}

#[test]
fn eventfd_read_invalid_fd_preserves_ebadf() {
    let mut value = 0_u64;
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { eventfd_read(-1, &mut value) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EBADF);
}

#[test]
fn eventfd_read_valid_fd_null_output_sets_efault() {
    let fd = unsafe { libc::eventfd(1, 0) };
    assert!(fd >= 0, "eventfd should create a readable descriptor");

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { eventfd_read(fd, ptr::null_mut()) };
    let err = unsafe { *__errno_location() };

    unsafe {
        libc::close(fd);
    }

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn eventfd_read_invalid_fd_null_output_preserves_ebadf_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::eventfd_read(-1, ptr::null_mut()) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { eventfd_read(-1, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EBADF,
        "unexpected errno from eventfd_read(-1, NULL): {abi_err}"
    );
}

#[test]
fn eventfd_read_nonblocking_empty_counter_sets_eagain_like_host() {
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
    assert!(fd >= 0, "eventfd should create a nonblocking descriptor");

    let mut host_value = 0_u64;
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::eventfd_read(fd, &mut host_value) };
    let host_err = unsafe { *libc::__errno_location() };

    let mut abi_value = 0_u64;
    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { eventfd_read(fd, &mut abi_value) };
    let abi_err = unsafe { *__errno_location() };

    unsafe {
        libc::close(fd);
    }

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EAGAIN);
    assert_eq!(host_value, 0);
    assert_eq!(abi_value, 0);
}

#[test]
fn eventfd_write_invalid_fd_forbidden_all_ones_preserves_ebadf_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::eventfd_write(-1, u64::MAX) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { eventfd_write(-1, u64::MAX) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EBADF);
}

#[test]
fn eventfd_write_valid_fd_forbidden_all_ones_sets_einval() {
    let fd = unsafe { libc::eventfd(0, 0) };
    assert!(fd >= 0, "eventfd should create a writable descriptor");

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::eventfd_write(fd, u64::MAX) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { eventfd_write(fd, u64::MAX) };
    let abi_err = unsafe { *__errno_location() };

    unsafe {
        libc::close(fd);
    }

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, host_rc);
    assert_eq!(abi_err, host_err);
    assert_eq!(abi_err, libc::EINVAL);
}

#[test]
fn close_range_reversed_bounds_set_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::close_range(5, 4, 0) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { close_range(5, 4, 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from close_range(5, 4, 0): {abi_err}"
    );
}

#[test]
fn close_range_invalid_flags_set_einval_like_host() {
    let invalid_flags = 0x8000_0000_u32;

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::close_range(0, 0, invalid_flags as libc::c_int) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { close_range(0, 0, invalid_flags) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from close_range(0, 0, 0x80000000): {abi_err}"
    );
}

#[test]
fn close_range_invalid_flags_on_reversed_bounds_set_einval_like_host() {
    let invalid_flags = 0x8000_0000_u32;

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::close_range(5, 4, invalid_flags as libc::c_int) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { close_range(5, 4, invalid_flags) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from close_range(5, 4, 0x80000000): {abi_err}"
    );
}

#[test]
fn posix_fadvise_invalid_fd_returns_ebadf_directly() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { posix_fadvise(-1, 0, 0, 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, libc::EBADF);
    assert_eq!(err, 0, "posix_fadvise should not report errors via errno");
}

#[test]
fn renameat2_null_paths_set_efault() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { renameat2(libc::AT_FDCWD, ptr::null(), libc::AT_FDCWD, ptr::null(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn renameat2_invalid_flags_override_both_null_paths_with_einval_like_host() {
    let invalid_flags = 0x8000_0000_u32;

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            invalid_flags,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        renameat2(
            libc::AT_FDCWD,
            ptr::null(),
            libc::AT_FDCWD,
            ptr::null(),
            invalid_flags,
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from renameat2(AT_FDCWD, NULL, AT_FDCWD, NULL, 0x80000000): {abi_err}"
    );
}

#[test]
fn renameat2_invalid_flags_override_null_newpath_with_einval_like_host() {
    let invalid_flags = 0x8000_0000_u32;
    let dot = CString::new(".").unwrap();

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            dot.as_ptr(),
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            invalid_flags,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        renameat2(
            libc::AT_FDCWD,
            dot.as_ptr(),
            libc::AT_FDCWD,
            ptr::null(),
            invalid_flags,
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from renameat2(AT_FDCWD, \".\", AT_FDCWD, NULL, 0x80000000): {abi_err}"
    );
}

#[test]
fn renameat2_null_oldpath_sets_efault() {
    let dot = CString::new(".").unwrap();

    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { renameat2(libc::AT_FDCWD, ptr::null(), libc::AT_FDCWD, dot.as_ptr(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn getcpu_invalid_pointer_sets_efault() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe {
        getcpu(
            std::ptr::dangling_mut::<libc::c_uint>(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn getcpu_all_null_outputs_succeeds_without_touching_errno() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { getcpu(ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, 0, "getcpu(NULL, NULL, NULL) should succeed");
    assert_eq!(err, 0, "getcpu(NULL, NULL, NULL) should not touch errno");
}

#[test]
fn getcpu_null_cpu_pointer_with_valid_node_succeeds_without_touching_errno_like_host() {
    let mut host_node = 0_u32;
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            ptr::null_mut::<libc::c_uint>(),
            &mut host_node as *mut u32,
            ptr::null_mut::<libc::c_void>(),
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    let mut abi_node = 0_u32;
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { getcpu(ptr::null_mut(), &mut abi_node, ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, 0, "host getcpu(NULL, &node, NULL) should succeed");
    assert_eq!(abi_rc, 0, "getcpu(NULL, &node, NULL) should succeed");
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::E2BIG,
        "getcpu(NULL, &node, NULL) should preserve errno"
    );
}

#[test]
fn getcpu_null_node_pointer_with_valid_cpu_succeeds_without_touching_errno_like_host() {
    let mut host_cpu = 0_u32;
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            &mut host_cpu as *mut u32,
            ptr::null_mut::<libc::c_uint>(),
            ptr::null_mut::<libc::c_void>(),
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    let mut abi_cpu = 0_u32;
    unsafe {
        *__errno_location() = libc::E2BIG;
    }
    let abi_rc = unsafe { getcpu(&mut abi_cpu, ptr::null_mut(), ptr::null_mut()) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, 0, "host getcpu(&cpu, NULL, NULL) should succeed");
    assert_eq!(abi_rc, 0, "getcpu(&cpu, NULL, NULL) should succeed");
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::E2BIG,
        "getcpu(&cpu, NULL, NULL) should preserve errno"
    );
}

#[test]
fn signalfd4_invalid_flags_set_einval() {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        *__errno_location() = 0;
    }
    let rc = unsafe { signalfd4(-1, (&mask as *const libc::sigset_t).cast(), -1) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EINVAL);
}

#[test]
fn signalfd4_valid_mask_zero_flags_succeeds_without_touching_errno() {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        *__errno_location() = libc::EAGAIN;
    }
    let fd = unsafe { signalfd4(-1, (&mask as *const libc::sigset_t).cast(), 0) };
    let err = unsafe { *__errno_location() };

    assert!(fd >= 0, "signalfd4(-1, &mask, 0) should succeed");
    assert_eq!(
        err,
        libc::EAGAIN,
        "signalfd4(-1, &mask, 0) should not touch errno"
    );

    unsafe {
        libc::close(fd);
    }
}

#[test]
fn signalfd4_null_mask_with_exact_sizemask_sets_efault_like_host() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { signalfd4(-1, ptr::null(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn signalfd4_null_mask_keeps_efault_even_with_invalid_flags_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_signalfd4,
            -1,
            ptr::null::<libc::sigset_t>(),
            std::mem::size_of::<u64>(),
            -1,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { signalfd4(-1, ptr::null(), -1) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EFAULT,
        "unexpected errno from signalfd4(-1, NULL, -1): {abi_err}"
    );
}

#[test]
fn mount_setattr_null_path_sets_einval_like_host() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { mount_setattr(libc::AT_FDCWD, ptr::null(), 0, ptr::null_mut(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EINVAL,
        "unexpected errno from mount_setattr(null): {err}"
    );
}

#[test]
fn fsconfig_invalid_fsfd_with_null_key_value_sets_einval_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            -1,
            FSCONFIG_SET_FLAG_CMD,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0_usize,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsconfig(-1, FSCONFIG_SET_FLAG_CMD, ptr::null(), ptr::null(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from fsconfig(-1, FSCONFIG_SET_FLAG, NULL, NULL, 0): {abi_err}"
    );
}

#[test]
fn fsconfig_invalid_fsfd_with_set_flag_key_sets_einval_like_host() {
    let key = CString::new("k").expect("valid key");
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { fsconfig(-1, FSCONFIG_SET_FLAG_CMD, key.as_ptr(), ptr::null(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EINVAL,
        "unexpected errno from fsconfig(-1, FSCONFIG_SET_FLAG, \"k\", NULL, 0): {err}"
    );
}

#[test]
fn fsconfig_invalid_command_on_invalid_fsfd_still_sets_einval_like_host() {
    let key = CString::new("k").expect("valid key");
    let invalid_cmd = 999_u32;

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            -1,
            invalid_cmd,
            key.as_ptr(),
            ptr::null::<libc::c_char>(),
            0_usize,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsconfig(-1, invalid_cmd, key.as_ptr(), ptr::null(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from fsconfig(-1, 999, \"k\", NULL, 0): {abi_err}"
    );
}

#[test]
fn fsconfig_invalid_fsfd_with_string_payload_sets_einval_like_host() {
    let key = CString::new("k").expect("valid key");
    let value = CString::new("v").expect("valid value");
    let set_string_cmd = 1_u32;

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            -1,
            set_string_cmd,
            key.as_ptr(),
            value.as_ptr(),
            0_usize,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsconfig(-1, set_string_cmd, key.as_ptr(), value.as_ptr().cast(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EINVAL,
        "unexpected errno from fsconfig(-1, FSCONFIG_SET_STRING, \"k\", \"v\", 0): {abi_err}"
    );
}

#[test]
fn fsopen_nonzero_flags_with_valid_fsname_preserves_eperm_like_host() {
    let fsname = CString::new("tmpfs").expect("valid fsname");
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { fsopen(fsname.as_ptr(), 1) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EPERM,
        "unexpected errno from fsopen(\"tmpfs\", 1): {err}"
    );
}

#[test]
fn fsopen_null_fsname_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::syscall(libc::SYS_fsopen, ptr::null::<libc::c_char>(), 0_u32) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsopen(ptr::null(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fsopen(NULL, 0): {abi_err}"
    );
}

#[test]
fn fsopen_null_fsname_nonzero_flags_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::syscall(libc::SYS_fsopen, ptr::null::<libc::c_char>(), 1_u32) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsopen(ptr::null(), 1) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fsopen(NULL, 1): {abi_err}"
    );
}

#[test]
fn fsmount_invalid_fsfd_preserves_unprivileged_eperm_like_host() {
    for flags in [0_u32, 1_u32] {
        unsafe {
            *libc::__errno_location() = 0;
        }
        let host_rc = unsafe { libc::syscall(libc::SYS_fsmount, -1, flags, 0_u32) };
        let host_err = unsafe { *libc::__errno_location() };

        unsafe {
            *__errno_location() = 0;
        }
        let abi_rc = unsafe { fsmount(-1, flags, 0) };
        let abi_err = unsafe { *__errno_location() };

        assert_eq!(host_rc, -1);
        assert_eq!(abi_rc, -1);
        assert_eq!(abi_err, host_err);
        assert_eq!(
            abi_err,
            libc::EPERM,
            "unexpected errno from fsmount(-1, {flags}, 0): {abi_err}"
        );
    }
}

#[test]
fn fsmount_invalid_flags_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::syscall(libc::SYS_fsmount, -1, 2_u32, 0_u32) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsmount(-1, 2, 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fsmount(-1, 2, 0): {abi_err}"
    );
}

#[test]
fn fsmount_invalid_attr_flags_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe { libc::syscall(libc::SYS_fsmount, -1, 0_u32, 1_u32) };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fsmount(-1, 0, 1) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fsmount(-1, 0, 1): {abi_err}"
    );
}

#[test]
fn move_mount_null_target_path_preserves_unprivileged_eperm_like_host() {
    let source_path = CString::new("/").expect("valid source path");

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            libc::AT_FDCWD,
            source_path.as_ptr(),
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            0_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        move_mount(
            libc::AT_FDCWD,
            source_path.as_ptr(),
            libc::AT_FDCWD,
            ptr::null(),
            0,
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from move_mount(AT_FDCWD, \"/\", AT_FDCWD, NULL, 0): {abi_err}"
    );
}

#[test]
fn move_mount_both_null_paths_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            0_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { move_mount(libc::AT_FDCWD, ptr::null(), libc::AT_FDCWD, ptr::null(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from move_mount(AT_FDCWD, NULL, AT_FDCWD, NULL, 0): {abi_err}"
    );
}

#[test]
fn move_mount_both_null_paths_with_nonzero_flags_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            1_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { move_mount(libc::AT_FDCWD, ptr::null(), libc::AT_FDCWD, ptr::null(), 1) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from move_mount(AT_FDCWD, NULL, AT_FDCWD, NULL, 1): {abi_err}"
    );
}

#[test]
fn move_mount_null_source_path_with_nonzero_flags_preserves_unprivileged_eperm_like_host() {
    let target_path = CString::new("/").expect("valid target path");

    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            libc::AT_FDCWD,
            target_path.as_ptr(),
            1_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe {
        move_mount(
            libc::AT_FDCWD,
            ptr::null(),
            libc::AT_FDCWD,
            target_path.as_ptr(),
            1,
        )
    };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from move_mount(AT_FDCWD, NULL, AT_FDCWD, \"/\", 1): {abi_err}"
    );
}

#[test]
fn fspick_null_path_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_fspick,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            0_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fspick(libc::AT_FDCWD, ptr::null(), 0) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fspick(AT_FDCWD, NULL, 0): {abi_err}"
    );
}

#[test]
fn fspick_null_path_nonzero_flags_preserves_unprivileged_eperm_like_host() {
    unsafe {
        *libc::__errno_location() = 0;
    }
    let host_rc = unsafe {
        libc::syscall(
            libc::SYS_fspick,
            libc::AT_FDCWD,
            ptr::null::<libc::c_char>(),
            1_u32,
        )
    };
    let host_err = unsafe { *libc::__errno_location() };

    unsafe {
        *__errno_location() = 0;
    }
    let abi_rc = unsafe { fspick(libc::AT_FDCWD, ptr::null(), 1) };
    let abi_err = unsafe { *__errno_location() };

    assert_eq!(host_rc, -1);
    assert_eq!(abi_rc, -1);
    assert_eq!(abi_err, host_err);
    assert_eq!(
        abi_err,
        libc::EPERM,
        "unexpected errno from fspick(AT_FDCWD, NULL, 1): {abi_err}"
    );
}

#[test]
fn open_tree_null_path_sets_efault_like_host() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { open_tree(libc::AT_FDCWD, ptr::null(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EFAULT,
        "unexpected errno from open_tree(null): {err}"
    );
}

#[test]
fn pidfd_open_current_pid_succeeds_without_touching_errno() {
    unsafe {
        *__errno_location() = libc::EAGAIN;
    }
    let pidfd = unsafe { pidfd_open(libc::getpid(), 0) };
    let err = unsafe { *__errno_location() };

    assert!(pidfd >= 0, "pidfd_open(getpid(), 0) should succeed");
    assert_eq!(
        err,
        libc::EAGAIN,
        "pidfd_open(getpid(), 0) should not touch errno"
    );

    unsafe {
        libc::close(pidfd);
    }
}

#[test]
fn pidfd_open_current_pid_invalid_flags_set_einval_like_host() {
    // bd-3srp: host glibc surfaces EINVAL for pidfd_open(getpid(), 1).
    // Assertion already exact — keeping as the host-parity regression
    // gate for flag validation.
    unsafe {
        *__errno_location() = libc::EAGAIN;
    }
    let pidfd = unsafe { pidfd_open(libc::getpid(), 1) };
    let err = unsafe { *__errno_location() };

    assert_eq!(pidfd, -1);
    assert_eq!(
        err,
        libc::EINVAL,
        "unexpected errno from pidfd_open(getpid(), 1): {err}"
    );
}

#[test]
fn pidfd_open_invalid_pid_sets_einval_like_host() {
    // bd-11sh: host glibc surfaces EINVAL for pidfd_open(-1, 0) —
    // negative pid fails validation before any process-lookup step.
    unsafe {
        *__errno_location() = libc::EAGAIN;
    }
    let pidfd = unsafe { pidfd_open(-1, 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(pidfd, -1);
    assert_eq!(
        err,
        libc::EINVAL,
        "unexpected errno from pidfd_open(-1, 0): {err}"
    );
}

#[test]
fn pidfd_open_invalid_pid_dominates_invalid_flags_with_einval_like_host() {
    // bd-k59i: host glibc keeps the invalid-pid EINVAL contract even
    // when flags are also invalid.
    unsafe {
        *__errno_location() = libc::EAGAIN;
    }
    let pidfd = unsafe { pidfd_open(-1, 1) };
    let err = unsafe { *__errno_location() };

    assert_eq!(pidfd, -1);
    assert_eq!(
        err,
        libc::EINVAL,
        "unexpected errno from pidfd_open(-1, 1): {err}"
    );
}

#[test]
fn pidfd_send_signal_invalid_pidfd_sets_ebadf_like_host() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { pidfd_send_signal(-1, 0, ptr::null(), 0) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EBADF,
        "unexpected errno from pidfd_send_signal(-1): {err}"
    );
}

#[test]
fn pidfd_send_signal_invalid_flags_do_not_override_bad_pidfd() {
    unsafe {
        *__errno_location() = 0;
    }
    let rc = unsafe { pidfd_send_signal(-1, 0, ptr::null(), 1) };
    let err = unsafe { *__errno_location() };

    assert_eq!(rc, -1);
    assert_eq!(
        err,
        libc::EBADF,
        "unexpected errno from pidfd_send_signal(-1, flags=1): {err}"
    );
}

#[test]
fn sched_getcpu_success_does_not_set_errno() {
    unsafe {
        *__errno_location() = 0;
    }
    let cpu = unsafe { sched_getcpu() };
    let err = unsafe { *__errno_location() };

    assert!(cpu >= 0, "sched_getcpu should succeed on Linux");
    assert_eq!(err, 0, "sched_getcpu success should not touch errno");
}

#[test]
fn sched_cpualloc_large_set_roundtrips_and_frees() {
    const CPU_COUNT: libc::c_int = 4096;
    let set = unsafe { __sched_cpualloc(CPU_COUNT) };
    assert!(
        !set.is_null(),
        "__sched_cpualloc should allocate large cpusets"
    );

    let size = (CPU_COUNT as usize).div_ceil(8).max(128);
    let bytes = unsafe { std::slice::from_raw_parts_mut(set.cast::<u8>(), size) };
    bytes[0] = 0b0000_0011;
    bytes[size - 1] = 0b1000_0000;

    let count = unsafe { __sched_cpucount(size, set.cast()) };
    assert_eq!(count, 3, "__sched_cpucount should count all set bits");

    unsafe { __sched_cpufree(set) };
}
