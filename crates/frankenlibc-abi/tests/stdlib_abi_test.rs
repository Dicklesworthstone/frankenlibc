#![cfg(target_os = "linux")]

//! Integration tests for `<stdlib.h>` ABI entrypoints.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::stdlib_abi::{
    atoll, clearenv, getenv, mkostemp, mkostemps, mkstemps, reallocarray, setenv, strtold, strtoll,
    strtoull,
};
use frankenlibc_abi::unistd_abi::{
    confstr, creat64, ctermid, fpathconf, fstat64, fstatat64, ftruncate64, get_avphys_pages,
    get_nprocs, get_nprocs_conf, get_phys_pages, getdomainname, gethostid, getlogin, getlogin_r,
    getpagesize, lockf, lseek64, lstat64, mkdtemp, open64, pathconf, posix_fallocate,
    posix_madvise, pread64, pwrite64, setdomainname, sethostname, stat64, sysconf, truncate64,
};
use std::os::fd::AsRawFd;
use std::ptr;

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
fn getlogin_and_getlogin_r_match_pwd_lookup() {
    // SAFETY: geteuid has no pointer preconditions.
    let uid = unsafe { libc::geteuid() };
    // SAFETY: getpwuid has no pointer preconditions.
    let pwd = unsafe { frankenlibc_abi::pwd_abi::getpwuid(uid) };
    assert!(!pwd.is_null(), "getpwuid should resolve current effective uid");

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

    let mut buf = vec![0_i8; expected.as_bytes().len() + 1];
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
    assert!(!pwd.is_null(), "getpwuid should resolve current effective uid");
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
        assert_eq!(unsafe { getlogin_r(tiny.as_mut_ptr(), tiny.len()) }, libc::ERANGE);
    }
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
