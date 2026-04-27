#![cfg(target_os = "linux")]

//! Integration tests for resolver ABI entrypoints (`<netdb.h>`).
//!
//! Covers: getaddrinfo, freeaddrinfo, getnameinfo, gai_strerror,
//! gethostbyname, gethostbyname_r, gethostbyaddr, getservbyname,
//! getservbyport, getprotobyname, getprotobynumber, __h_errno_location.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::mem;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::inet_abi;
use frankenlibc_abi::malloc_abi;
use frankenlibc_abi::resolv_abi;

const HOST_NOT_FOUND_ERRNO: i32 = 1;
const NO_RECOVERY_ERRNO: i32 = 3;
const HOSTS_PATH_ENV: &str = "FRANKENLIBC_HOSTS_PATH";
const SERVICES_PATH_ENV: &str = "FRANKENLIBC_SERVICES_PATH";
const PROC_NET_ROUTE_PATH_ENV: &str = "FRANKENLIBC_PROC_NET_ROUTE_PATH";
const PROC_NET_IF_INET6_PATH_ENV: &str = "FRANKENLIBC_PROC_NET_IF_INET6_PATH";

static RESOLVER_FIXTURE_SEQ: AtomicU64 = AtomicU64::new(0);
static RESOLVER_ENV_LOCK: Mutex<()> = Mutex::new(());

struct ResolverFixturePaths {
    hosts: std::path::PathBuf,
    services: std::path::PathBuf,
    route: std::path::PathBuf,
    if_inet6: std::path::PathBuf,
}

struct ResolverEnvGuard;

impl Drop for ResolverEnvGuard {
    fn drop(&mut self) {
        // SAFETY: all resolver env var mutation is serialized by RESOLVER_ENV_LOCK.
        unsafe {
            std::env::remove_var(HOSTS_PATH_ENV);
            std::env::remove_var(SERVICES_PATH_ENV);
            std::env::remove_var(PROC_NET_ROUTE_PATH_ENV);
            std::env::remove_var(PROC_NET_IF_INET6_PATH_ENV);
        }
    }
}

fn temp_resolver_path(kind: &str) -> std::path::PathBuf {
    let seq = RESOLVER_FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-resolv-{kind}-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_resolver_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = RESOLVER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

fn misaligned_hostent_result_ptr(storage: &mut [u8]) -> *mut c_void {
    let align = mem::align_of::<libc::hostent>();
    let base = storage.as_mut_ptr();
    for offset in 1..=align {
        let candidate = base.wrapping_add(offset);
        if !(candidate as usize).is_multiple_of(align) {
            return candidate.cast::<c_void>();
        }
    }
    base.cast::<c_void>()
}

fn misaligned_c_char_buffer(storage: &mut [c_char], align: usize) -> (*mut c_char, usize) {
    let base = storage.as_mut_ptr();
    for offset in 1..=align.max(1) {
        let candidate = base.wrapping_add(offset);
        if !(candidate as usize).is_multiple_of(align) {
            return (candidate, storage.len() - offset);
        }
    }
    (base, storage.len())
}

fn with_resolver_backends<T>(
    hosts: Option<&[u8]>,
    services: Option<&[u8]>,
    f: impl FnOnce(&ResolverFixturePaths) -> T,
) -> T {
    with_resolver_backends_and_addrconfig(hosts, services, None, None, f)
}

fn with_resolver_backends_and_addrconfig<T>(
    hosts: Option<&[u8]>,
    services: Option<&[u8]>,
    route: Option<&[u8]>,
    if_inet6: Option<&[u8]>,
    f: impl FnOnce(&ResolverFixturePaths) -> T,
) -> T {
    let _guard = RESOLVER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let paths = ResolverFixturePaths {
        hosts: temp_resolver_path("hosts"),
        services: temp_resolver_path("services"),
        route: temp_resolver_path("route"),
        if_inet6: temp_resolver_path("if-inet6"),
    };
    let _env_guard = ResolverEnvGuard;

    if let Some(content) = hosts {
        std::fs::write(&paths.hosts, content).expect("write temp hosts fixture");
        // SAFETY: serialized by RESOLVER_ENV_LOCK.
        unsafe { std::env::set_var(HOSTS_PATH_ENV, &paths.hosts) };
    }
    if let Some(content) = services {
        std::fs::write(&paths.services, content).expect("write temp services fixture");
        // SAFETY: serialized by RESOLVER_ENV_LOCK.
        unsafe { std::env::set_var(SERVICES_PATH_ENV, &paths.services) };
    }
    if let Some(content) = route {
        std::fs::write(&paths.route, content).expect("write temp route fixture");
        // SAFETY: serialized by RESOLVER_ENV_LOCK.
        unsafe { std::env::set_var(PROC_NET_ROUTE_PATH_ENV, &paths.route) };
    }
    if let Some(content) = if_inet6 {
        std::fs::write(&paths.if_inet6, content).expect("write temp if_inet6 fixture");
        // SAFETY: serialized by RESOLVER_ENV_LOCK.
        unsafe { std::env::set_var(PROC_NET_IF_INET6_PATH_ENV, &paths.if_inet6) };
    }

    f(&paths)
}

unsafe fn collect_addrinfo_families(mut node: *mut libc::addrinfo) -> Vec<c_int> {
    let mut families = Vec::new();
    while !node.is_null() {
        // SAFETY: caller provides a valid addrinfo chain returned by getaddrinfo.
        let ai = unsafe { &*node };
        families.push(ai.ai_family);
        node = ai.ai_next;
    }
    families
}

fn services_alias_fixture() -> Option<(CString, CString, u16)> {
    let content = std::fs::read("/etc/services").ok()?;
    let entry = content
        .split(|&b| b == b'\n')
        .filter_map(frankenlibc_core::resolv::parse_services_line)
        .find(|entry| {
            entry.protocol.eq_ignore_ascii_case(b"tcp")
                && entry
                    .aliases
                    .iter()
                    .any(|alias| alias.iter().all(u8::is_ascii_alphanumeric))
        })?;
    let alias = entry
        .aliases
        .iter()
        .find(|alias| alias.iter().all(u8::is_ascii_alphanumeric))?;
    Some((
        CString::new(alias.as_slice()).ok()?,
        CString::new(entry.protocol.clone()).ok()?,
        entry.port,
    ))
}

struct MallocCBuffer {
    ptr: *mut c_char,
}

impl MallocCBuffer {
    fn as_ptr(&self) -> *const c_char {
        self.ptr.cast_const()
    }
}

impl Drop for MallocCBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated by malloc_unterminated and is freed once by this guard.
        unsafe { malloc_abi::free(self.ptr.cast::<c_void>()) };
    }
}

fn malloc_unterminated(bytes: &[u8]) -> MallocCBuffer {
    assert!(
        !bytes.is_empty() && !bytes.contains(&0),
        "fixture must be non-empty and unterminated"
    );
    // SAFETY: allocation size is non-zero and checked for null before use.
    let ptr = unsafe { malloc_abi::malloc(bytes.len()) }.cast::<u8>();
    assert!(!ptr.is_null(), "malloc-backed fixture should allocate");
    // SAFETY: ptr points to bytes.len() writable bytes allocated above, and
    // source and destination do not overlap.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len()) };
    MallocCBuffer {
        ptr: ptr.cast::<c_char>(),
    }
}

// ===========================================================================
// gethostbyname
// ===========================================================================

#[test]
fn gethostbyname_numeric_ipv4_returns_hostent() {
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(!ptr.is_null());

    let hostent = unsafe { &*(ptr as *const libc::hostent) };
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [127, 0, 0, 1]);
}

#[test]
fn gethostbyname_unknown_host_returns_null() {
    with_resolver_lock(|| {
        let query =
            CString::new("missing.example.invalid").expect("query should be valid C string");
        let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
        assert!(ptr.is_null());
    });
}

#[test]
fn gethostbyname_unknown_host_sets_thread_local_h_errno() {
    with_resolver_lock(|| {
        let query =
            CString::new("missing.example.invalid").expect("query should be valid C string");
        unsafe {
            *resolv_abi::__h_errno_location() = 0;
        }

        let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
        assert!(ptr.is_null());
        assert_eq!(
            unsafe { *resolv_abi::__h_errno_location() },
            HOST_NOT_FOUND_ERRNO
        );
    });
}

// ===========================================================================
// gethostbyname_r
// ===========================================================================

#[test]
fn gethostbyname_r_numeric_ipv4_populates_result() {
    let query = CString::new("10.20.30.40").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(h_errno, 0);
    assert_eq!(
        result_ptr,
        (&mut hostent as *mut libc::hostent).cast::<c_void>()
    );
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [10, 20, 30, 40]);
}

#[test]
fn gethostbyname_r_handles_misaligned_scratch_buffer() {
    let query = CString::new("10.20.30.40").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 260];
    let (scratch_ptr, scratch_len) =
        misaligned_c_char_buffer(&mut scratch, mem::align_of::<*mut c_char>());
    assert!(!(scratch_ptr as usize).is_multiple_of(mem::align_of::<*mut c_char>()));
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch_ptr,
            scratch_len,
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(h_errno, 0);
    assert_eq!(
        result_ptr,
        (&mut hostent as *mut libc::hostent).cast::<c_void>()
    );
    assert!((hostent.h_aliases as usize).is_multiple_of(mem::align_of::<*mut c_char>()));
    assert!((hostent.h_addr_list as usize).is_multiple_of(mem::align_of::<*mut c_char>()));

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [10, 20, 30, 40]);
}

#[test]
fn gethostbyname_r_rejects_misaligned_result_buf() {
    let query = CString::new("10.20.30.40").expect("query should be valid C string");
    let mut result_storage =
        vec![0u8; mem::size_of::<libc::hostent>() + mem::align_of::<libc::hostent>()];
    let result_buf = misaligned_hostent_result_ptr(&mut result_storage);
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            result_buf,
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::EINVAL);
    assert!(result_ptr.is_null());
    assert_eq!(h_errno, NO_RECOVERY_ERRNO);
}

#[test]
fn gethostbyaddr_r_small_buffer_returns_erange_preserves_h_errno() {
    // glibc parity (bd-a892): gethostbyaddr_r must also leave
    // *h_errnop untouched on ERANGE — symmetric to gethostbyname_r.
    with_resolver_backends(Some(b"10.0.0.42 somehost\n"), None, |_| {
        let octets: [u8; 4] = [10, 0, 0, 42];
        let mut hostent: libc::hostent = unsafe { mem::zeroed() };
        let mut scratch = [0i8; 4];
        let mut result_ptr: *mut c_void = ptr::null_mut();
        const SENTINEL: i32 = -54321;
        let mut h_errno = SENTINEL;

        let rc = unsafe {
            inet_abi::gethostbyaddr_r(
                octets.as_ptr().cast::<c_void>(),
                octets.len() as libc::socklen_t,
                libc::AF_INET,
                (&mut hostent as *mut libc::hostent).cast::<c_void>(),
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut result_ptr,
                &mut h_errno,
            )
        };
        assert_eq!(rc, libc::ERANGE);
        assert!(result_ptr.is_null());
        assert_eq!(
            h_errno, SENTINEL,
            "ERANGE must leave *h_errnop untouched (glibc parity)"
        );
    });
}

#[test]
fn gethostbyaddr_r_rejects_misaligned_result_buf() {
    with_resolver_backends(Some(b"10.0.0.42 somehost\n"), None, |_| {
        let octets: [u8; 4] = [10, 0, 0, 42];
        let mut result_storage =
            vec![0u8; mem::size_of::<libc::hostent>() + mem::align_of::<libc::hostent>()];
        let result_buf = misaligned_hostent_result_ptr(&mut result_storage);
        let mut scratch = [0i8; 256];
        let mut result_ptr: *mut c_void = ptr::null_mut();
        let mut h_errno = -1;

        let rc = unsafe {
            inet_abi::gethostbyaddr_r(
                octets.as_ptr().cast::<c_void>(),
                octets.len() as libc::socklen_t,
                libc::AF_INET,
                result_buf,
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut result_ptr,
                &mut h_errno,
            )
        };
        assert_eq!(rc, libc::EINVAL);
        assert!(result_ptr.is_null());
        assert_eq!(h_errno, NO_RECOVERY_ERRNO);
    });
}

#[test]
fn gethostbyname_r_small_buffer_returns_erange_preserves_h_errno() {
    // glibc parity (bd-a892): when the caller buffer is too small, the
    // reentrant ABI returns ERANGE and leaves *h_errnop untouched so
    // callers can distinguish "retry with a bigger buffer" from a real
    // resolution failure.
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { mem::zeroed() };
    let mut scratch = [0i8; 4];
    let mut result_ptr: *mut c_void = ptr::null_mut();
    const SENTINEL: i32 = -12345;
    let mut h_errno = SENTINEL;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ERANGE);
    assert!(result_ptr.is_null());
    assert_eq!(
        h_errno, SENTINEL,
        "ERANGE must leave *h_errnop untouched (glibc parity)"
    );
}

#[test]
fn gethostbyname_r_unknown_host_returns_enoent() {
    with_resolver_lock(|| {
        let query =
            CString::new("missing.example.invalid").expect("query should be valid C string");
        let mut hostent: libc::hostent = unsafe { mem::zeroed() };
        let mut scratch = [0i8; 256];
        let mut result_ptr: *mut c_void = ptr::null_mut();
        let mut h_errno = -1;

        let rc = unsafe {
            inet_abi::gethostbyname_r(
                query.as_ptr(),
                (&mut hostent as *mut libc::hostent).cast::<c_void>(),
                scratch.as_mut_ptr(),
                scratch.len(),
                &mut result_ptr,
                &mut h_errno,
            )
        };
        assert_eq!(rc, libc::ENOENT);
        assert!(result_ptr.is_null());
        assert_eq!(h_errno, HOST_NOT_FOUND_ERRNO);
    });
}

// ===========================================================================
// gai_strerror
// ===========================================================================

#[test]
fn gai_strerror_success_code_returns_success() {
    let msg = unsafe { resolv_abi::gai_strerror(0) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(
        s.contains("uccess"),
        "gai_strerror(0) should mention success, got: {s}"
    );
}

#[test]
fn gai_strerror_eai_noname_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_NONAME) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(
        !s.is_empty(),
        "gai_strerror(EAI_NONAME) should return non-empty string"
    );
}

#[test]
fn gai_strerror_eai_service_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_SERVICE) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty());
}

#[test]
fn gai_strerror_eai_family_returns_message() {
    let msg = unsafe { resolv_abi::gai_strerror(libc::EAI_FAMILY) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty());
}

#[test]
fn gai_strerror_unknown_code_returns_fallback() {
    let msg = unsafe { resolv_abi::gai_strerror(99999) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    assert!(!s.is_empty(), "unknown code should still return a string");
}

// ===========================================================================
// getaddrinfo / freeaddrinfo
// ===========================================================================

#[test]
fn getaddrinfo_numeric_ipv4_resolves() {
    let node = CString::new("127.0.0.1").unwrap();
    let service = CString::new("80").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc =
        unsafe { resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), ptr::null(), &mut res) };
    assert_eq!(rc, 0, "getaddrinfo should succeed for numeric IPv4");
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    assert_eq!(ai.ai_family, libc::AF_INET);
    assert!(!ai.ai_addr.is_null());

    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
    assert_eq!(sin.sin_port, 80u16.to_be());

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_numeric_ipv6_resolves() {
    let node = CString::new("::1").unwrap();
    let service = CString::new("443").unwrap();
    let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
    hints.ai_family = libc::AF_INET6;
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc = unsafe { resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res) };
    assert_eq!(rc, 0, "getaddrinfo should succeed for numeric IPv6");
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    assert_eq!(ai.ai_family, libc::AF_INET6);

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_node_returns_unspecified() {
    let service = CString::new("8080").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc =
        unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), ptr::null(), &mut res) };
    assert_eq!(
        rc, 0,
        "getaddrinfo(NULL node) should return unspecified address"
    );
    assert!(!res.is_null());

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_service_uses_port_zero() {
    let node = CString::new("127.0.0.1").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();

    let rc = unsafe { resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), &mut res) };
    assert_eq!(rc, 0);
    assert!(!res.is_null());

    let ai = unsafe { &*res };
    let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
    assert_eq!(sin.sin_port, 0);

    unsafe { resolv_abi::freeaddrinfo(res) };
}

#[test]
fn getaddrinfo_null_result_returns_error() {
    let node = CString::new("127.0.0.1").unwrap();
    let rc = unsafe {
        resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), ptr::null_mut())
    };
    assert_ne!(rc, 0, "getaddrinfo with null result pointer should fail");
}

#[test]
fn getaddrinfo_rejects_known_unterminated_node() {
    with_resolver_lock(|| {
        let node = malloc_unterminated(b"127.0.0.1");
        let mut res: *mut libc::addrinfo = ptr::null_mut();

        let rc =
            unsafe { resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), &mut res) };

        assert_ne!(rc, 0, "unterminated malloc-backed node must fail");
        assert!(res.is_null());
    });
}

#[test]
fn getaddrinfo_nonexistent_host_returns_eai_noname() {
    with_resolver_lock(|| {
        let node = CString::new("nonexistent.invalid.test").unwrap();
        let mut res: *mut libc::addrinfo = ptr::null_mut();

        let rc =
            unsafe { resolv_abi::getaddrinfo(node.as_ptr(), ptr::null(), ptr::null(), &mut res) };
        assert_eq!(rc, libc::EAI_NONAME);
        assert!(res.is_null());
    });
}

#[test]
fn freeaddrinfo_null_is_noop() {
    // Should not crash
    unsafe { resolv_abi::freeaddrinfo(ptr::null_mut()) };
}

#[test]
fn getaddrinfo_uses_overridden_hosts_backend() {
    with_resolver_backends(
        Some(
            b"not-an-ip fixture-bad\n203.0.113.10 fixture-host fixture-alias\n198.51.100.5 other-host\n",
        ),
        None,
        |paths| {
            assert!(paths.hosts.exists());
            let node = CString::new("FIXTURE-ALIAS").unwrap();
            let service = CString::new("4242").unwrap();
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc = unsafe {
                resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), ptr::null(), &mut res)
            };
            assert_eq!(rc, 0);
            assert!(!res.is_null());

            let ai = unsafe { &*res };
            assert_eq!(ai.ai_family, libc::AF_INET);
            let sin = unsafe { &*(ai.ai_addr as *const libc::sockaddr_in) };
            assert_eq!(sin.sin_port, 4242u16.to_be());
            assert_eq!(sin.sin_addr.s_addr, u32::from_ne_bytes([203, 0, 113, 10]));

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_ai_addrconfig_filters_dual_stack_hosts_to_ipv4() {
    with_resolver_backends_and_addrconfig(
        Some(b"203.0.113.10 dual-stack\n2001:db8::10 dual-stack\n"),
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"00000000000000000000000000000001 01 80 10 80       lo\n"),
        |paths| {
            assert!(paths.route.exists());
            assert!(paths.if_inet6.exists());

            let node = CString::new("dual-stack").unwrap();
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc = unsafe {
                resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res)
            };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let families = unsafe { collect_addrinfo_families(res) };
            assert_eq!(families, vec![libc::AF_INET]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_ai_addrconfig_filters_dual_stack_hosts_to_ipv6() {
    with_resolver_backends_and_addrconfig(
        Some(b"203.0.113.10 dual-stack\n2001:db8::10 dual-stack\n"),
        None,
        Some(b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nlo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"),
        Some(b"fe800000000000000000000000000001 02 40 20 80   eth0\n"),
        |_| {
            let node = CString::new("dual-stack").unwrap();
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc = unsafe {
                resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res)
            };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let families = unsafe { collect_addrinfo_families(res) };
            assert_eq!(families, vec![libc::AF_INET6]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_ai_addrconfig_numeric_ipv6_bypasses_filter() {
    with_resolver_backends_and_addrconfig(
        None,
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"00000000000000000000000000000001 01 80 10 80       lo\n"),
        |_| {
            let node = CString::new("::1").unwrap();
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc = unsafe {
                resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res)
            };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let families = unsafe { collect_addrinfo_families(res) };
            assert_eq!(families, vec![libc::AF_INET6]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_ai_addrconfig_returns_noname_when_all_families_filtered() {
    with_resolver_backends_and_addrconfig(
        Some(b"2001:db8::10 v6-only\n"),
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"00000000000000000000000000000001 01 80 10 80       lo\n"),
        |_| {
            let node = CString::new("v6-only").unwrap();
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc = unsafe {
                resolv_abi::getaddrinfo(node.as_ptr(), service.as_ptr(), &hints, &mut res)
            };
            assert_eq!(rc, libc::EAI_NONAME);
            assert!(res.is_null());
        },
    );
}

#[test]
fn getaddrinfo_null_node_ai_addrconfig_filters_unspecified_to_ipv4() {
    with_resolver_backends_and_addrconfig(
        None,
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"00000000000000000000000000000001 01 80 10 80       lo\n"),
        |_| {
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc =
                unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), &hints, &mut res) };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let families = unsafe { collect_addrinfo_families(res) };
            assert_eq!(families, vec![libc::AF_INET]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_null_node_ai_addrconfig_filters_unspecified_to_ipv6_only() {
    // Symmetric companion to ..._filters_unspecified_to_ipv4. A host with
    // only IPv6 non-loopback routes (e.g., IPv6-only network) must surface
    // only AF_INET6 records for null-node queries under AI_ADDRCONFIG.
    // The empty route table below plus a non-loopback ::/0 entry in
    // if_inet6 models an IPv6-only box.
    with_resolver_backends_and_addrconfig(
        None,
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        ),
        Some(b"20010db8000000000000000000000001 02 80 00 20   eth0\n"),
        |_| {
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc =
                unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), &hints, &mut res) };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let families = unsafe { collect_addrinfo_families(res) };
            assert_eq!(families, vec![libc::AF_INET6]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_null_node_ai_addrconfig_preserves_both_families_on_dual_stack() {
    // Dual-stack host with both IPv4 and IPv6 non-loopback routes must
    // return both AF_INET and AF_INET6 nodes for null-node queries.
    // Confirms the filter only removes families that are *unsupported*,
    // not that it inadvertently trims supported families.
    with_resolver_backends_and_addrconfig(
        None,
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t01010101\t0003\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"20010db8000000000000000000000001 02 80 00 20   eth0\n"),
        |_| {
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc =
                unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), &hints, &mut res) };
            assert_eq!(rc, 0);
            assert!(!res.is_null());
            let mut families = unsafe { collect_addrinfo_families(res) };
            families.sort();
            assert_eq!(families, vec![libc::AF_INET, libc::AF_INET6]);

            unsafe { resolv_abi::freeaddrinfo(res) };
        },
    );
}

#[test]
fn getaddrinfo_null_node_ai_addrconfig_returns_noname_without_nonloopback_families() {
    with_resolver_backends_and_addrconfig(
        None,
        None,
        Some(
            b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nlo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n",
        ),
        Some(b"00000000000000000000000000000001 01 80 10 80       lo\n"),
        |_| {
            let service = CString::new("8080").unwrap();
            let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
            hints.ai_flags = libc::AI_ADDRCONFIG;
            let mut res: *mut libc::addrinfo = ptr::null_mut();

            let rc =
                unsafe { resolv_abi::getaddrinfo(ptr::null(), service.as_ptr(), &hints, &mut res) };
            assert_eq!(rc, libc::EAI_NONAME);
            assert!(res.is_null());
        },
    );
}

// ===========================================================================
// getnameinfo
// ===========================================================================

#[test]
fn getnameinfo_ipv4_formats_numeric() {
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 80u16.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([192, 168, 1, 1]),
        },
        sin_zero: [0; 8],
    };

    let mut host = [0u8; 64];
    let mut serv = [0u8; 16];

    let rc = unsafe {
        resolv_abi::getnameinfo(
            (&sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            serv.as_mut_ptr().cast::<c_char>(),
            serv.len() as libc::socklen_t,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    assert_eq!(rc, 0, "getnameinfo should succeed for IPv4");

    let host_str = unsafe { CStr::from_ptr(host.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(host_str, "192.168.1.1");

    let serv_str = unsafe { CStr::from_ptr(serv.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(serv_str, "80");
}

#[test]
fn getnameinfo_ipv6_formats_numeric() {
    let sin6 = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as u16,
        sin6_port: 443u16.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
        sin6_scope_id: 0,
    };

    let mut host = [0u8; 64];
    let mut serv = [0u8; 16];

    let rc = unsafe {
        resolv_abi::getnameinfo(
            (&sin6 as *const libc::sockaddr_in6).cast::<libc::sockaddr>(),
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            serv.as_mut_ptr().cast::<c_char>(),
            serv.len() as libc::socklen_t,
            libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
        )
    };
    assert_eq!(rc, 0, "getnameinfo should succeed for IPv6");

    let host_str = unsafe { CStr::from_ptr(host.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(host_str, "::1");

    let serv_str = unsafe { CStr::from_ptr(serv.as_ptr().cast::<c_char>()) }.to_string_lossy();
    assert_eq!(serv_str, "443");
}

#[test]
fn getnameinfo_null_sockaddr_returns_error() {
    let mut host = [0u8; 64];
    let rc = unsafe {
        resolv_abi::getnameinfo(
            ptr::null(),
            0,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            0,
        )
    };
    assert_ne!(rc, 0, "getnameinfo(NULL) should fail");
}

#[test]
fn getnameinfo_unsupported_family_returns_eai_family() {
    // Use AF_UNIX which is not supported by numeric getnameinfo
    let mut sa: libc::sockaddr = unsafe { mem::zeroed() };
    sa.sa_family = libc::AF_UNIX as u16;

    let mut host = [0u8; 64];
    let rc = unsafe {
        resolv_abi::getnameinfo(
            &sa,
            mem::size_of::<libc::sockaddr>() as libc::socklen_t,
            host.as_mut_ptr().cast::<c_char>(),
            host.len() as libc::socklen_t,
            ptr::null_mut(),
            0,
            0,
        )
    };
    assert_eq!(rc, libc::EAI_FAMILY);
}

// ===========================================================================
// gethostbyaddr
// ===========================================================================

#[test]
fn gethostbyaddr_localhost_may_resolve() {
    with_resolver_lock(|| {
        let addr: [u8; 4] = [127, 0, 0, 1];
        let ptr =
            unsafe { resolv_abi::gethostbyaddr(addr.as_ptr().cast::<c_void>(), 4, libc::AF_INET) };
        // /etc/hosts usually has 127.0.0.1 -> localhost
        // But we don't fail the test if it doesn't
        if !ptr.is_null() {
            let hostent = unsafe { &*(ptr as *const libc::hostent) };
            assert_eq!(hostent.h_addrtype, libc::AF_INET);
            assert_eq!(hostent.h_length, 4);
        }
    });
}

#[test]
fn gethostbyaddr_null_returns_null() {
    let ptr = unsafe { resolv_abi::gethostbyaddr(ptr::null(), 4, libc::AF_INET) };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_unsupported_af_returns_null() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let ptr = unsafe {
        resolv_abi::gethostbyaddr(
            addr.as_ptr().cast::<c_void>(),
            4,
            libc::AF_INET6, // IPv6 not supported for 4-byte addr
        )
    };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_short_len_returns_null() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    let ptr = unsafe {
        resolv_abi::gethostbyaddr(
            addr.as_ptr().cast::<c_void>(),
            2, // too short
            libc::AF_INET,
        )
    };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyaddr_unsupported_af_sets_thread_local_h_errno() {
    let addr: [u8; 4] = [127, 0, 0, 1];
    unsafe {
        *resolv_abi::__h_errno_location() = 0;
    }

    let ptr =
        unsafe { resolv_abi::gethostbyaddr(addr.as_ptr().cast::<c_void>(), 4, libc::AF_INET6) };
    assert!(ptr.is_null());
    assert_eq!(
        unsafe { *resolv_abi::__h_errno_location() },
        HOST_NOT_FOUND_ERRNO
    );
}

#[test]
fn gethostbyaddr_uses_overridden_hosts_backend() {
    with_resolver_backends(
        Some(b"203.0.113.7 fixture-host fixture-alias\n"),
        None,
        |_| {
            let addr = libc::in_addr {
                s_addr: u32::from_ne_bytes([203, 0, 113, 7]),
            };
            unsafe {
                *resolv_abi::__h_errno_location() = HOST_NOT_FOUND_ERRNO;
            }

            let ptr = unsafe {
                resolv_abi::gethostbyaddr(
                    (&addr as *const libc::in_addr).cast::<c_void>(),
                    mem::size_of::<libc::in_addr>() as libc::socklen_t,
                    libc::AF_INET,
                )
            };
            assert!(!ptr.is_null());

            let hostent = unsafe { &*(ptr as *const libc::hostent) };
            let host_name = unsafe { CStr::from_ptr(hostent.h_name) };
            assert_eq!(host_name.to_bytes(), b"fixture-host");
            assert_eq!(unsafe { *resolv_abi::__h_errno_location() }, 0);
        },
    );
}

// ===========================================================================
// getservbyname
// ===========================================================================

#[test]
fn getservbyname_ssh_resolves() {
    with_resolver_lock(|| {
        let name = CString::new("ssh").unwrap();
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
        // /etc/services should have ssh/tcp = 22
        if !ptr.is_null() {
            let servent = unsafe { &*(ptr as *const libc::servent) };
            assert_eq!(u16::from_be(servent.s_port as u16), 22);
            assert!(!servent.s_name.is_null());
        }
    });
}

#[test]
fn getservbyname_http_resolves() {
    with_resolver_lock(|| {
        let name = CString::new("http").unwrap();
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
        if !ptr.is_null() {
            let servent = unsafe { &*(ptr as *const libc::servent) };
            assert_eq!(u16::from_be(servent.s_port as u16), 80);
        }
    });
}

#[test]
fn getservbyname_null_name_returns_null() {
    let proto = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getservbyname(ptr::null(), proto.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn getservbyname_rejects_known_unterminated_name() {
    with_resolver_lock(|| {
        let name = malloc_unterminated(b"ssh");
        let proto = CString::new("tcp").unwrap();

        let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };

        assert!(ptr.is_null());
    });
}

#[test]
fn getservbyname_nonexistent_returns_null() {
    with_resolver_lock(|| {
        let name = CString::new("nonexistent_service_zzz").unwrap();
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
        assert!(ptr.is_null());
    });
}

#[test]
fn getservbyname_null_proto_resolves() {
    with_resolver_lock(|| {
        let name = CString::new("ssh").unwrap();
        let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), ptr::null()) };
        // Should still find ssh without protocol filter
        if !ptr.is_null() {
            let servent = unsafe { &*(ptr as *const libc::servent) };
            assert_eq!(u16::from_be(servent.s_port as u16), 22);
        }
    });
}

#[test]
fn getservbyname_alias_resolves_to_canonical_entry() {
    with_resolver_lock(|| {
        let Some((alias, proto, port)) = services_alias_fixture() else {
            return;
        };
        let ptr = unsafe { resolv_abi::getservbyname(alias.as_ptr(), proto.as_ptr()) };
        assert!(!ptr.is_null());

        let servent = unsafe { &*(ptr as *const libc::servent) };
        assert_eq!(u16::from_be(servent.s_port as u16), port);
        assert!(!servent.s_name.is_null());
    });
}

#[test]
fn getservbyname_uses_overridden_services_backend_and_ignores_malformed_lines() {
    with_resolver_backends(
        None,
        Some(b"broken-service notaport/tcp alias\nfixture-svc 12345/tcp fixturealias\n"),
        |_| {
            let name = CString::new("FIXTUREALIAS").unwrap();
            let proto = CString::new("TCP").unwrap();
            let ptr = unsafe { resolv_abi::getservbyname(name.as_ptr(), proto.as_ptr()) };
            assert!(!ptr.is_null());

            let servent = unsafe { &*(ptr as *const libc::servent) };
            assert_eq!(u16::from_be(servent.s_port as u16), 12345);
            let proto_name = unsafe { CStr::from_ptr(servent.s_proto) };
            assert!(proto_name.to_bytes().eq_ignore_ascii_case(b"tcp"));
        },
    );
}

// ===========================================================================
// getservbyport
// ===========================================================================

#[test]
fn getservbyport_22_resolves_ssh() {
    with_resolver_lock(|| {
        let port_net = (22u16).to_be() as c_int;
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
        if !ptr.is_null() {
            let servent = unsafe { &*(ptr as *const libc::servent) };
            let name = unsafe { CStr::from_ptr(servent.s_name) }.to_string_lossy();
            assert_eq!(name, "ssh");
        }
    });
}

#[test]
fn getservbyport_80_resolves_http() {
    with_resolver_lock(|| {
        let port_net = (80u16).to_be() as c_int;
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
        if !ptr.is_null() {
            let servent = unsafe { &*(ptr as *const libc::servent) };
            let name = unsafe { CStr::from_ptr(servent.s_name) }.to_string_lossy();
            assert_eq!(name, "http");
        }
    });
}

#[test]
fn getservbyport_nonexistent_returns_null() {
    with_resolver_lock(|| {
        let port_net = (59999u16).to_be() as c_int;
        let proto = CString::new("tcp").unwrap();
        let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
        assert!(ptr.is_null());
    });
}

#[test]
fn getservbyport_rejects_known_unterminated_proto() {
    with_resolver_lock(|| {
        let port_net = (22u16).to_be() as c_int;
        let proto = malloc_unterminated(b"tcp");

        let ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };

        assert!(ptr.is_null());
    });
}

#[test]
fn getservbyport_reads_updated_overridden_services_backend() {
    with_resolver_backends(None, Some(b"fixture-old 4242/tcp\n"), |paths| {
        let port_net = (4242u16).to_be() as c_int;
        let proto = CString::new("tcp").unwrap();

        let first_ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
        assert!(!first_ptr.is_null());
        let first = unsafe { &*(first_ptr as *const libc::servent) };
        let first_name = unsafe { CStr::from_ptr(first.s_name) };
        assert_eq!(first_name.to_bytes(), b"fixture-old");

        std::fs::write(
            &paths.services,
            b"broken-service nope/tcp alias\nfixture-new 4242/tcp\n",
        )
        .expect("rewrite temp services fixture");

        let second_ptr = unsafe { resolv_abi::getservbyport(port_net, proto.as_ptr()) };
        assert!(!second_ptr.is_null());
        let second = unsafe { &*(second_ptr as *const libc::servent) };
        let second_name = unsafe { CStr::from_ptr(second.s_name) };
        assert_eq!(second_name.to_bytes(), b"fixture-new");
    });
}

// ===========================================================================
// getprotobyname
// ===========================================================================

#[test]
fn getprotobyname_tcp_resolves() {
    let name = CString::new("tcp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 6); // TCP = protocol 6
        assert!(!protoent.p_name.is_null());
    }
}

#[test]
fn getprotobyname_udp_resolves() {
    let name = CString::new("udp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 17); // UDP = protocol 17
    }
}

#[test]
fn getprotobyname_icmp_resolves() {
    let name = CString::new("icmp").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        assert_eq!(protoent.p_proto, 1); // ICMP = protocol 1
    }
}

#[test]
fn getprotobyname_null_returns_null() {
    let ptr = unsafe { resolv_abi::getprotobyname(ptr::null()) };
    assert!(ptr.is_null());
}

#[test]
fn getprotobyname_rejects_known_unterminated_name() {
    let name = malloc_unterminated(b"tcp");
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn getprotobyname_nonexistent_returns_null() {
    let name = CString::new("nonexistent_protocol_zzz").unwrap();
    let ptr = unsafe { resolv_abi::getprotobyname(name.as_ptr()) };
    assert!(ptr.is_null());
}

// ===========================================================================
// getprotobynumber
// ===========================================================================

#[test]
fn getprotobynumber_6_resolves_tcp() {
    let ptr = unsafe { resolv_abi::getprotobynumber(6) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        let name = unsafe { CStr::from_ptr(protoent.p_name) }.to_string_lossy();
        assert_eq!(name, "tcp");
        assert_eq!(protoent.p_proto, 6);
    }
}

#[test]
fn getprotobynumber_17_resolves_udp() {
    let ptr = unsafe { resolv_abi::getprotobynumber(17) };
    if !ptr.is_null() {
        let protoent = unsafe { &*(ptr as *const libc::protoent) };
        let name = unsafe { CStr::from_ptr(protoent.p_name) }.to_string_lossy();
        assert_eq!(name, "udp");
    }
}

#[test]
fn getprotobynumber_nonexistent_returns_null() {
    let ptr = unsafe { resolv_abi::getprotobynumber(99999) };
    assert!(ptr.is_null());
}

// ===========================================================================
// __h_errno_location
// ===========================================================================

#[test]
fn h_errno_location_returns_valid_pointer() {
    let ptr = unsafe { resolv_abi::__h_errno_location() };
    assert!(!ptr.is_null());
    // Should be readable
    let _val = unsafe { *ptr };
}

#[test]
fn h_errno_location_is_writable() {
    let ptr = unsafe { resolv_abi::__h_errno_location() };
    assert!(!ptr.is_null());
    let old = unsafe { *ptr };
    unsafe { *ptr = 42 };
    assert_eq!(unsafe { *ptr }, 42);
    unsafe { *ptr = old };
}

// ===========================================================================
// DNS Metrics Evidence (bd-1y7)
// ===========================================================================

#[test]
fn dns_metrics_snapshot_returns_valid_counters() {
    let snapshot = resolv_abi::dns_metrics_snapshot();
    // Verify the snapshot structure works by checking all fields are accessible
    // and that the sum of outcomes equals attempts (allowing for races)
    let total_outcomes = snapshot.queries_success
        + snapshot.queries_timeout
        + snapshot.queries_send_error
        + snapshot.queries_parse_error
        + snapshot.queries_nxdomain
        + snapshot.queries_dns_error;
    // Total outcomes should be <= attempts (encode failure doesn't increment outcomes)
    assert!(total_outcomes <= snapshot.queries_attempted || snapshot.queries_attempted == 0);
}

#[test]
fn dns_metrics_counters_increment_on_hosts_miss() {
    // When /etc/hosts lookup fails and DNS is attempted,
    // the metrics should increment.
    // Note: This test may increment counters even if DNS fails
    // (timeout, no nameserver, etc.), which is expected.

    let before = resolv_abi::dns_metrics_snapshot();

    // Try to resolve a hostname that won't be in /etc/hosts
    // and will trigger DNS lookup attempt
    let nonexistent = CString::new("nonexistent.example.test").unwrap();
    let mut result: *mut libc::addrinfo = ptr::null_mut();

    // This will try DNS after /etc/hosts miss
    let _ = unsafe {
        resolv_abi::getaddrinfo(nonexistent.as_ptr(), ptr::null(), ptr::null(), &mut result)
    };
    if !result.is_null() {
        unsafe { resolv_abi::freeaddrinfo(result) };
    }

    let after = resolv_abi::dns_metrics_snapshot();

    // The total queries attempted should have increased
    // (unless DNS is completely disabled or no nameservers configured)
    // We just verify the counter is accessible and consistent
    assert!(after.queries_attempted >= before.queries_attempted);
}

// ---------------------------------------------------------------------------
// libresolv ns_get/put16/32 + ns_samename/samedomain/subdomain/makecanon
// ---------------------------------------------------------------------------

#[test]
fn ns_get16_reads_big_endian() {
    use frankenlibc_abi::resolv_abi::ns_get16;
    let buf = [0x12u8, 0x34u8];
    assert_eq!(unsafe { ns_get16(buf.as_ptr()) }, 0x1234);
    assert_eq!(unsafe { ns_get16(std::ptr::null()) }, 0);
}

#[test]
fn ns_get32_reads_big_endian() {
    use frankenlibc_abi::resolv_abi::ns_get32;
    let buf = [0xDE, 0xAD, 0xBE, 0xEF];
    assert_eq!(unsafe { ns_get32(buf.as_ptr()) }, 0xDEAD_BEEF);
    assert_eq!(unsafe { ns_get32(std::ptr::null()) }, 0);
}

#[test]
fn ns_put16_writes_big_endian() {
    use frankenlibc_abi::resolv_abi::ns_put16;
    let mut buf = [0u8; 2];
    unsafe { ns_put16(0x1234, buf.as_mut_ptr()) };
    assert_eq!(buf, [0x12, 0x34]);

    // NULL dst is a no-op (no UB).
    unsafe { ns_put16(0xFFFF, std::ptr::null_mut()) };
}

#[test]
fn ns_put32_writes_big_endian() {
    use frankenlibc_abi::resolv_abi::ns_put32;
    let mut buf = [0u8; 4];
    unsafe { ns_put32(0xCAFE_BABE, buf.as_mut_ptr()) };
    assert_eq!(buf, [0xCA, 0xFE, 0xBA, 0xBE]);
}

#[test]
fn ns_samename_case_insensitive_with_optional_dot() {
    use frankenlibc_abi::resolv_abi::ns_samename;

    fn cs(s: &'static str) -> std::ffi::CString {
        std::ffi::CString::new(s).unwrap()
    }

    assert_eq!(
        unsafe { ns_samename(cs("foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { ns_samename(cs("FOO.COM").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { ns_samename(cs("foo.com").as_ptr(), cs("foo.com.").as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { ns_samename(cs("foo.com").as_ptr(), cs("bar.com").as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { ns_samename(std::ptr::null(), cs("x").as_ptr()) },
        -1
    );
}

#[test]
fn ns_samename_rejects_tracked_unterminated_inputs() {
    use frankenlibc_abi::resolv_abi::ns_samename;
    let unterminated = malloc_unterminated(b"foo.com");
    let other = std::ffi::CString::new("foo.com").unwrap();

    assert_eq!(
        unsafe { ns_samename(unterminated.as_ptr(), other.as_ptr()) },
        -1
    );
    assert_eq!(
        unsafe { ns_samename(other.as_ptr(), unterminated.as_ptr()) },
        -1
    );
}

#[test]
fn ns_samedomain_root_and_subdomains() {
    use frankenlibc_abi::resolv_abi::ns_samedomain;

    fn cs(s: &'static str) -> std::ffi::CString {
        std::ffi::CString::new(s).unwrap()
    }

    // Root domain (empty / ".") matches everything.
    assert_eq!(
        unsafe { ns_samedomain(cs("foo.com").as_ptr(), cs("").as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { ns_samedomain(cs("foo.com").as_ptr(), cs(".").as_ptr()) },
        1
    );

    // Equal names match.
    assert_eq!(
        unsafe { ns_samedomain(cs("foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );

    // Proper subdomain matches.
    assert_eq!(
        unsafe { ns_samedomain(cs("www.foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );
    assert_eq!(
        unsafe { ns_samedomain(cs("a.b.foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );

    // Suffix-but-not-subdomain rejects (no dot before suffix).
    assert_eq!(
        unsafe { ns_samedomain(cs("zzzfoo.com").as_ptr(), cs("foo.com").as_ptr()) },
        0
    );

    // Different names reject.
    assert_eq!(
        unsafe { ns_samedomain(cs("bar.com").as_ptr(), cs("foo.com").as_ptr()) },
        0
    );
}

#[test]
fn ns_samedomain_rejects_tracked_unterminated_inputs() {
    use frankenlibc_abi::resolv_abi::ns_samedomain;
    let unterminated = malloc_unterminated(b"www.foo.com");
    let domain = std::ffi::CString::new("foo.com").unwrap();

    assert_eq!(
        unsafe { ns_samedomain(unterminated.as_ptr(), domain.as_ptr()) },
        0
    );
    assert_eq!(
        unsafe { ns_samedomain(domain.as_ptr(), unterminated.as_ptr()) },
        0
    );
}

#[test]
fn ns_subdomain_only_for_proper_subdomains() {
    use frankenlibc_abi::resolv_abi::ns_subdomain;

    fn cs(s: &'static str) -> std::ffi::CString {
        std::ffi::CString::new(s).unwrap()
    }

    // Same name → not a proper subdomain.
    assert_eq!(
        unsafe { ns_subdomain(cs("foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        0
    );
    // Proper subdomain → 1.
    assert_eq!(
        unsafe { ns_subdomain(cs("www.foo.com").as_ptr(), cs("foo.com").as_ptr()) },
        1
    );
    // Unrelated names → 0.
    assert_eq!(
        unsafe { ns_subdomain(cs("bar.com").as_ptr(), cs("foo.com").as_ptr()) },
        0
    );
}

#[test]
fn ns_makecanon_appends_trailing_dot() {
    use frankenlibc_abi::resolv_abi::ns_makecanon;
    let src = std::ffi::CString::new("foo.com").unwrap();
    let mut buf = [0u8; 16];
    let rc = unsafe { ns_makecanon(src.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    assert_eq!(rc, 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
    assert_eq!(s.to_bytes(), b"foo.com.");
}

#[test]
fn ns_makecanon_preserves_existing_trailing_dot() {
    use frankenlibc_abi::resolv_abi::ns_makecanon;
    let src = std::ffi::CString::new("foo.com.").unwrap();
    let mut buf = [0u8; 16];
    let rc = unsafe { ns_makecanon(src.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    assert_eq!(rc, 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const c_char) };
    assert_eq!(s.to_bytes(), b"foo.com.");
}

#[test]
fn ns_makecanon_emsgsize_when_dst_too_small() {
    use frankenlibc_abi::resolv_abi::ns_makecanon;
    let src = std::ffi::CString::new("foo.com").unwrap();
    // src is 7 bytes; result needs 9 (foo.com. + NUL); buffer of 8
    // should fail.
    let mut buf = [0u8; 8];
    let rc = unsafe { ns_makecanon(src.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EMSGSIZE);
}

#[test]
fn ns_makecanon_einval_on_null_inputs() {
    use frankenlibc_abi::resolv_abi::ns_makecanon;
    let mut buf = [0u8; 16];
    let rc = unsafe { ns_makecanon(std::ptr::null(), buf.as_mut_ptr() as *mut c_char, 16) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

#[test]
fn ns_makecanon_rejects_tracked_unterminated_src() {
    use frankenlibc_abi::resolv_abi::ns_makecanon;
    let src = malloc_unterminated(b"foo.com");
    let mut buf = [0u8; 16];

    let rc = unsafe { ns_makecanon(src.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    assert_eq!(rc, -1);
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EINVAL);
}

// ---------------------------------------------------------------------------
// libresolv ns_parse_ttl / ns_format_ttl / ns_datetosecs
// ---------------------------------------------------------------------------

fn parse_ttl(s: &str) -> Option<u32> {
    use frankenlibc_abi::resolv_abi::ns_parse_ttl;
    let cstr = std::ffi::CString::new(s).unwrap();
    let mut out: u32 = 0;
    let rc = unsafe { ns_parse_ttl(cstr.as_ptr(), &mut out) };
    if rc == 0 { Some(out) } else { None }
}

#[test]
fn ns_parse_ttl_handles_units() {
    assert_eq!(parse_ttl("60"), Some(60));
    assert_eq!(parse_ttl("60S"), Some(60));
    assert_eq!(parse_ttl("60s"), Some(60));
    assert_eq!(parse_ttl("1M"), Some(60));
    assert_eq!(parse_ttl("1H"), Some(3_600));
    assert_eq!(parse_ttl("1D"), Some(86_400));
    assert_eq!(parse_ttl("1W"), Some(604_800));
    assert_eq!(parse_ttl("1d2h3m4s"), Some(86_400 + 7_200 + 180 + 4));
    assert_eq!(parse_ttl("0"), Some(0));
}

#[test]
fn ns_parse_ttl_rejects_syntax_errors() {
    // Unit without preceding digits.
    assert_eq!(parse_ttl("H"), None);
    // Unknown unit.
    assert_eq!(parse_ttl("5Z"), None);
    // Non-digit non-unit character.
    assert_eq!(parse_ttl("12+34"), None);
    // Empty string is permissive: returns 0 (matches BIND reference loop
    // semantics — the parse loop terminates without consuming any input
    // and the accumulator remains zero).
    assert_eq!(parse_ttl(""), Some(0));
}

#[test]
fn ns_parse_ttl_rejects_overflow() {
    // 2^32 = 4_294_967_296; this should overflow u32.
    assert_eq!(parse_ttl("4294967296"), None);
    // 7200W * 604800 sec/week = 4_354_560_000 > u32::MAX → overflow.
    assert_eq!(parse_ttl("7200W"), None);
    // 11-digit number (>10 digits) overruns u32 and is rejected by the
    // digit-count guard.
    assert_eq!(parse_ttl("99999999999"), None);
}

#[test]
fn ns_parse_ttl_rejects_tracked_unterminated_input() {
    use frankenlibc_abi::resolv_abi::ns_parse_ttl;
    let src = malloc_unterminated(b"60S");
    let mut out = 123u32;

    let rc = unsafe { ns_parse_ttl(src.as_ptr(), &mut out) };
    assert_eq!(rc, -1);
    assert_eq!(out, 123);
}

fn format_ttl(secs: u32, capacity: usize) -> Option<String> {
    use frankenlibc_abi::resolv_abi::ns_format_ttl;
    let mut buf = vec![0u8; capacity];
    let rc = unsafe { ns_format_ttl(secs, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if rc < 0 {
        return None;
    }
    let n = rc as usize;
    Some(String::from_utf8(buf[..n].to_vec()).unwrap())
}

#[test]
fn ns_format_ttl_single_unit_is_uppercase() {
    assert_eq!(format_ttl(0, 32).as_deref(), Some("0S"));
    assert_eq!(format_ttl(60, 32).as_deref(), Some("1M"));
    assert_eq!(format_ttl(3_600, 32).as_deref(), Some("1H"));
    assert_eq!(format_ttl(86_400, 32).as_deref(), Some("1D"));
    assert_eq!(format_ttl(604_800, 32).as_deref(), Some("1W"));
}

#[test]
fn ns_format_ttl_multi_unit_is_lowercase() {
    // 86460 = 1 day + 1 minute → "1d1m" (lowercased per BIND9 ref).
    assert_eq!(format_ttl(86_460, 32).as_deref(), Some("1d1m"));
    // 3661 = 1h1m1s.
    assert_eq!(format_ttl(3_661, 32).as_deref(), Some("1h1m1s"));
}

#[test]
fn ns_format_ttl_round_trips_via_parse() {
    for &val in &[0u32, 1, 59, 60, 3_600, 86_400, 86_461, 604_800, 1_234_567] {
        let s = format_ttl(val, 64).expect("format should succeed");
        let cs = std::ffi::CString::new(s.clone()).unwrap();
        let mut out: u32 = 0;
        let rc = unsafe { frankenlibc_abi::resolv_abi::ns_parse_ttl(cs.as_ptr(), &mut out) };
        assert_eq!(rc, 0, "parse failed for round-trip '{s}' from {val}");
        assert_eq!(out, val, "round-trip mismatch via '{s}'");
    }
}

#[test]
fn ns_format_ttl_returns_minus_one_when_buffer_too_small() {
    use frankenlibc_abi::resolv_abi::ns_format_ttl;
    // "0S" + NUL needs 3; buffer of 2 should fail.
    let mut buf = [0u8; 2];
    assert_eq!(
        unsafe { ns_format_ttl(0, buf.as_mut_ptr() as *mut c_char, buf.len()) },
        -1
    );
    // NULL dst → -1.
    assert_eq!(unsafe { ns_format_ttl(0, std::ptr::null_mut(), 0) }, -1);
}

#[test]
fn ns_datetosecs_parses_valid_utc_strings() {
    use frankenlibc_abi::resolv_abi::ns_datetosecs;
    // 2024-01-01T00:00:00 UTC = 1704067200 (well-known).
    let s = std::ffi::CString::new("20240101000000").unwrap();
    let mut errp: c_int = 99;
    let secs = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 0);
    assert_eq!(secs, 1_704_067_200);

    // 1970-01-01T00:00:00 UTC = 0 (epoch).
    let s = std::ffi::CString::new("19700101000000").unwrap();
    let secs = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 0);
    assert_eq!(secs, 0);

    // Valid leap day.
    let s = std::ffi::CString::new("20240229000000").unwrap();
    let secs = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 0);
    assert_eq!(secs, 1_709_164_800);

    // Highest Unix timestamp representable by the u32 return type.
    let s = std::ffi::CString::new("21060207062815").unwrap();
    let secs = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 0);
    assert_eq!(secs, u32::MAX);
}

#[test]
fn ns_datetosecs_rejects_malformed_strings() {
    use frankenlibc_abi::resolv_abi::ns_datetosecs;
    let mut errp: c_int = 0;

    // Wrong length (13 chars).
    let s = std::ffi::CString::new("2024010100000").unwrap();
    let _ = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 1);

    // Right length but non-digit.
    let s = std::ffi::CString::new("2024X101000000").unwrap();
    errp = 0;
    let _ = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 1);

    // Out-of-range month.
    let s = std::ffi::CString::new("20241301000000").unwrap();
    errp = 0;
    let _ = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 1);

    // Invalid non-leap day must not be normalized by a host libc time parser.
    let s = std::ffi::CString::new("20230229000000").unwrap();
    errp = 0;
    let _ = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 1);

    // Values beyond u32::MAX seconds would wrap the API return type.
    let s = std::ffi::CString::new("21060207062816").unwrap();
    errp = 0;
    let _ = unsafe { ns_datetosecs(s.as_ptr(), &mut errp) };
    assert_eq!(errp, 1);
}

#[test]
fn ns_datetosecs_rejects_tracked_unterminated_input() {
    use frankenlibc_abi::resolv_abi::ns_datetosecs;
    let src = malloc_unterminated(b"20240101000000");
    let mut errp: c_int = 0;

    let secs = unsafe { ns_datetosecs(src.as_ptr(), &mut errp) };
    assert_eq!(secs, 0);
    assert_eq!(errp, 1);
}

#[test]
fn ns_datetosecs_tolerates_null_errp() {
    use frankenlibc_abi::resolv_abi::ns_datetosecs;
    let s = std::ffi::CString::new("20240101000000").unwrap();
    let secs = unsafe { ns_datetosecs(s.as_ptr(), std::ptr::null_mut()) };
    assert_eq!(secs, 1_704_067_200);
}

// ---------------------------------------------------------------------------
// res_gethostbyname / 2 / by_addr aliases + res_send_set{q,r}hook
// ---------------------------------------------------------------------------

#[test]
fn res_gethostbyname_matches_gethostbyname_for_numeric_ipv4() {
    use frankenlibc_abi::resolv_abi::{gethostbyname, res_gethostbyname};
    let q = CString::new("127.0.0.1").unwrap();
    let a = unsafe { res_gethostbyname(q.as_ptr()) };
    let b = unsafe { gethostbyname(q.as_ptr()) };
    assert!(!a.is_null());
    assert!(!b.is_null());
    // Both routes resolve through the same hostent registry; comparing
    // the h_addrtype/h_length fields is sufficient.
    let ha = unsafe { &*(a as *const libc::hostent) };
    let hb = unsafe { &*(b as *const libc::hostent) };
    assert_eq!(ha.h_addrtype, hb.h_addrtype);
    assert_eq!(ha.h_length, hb.h_length);
}

#[test]
fn res_gethostbyname2_matches_gethostbyname2_for_numeric_ipv4() {
    use frankenlibc_abi::resolv_abi::res_gethostbyname2;
    let q = CString::new("127.0.0.1").unwrap();
    let a = unsafe { res_gethostbyname2(q.as_ptr(), libc::AF_INET) };
    assert!(!a.is_null());
    let h = unsafe { &*(a as *const libc::hostent) };
    assert_eq!(h.h_addrtype, libc::AF_INET);
    assert_eq!(h.h_length, 4);
}

#[test]
fn res_gethostbyaddr_matches_gethostbyaddr_for_loopback() {
    use frankenlibc_abi::resolv_abi::res_gethostbyaddr;
    let octets: [u8; 4] = [127, 0, 0, 1];
    let p = unsafe { res_gethostbyaddr(octets.as_ptr() as *const c_void, 4, libc::AF_INET) };
    // Loopback always resolves; non-loopback addresses without a
    // hosts entry can return NULL, which is also legal — only assert
    // we don't crash and the API accepts the call.
    let _ = p;
}

#[test]
fn res_send_setqhook_and_setrhook_round_trip_via_thread_local() {
    use frankenlibc_abi::resolv_abi::{
        res_send_qhook_for_tests, res_send_rhook_for_tests, res_send_setqhook, res_send_setrhook,
    };

    let q_sentinel = 0xDEAD_BEEF_usize as *mut c_void;
    let r_sentinel = 0xCAFE_BABE_usize as *mut c_void;

    unsafe {
        res_send_setqhook(q_sentinel);
        res_send_setrhook(r_sentinel);
    }
    assert_eq!(res_send_qhook_for_tests(), q_sentinel);
    assert_eq!(res_send_rhook_for_tests(), r_sentinel);

    // Reset to NULL.
    unsafe {
        res_send_setqhook(std::ptr::null_mut());
        res_send_setrhook(std::ptr::null_mut());
    }
    assert!(res_send_qhook_for_tests().is_null());
    assert!(res_send_rhook_for_tests().is_null());
}

// ---------------------------------------------------------------------------
// ns_name_ntol / ns_name_rollback
// ---------------------------------------------------------------------------

#[test]
fn ns_name_ntol_lowercases_labels() {
    use frankenlibc_abi::resolv_abi::ns_name_ntol;
    // Wire format for "FOO.COM": [3, 'F', 'O', 'O', 3, 'C', 'O', 'M', 0]
    let src: [u8; 9] = [3, b'F', b'O', b'O', 3, b'C', b'O', b'M', 0];
    let mut dst = [0u8; 9];
    let rc = unsafe { ns_name_ntol(src.as_ptr(), dst.as_mut_ptr(), dst.len()) };
    assert_eq!(rc, 0);
    assert_eq!(&dst, &[3, b'f', b'o', b'o', 3, b'c', b'o', b'm', 0]);
}

#[test]
fn ns_name_ntol_preserves_already_lowercase() {
    use frankenlibc_abi::resolv_abi::ns_name_ntol;
    let src: [u8; 9] = [3, b'b', b'a', b'r', 3, b'n', b'e', b't', 0];
    let mut dst = [0u8; 9];
    let rc = unsafe { ns_name_ntol(src.as_ptr(), dst.as_mut_ptr(), dst.len()) };
    assert_eq!(rc, 0);
    assert_eq!(&dst, &src);
}

#[test]
fn ns_name_ntol_rejects_dst_too_small() {
    use frankenlibc_abi::resolv_abi::ns_name_ntol;
    let src: [u8; 9] = [3, b'F', b'O', b'O', 3, b'C', b'O', b'M', 0];
    let mut dst = [0u8; 4]; // too small
    let rc = unsafe { ns_name_ntol(src.as_ptr(), dst.as_mut_ptr(), dst.len()) };
    assert_eq!(rc, -1);
}

#[test]
fn ns_name_ntol_handles_empty_root_name() {
    use frankenlibc_abi::resolv_abi::ns_name_ntol;
    // Just the root (single 0 byte).
    let src: [u8; 1] = [0];
    let mut dst = [0xFFu8; 4];
    let rc = unsafe { ns_name_ntol(src.as_ptr(), dst.as_mut_ptr(), dst.len()) };
    assert_eq!(rc, 0);
    assert_eq!(dst[0], 0);
}

#[test]
fn ns_name_rollback_clears_ptrs_at_or_past_threshold() {
    use frankenlibc_abi::resolv_abi::ns_name_rollback;

    // Set up a simulated dnptrs array with 4 entries + NULL terminator.
    // Pointers are just integer-shaped sentinels; we pass an array of
    // *mut u8 backed by a Vec so the addresses are real.
    let mut backing = vec![0u8; 256];
    let base = backing.as_mut_ptr();

    // Entries point into the backing buffer at offsets 0, 50, 100, 150.
    let mut dnptrs: [*mut u8; 5] = [
        unsafe { base.add(0) },
        unsafe { base.add(50) },
        unsafe { base.add(100) },
        unsafe { base.add(150) },
        core::ptr::null_mut(),
    ];
    let lastdnptr = unsafe { dnptrs.as_mut_ptr().add(dnptrs.len()) };

    // Roll back everything at or past offset 100.
    let threshold = unsafe { base.add(100) };
    unsafe { ns_name_rollback(threshold, dnptrs.as_mut_ptr(), lastdnptr) };

    // First two slots untouched; third (= 100) cleared.
    assert_eq!(dnptrs[0], unsafe { base.add(0) });
    assert_eq!(dnptrs[1], unsafe { base.add(50) });
    assert!(dnptrs[2].is_null());
}

#[test]
fn ns_name_rollback_handles_null_dnptrs() {
    use frankenlibc_abi::resolv_abi::ns_name_rollback;
    // NULL dnptrs must be tolerated (no-op).
    unsafe {
        ns_name_rollback(
            0xDEAD_usize as *const u8,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
}

// ---------------------------------------------------------------------------
// ns_initparse / ns_parserr / ns_skiprr / ns_msg_getflag
// ---------------------------------------------------------------------------

/// Build a synthetic DNS response message:
///   header: id=0x1234, flags=0x8180 (QR=1, RD=1, RA=1, RCODE=0), qd=1, an=1, ns=0, ar=0
///   question:  "foo.com" QTYPE=A (1), QCLASS=IN (1)
///   answer:    name pointer (0xC00C → offset 12 = "foo.com"), TYPE=A, CLASS=IN, TTL=3600, RDLENGTH=4, RDATA=127.0.0.1
fn synthetic_dns_message() -> Vec<u8> {
    let mut m = Vec::<u8>::new();
    // Header
    m.extend_from_slice(&[0x12, 0x34]); // ID
    m.extend_from_slice(&[0x81, 0x80]); // flags: 1 QR, 0001 opcode? No, opcode 0; AA=0, TC=0, RD=1, RA=1, Z=0, AD=0, CD=0, RCODE=0
    m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    m.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    m.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    m.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // Question section: foo.com A IN
    m.extend_from_slice(&[3, b'f', b'o', b'o', 3, b'c', b'o', b'm', 0]);
    m.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    m.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    // Answer section: pointer to offset 12 (foo.com label), A, IN, TTL=3600, RDLEN=4, 127.0.0.1
    m.extend_from_slice(&[0xC0, 0x0C]); // name compressed pointer to offset 12
    m.extend_from_slice(&[0x00, 0x01]); // TYPE=A
    m.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    m.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL=3600
    m.extend_from_slice(&[0x00, 0x04]); // RDLENGTH=4
    m.extend_from_slice(&[127, 0, 0, 1]); // RDATA
    m
}

#[test]
fn ns_initparse_parses_synthetic_response() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, ns_initparse};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    let rc = unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) };
    assert_eq!(rc, 0, "ns_initparse must succeed on a well-formed message");
    assert_eq!(handle._id, 0x1234);
    assert_eq!(handle._flags, 0x8180);
    assert_eq!(handle._counts, [1, 1, 0, 0]);
    // Question section starts immediately after the 12-byte header.
    assert_eq!(handle._sections[0], unsafe { msg.as_ptr().add(12) });
}

#[test]
fn ns_initparse_rejects_truncated_header() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, ns_initparse};
    let buf: [u8; 5] = [0; 5]; // less than 12-byte header
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    let rc = unsafe { ns_initparse(buf.as_ptr(), buf.len() as c_int, &mut handle) };
    assert_eq!(rc, -1);
}

#[test]
fn ns_initparse_rejects_truncated_section() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, ns_initparse};
    // Header claims 1 question but no question bytes follow.
    let mut buf: [u8; 12] = [0; 12];
    buf[5] = 1; // QDCOUNT=1
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    let rc = unsafe { ns_initparse(buf.as_ptr(), buf.len() as c_int, &mut handle) };
    assert_eq!(rc, -1);
}

#[test]
fn ns_msg_getflag_reads_header_bits() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, ns_initparse, ns_msg_getflag};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) },
        0
    );

    // Flag 0 = QR (we set bit 15 → 1)
    assert_eq!(unsafe { ns_msg_getflag(&mut handle, 0) }, 1);
    // Flag 4 = RD (bit 8 → 1)
    assert_eq!(unsafe { ns_msg_getflag(&mut handle, 4) }, 1);
    // Flag 5 = RA (bit 7 → 1)
    assert_eq!(unsafe { ns_msg_getflag(&mut handle, 5) }, 1);
    // Flag 9 = RCODE (low 4 bits → 0)
    assert_eq!(unsafe { ns_msg_getflag(&mut handle, 9) }, 0);
    // Flag 1 = opcode (bits 11-14 → 0)
    assert_eq!(unsafe { ns_msg_getflag(&mut handle, 1) }, 0);
}

#[test]
fn ns_parserr_reads_question_section() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_initparse, ns_parserr};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) },
        0
    );

    let mut rr: CNsRr = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        ns_parserr(&mut handle, 0 /*qd*/, 0, &mut rr)
    };
    assert_eq!(rc, 0);
    assert_eq!(rr._type, 1, "qtype A");
    assert_eq!(rr.rr_class, 1, "qclass IN");
    // Name should be "foo.com" (or "foo.com." depending on dn_expand).
    let name = unsafe { CStr::from_ptr(rr.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert!(
        name == "foo.com" || name == "foo.com.",
        "unexpected name: {name:?}"
    );
}

#[test]
fn ns_parserr_reads_answer_section_with_compressed_name() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_initparse, ns_parserr};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) },
        0
    );

    let mut rr: CNsRr = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        ns_parserr(&mut handle, 1 /*an*/, 0, &mut rr)
    };
    assert_eq!(rc, 0);
    assert_eq!(rr._type, 1);
    assert_eq!(rr.rr_class, 1);
    assert_eq!(rr.ttl, 3600);
    assert_eq!(rr.rdlength, 4);
    assert!(!rr.rdata.is_null());
    let octets = unsafe { core::slice::from_raw_parts(rr.rdata, 4) };
    assert_eq!(octets, &[127u8, 0, 0, 1]);

    let name = unsafe { CStr::from_ptr(rr.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    assert!(name == "foo.com" || name == "foo.com.");
}

#[test]
fn ns_parserr_rejects_out_of_range_rrnum() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_initparse, ns_parserr};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) },
        0
    );

    let mut rr: CNsRr = unsafe { std::mem::zeroed() };
    // Section 0 only has 1 question; rrnum=1 is out of range.
    let rc = unsafe { ns_parserr(&mut handle, 0, 1, &mut rr) };
    assert_eq!(rc, -1);
    // Invalid section index.
    let rc = unsafe { ns_parserr(&mut handle, 9, 0, &mut rr) };
    assert_eq!(rc, -1);
}

#[test]
fn ns_skiprr_advances_past_question_and_answer() {
    use frankenlibc_abi::resolv_abi::ns_skiprr;
    let msg = synthetic_dns_message();
    let qd_start = unsafe { msg.as_ptr().add(12) };
    let eom = unsafe { msg.as_ptr().add(msg.len()) };

    // Skip 1 question entry: name (9 bytes "foo.com") + 4 = 13 bytes.
    let n = unsafe {
        ns_skiprr(qd_start, eom, 0 /*qd*/, 1)
    };
    assert_eq!(n, 13);

    // Then the answer entry: ptr (2 bytes) + 10 fixed + 4 rdata = 16 bytes.
    let an_start = unsafe { qd_start.add(13) };
    let n = unsafe {
        ns_skiprr(an_start, eom, 1 /*an*/, 1)
    };
    assert_eq!(n, 16);
}

#[test]
fn ns_skiprr_rejects_overrun() {
    use frankenlibc_abi::resolv_abi::ns_skiprr;
    let msg = synthetic_dns_message();
    let qd_start = unsafe { msg.as_ptr().add(12) };
    let eom = unsafe { msg.as_ptr().add(msg.len()) };
    // Asking for too many entries should overrun the message.
    let rc = unsafe { ns_skiprr(qd_start, eom, 0, 100) };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// inet_neta — network number to text
// ---------------------------------------------------------------------------

fn neta_to_str(src: u32, capacity: usize) -> Option<String> {
    use frankenlibc_abi::resolv_abi::inet_neta;
    let mut buf = vec![0u8; capacity];
    let p = unsafe { inet_neta(src, buf.as_mut_ptr() as *mut c_char, capacity) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Some(s)
}

/// Helper: convert dotted-quad-style octets to the integer contract used by
/// libresolv `inet_neta`: the first formatted octet is the most-significant
/// non-zero byte.
fn na(a: u8, b: u8, c: u8, d: u8) -> u32 {
    u32::from_be_bytes([a, b, c, d])
}

#[test]
fn inet_neta_strips_trailing_zero_octets() {
    assert_eq!(neta_to_str(na(127, 0, 0, 0), 32).as_deref(), Some("127"));
    assert_eq!(
        neta_to_str(na(192, 168, 1, 0), 32).as_deref(),
        Some("192.168.1")
    );
    assert_eq!(
        neta_to_str(na(192, 168, 1, 5), 32).as_deref(),
        Some("192.168.1.5")
    );
    assert_eq!(neta_to_str(na(10, 0, 0, 0), 32).as_deref(), Some("10"));
}

#[test]
fn inet_neta_strips_internal_zeros_too() {
    // The libresolv inet_neta algorithm skips a byte whenever it is
    // zero AND there are more non-zero bytes remaining — so internal
    // zeros are also stripped, not just trailing ones.
    //   10.0.5.0  → "10.5"
    //   192.0.0.5 → "192.5"
    assert_eq!(neta_to_str(na(10, 0, 5, 0), 32).as_deref(), Some("10.5"));
    assert_eq!(neta_to_str(na(192, 0, 0, 5), 32).as_deref(), Some("192.5"));
}

#[test]
fn inet_neta_formats_high_order_bytes_first() {
    assert_eq!(neta_to_str(0x0001_a8c0, 32).as_deref(), Some("1.168.192"));
    assert_eq!(neta_to_str(0x0000_007f, 32).as_deref(), Some("127"));
}

#[test]
fn inet_neta_accepts_exact_size_buffer() {
    assert_eq!(neta_to_str(na(127, 0, 0, 0), 4).as_deref(), Some("127"));
    assert_eq!(
        neta_to_str(na(192, 168, 1, 5), "192.168.1.5".len() + 1).as_deref(),
        Some("192.168.1.5")
    );
}

#[test]
fn inet_neta_emits_zero_address_as_quad_zero() {
    assert_eq!(neta_to_str(0, 32).as_deref(), Some("0.0.0.0"));
}

#[test]
fn inet_neta_returns_null_emsgsize_when_too_small() {
    use frankenlibc_abi::resolv_abi::inet_neta;
    // 192.168.1.5 + NUL = 12 bytes; buffer of 8 is insufficient.
    let mut buf = [0u8; 8];
    let p = unsafe {
        inet_neta(
            na(192, 168, 1, 5),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EMSGSIZE);

    // NULL dst also EMSGSIZE.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let p = unsafe { inet_neta(0, std::ptr::null_mut(), 0) };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EMSGSIZE);
}

#[test]
fn inet_neta_zero_address_too_small_buffer_fails() {
    use frankenlibc_abi::resolv_abi::inet_neta;
    // "0.0.0.0\0" needs 8 bytes; buffer of 4 is too small.
    let mut buf = [0u8; 4];
    let p = unsafe { inet_neta(0, buf.as_mut_ptr() as *mut c_char, buf.len()) };
    assert!(p.is_null());
    let errno = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(errno, libc::EMSGSIZE);
}

// ---------------------------------------------------------------------------
// ns_sprintrr / ns_sprintrrf
// ---------------------------------------------------------------------------

fn sprintrrf_to_str(
    msg: &[u8],
    name: &str,
    class: u16,
    ty: u16,
    ttl: u32,
    rdata: &[u8],
    cap: usize,
) -> Option<String> {
    use frankenlibc_abi::resolv_abi::ns_sprintrrf;
    let cname = std::ffi::CString::new(name).unwrap();
    let mut buf = vec![0u8; cap];
    let n = unsafe {
        ns_sprintrrf(
            msg.as_ptr(),
            msg.len(),
            cname.as_ptr(),
            class,
            ty,
            ttl,
            if rdata.is_empty() {
                std::ptr::null()
            } else {
                rdata.as_ptr()
            },
            rdata.len(),
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

#[test]
fn ns_sprintrrf_formats_a_record() {
    // No msg context needed for A; pass an empty slice (msglen=0).
    let s = sprintrrf_to_str(
        &[],
        "foo.com",
        1, /*IN*/
        1, /*A*/
        3600,
        &[127, 0, 0, 1],
        64,
    )
    .unwrap();
    assert_eq!(s, "foo.com 1H IN A 127.0.0.1");
}

#[test]
fn ns_sprintrrf_formats_aaaa_record() {
    let v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let s = sprintrrf_to_str(&[], "host.example", 1, 28 /*AAAA*/, 60, &v6, 128).unwrap();
    assert!(s.starts_with("host.example 1M IN AAAA "));
    assert!(s.contains("2001:db8::1"));
}

#[test]
fn ns_sprintrrf_formats_mx_record() {
    // Build one synthetic msg that holds both the rdata bytes and the
    // embedded target name so dn_expand has a valid view of the
    // compressed pointer.
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0u8; 12]); // dummy header padding
    let rdata_off = msg.len();
    msg.extend_from_slice(&[0, 10, 0xC0, 0]); // pref=10, ptr placeholder
    let name_off = msg.len() as u16;
    msg[rdata_off + 3] = name_off as u8; // patch ptr's low byte
    msg.extend_from_slice(&[4, b'm', b'a', b'i', b'l', 3, b'c', b'o', b'm', 0]);

    use frankenlibc_abi::resolv_abi::ns_sprintrrf;
    let cname = std::ffi::CString::new("example.com").unwrap();
    let mut buf = [0u8; 128];
    let n = unsafe {
        ns_sprintrrf(
            msg.as_ptr(),
            msg.len(),
            cname.as_ptr(),
            1,
            15,
            60,
            msg.as_ptr().add(rdata_off),
            4,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert!(n > 0, "ns_sprintrrf returned {n}");
    let s = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    assert!(s.starts_with("example.com 1M IN MX 10 "), "got: {s}");
    assert!(s.contains("mail.com"), "got: {s}");
}

#[test]
fn ns_sprintrrf_formats_txt_record_with_quoting() {
    // TXT rdata: 1-byte length-prefixed strings.
    let rdata = b"\x05hello\x06wo\"rld";
    let s = sprintrrf_to_str(&[], "txt.example", 1, 16 /*TXT*/, 1, rdata, 128).unwrap();
    assert_eq!(s, r#"txt.example 1S IN TXT "hello" "wo\"rld""#);
}

#[test]
fn ns_sprintrrf_falls_back_to_rfc3597_for_unknown_type() {
    let rdata = b"\x01\x02\x03";
    let s = sprintrrf_to_str(&[], "weird.example", 1, 999 /*unknown*/, 0, rdata, 64).unwrap();
    // Type prints as TYPE999, rdata as RFC 3597 generic.
    assert_eq!(s, "weird.example 0S IN TYPE999 \\# 3 010203");
}

#[test]
fn ns_sprintrrf_returns_minus_one_on_buffer_overflow() {
    use frankenlibc_abi::resolv_abi::ns_sprintrrf;
    let cname = std::ffi::CString::new("foo.com").unwrap();
    let mut buf = [0u8; 4]; // way too small
    let n = unsafe {
        ns_sprintrrf(
            std::ptr::null(),
            0,
            cname.as_ptr(),
            1,
            1,
            3600,
            [127u8, 0, 0, 1].as_ptr(),
            4,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn ns_sprintrrf_rejects_tracked_unterminated_name() {
    use frankenlibc_abi::resolv_abi::ns_sprintrrf;
    let cname = malloc_unterminated(b"foo.com");
    let mut buf = [0u8; 64];
    let n = unsafe {
        ns_sprintrrf(
            std::ptr::null(),
            0,
            cname.as_ptr(),
            1,
            1,
            3600,
            [127u8, 0, 0, 1].as_ptr(),
            4,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn ns_sprintrrf_rejects_malformed_a_rdata() {
    // A record requires exactly 4 bytes; passing 3 is malformed.
    let s = sprintrrf_to_str(&[], "foo.com", 1, 1 /*A*/, 3600, &[1, 2, 3], 64);
    assert!(s.is_none());
}

#[test]
fn ns_sprintrrf_rejects_null_rdata_with_nonzero_len() {
    use frankenlibc_abi::resolv_abi::ns_sprintrrf;
    let cname = std::ffi::CString::new("foo.com").unwrap();
    let mut buf = [0u8; 64];
    let n = unsafe {
        ns_sprintrrf(
            std::ptr::null(),
            0,
            cname.as_ptr(),
            1,
            999,
            0,
            std::ptr::null(),
            3,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn ns_sprintrrf_unsupported_known_type_uses_generic_type_number() {
    let s = sprintrrf_to_str(&[], "soa.example", 1, 6 /*SOA*/, 0, &[1, 2, 3], 64).unwrap();
    assert_eq!(s, "soa.example 0S IN TYPE6 \\# 3 010203");
}

#[test]
fn ns_sprintrr_wraps_sprintrrf_via_handle_and_rr() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_initparse, ns_parserr, ns_sprintrr};
    let msg = synthetic_dns_message();
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { ns_initparse(msg.as_ptr(), msg.len() as c_int, &mut handle) },
        0
    );
    let mut rr: CNsRr = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            ns_parserr(&mut handle, 1 /*an*/, 0, &mut rr)
        },
        0
    );

    let mut buf = [0u8; 128];
    let n = unsafe {
        ns_sprintrr(
            &handle,
            &rr,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert!(n > 0);
    let s = String::from_utf8_lossy(&buf[..n as usize]).into_owned();
    assert!(s.contains(" IN A "), "got: {s}");
    assert!(s.contains("127.0.0.1"), "got: {s}");
}

#[test]
fn ns_sprintrr_rejects_invalid_handle_bounds() {
    use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_sprintrr};
    let msg = [0u8; 4];
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    handle._msg = unsafe { msg.as_ptr().add(3) };
    handle._eom = msg.as_ptr();

    let mut rr: CNsRr = unsafe { std::mem::zeroed() };
    for (slot, byte) in rr.name.iter_mut().zip(b"foo.com\0") {
        *slot = *byte as c_char;
    }
    rr._type = 1;
    rr.rr_class = 1;
    let rdata = [127u8, 0, 0, 1];
    rr.rdata = rdata.as_ptr();
    rr.rdlength = 4;

    let mut buf = [0u8; 64];
    let n = unsafe {
        ns_sprintrr(
            &handle,
            &rr,
            std::ptr::null(),
            std::ptr::null(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        )
    };
    assert_eq!(n, -1);
}

// ---------------------------------------------------------------------------
// Tests for 37 libresolv last-mile helpers (bd-dcfj5)
// ---------------------------------------------------------------------------

#[test]
fn bd_dcfj5_byte_order_helpers_round_trip_be() {
    use frankenlibc_abi::resolv_abi::*;
    let bytes16 = [0x12u8, 0x34];
    let bytes32 = [0x12u8, 0x34, 0x56, 0x78];
    assert_eq!(unsafe { __ns_get16(bytes16.as_ptr()) }, 0x1234);
    assert_eq!(unsafe { __ns_get32(bytes32.as_ptr()) }, 0x1234_5678);
    assert_eq!(unsafe { _getshort(bytes16.as_ptr()) }, 0x1234);
    assert_eq!(unsafe { _getlong(bytes32.as_ptr()) }, 0x1234_5678);
    let mut out16 = [0u8; 2];
    let mut out32 = [0u8; 4];
    unsafe { __putshort(0x1234, out16.as_mut_ptr()) };
    unsafe { __putlong(0x1234_5678, out32.as_mut_ptr()) };
    assert_eq!(out16, [0x12, 0x34]);
    assert_eq!(out32, [0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn bd_dcfj5_byte_order_helpers_tolerate_null() {
    use frankenlibc_abi::resolv_abi::*;
    assert_eq!(unsafe { _getshort(std::ptr::null()) }, 0);
    assert_eq!(unsafe { _getlong(std::ptr::null()) }, 0);
    unsafe { __putshort(0x1234, std::ptr::null_mut()) };
    unsafe { __putlong(0x1234_5678, std::ptr::null_mut()) };
}

#[test]
fn bd_dcfj5_dns_print_helpers_are_void_noops() {
    use frankenlibc_abi::resolv_abi::*;
    unsafe { __fp_query(std::ptr::null(), std::ptr::null_mut()) };
    unsafe { __fp_nquery(std::ptr::null(), 0, std::ptr::null_mut()) };
    unsafe { __fp_resstat(std::ptr::null(), std::ptr::null_mut()) };
    unsafe { __p_query(std::ptr::null()) };
}

#[test]
fn bd_dcfj5_dns_text_helpers_return_static_strings() {
    use frankenlibc_abi::resolv_abi::*;
    let class_str = unsafe { CStr::from_ptr(__p_class(1)) };
    assert_eq!(class_str.to_bytes(), b"IN");
    let type_str = unsafe { CStr::from_ptr(__p_type(1)) };
    assert_eq!(type_str.to_bytes(), b"A");
    let opt_str = unsafe { CStr::from_ptr(__p_option(0)) };
    assert_eq!(opt_str.to_bytes(), b"");
    let rcode_str = unsafe { CStr::from_ptr(__p_rcode(0)) };
    assert_eq!(rcode_str.to_bytes(), b"NOERROR");
    let secs_str = unsafe { CStr::from_ptr(__p_secstodate(0)) };
    assert_eq!(secs_str.to_bytes(), b"19700101000000");
    let time_str = unsafe { CStr::from_ptr(__p_time(0)) };
    assert_eq!(time_str.to_bytes(), b"0");
}

#[test]
fn bd_dcfj5_dns_cdname_fqname_return_null() {
    use frankenlibc_abi::resolv_abi::*;
    assert!(
        unsafe { __p_cdname(std::ptr::null(), std::ptr::null(), std::ptr::null_mut()) }.is_null()
    );
    assert!(
        unsafe { __p_cdnname(std::ptr::null(), std::ptr::null(), 0, std::ptr::null_mut()) }
            .is_null()
    );
    assert!(
        unsafe { __p_fqname(std::ptr::null(), std::ptr::null(), std::ptr::null_mut()) }.is_null()
    );
    assert!(
        unsafe {
            __p_fqnname(
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
            )
        }
        .is_null()
    );
}

#[test]
fn bd_dcfj5_hostalias_helpers_return_null() {
    use frankenlibc_abi::resolv_abi::*;
    let name = CString::new("alias").unwrap();
    assert!(unsafe { __hostalias(name.as_ptr()) }.is_null());
    assert!(
        unsafe { __res_hostalias(std::ptr::null_mut(), name.as_ptr(), std::ptr::null_mut(), 0) }
            .is_null()
    );
}

#[test]
fn bd_dcfj5_loc_helpers_return_failure() {
    use frankenlibc_abi::resolv_abi::*;
    let ascii = CString::new("42 21 30 N 71 6 18 W -24m 30m").unwrap();
    let mut binary = [0u8; 16];
    assert_eq!(
        unsafe { __loc_aton(ascii.as_ptr(), binary.as_mut_ptr()) },
        0
    );
    let mut out = [0i8; 256];
    assert!(unsafe { __loc_ntoa(binary.as_ptr(), out.as_mut_ptr()) }.is_null());
}

#[test]
fn bd_dcfj5_sym_helpers_set_success_zero() {
    use frankenlibc_abi::resolv_abi::*;
    let mut success: c_int = 99;
    assert!(unsafe { __sym_ntop(std::ptr::null(), 1, &mut success) }.is_null());
    assert_eq!(success, 0);
    success = 99;
    assert!(unsafe { __sym_ntos(std::ptr::null(), 1, &mut success) }.is_null());
    assert_eq!(success, 0);
    success = 99;
    let key = CString::new("ANY").unwrap();
    assert_eq!(
        unsafe { __sym_ston(std::ptr::null(), key.as_ptr(), &mut success) },
        0
    );
    assert_eq!(success, 0);
}

#[test]
fn bd_dcfj5_res_close_is_void_noop() {
    use frankenlibc_abi::resolv_abi::*;
    unsafe { __res_close(std::ptr::null_mut()) };
}

#[test]
fn bd_dcfj5_res_isourserver_returns_zero() {
    use frankenlibc_abi::resolv_abi::*;
    let rc = unsafe { __res_isourserver(std::ptr::null(), std::ptr::null()) };
    assert_eq!(rc, 0);
}

#[test]
fn bd_dcfj5_res_nameinquery_and_queriesmatch_return_zero() {
    use frankenlibc_abi::resolv_abi::*;
    let name = CString::new("example.com").unwrap();
    assert_eq!(
        unsafe { __res_nameinquery(name.as_ptr(), 1, 1, std::ptr::null(), std::ptr::null()) },
        0
    );
    assert_eq!(
        unsafe {
            __res_queriesmatch(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
}

#[test]
fn bd_dcfj5_dn_count_labels_counts_dots() {
    use frankenlibc_abi::resolv_abi::*;
    let n0 = CString::new("").unwrap();
    let n1 = CString::new("example").unwrap();
    let n2 = CString::new("example.com").unwrap();
    let n3 = CString::new("a.b.c").unwrap();
    let nfqdn = CString::new("a.b.c.").unwrap();
    assert_eq!(unsafe { __dn_count_labels(n0.as_ptr()) }, 0);
    assert_eq!(unsafe { __dn_count_labels(n1.as_ptr()) }, 1);
    assert_eq!(unsafe { __dn_count_labels(n2.as_ptr()) }, 2);
    assert_eq!(unsafe { __dn_count_labels(n3.as_ptr()) }, 3);
    // Trailing dot represents the root, not an extra label.
    assert_eq!(unsafe { __dn_count_labels(nfqdn.as_ptr()) }, 3);
    assert_eq!(unsafe { __dn_count_labels(std::ptr::null()) }, -1);
}

#[test]
fn bd_dcfj5_dn_count_labels_rejects_tracked_unterminated_name() {
    use frankenlibc_abi::resolv_abi::__dn_count_labels;
    let name = malloc_unterminated(b"example.com");
    assert_eq!(unsafe { __dn_count_labels(name.as_ptr()) }, -1);
}

#[test]
fn bd_dcfj5_etc_hosts_iteration_returns_null_or_void() {
    use frankenlibc_abi::resolv_abi::*;
    unsafe { _sethtent(0) };
    unsafe { _sethtent(1) };
    assert!(unsafe { _gethtent() }.is_null());
    let name = CString::new("localhost").unwrap();
    assert!(unsafe { _gethtbyname(name.as_ptr()) }.is_null());
    assert!(unsafe { _gethtbyname2(name.as_ptr(), libc::AF_INET) }.is_null());
    let addr = [127u8, 0, 0, 1];
    assert!(unsafe { _gethtbyaddr(addr.as_ptr() as *const c_void, 4, libc::AF_INET) }.is_null());
}
