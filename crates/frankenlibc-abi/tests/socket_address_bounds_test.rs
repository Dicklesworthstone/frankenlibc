#![cfg(target_os = "linux")]
//! Real ABI calls; independent children isolate modes, quarantine and seccomp.
use frankenlibc_abi::{errno_abi, malloc_abi, socket_abi};
use std::mem::size_of;
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_SOCKADDR_CHILD";
const ENTRIES: &[&str] = &[
    "accept",
    "__accept",
    "accept4",
    "recvfrom",
    "__recvfrom",
    "getpeername",
    "__getpeername",
    "getsockname",
    "__getsockname",
];
const COMMON: &[&str] = &[
    "valid",
    "truncated",
    "zero",
    "negative-length",
    "readonly-length",
    "bad-fd",
];
const HARDENED: &[&str] = &[
    "bad-length",
    "null-length",
    "wrap-length",
    "short-length",
    "quarantined-length",
    "short-address",
    "quarantined-address",
    "wrap-address",
    "unaligned-length",
    "fallback",
    "denied-copy",
];

struct Allocation {
    pointer: *mut u8,
    live: bool,
}
impl Allocation {
    fn new(bytes: usize) -> Self {
        let pointer = unsafe { malloc_abi::malloc(bytes) }.cast::<u8>();
        assert!(!pointer.is_null());
        assert_eq!(
            malloc_abi::malloc_known_remaining_for_tests(pointer.cast()),
            Some(bytes)
        );
        unsafe { pointer.write_bytes(0xa5, bytes) };
        Self {
            pointer,
            live: true,
        }
    }
    fn quarantine(&mut self) {
        unsafe { malloc_abi::free(self.pointer.cast()) };
        self.live = false;
        assert_eq!(
            malloc_abi::malloc_known_remaining_for_tests(self.pointer.cast()),
            Some(0)
        );
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if self.live {
            unsafe { malloc_abi::free(self.pointer.cast()) };
        }
    }
}
struct Fds([libc::c_int; 2]);
impl Drop for Fds {
    fn drop(&mut self) {
        for fd in self.0 {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}
struct Page(*mut libc::c_void, usize);
impl Page {
    fn new() -> Self {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(size > 0);
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        Self(pointer, size as usize)
    }
}
impl Drop for Page {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0, self.1) };
    }
}
fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}
fn accepting(entry: &str) -> bool {
    matches!(entry, "accept" | "__accept" | "accept4")
}
fn receiving(entry: &str) -> bool {
    matches!(entry, "recvfrom" | "__recvfrom")
}

fn bind_loopback(fd: libc::c_int) -> libc::sockaddr_in {
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    address.sin_family = libc::AF_INET as _;
    address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    assert_eq!(
        unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as _,
            )
        },
        0
    );
    let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut length,
            )
        },
        0
    );
    address
}
fn setup(entry: &str, empty: bool) -> Fds {
    let accept = accepting(entry);
    let kind = if accept {
        libc::SOCK_STREAM
    } else {
        libc::SOCK_DGRAM
    };
    let mut fds = Fds([-1; 2]);
    fds.0[0] = unsafe {
        libc::socket(
            libc::AF_INET,
            kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    fds.0[1] = unsafe { libc::socket(libc::AF_INET, kind | libc::SOCK_CLOEXEC, 0) };
    assert!(fds.0.iter().all(|&fd| fd >= 0));
    let left = bind_loopback(fds.0[0]);
    let right = bind_loopback(fds.0[1]);
    if accept {
        assert_eq!(unsafe { libc::listen(fds.0[0], 4) }, 0);
    }
    if !accept || !empty {
        assert_eq!(
            unsafe {
                libc::connect(
                    fds.0[1],
                    (&left as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as _,
                )
            },
            0
        );
    }
    if !accept {
        assert_eq!(
            unsafe {
                libc::connect(
                    fds.0[0],
                    (&right as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as _,
                )
            },
            0
        );
    }
    if receiving(entry) && !empty {
        assert_eq!(
            unsafe {
                libc::send(
                    fds.0[1],
                    [0x57u8; 64].as_ptr().cast(),
                    64,
                    libc::MSG_NOSIGNAL,
                )
            },
            64
        );
    }
    fds
}
fn deny_copy_routes(both: bool) {
    let mut filter = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for number in [
        libc::SYS_process_vm_readv,
        if both { libc::SYS_pipe2 } else { -1 },
    ] {
        if number < 0 {
            continue;
        }
        filter.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: number as u32,
        });
        filter.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });
    let program = libc::sock_fprog {
        len: filter.len() as _,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) },
        0
    );
    assert_eq!(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                2usize,
                &program as *const libc::sock_fprog,
            )
        },
        0
    );
}
#[allow(unused_assignments)]
fn run_case(entry: &str, case: &str) {
    malloc_abi::signal_runtime_ready_for_tests();
    assert!(ENTRIES.contains(&entry));
    assert!(
        COMMON.contains(&case)
            || HARDENED.contains(&case)
            || matches!(case, "null-address" | "would-block")
    );
    let fds = setup(entry, case == "would-block");
    let mut address = [0xa5u8; 128];
    let mut payload = [0x19u8; 64];
    let mut length: libc::socklen_t = 16;
    let mut lengths = Allocation::new(if case == "short-length" { 3 } else { 4 });
    let mut addresses = Allocation::new(if case == "short-address" { 2 } else { 128 });
    let page = Page::new();
    let mut unaligned = [0u8; 12];
    let mut output_address = address.as_mut_ptr().cast::<libc::sockaddr>();
    let mut output_length = &mut length as *mut libc::socklen_t;
    match case {
        "truncated" => length = 2,
        "zero" => length = 0,
        "negative-length" => length = u32::MAX,
        "null-address" => {
            output_address = ptr::null_mut();
            output_length = ptr::without_provenance_mut(1);
        }
        "bad-length" => output_length = ptr::without_provenance_mut(1),
        "null-length" => output_length = ptr::null_mut(),
        "wrap-length" => output_length = ptr::without_provenance_mut(usize::MAX - 1),
        "short-length" => output_length = lengths.pointer.cast(),
        "quarantined-length" => {
            unsafe { lengths.pointer.cast::<u32>().write(16) };
            lengths.quarantine();
            output_length = lengths.pointer.cast();
        }
        "short-address" => output_address = addresses.pointer.cast(),
        "quarantined-address" => {
            addresses.quarantine();
            output_address = addresses.pointer.cast();
        }
        "wrap-address" => output_address = ptr::without_provenance_mut(usize::MAX - 1),
        "unaligned-length" => {
            let offset = (5 - unaligned.as_ptr() as usize % 4) % 4;
            output_length = unaligned.as_mut_ptr().wrapping_add(offset).cast();
            assert_ne!(output_length as usize % 4, 0);
            unsafe { output_length.write_unaligned(16) };
        }
        "readonly-length" => {
            output_length = page.0.cast();
            unsafe { output_length.write(16) };
            assert_eq!(
                unsafe { libc::mprotect(page.0, page.1, libc::PROT_READ) },
                0
            );
        }
        _ => {}
    }
    let before_fds = fd_count();
    if matches!(case, "fallback" | "denied-copy") {
        deny_copy_routes(case == "denied-copy");
    }
    let fd = if case == "bad-fd" { -1 } else { fds.0[0] };
    let result: isize = unsafe {
        match entry {
            "accept" => socket_abi::accept(fd, output_address, output_length) as isize,
            "__accept" => socket_abi::__accept(fd, output_address, output_length) as isize,
            "accept4" => socket_abi::accept4(
                fd,
                output_address,
                output_length,
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            ) as isize,
            "recvfrom" => socket_abi::recvfrom(
                fd,
                payload.as_mut_ptr().cast(),
                64,
                libc::MSG_DONTWAIT,
                output_address,
                output_length,
            ),
            "__recvfrom" => socket_abi::__recvfrom(
                fd,
                payload.as_mut_ptr().cast(),
                64,
                libc::MSG_DONTWAIT,
                output_address,
                output_length,
            ),
            "getpeername" => socket_abi::getpeername(fd, output_address, output_length) as isize,
            "__getpeername" => {
                socket_abi::__getpeername(fd, output_address, output_length) as isize
            }
            "getsockname" => socket_abi::getsockname(fd, output_address, output_length) as isize,
            "__getsockname" => {
                socket_abi::__getsockname(fd, output_address, output_length) as isize
            }
            _ => unreachable!(),
        }
    };
    let error = unsafe { *errno_abi::__errno_location() };
    let rejected = HARDENED.contains(&case) && !matches!(case, "unaligned-length" | "fallback");
    let failure = rejected
        || matches!(
            case,
            "readonly-length" | "negative-length" | "bad-fd" | "would-block"
        );
    if accepting(entry) && result >= 0 {
        let descriptor_flags = unsafe { libc::fcntl(result as _, libc::F_GETFD) };
        let status_flags = unsafe { libc::fcntl(result as _, libc::F_GETFL) };
        assert_eq!(unsafe { libc::close(result as _) }, 0);
        if entry == "accept4" {
            assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
            assert_ne!(status_flags & libc::O_NONBLOCK, 0);
        }
    }
    assert_eq!(fd_count(), before_fds, "failed accept leaked a descriptor");
    if failure {
        assert_eq!(
            result, -1,
            "rejected address reached socket I/O: {entry}/{case}"
        );
        let expected = match case {
            "negative-length" => libc::EINVAL,
            "bad-fd" => libc::EBADF,
            "would-block" => libc::EAGAIN,
            "denied-copy" => libc::EPERM,
            _ => libc::EFAULT,
        };
        assert_eq!(error, expected, "{entry}/{case}: errno");
        if rejected || matches!(case, "bad-fd" | "would-block") {
            assert_eq!(address, [0xa5; 128]);
            assert_eq!(payload, [0x19; 64]);
        }
    } else {
        if accepting(entry) {
            assert!(result >= 0, "{entry}/{case}: errno={error}");
        } else {
            assert_eq!(
                result,
                if receiving(entry) { 64 } else { 0 },
                "{entry}/{case}: errno={error}"
            );
        }
        if case != "null-address" {
            assert_eq!(
                unsafe { output_length.read_unaligned() },
                16,
                "address length not published"
            );
            let changed = if case == "zero" {
                0
            } else if case == "truncated" {
                2
            } else {
                16
            };
            assert!(address[changed..].iter().all(|&byte| byte == 0xa5));
            if changed != 0 {
                assert_eq!(
                    libc::sa_family_t::from_ne_bytes([address[0], address[1]]) as libc::c_int,
                    libc::AF_INET
                );
            }
        } else {
            assert_eq!(address, [0xa5; 128]);
        }
        if receiving(entry) {
            assert_eq!(payload, [0x57; 64]);
        }
    }
    // Early validation must not consume pending network work. Conversely,
    // publication faults happen after the accepted connection / data transfer.
    let stays_queued = rejected || case == "bad-fd";
    if accepting(entry) {
        let next = unsafe {
            libc::accept4(
                fds.0[0],
                ptr::null_mut(),
                ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        let next_error = unsafe { *libc::__errno_location() };
        if next >= 0 {
            unsafe { libc::close(next) };
        }
        if stays_queued {
            assert!(next >= 0, "validation consumed pending connection");
        } else {
            assert_eq!(next, -1);
            assert_eq!(next_error, libc::EAGAIN);
        }
    } else if receiving(entry) {
        let mut rest = [0u8; 64];
        let next = unsafe {
            libc::recv(
                fds.0[0],
                rest.as_mut_ptr().cast(),
                rest.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if stays_queued {
            assert_eq!(next, 64, "validation consumed queued datagram");
            assert_eq!(rest, [0x57; 64]);
        } else {
            assert_eq!(next, -1);
            assert_eq!(unsafe { *libc::__errno_location() }, libc::EAGAIN);
        }
    }
    drop((lengths, addresses, page));
}
#[test]
fn socket_address_bounds_matrix() {
    if let Ok(selected) = std::env::var(CHILD) {
        let (entry, case) = selected.split_once(':').expect("entry:case");
        run_case(entry, case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    let mut count = 0;
    for &entry in ENTRIES {
        for mode in ["strict", "hardened"] {
            let mut cases = COMMON.to_vec();
            if accepting(entry) || receiving(entry) {
                cases.extend(["null-address", "would-block"]);
            }
            if mode == "hardened" {
                cases.extend_from_slice(HARDENED);
            }
            for case in cases {
                let mut child = Command::new(&executable)
                    .args([
                        "--exact",
                        "socket_address_bounds_matrix",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, format!("{entry}:{case}"))
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut timed_out = false;
                while child.try_wait().unwrap().is_none() {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let output = child.wait_with_output().unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                count += 1;
                if timed_out || !output.status.success() || !stdout.contains("1 passed;") {
                    failures.push(format!(
                        "{entry}/{case}/{mode}: timeout={timed_out} status={}\n{stdout}\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(count, 227);
    println!("227 isolated socket-address ABI cases passed");
}
