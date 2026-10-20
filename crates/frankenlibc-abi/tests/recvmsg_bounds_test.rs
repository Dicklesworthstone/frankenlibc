#![cfg(target_os = "linux")]

//! Actual recvmsg ABI/alias regressions. Every mode/case runs in a child so
//! immutable mode selection, quarantine, seccomp and faults cannot contaminate
//! another test. The host socket APIs are kernel controls, not the subject.
use frankenlibc_abi::{errno_abi, malloc_abi, socket_abi};
use std::mem::{offset_of, size_of};
use std::process::{Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_RECVMSG_CHILD";
const SIZE: usize = 64;
const MARKER: u8 = 0x2c;
const INITIAL_FLAGS: libc::c_int = 0x1234;
const EMPTY: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};
const COMMON: &[&str] = &[
    "valid",
    "split",
    "maximum",
    "zero",
    "zero-element",
    "empty-datagram",
    "truncation",
    "truncation-length",
    "peek",
    "bad-header",
    "null-header",
    "bad-iov",
    "null-iov",
    "bad-count",
    "full-width-count",
    "unaligned-header",
    "unaligned-iov",
    "readonly-iov",
    "readonly-header",
    "readonly-flags",
    "readonly-controllen",
    "readonly-namelen",
    "rights",
    "rights-truncated",
    "name",
    "name-truncated",
    "would-block",
];
const HARDENED: &[&str] = &[
    "oversize",
    "interior-overrun",
    "quarantine",
    "short-iov",
    "short-header",
    "quarantined-iov",
    "quarantined-header",
    "control-overrun",
    "name-overrun",
    "control-quarantine",
    "name-quarantine",
    "fallback",
    "fallback-output-fault",
    "denied-copy",
];

struct Allocation {
    pointer: *mut u8,
    bytes: usize,
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
        unsafe { pointer.write_bytes(MARKER, bytes) };
        Self {
            pointer,
            bytes,
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
    fn assert_bytes(&self, changed: usize) {
        assert!(self.live && changed <= self.bytes);
        for index in 0..self.bytes {
            assert_eq!(
                unsafe { self.pointer.add(index).read() },
                if index < changed { 0x57 } else { MARKER },
                "payload/canary at {index}"
            );
        }
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if self.live {
            unsafe { malloc_abi::free(self.pointer.cast()) };
        }
    }
}

struct Mapping {
    pointer: *mut u8,
    page: usize,
}
impl Mapping {
    fn new() -> Self {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let page = page as usize;
        let pointer = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        Self {
            pointer: pointer.cast(),
            page,
        }
    }
    fn readonly(&self, start: usize, pages: usize) {
        assert_eq!(
            unsafe {
                libc::mprotect(
                    self.pointer.wrapping_add(start * self.page).cast(),
                    self.page * pages,
                    libc::PROT_READ,
                )
            },
            0
        );
    }
    fn header(&self) -> *mut libc::msghdr {
        self.pointer
            .wrapping_add(self.page - offset_of!(libc::msghdr, msg_flags))
            .cast()
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::munmap(self.pointer.cast(), self.page * 2) },
            0
        );
    }
}

struct Sockets([libc::c_int; 2]);
impl Sockets {
    fn new(named: bool) -> (Self, libc::sockaddr_in) {
        let mut sockets = Self([-1; 2]);
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        if named {
            for fd in &mut sockets.0 {
                *fd = unsafe {
                    libc::socket(
                        libc::AF_INET,
                        libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                        0,
                    )
                };
                assert!(*fd >= 0);
            }
            address.sin_family = libc::AF_INET as _;
            address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            assert_eq!(
                unsafe {
                    libc::bind(
                        sockets.0[1],
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
                        sockets.0[1],
                        (&mut address as *mut libc::sockaddr_in).cast(),
                        &mut length,
                    )
                },
                0
            );
        } else {
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                        0,
                        sockets.0.as_mut_ptr(),
                    )
                },
                0
            );
        }
        (sockets, address)
    }
    fn drain(&self) -> (isize, libc::c_int, [u8; SIZE + 1]) {
        let mut bytes = [0u8; SIZE + 1];
        let count = unsafe {
            libc::recv(
                self.0[1],
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        let error = unsafe { *libc::__errno_location() };
        (count, error, bytes)
    }
}
impl Drop for Sockets {
    fn drop(&mut self) {
        for fd in self.0 {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

fn deny_copy_routes(deny_pipe: bool) {
    let mut filters = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for number in [
        libc::SYS_process_vm_readv,
        if deny_pipe { libc::SYS_pipe2 } else { -1 },
    ] {
        if number < 0 {
            continue;
        }
        filters.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: number as u32,
        });
        filters.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        });
    }
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
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

fn enqueue(
    sockets: &Sockets,
    named: bool,
    address: &libc::sockaddr_in,
    rights: bool,
    bytes: usize,
) {
    let data = [0x57u8; SIZE + 1];
    let mut vector = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: bytes,
    };
    let mut control = [0usize; 8];
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut vector;
    header.msg_iovlen = 1;
    if named {
        header.msg_name = (address as *const libc::sockaddr_in).cast_mut().cast();
        header.msg_namelen = size_of::<libc::sockaddr_in>() as _;
    }
    if rights {
        header.msg_control = control.as_mut_ptr().cast();
        header.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as _) } as usize;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&header);
            assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as usize;
            libc::CMSG_DATA(cmsg)
                .cast::<libc::c_int>()
                .write_unaligned(sockets.0[0]);
        }
    }
    assert_eq!(
        unsafe {
            libc::sendmsg(
                sockets.0[0],
                &header,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        },
        bytes as isize
    );
}

fn run_receive(entry: &str, case: &str) {
    malloc_abi::signal_runtime_ready_for_tests();
    assert!(
        COMMON.contains(&case) || HARDENED.contains(&case),
        "unknown case {case}"
    );
    let named = matches!(
        case,
        "name" | "name-truncated" | "name-overrun" | "name-quarantine"
    );
    let rights = matches!(case, "rights" | "rights-truncated");
    let output_fault = matches!(
        case,
        "readonly-header"
            | "readonly-flags"
            | "readonly-controllen"
            | "readonly-namelen"
            | "fallback-output-fault"
    );
    let input_fault = matches!(
        case,
        "bad-header"
            | "null-header"
            | "bad-iov"
            | "null-iov"
            | "bad-count"
            | "full-width-count"
            | "oversize"
            | "interior-overrun"
            | "quarantine"
            | "short-iov"
            | "short-header"
            | "quarantined-iov"
            | "quarantined-header"
            | "control-overrun"
            | "name-overrun"
            | "control-quarantine"
            | "name-quarantine"
            | "denied-copy"
    );
    let (sockets, address) = Sockets::new(named);
    let mut payload = Allocation::new(SIZE);
    let mut auxiliary = Allocation::new(128);
    let mut descriptor_storage = Allocation::new(if case == "short-iov" {
        size_of::<libc::iovec>() - 1
    } else {
        size_of::<libc::iovec>()
    });
    let mut header_storage = Allocation::new(if case == "short-header" {
        size_of::<libc::msghdr>() - 1
    } else {
        size_of::<libc::msghdr>()
    });
    let mapping = Mapping::new();
    let mut unaligned_header = vec![0u8; size_of::<libc::msghdr>() + 1];
    let mut unaligned_iov = vec![0u8; size_of::<libc::iovec>() + 1];
    let mut vectors = [EMPTY; 1024];
    vectors[0] = libc::iovec {
        iov_base: payload.pointer.cast(),
        iov_len: SIZE,
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = vectors.as_mut_ptr();
    header.msg_iovlen = 1;
    header.msg_flags = INITIAL_FLAGS;
    header.msg_namelen = 17; // NULL name must leave this value unchanged.
    header.msg_controllen = 23; // NULL control is returned with length zero.
    let mut capacity = SIZE;
    let mut flags = libc::MSG_DONTWAIT;
    let send_length = if case == "empty-datagram" {
        0
    } else if matches!(case, "truncation" | "truncation-length" | "oversize") || output_fault {
        SIZE + 1
    } else {
        SIZE
    };
    match case {
        "split" => {
            vectors[0].iov_len = 24;
            vectors[1] = libc::iovec {
                iov_base: payload.pointer.wrapping_add(24).cast(),
                iov_len: 40,
            };
            header.msg_iovlen = 2;
        }
        "maximum" => {
            vectors[1023] = vectors[0];
            vectors[0] = EMPTY;
            header.msg_iovlen = 1024;
        }
        "zero" => {
            header.msg_iov = ptr::null_mut();
            header.msg_iovlen = 0;
            capacity = 0;
        }
        "zero-element" => {
            vectors[0] = libc::iovec {
                iov_base: ptr::without_provenance_mut(1),
                iov_len: 0,
            };
            capacity = 0;
        }
        "truncation" | "truncation-length" => {
            vectors[0].iov_len = SIZE / 2;
            capacity = SIZE / 2;
        }
        "peek" => {
            flags |= libc::MSG_PEEK;
        }
        "bad-iov" => {
            header.msg_iov = ptr::without_provenance_mut(1);
        }
        "null-iov" => {
            header.msg_iov = ptr::null_mut();
        }
        "bad-count" => {
            header.msg_iovlen = 1025;
        }
        "full-width-count" => {
            header.msg_iovlen = usize::MAX;
        }
        "oversize" => {
            vectors[0].iov_len = SIZE + 1;
        }
        "interior-overrun" => {
            vectors[0].iov_base = payload.pointer.wrapping_add(32).cast();
            vectors[0].iov_len = 33;
        }
        "quarantine" => {
            payload.quarantine();
        }
        _ => {}
    }
    if case == "truncation-length" {
        flags |= libc::MSG_TRUNC;
    }
    if rights || matches!(case, "control-overrun" | "control-quarantine") {
        header.msg_control = auxiliary.pointer.cast();
        header.msg_controllen = if case == "rights-truncated" {
            1
        } else if case == "control-overrun" {
            auxiliary.bytes + 1
        } else {
            auxiliary.bytes
        };
        if rights {
            flags |= libc::MSG_CMSG_CLOEXEC;
        }
        if case == "control-quarantine" {
            auxiliary.quarantine();
        }
    }
    if named || case == "readonly-namelen" {
        header.msg_name = auxiliary.pointer.cast();
        header.msg_namelen = if case == "name-truncated" {
            2
        } else if case == "name-overrun" {
            auxiliary.bytes as libc::socklen_t + 1
        } else {
            auxiliary.bytes as libc::socklen_t
        };
        if case == "name-quarantine" {
            auxiliary.quarantine();
        }
    }
    if matches!(case, "short-iov" | "quarantined-iov") {
        unsafe {
            ptr::copy_nonoverlapping(
                vectors.as_ptr().cast::<u8>(),
                descriptor_storage.pointer,
                descriptor_storage.bytes,
            )
        };
        header.msg_iov = descriptor_storage.pointer.cast();
        if case == "quarantined-iov" {
            descriptor_storage.quarantine();
        }
    }
    if case == "unaligned-iov" {
        unsafe {
            ptr::copy_nonoverlapping(
                vectors.as_ptr().cast::<u8>(),
                unaligned_iov.as_mut_ptr().add(1),
                size_of::<libc::iovec>(),
            )
        };
        header.msg_iov = unaligned_iov.as_mut_ptr().wrapping_add(1).cast();
    }
    if case == "readonly-iov" {
        unsafe { ptr::copy_nonoverlapping(vectors.as_ptr(), mapping.pointer.cast(), 1) };
        header.msg_iov = mapping.pointer.cast();
        mapping.readonly(0, 1);
    }
    let original_pointers = (
        header.msg_name,
        header.msg_iov,
        header.msg_iovlen,
        header.msg_control,
    );
    let original_lengths = (header.msg_namelen, header.msg_controllen);
    let original_vectors: Vec<_> = vectors.iter().map(|v| (v.iov_base, v.iov_len)).collect();
    let mut submitted: *mut libc::msghdr = &mut header;
    if case == "unaligned-header" {
        submitted = unaligned_header.as_mut_ptr().wrapping_add(1).cast();
        unsafe {
            ptr::copy_nonoverlapping(
                (&header as *const libc::msghdr).cast::<u8>(),
                submitted.cast(),
                size_of::<libc::msghdr>(),
            )
        };
    }
    if matches!(case, "short-header" | "quarantined-header") {
        unsafe {
            ptr::copy_nonoverlapping(
                (&header as *const libc::msghdr).cast::<u8>(),
                header_storage.pointer,
                header_storage.bytes,
            )
        };
        submitted = header_storage.pointer.cast();
        if case == "quarantined-header" {
            header_storage.quarantine();
        }
    }
    if output_fault {
        submitted = mapping.header();
        unsafe { ptr::copy_nonoverlapping(&header, submitted, 1) };
        match case {
            "readonly-flags" => mapping.readonly(1, 1),
            "readonly-controllen" | "readonly-namelen" => mapping.readonly(0, 1),
            _ => mapping.readonly(0, 2),
        }
    }
    if case == "bad-header" {
        submitted = ptr::without_provenance_mut(1);
    }
    if case == "null-header" {
        submitted = ptr::null_mut();
    }
    if case != "would-block" {
        enqueue(&sockets, named, &address, rights, send_length);
    }
    if matches!(case, "fallback" | "fallback-output-fault" | "denied-copy") {
        deny_copy_routes(case == "denied-copy");
    }
    let result = unsafe {
        match entry {
            "recvmsg" => socket_abi::recvmsg(sockets.0[1], submitted, flags),
            "__recvmsg" => socket_abi::__recvmsg(sockets.0[1], submitted, flags),
            _ => panic!("unknown entry {entry}"),
        }
    };
    let error = unsafe { *errno_abi::__errno_location() };
    if input_fault {
        assert_eq!(
            result, -1,
            "{entry}/{case}: rejected input reached socket I/O"
        );
        let expected = match case {
            "bad-count" | "full-width-count" => libc::EMSGSIZE,
            "denied-copy" => libc::EPERM,
            _ => libc::EFAULT,
        };
        assert_eq!(error, expected, "{entry}/{case}: errno");
        let (queued, _, data) = sockets.drain();
        assert_eq!(
            queued, send_length as isize,
            "{entry}/{case}: rejection consumed queued data"
        );
        assert_eq!(&data[..send_length], &vec![0x57; send_length]);
        if payload.live {
            payload.assert_bytes(0);
        }
        if auxiliary.live {
            for index in 0..auxiliary.bytes {
                assert_eq!(unsafe { auxiliary.pointer.add(index).read() }, MARKER);
            }
        }
        return;
    }
    // All remaining submitted headers have fully initialized, readable backing
    // storage, including the deliberately unaligned and read-only variants.
    let returned = unsafe { submitted.read_unaligned() };
    assert_eq!(
        (
            returned.msg_name,
            returned.msg_iov,
            returned.msg_iovlen,
            returned.msg_control
        ),
        original_pointers,
        "{entry}/{case}: receive overwrote an input pointer/count"
    );
    assert_eq!(
        vectors
            .iter()
            .map(|v| (v.iov_base, v.iov_len))
            .collect::<Vec<_>>(),
        original_vectors
    );
    if output_fault {
        assert_eq!(result, -1, "{entry}/{case}: output write fault was lost");
        assert_eq!(error, libc::EFAULT);
        assert_eq!(
            returned.msg_flags,
            if case == "readonly-controllen" {
                libc::MSG_TRUNC
            } else {
                INITIAL_FLAGS
            }
        );
        assert_eq!(
            (returned.msg_namelen, returned.msg_controllen),
            original_lengths
        );
        payload.assert_bytes(SIZE);
    } else if case == "would-block" {
        assert_eq!(result, -1);
        assert_eq!(error, libc::EAGAIN);
        assert_eq!(returned.msg_flags, INITIAL_FLAGS);
        assert_eq!(
            (returned.msg_namelen, returned.msg_controllen),
            original_lengths
        );
        payload.assert_bytes(0);
    } else {
        let written = capacity.min(send_length);
        let expected = if case == "truncation-length" {
            send_length
        } else {
            written
        };
        assert_eq!(
            result, expected as isize,
            "{entry}/{case}: receive errno={error}"
        );
        payload.assert_bytes(written);
        assert_eq!(
            returned.msg_flags & libc::MSG_TRUNC,
            if send_length > capacity {
                libc::MSG_TRUNC
            } else {
                0
            },
            "{entry}/{case}: flags not copied back"
        );
        if case == "rights" {
            // Close the installed descriptor before checking ancillary metadata.
            let control = unsafe { libc::CMSG_FIRSTHDR(&returned) };
            assert!(!control.is_null());
            let fd = unsafe {
                libc::CMSG_DATA(control)
                    .cast::<libc::c_int>()
                    .read_unaligned()
            };
            let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(unsafe { libc::close(fd) }, 0);
            assert!(fd_flags >= 0 && fd_flags & libc::FD_CLOEXEC != 0);
            assert_eq!(unsafe { (*control).cmsg_level }, libc::SOL_SOCKET);
            assert_eq!(unsafe { (*control).cmsg_type }, libc::SCM_RIGHTS);
            assert_eq!(returned.msg_controllen, unsafe {
                libc::CMSG_SPACE(size_of::<libc::c_int>() as _)
            } as usize);
            assert_eq!(returned.msg_flags & libc::MSG_CTRUNC, 0);
        } else {
            assert_eq!(
                returned.msg_controllen, 0,
                "{entry}/{case}: control length not copied back"
            );
            assert_eq!(
                returned.msg_flags & libc::MSG_CTRUNC,
                if case == "rights-truncated" {
                    libc::MSG_CTRUNC
                } else {
                    0
                }
            );
        }
        if named {
            assert_eq!(
                returned.msg_namelen as usize,
                size_of::<libc::sockaddr_in>()
            );
            let family = unsafe {
                auxiliary
                    .pointer
                    .cast::<libc::sa_family_t>()
                    .read_unaligned()
            };
            assert_eq!(family as libc::c_int, libc::AF_INET);
            let address_bytes = if case == "name-truncated" {
                2
            } else {
                size_of::<libc::sockaddr_in>()
            };
            for index in address_bytes..auxiliary.bytes {
                assert_eq!(unsafe { auxiliary.pointer.add(index).read() }, MARKER);
            }
            if case == "name" {
                let source = unsafe {
                    auxiliary
                        .pointer
                        .cast::<libc::sockaddr_in>()
                        .read_unaligned()
                };
                assert_eq!(source.sin_addr.s_addr, u32::from_ne_bytes([127, 0, 0, 1]));
                assert_ne!(source.sin_port, 0);
            }
        } else {
            assert_eq!(returned.msg_namelen, original_lengths.0);
        }
    }
    let (queued, queue_error, data) = sockets.drain();
    if case == "peek" {
        assert_eq!(queued, send_length as isize);
        assert_eq!(&data[..send_length], &vec![0x57; send_length]);
    } else {
        assert_eq!(
            queued, -1,
            "{entry}/{case}: completed receive left a datagram queued"
        );
        assert_eq!(queue_error, libc::EAGAIN);
    }
    // Explicitly keep every raw-pointer backing allocation alive through I/O.
    drop((
        descriptor_storage,
        header_storage,
        auxiliary,
        mapping,
        unaligned_header,
        unaligned_iov,
    ));
}

#[test]
fn recvmsg_bounds_matrix() {
    if let Ok(selection) = std::env::var(CHILD) {
        let (entry, case) = selection.split_once(':').expect("entry:case");
        run_receive(entry, case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    let mut executed = 0;
    for entry in ["recvmsg", "__recvmsg"] {
        for mode in ["strict", "hardened"] {
            for &case in COMMON
                .iter()
                .chain(if mode == "hardened" { HARDENED } else { &[] }.iter())
            {
                let mut child = Command::new(&executable)
                    .args([
                        "--exact",
                        "recvmsg_bounds_matrix",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, format!("{entry}:{case}"))
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("start receive case");
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
                executed += 1;
                let stdout = String::from_utf8_lossy(&output.stdout);
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
    assert_eq!(executed, 136);
    println!("136 isolated recvmsg ABI cases passed");
}
