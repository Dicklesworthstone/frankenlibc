use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::socket_abi;
use frankenlibc_core::errno;

#[test]
fn bind_invalid_fd_sets_ebadf_errno() {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;

    let rc = unsafe {
        socket_abi::bind(
            -1,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn send_invalid_fd_sets_ebadf_errno() {
    let byte = b'x';
    let rc = unsafe { socket_abi::send(-1, &byte as *const u8 as *const libc::c_void, 1, 0) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn recv_invalid_fd_sets_ebadf_errno() {
    let mut byte = 0u8;
    let rc = unsafe { socket_abi::recv(-1, &mut byte as *mut u8 as *mut libc::c_void, 1, 0) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}

#[test]
fn shutdown_invalid_fd_sets_ebadf_errno() {
    let rc = unsafe { socket_abi::shutdown(-1, libc::SHUT_RDWR) };
    assert_eq!(rc, -1);

    let err = unsafe { *__errno_location() };
    assert_eq!(err, errno::EBADF);
}
