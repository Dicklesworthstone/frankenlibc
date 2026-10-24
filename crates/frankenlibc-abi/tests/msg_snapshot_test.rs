#![cfg(target_os = "linux")]

//! Compile the exact production header/vector importer, not a model of it.
mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
#[path = "../src/msg_snapshot.rs"]
mod msg_snapshot;

#[test]
fn header_and_vector_mutation_cannot_change_the_submitted_graph() {
    let mut payload = [0x39u8; 64];
    let mut vector = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 64 };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut vector;
    header.msg_iovlen = 1;
    let mut prepared = msg_snapshot::PreparedMessage::prepare(&header).unwrap();
    // Modify both levels after import. The submitted graph must retain neither.
    vector.iov_len = usize::MAX;
    header.msg_iov = std::ptr::without_provenance_mut(1);
    header.msg_iovlen = usize::MAX;
    std::hint::black_box((&header, &vector));
    let submitted = prepared.as_mut_ptr();
    assert_ne!(submitted.cast_const(), &header as *const _);
    let imported = unsafe { &*submitted };
    assert_eq!(imported.msg_iovlen, 1);
    assert_ne!(imported.msg_iov, &mut vector as *mut _);
    assert_eq!(unsafe { (*imported.msg_iov).iov_len }, 64);
    assert_eq!(unsafe { (*imported.msg_iov).iov_base }, payload.as_mut_ptr().cast());
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) }, 0);
    let result = unsafe { libc::sendmsg(fds[0], submitted, libc::MSG_DONTWAIT) };
    let mut received = [0u8; 65];
    let count = unsafe { libc::recv(fds[1], received.as_mut_ptr().cast(), received.len(), libc::MSG_DONTWAIT) };
    unsafe { libc::close(fds[0]); libc::close(fds[1]); }
    assert_eq!(result, 64);
    assert_eq!(count, 64);
    assert_eq!(&received[..64], &payload);
}

#[test]
fn header_import_reports_unreadable_memory_without_dereferencing_it() {
    assert!(matches!(msg_snapshot::PreparedMessage::prepare(std::ptr::without_provenance(1)),
        Err(libc::EFAULT)));
    assert!(matches!(msg_snapshot::PreparedMessage::prepare(std::ptr::null()),
        Err(libc::EFAULT)));
}

#[test]
fn generic_kernel_copy_checks_both_ends_and_preserves_host_errno() {
    let source = [0x61u8; 17];
    let mut destination = [0u8; 18];
    unsafe {
        *libc::__errno_location() = libc::EDOM;
        iov_snapshot::copy_user_bytes(source.as_ptr(), destination.as_mut_ptr().add(1), 17).unwrap();
        assert_eq!(*libc::__errno_location(), libc::EDOM);
        assert_eq!(iov_snapshot::copy_user_bytes(source.as_ptr(), std::ptr::without_provenance_mut(1), 17),
            Err(libc::EFAULT));
        assert_eq!(*libc::__errno_location(), libc::EDOM);
        assert_eq!(iov_snapshot::copy_user_bytes(std::ptr::without_provenance(1), destination.as_mut_ptr(), 17),
            Err(libc::EFAULT));
        assert_eq!(iov_snapshot::copy_user_bytes(std::ptr::null(), std::ptr::null_mut(), 0), Ok(()));
    }
    assert_eq!(destination[0], 0);
    assert_eq!(&destination[1..], &source);
}
