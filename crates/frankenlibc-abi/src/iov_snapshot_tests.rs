use super::*;

fn expect_error(result: Result<PreparedIovecs, c_int>, expected: c_int) {
    match result {
        Ok(_) => panic!("descriptor import unexpectedly succeeded"),
        Err(error) => assert_eq!(error, expected),
    }
}

#[test]
fn strict_path_does_not_import_caller_memory() {
    let invalid = ptr::without_provenance::<libc::iovec>(1);
    let prepared = PreparedIovecs::prepare(invalid, 1, false).unwrap();
    assert_eq!(prepared.as_ptr(), invalid);
}

#[test]
fn empty_invalid_counts_and_null_arrays_remain_kernel_inputs() {
    let invalid = ptr::without_provenance::<libc::iovec>(1);
    for count in [-1, 0, 1025, c_int::MAX] {
        let prepared = PreparedIovecs::prepare(invalid, count, true).unwrap();
        assert_eq!(prepared.as_ptr(), invalid);
    }
    assert!(
        PreparedIovecs::prepare(ptr::null(), 1, true)
            .unwrap()
            .as_ptr()
            .is_null()
    );
}

#[test]
fn stack_descriptors_do_not_bypass_tracked_buffer_bounds() {
    let mut payload = [0u8; 16];
    let base = payload.as_mut_ptr().cast::<c_void>();
    let iov = [libc::iovec {
        iov_base: base,
        iov_len: 17,
    }];
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 1, |address| {
            (address == base as usize).then_some(16)
        }),
        errno::EFAULT,
    );
}

#[test]
fn explicit_rejection_cannot_become_untracked_permission() {
    let mut payload = [0u8; 16];
    let base = payload.as_mut_ptr().cast::<c_void>();
    let iov = [libc::iovec {
        iov_base: base,
        iov_len: 1,
    }];
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 1, |address| {
            (address == base as usize).then_some(0)
        }),
        errno::EFAULT,
    );
}

#[test]
fn descriptor_extent_is_checked_before_import() {
    let iov = [EMPTY_IOVEC; 2];
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 2, |address| {
            (address == iov.as_ptr() as usize).then_some(size_of::<libc::iovec>())
        }),
        errno::EFAULT,
    );
}

#[test]
fn zero_length_entries_do_not_access_even_rejected_or_null_bases() {
    let iov = [
        EMPTY_IOVEC,
        libc::iovec {
            iov_base: ptr::without_provenance_mut::<c_void>(1),
            iov_len: 0,
        },
    ];
    let prepared = PreparedIovecs::snapshot_with(iov.as_ptr(), 2, |address| {
        if address == iov.as_ptr() as usize {
            None
        } else {
            Some(0)
        }
    })
    .unwrap();
    assert_eq!(prepared.entries().len(), 2);
}

#[test]
fn nonzero_null_buffers_are_rejected() {
    let iov = [libc::iovec {
        iov_base: ptr::null_mut(),
        iov_len: 1,
    }];
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 1, |_| None),
        errno::EFAULT,
    );
}

#[test]
fn overflowing_buffer_addresses_are_rejected() {
    let iov = [libc::iovec {
        iov_base: ptr::without_provenance_mut::<c_void>(usize::MAX - 1),
        iov_len: 8,
    }];
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 1, |_| None),
        errno::EFAULT,
    );
}

#[test]
fn aggregate_length_must_fit_ssize_t() {
    let iov = [
        libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: isize::MAX as usize,
        },
        libc::iovec {
            iov_base: ptr::null_mut(),
            iov_len: 1,
        },
    ];
    // Length validation precedes dereference/null/bounds decisions, as it does
    // during Linux's iovec import. No payload is accessed in this test.
    expect_error(
        PreparedIovecs::snapshot_with(iov.as_ptr(), 2, |_| None),
        errno::EINVAL,
    );
}

#[test]
fn unaligned_caller_descriptors_are_imported_without_rust_references() {
    let mut bytes = [0u8; size_of::<libc::iovec>() + 1];
    let source = bytes.as_mut_ptr().wrapping_add(1).cast::<libc::iovec>();
    // SAFETY: bytes contains enough writable storage; write_unaligned does not
    // impose iovec alignment on this intentionally unaligned kernel input.
    unsafe { source.write_unaligned(EMPTY_IOVEC) };
    let prepared = PreparedIovecs::snapshot_with(source, 1, |_| None).unwrap();
    assert_eq!(prepared.entries()[0].iov_len, 0);
    assert_ne!(prepared.as_ptr(), source.cast_const());
}

#[test]
fn descriptor_mutation_after_import_does_not_change_submitted_io() {
    let original_payload = [b'o', b'k'];
    let replacement_payload = [b'n', b'o'];
    let mut iov = [libc::iovec {
        iov_base: original_payload.as_ptr().cast_mut().cast(),
        iov_len: 2,
    }];
    let prepared = PreparedIovecs::snapshot_with(iov.as_ptr(), 1, |_| None).unwrap();
    iov[0].iov_base = replacement_payload.as_ptr().cast_mut().cast();
    assert_ne!(iov[0].iov_base, prepared.entries()[0].iov_base);

    let mut fds = [-1; 2];
    // SAFETY: both output descriptors fit fds. Subsequent I/O uses live buffers
    // and these owned descriptors, closed before assertions on the result.
    unsafe { syscall::sys_pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }.unwrap();
    let written = unsafe { syscall::sys_writev(fds[1], prepared.as_ptr().cast(), 1) };
    let mut output = [0u8; 2];
    let read = if written == Ok(2) {
        unsafe { syscall::sys_read(fds[0], output.as_mut_ptr(), output.len()) }
    } else {
        Err(errno::EIO)
    };
    unsafe {
        syscall::syscall1(libc::SYS_close as usize, fds[0] as usize);
        syscall::syscall1(libc::SYS_close as usize, fds[1] as usize);
    }
    assert_eq!(written, Ok(2));
    assert_eq!(read, Ok(2));
    assert_eq!(output, original_payload);
}

#[test]
fn maximum_sized_import_uses_owned_mapping() {
    let iov = [EMPTY_IOVEC; MAX_IOVECS];
    let prepared = PreparedIovecs::snapshot_with(iov.as_ptr(), MAX_IOVECS, |_| None).unwrap();
    assert!(matches!(&prepared.storage, Storage::Mapped(_)));
    assert_eq!(prepared.entries().len(), MAX_IOVECS);
    assert_ne!(prepared.as_ptr(), iov.as_ptr());
    assert!(prepared.entries().iter().all(|entry| entry.iov_len == 0));
}

#[test]
fn inaccessible_descriptor_address_returns_efault_not_a_signal() {
    let inaccessible = ptr::without_provenance::<libc::iovec>(1);
    expect_error(
        PreparedIovecs::snapshot_with(inaccessible, 1, |_| None),
        errno::EFAULT,
    );
}

#[test]
fn incomplete_descriptor_import_is_rejected() {
    // 64 KiB is a multiple of every Linux base-page size used on the supported
    // targets. Put the last descriptor across a protected mapping boundary.
    const HALF: usize = 65536;
    let mapping = Mapping::new(2 * HALF).unwrap();
    let boundary = mapping.base.cast::<u8>().wrapping_add(HALF);
    kernel_result(unsafe {
        syscall::syscall3(
            libc::SYS_mprotect as usize,
            boundary as usize,
            HALF,
            libc::PROT_NONE as usize,
        )
    })
    .unwrap();
    let source = boundary
        .wrapping_sub(size_of::<libc::iovec>() / 2)
        .cast::<libc::iovec>();
    expect_error(
        PreparedIovecs::snapshot_with(source, 1, |_| None),
        errno::EFAULT,
    );
}

#[test]
fn raw_kernel_errors_are_not_confused_with_short_reads() {
    for error in [
        errno::EFAULT,
        errno::EINTR,
        errno::EPERM,
        errno::ENOSYS,
        errno::ENOMEM,
    ] {
        assert_eq!(kernel_result((-error as isize) as usize), Err(error));
    }
    assert_eq!(kernel_result(0), Ok(0));
    assert_eq!(kernel_result(16), Ok(16));
}

#[test]
fn private_pipe_fallback_copies_descriptors_and_rejects_faults() {
    let source = [EMPTY_IOVEC; MAX_IOVECS];
    let mut destination = [EMPTY_IOVEC; MAX_IOVECS];
    let bytes = std::mem::size_of_val(&source);
    unsafe { copy_descriptors_with_pipe(source.as_ptr(), destination.as_mut_ptr(), bytes) }
        .unwrap();
    assert!(
        destination
            .iter()
            .all(|entry| entry.iov_len == 0 && entry.iov_base.is_null())
    );
    let fault = unsafe {
        copy_descriptors_with_pipe(
            ptr::without_provenance::<libc::iovec>(1),
            destination.as_mut_ptr(),
            bytes,
        )
    };
    assert_eq!(fault, Err(errno::EFAULT));
}
