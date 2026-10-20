#![cfg(target_os = "linux")]
//! These imports compile the production source and use the real tracker.
use std::mem::size_of;
use std::ptr;

mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
#[path = "../src/sockaddr_snapshot.rs"]
mod sockaddr_snapshot;
use sockaddr_snapshot::PreparedSockaddr;

#[test]
fn changed_caller_length_cannot_enlarge_the_submitted_capacity() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0);
    let mut address = [0xa5u8; 128];
    let mut length = 2;
    let mut prepared = PreparedSockaddr::prepare(address.as_mut_ptr().cast(), &mut length).unwrap();
    length = 128;
    std::hint::black_box(&length);
    let result =
        unsafe { libc::getsockname(fd, address.as_mut_ptr().cast(), prepared.as_mut_ptr()) };
    unsafe { libc::close(fd) };
    assert_eq!(result, 0);
    assert!(
        address[2..].iter().all(|&b| b == 0xa5),
        "changed caller capacity reached kernel"
    );
    unsafe { prepared.publish() }.unwrap();
    assert_eq!(length as usize, size_of::<libc::sockaddr_in>());
    assert_eq!(
        libc::sa_family_t::from_ne_bytes([address[0], address[1]]) as libc::c_int,
        libc::AF_INET
    );
}

#[test]
fn bad_length_addresses_are_fault_checked() {
    let mut address = [0u8; 128];
    for bad in [0, 1, usize::MAX - 1] {
        assert!(matches!(
            PreparedSockaddr::prepare(
                address.as_mut_ptr().cast(),
                ptr::without_provenance_mut(bad)
            ),
            Err(libc::EFAULT)
        ));
    }
}

#[test]
fn null_optional_address_never_reads_or_publishes_length() {
    let bad = ptr::without_provenance_mut(1);
    let mut prepared = PreparedSockaddr::prepare(ptr::null_mut(), bad).unwrap();
    assert_eq!(prepared.as_mut_ptr(), bad);
    assert_eq!(unsafe { prepared.publish() }, Ok(()));
}

#[test]
fn unaligned_length_is_imported_and_published_without_references() {
    let mut address = [0u8; 128];
    let mut storage = [0xa5u8; 12];
    let shift = (5 - storage.as_ptr() as usize % 4) % 4;
    let length = storage
        .as_mut_ptr()
        .wrapping_add(shift)
        .cast::<libc::socklen_t>();
    assert_ne!(length as usize % 4, 0);
    unsafe { length.write_unaligned(8) };
    let mut prepared = PreparedSockaddr::prepare(address.as_mut_ptr().cast(), length).unwrap();
    unsafe {
        prepared.as_mut_ptr().write(16);
        prepared.publish().unwrap();
    }
    assert_eq!(unsafe { length.read_unaligned() }, 16);
    assert!(
        storage[..shift]
            .iter()
            .chain(storage[shift + 4..].iter())
            .all(|&b| b == 0xa5)
    );
}

#[test]
fn negative_lengths_are_left_for_the_kernel_to_reject() {
    let mut length = u32::MAX;
    let mut prepared =
        PreparedSockaddr::prepare(ptr::without_provenance_mut(usize::MAX - 1), &mut length)
            .unwrap();
    assert_eq!(unsafe { *prepared.as_mut_ptr() }, u32::MAX);
}

#[test]
fn output_pointer_wrap_is_rejected() {
    let mut length = 4;
    assert!(matches!(
        PreparedSockaddr::prepare(ptr::without_provenance_mut(usize::MAX - 1), &mut length),
        Err(libc::EFAULT)
    ));
}

#[test]
fn publish_preserves_host_errno() {
    let mut address = [0u8; 128];
    let mut length = 8;
    let mut prepared = PreparedSockaddr::prepare(address.as_mut_ptr().cast(), &mut length).unwrap();
    unsafe {
        *libc::__errno_location() = libc::EDOM;
        prepared.as_mut_ptr().write(16);
        prepared.publish().unwrap();
        assert_eq!(*libc::__errno_location(), libc::EDOM);
    }
    assert_eq!(length, 16);
}

#[test]
fn original_path_does_not_import_or_copy() {
    let mut length = 23;
    let mut prepared = PreparedSockaddr::original(&mut length);
    assert_eq!(prepared.as_mut_ptr(), &mut length as *mut _);
    assert_eq!(unsafe { prepared.publish() }, Ok(()));
    assert_eq!(length, 23);
}
