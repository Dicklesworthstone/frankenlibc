#![cfg(target_os = "linux")]

//! Compile the production importer and receive-output copier, not a model.
use std::mem::{offset_of, size_of};
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
#[path = "../src/msg_snapshot.rs"]
mod msg_snapshot;

fn returned_message(named: bool) -> msg_snapshot::PreparedMessage {
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    if named {
        // No bytes are read from this optional, zero-length region by prepare.
        header.msg_name = ptr::without_provenance_mut(1);
    }
    let mut prepared = msg_snapshot::PreparedMessage::prepare(&header).unwrap();
    // Simulate the scalar results written by recvmsg to our owned header.
    unsafe {
        let imported = prepared.as_mut_ptr();
        (*imported).msg_namelen = 31;
        (*imported).msg_flags = libc::MSG_TRUNC;
        (*imported).msg_controllen = 29;
    }
    prepared
}

fn scalar_bytes_only(named: bool) {
    let prepared = returned_message(named);
    let mut bytes = vec![0xa5u8; size_of::<libc::msghdr>() + 2];
    let mut expected = bytes.clone();
    let mut write_expected = |offset: usize, value: &[u8]| {
        expected[1 + offset..1 + offset + value.len()].copy_from_slice(value);
    };
    if named {
        write_expected(offset_of!(libc::msghdr, msg_namelen), &(31 as libc::socklen_t).to_ne_bytes());
    }
    write_expected(offset_of!(libc::msghdr, msg_flags), &libc::MSG_TRUNC.to_ne_bytes());
    write_expected(offset_of!(libc::msghdr, msg_controllen), &29usize.to_ne_bytes());
    // Deliberately unaligned. The byte array is initialized, not borrowed as a
    // msghdr; all non-output bytes (including pointers and padding) must survive.
    let target = bytes.as_mut_ptr().wrapping_add(1).cast();
    unsafe { prepared.copy_received_outputs(target) }.unwrap();
    assert_eq!(bytes, expected, "copy-back changed an input field or padding");
}

#[test]
fn copy_back_changes_only_named_output_scalars() { scalar_bytes_only(true); }

#[test]
fn null_name_leaves_namelen_and_all_pointer_bytes_untouched() { scalar_bytes_only(false); }

#[test]
fn invalid_output_addresses_are_fault_checked() {
    let prepared = returned_message(false);
    for address in [0usize, 1, usize::MAX - 3] {
        assert_eq!(
            unsafe { prepared.copy_received_outputs(ptr::without_provenance_mut(address)) },
            Err(libc::EFAULT),
        );
    }
}

#[test]
fn copy_back_preserves_errno_on_success_and_fault() {
    let prepared = returned_message(false);
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    unsafe {
        *libc::__errno_location() = libc::EDOM;
        prepared.copy_received_outputs(&mut header).unwrap();
        assert_eq!(*libc::__errno_location(), libc::EDOM);
        assert_eq!(prepared.copy_received_outputs(ptr::without_provenance_mut(1)), Err(libc::EFAULT));
        assert_eq!(*libc::__errno_location(), libc::EDOM);
    }
}

struct Pages { base: *mut u8, page: usize }
impl Pages {
    fn new() -> Self {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page > 0);
        let page = page as usize;
        let base = unsafe {
            libc::mmap(ptr::null_mut(), page * 2, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(base, libc::MAP_FAILED);
        unsafe { base.cast::<u8>().write_bytes(0x51, page * 2) };
        Self { base: base.cast(), page }
    }
    fn target(&self) -> *mut libc::msghdr {
        self.base.wrapping_add(self.page - offset_of!(libc::msghdr, msg_flags)).cast()
    }
    fn readonly(&self, page: usize) {
        assert_eq!(unsafe {
            libc::mprotect(self.base.wrapping_add(page * self.page).cast(), self.page, libc::PROT_READ)
        }, 0);
    }
    fn flags(&self) -> libc::c_int {
        unsafe { self.target().cast::<u8>().add(offset_of!(libc::msghdr, msg_flags)).cast::<libc::c_int>().read_unaligned() }
    }
    fn control_len(&self) -> usize {
        unsafe { self.target().cast::<u8>().add(offset_of!(libc::msghdr, msg_controllen)).cast::<usize>().read_unaligned() }
    }
}
impl Drop for Pages {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::munmap(self.base.cast(), self.page * 2) }, 0);
    }
}

#[test]
fn flags_are_published_before_a_control_length_fault() {
    let prepared = returned_message(false);
    let pages = Pages::new();
    let original_control = pages.control_len();
    pages.readonly(0); // controllen read-only, flags writable
    assert_eq!(unsafe { prepared.copy_received_outputs(pages.target()) }, Err(libc::EFAULT));
    assert_eq!(pages.flags(), libc::MSG_TRUNC);
    assert_eq!(pages.control_len(), original_control);
}

#[test]
fn a_flags_fault_does_not_publish_control_length() {
    let prepared = returned_message(false);
    let pages = Pages::new();
    let (original_flags, original_control) = (pages.flags(), pages.control_len());
    pages.readonly(1); // flags read-only, controllen writable
    assert_eq!(unsafe { prepared.copy_received_outputs(pages.target()) }, Err(libc::EFAULT));
    assert_eq!(pages.flags(), original_flags);
    assert_eq!(pages.control_len(), original_control);
}

#[test]
fn a_name_length_fault_stops_before_flags() {
    let prepared = returned_message(true);
    let pages = Pages::new();
    let original_flags = pages.flags();
    pages.readonly(0);
    assert_eq!(unsafe { prepared.copy_received_outputs(pages.target()) }, Err(libc::EFAULT));
    assert_eq!(pages.flags(), original_flags);
}

#[test]
fn copy_back_never_installs_the_owned_iovec_pointer() {
    let mut payload = [0u8; 64];
    let mut vector = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 64 };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = &mut vector;
    header.msg_iovlen = 1;
    let original_vector = header.msg_iov;
    let mut prepared = msg_snapshot::PreparedMessage::prepare(&header).unwrap();
    let imported = prepared.as_mut_ptr();
    assert_ne!(unsafe { (*imported).msg_iov }, original_vector);
    unsafe {
        (*imported).msg_flags = libc::MSG_TRUNC;
        (*imported).msg_controllen = 0;
        prepared.copy_received_outputs(&mut header).unwrap();
    }
    assert_eq!(header.msg_iov, original_vector);
    assert_eq!(header.msg_iovlen, 1);
    assert_eq!(header.msg_flags, libc::MSG_TRUNC);
    assert_eq!(vector.iov_len, 64);
    assert_eq!(vector.iov_base, payload.as_mut_ptr().cast());
}
