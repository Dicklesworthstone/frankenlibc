//! Hosts and networks database entry points for native ELF plugins.
//!
//! Lookups, enumeration cursors, borrowed answers, and h_errno must remain in
//! the same owned runtime as ordinary ABI callers and configured NSS sources.

use crate::{inet_abi as inet, resolv_abi as resolv, unistd_abi as unistd};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    if version.is_some_and(|version| version != baseline) {
        return None;
    }
    let function = match name {
        "__h_errno_location" => resolv::__h_errno_location as *const (),
        "hstrerror" => unistd::hstrerror as *const (),
        "herror" => unistd::herror as *const (),
        "gethostbyname" => resolv::gethostbyname as *const (),
        "gethostbyname2" => unistd::gethostbyname2 as *const (),
        "gethostbyaddr" => resolv::gethostbyaddr as *const (),
        "gethostbyname_r" => inet::gethostbyname_r as *const (),
        "gethostbyname2_r" => unistd::gethostbyname2_r as *const (),
        "gethostbyaddr_r" => inet::gethostbyaddr_r as *const (),
        "sethostent" => unistd::sethostent as *const (),
        "gethostent" => unistd::gethostent as *const (),
        "gethostent_r" => unistd::gethostent_r as *const (),
        "endhostent" => unistd::endhostent as *const (),
        "getnetent" => unistd::getnetent as *const (),
        "getnetent_r" => unistd::getnetent_r as *const (),
        "getnetbyname" => unistd::getnetbyname as *const (),
        "getnetbyname_r" => unistd::getnetbyname_r as *const (),
        "getnetbyaddr" => unistd::getnetbyaddr as *const (),
        "getnetbyaddr_r" => unistd::getnetbyaddr_r as *const (),
        "setnetent" => unistd::setnetent as *const (),
        "endnetent" => unistd::endnetent as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
