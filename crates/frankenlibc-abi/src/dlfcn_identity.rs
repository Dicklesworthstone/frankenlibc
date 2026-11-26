//! Native account lookup, enumeration, and supplementary-group bindings.
//!
//! Keep selected NSS sources, borrowed result storage, enumeration cursors, and
//! caller-buffer retries in the same runtime as ordinary ABI callers.

use crate::{grp_abi as group, pwd_abi as passwd, unistd_abi as unistd};

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
        "getpwnam" => passwd::getpwnam as *const (),
        "getpwuid" => passwd::getpwuid as *const (),
        "getpwnam_r" => passwd::getpwnam_r as *const (),
        "getpwuid_r" => passwd::getpwuid_r as *const (),
        "setpwent" => passwd::setpwent as *const (),
        "getpwent" => passwd::getpwent as *const (),
        "getpwent_r" => passwd::getpwent_r as *const (),
        "endpwent" => passwd::endpwent as *const (),
        "getgrnam" => group::getgrnam as *const (),
        "getgrgid" => group::getgrgid as *const (),
        "getgrnam_r" => group::getgrnam_r as *const (),
        "getgrgid_r" => group::getgrgid_r as *const (),
        "setgrent" => group::setgrent as *const (),
        "getgrent" => group::getgrent as *const (),
        "getgrent_r" => group::getgrent_r as *const (),
        "endgrent" => group::endgrent as *const (),
        "getgrouplist" => unistd::getgrouplist as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
