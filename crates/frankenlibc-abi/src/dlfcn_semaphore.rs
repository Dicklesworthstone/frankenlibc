//! One semaphore runtime for native plugins, with exact symbol versions.
use crate::{glibc_internal_abi, unistd_abi as sem};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let function = match name {
        "sem_open" => sem::sem_open as *const (),
        "sem_close" => sem::sem_close as *const (),
        "sem_unlink" => sem::sem_unlink as *const (),
        "sem_init" => sem::sem_init as *const (),
        "sem_destroy" => sem::sem_destroy as *const (),
        "sem_post" => sem::sem_post as *const (),
        "sem_wait" => sem::sem_wait as *const (),
        "sem_trywait" => sem::sem_trywait as *const (),
        "sem_timedwait" => sem::sem_timedwait as *const (),
        "sem_clockwait" => glibc_internal_abi::sem_clockwait as *const (),
        "sem_getvalue" => sem::sem_getvalue as *const (),
        _ => return None,
    };
    let first = if name == "sem_clockwait" {
        "GLIBC_2.30"
    } else if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    if version.is_some_and(|v| v != first && v != "GLIBC_2.34") {
        return None;
    }
    Some(function as usize as u64)
}
