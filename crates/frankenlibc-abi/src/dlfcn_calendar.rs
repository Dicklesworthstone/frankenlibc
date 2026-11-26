//! Calendar conversion and timezone state for native ELF objects.
//!
//! Native callers use the ordinary ABI's timezone cache, locale selection and
//! borrowed result storage. The three public timezone objects are addresses of
//! that same runtime state, not copies of values or host-libc data symbols.

use crate::{glibc_internal_abi as internal, time_abi as time, unistd_abi as unistd};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    let locale_version = if cfg!(target_arch = "aarch64") {
        baseline
    } else {
        "GLIBC_2.3"
    };
    let (address, expected_version) = match name {
        "gmtime" => (time::gmtime as *const (), baseline),
        "gmtime_r" => (time::gmtime_r as *const (), baseline),
        "localtime" => (time::localtime as *const (), baseline),
        "localtime_r" => (time::localtime_r as *const (), baseline),
        "mktime" => (time::mktime as *const (), baseline),
        "timegm" => (time::timegm as *const (), baseline),
        "timelocal" => (unistd::timelocal as *const (), baseline),
        "difftime" => (time::difftime as *const (), baseline),
        "asctime" => (time::asctime as *const (), baseline),
        "asctime_r" => (time::asctime_r as *const (), baseline),
        "ctime" => (time::ctime as *const (), baseline),
        "ctime_r" => (time::ctime_r as *const (), baseline),
        "tzset" => (time::tzset as *const (), baseline),
        "strftime" => (time::strftime as *const (), baseline),
        "strftime_l" => (unistd::strftime_l as *const (), locale_version),
        "strptime" => (time::strptime as *const (), baseline),
        "tzname" => ((&raw mut internal::tzname) as *const (), baseline),
        "timezone" => ((&raw mut internal::timezone) as *const (), baseline),
        "daylight" => ((&raw mut internal::daylight) as *const (), baseline),
        _ => return None,
    };
    version
        .is_none_or(|version| version == expected_version)
        .then_some(address as usize as u64)
}
